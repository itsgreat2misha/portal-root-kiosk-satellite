# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.
#
# Phase D flag-consolidation pins: the --full preset expands to
# exactly the documented full-setup action set, --dns replaces the
# two DNS flags, --restore <name> replaces the nine restore flags
# and --enable-updates (old spellings are a clean break), internal
# action ids stay byte-stable, and the restore-completeness gaps
# (OTA package recorded states, system-theme original, Meta
# authenticator component actions) behave as designed.

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import cli as cli_module  # noqa: E402
import provision_portal as provision_portal_module  # noqa: E402
from device_session import ProvisionError  # noqa: E402
from features.presence import (  # noqa: E402
    PresenceConfig,
    PresenceFeature,
    SYSTEM_THEME_BACKUP_REMOTE,
)
from features.settings import (  # noqa: E402
    META_AUTHENTICATOR_COMPONENTS,
    META_AUTHENTICATOR_PACKAGE,
    SettingsConfig,
    SettingsFeature,
)
from provision_portal import (  # noqa: E402
    OTA_PACKAGES_BACKUP_REMOTE,
    OTA_SETUP_PACKAGE,
    OTA_UI_PACKAGE,
    PortalProvisioner,
)


def parse(argv: list[str]):
    stderr = io.StringIO()
    with (
        mock.patch.object(sys, "argv", ["provision_portal.py", *argv]),
        contextlib.redirect_stderr(stderr),
    ):
        return provision_portal_module.parse_args()


def parse_error(argv: list[str]) -> str:
    stderr = io.StringIO()
    with (
        mock.patch.object(sys, "argv", ["provision_portal.py", *argv]),
        contextlib.redirect_stderr(stderr),
    ):
        with unittest.TestCase().assertRaises(SystemExit):
            provision_portal_module.parse_args()
    return stderr.getvalue()


def completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess([], returncode, stdout, "")


class FullPresetTest(unittest.TestCase):
    def test_full_expands_to_exactly_the_documented_setup(self) -> None:
        arguments = parse(["--full"])
        for attribute, value in cli_module.FULL_PRESET.items():
            self.assertEqual(getattr(arguments, attribute), value, attribute)
        # The preset is exactly the documented line: audio,
        # disable-updates, block-remote-wipe, debloat,
        # remove-meta-accounts, optimize-presence, allow-app-updates,
        # disable-adb-auth-timeout, DHCP DNS, autoroot.
        self.assertEqual(
            set(cli_module.FULL_PRESET),
            {
                "audio",
                "disable_updates",
                "block_remote_wipe",
                "debloat",
                "remove_meta_accounts",
                "optimize_presence",
                "allow_app_updates",
                "disable_adb_auth_timeout",
                "dhcp_dns",
                "autoroot",
            },
        )
        # Taste opt-ins stay out of the bundle.
        self.assertIsNone(arguments.presence_fps_cap)
        self.assertIsNone(arguments.system_theme_control)
        # Autoroot's implications still apply.
        self.assertTrue(arguments.shizuku)
        self.assertIsNotNone(arguments.custom_payload)

    def test_full_rejects_a_restore_of_a_preset_feature(self) -> None:
        self.assertIn(
            "--debloat cannot be combined with --restore bloat",
            parse_error(["--full", "--restore", "bloat"]),
        )


class DnsMergeTest(unittest.TestCase):
    def test_dns_off_is_the_dhcp_mode(self) -> None:
        arguments = parse(["--dns", "off"])
        self.assertTrue(arguments.dhcp_dns)
        self.assertIsNone(arguments.privacy_dns)

    def test_dns_hostname_is_the_private_dns_mode(self) -> None:
        arguments = parse(["--dns", "one.one.one.one"])
        self.assertEqual(arguments.privacy_dns, "one.one.one.one")
        self.assertFalse(arguments.dhcp_dns)

    def test_old_dns_spellings_are_a_clean_break(self) -> None:
        for argv in (
            ["--dhcp-dns"],
            ["--privacy-dns", "one.one.one.one"],
            ["--restore-privacy-dns"],
        ):
            with self.subTest(argv=argv):
                self.assertIn("unrecognized arguments", parse_error(argv))


class FakeDnsStore:
    """adb fake modelling the Private DNS settings store (the
    on-device backup file starts absent, so each apply backs up
    the live values first)."""

    def __init__(self, mode="off", specifier="null"):
        self.mode = mode
        self.specifier = specifier

    def adb_run(self, arguments, timeout=None, check=False):
        del timeout, check
        command = " ".join(str(argument) for argument in arguments)
        if "portal-private-dns-before-v1.json" in command and "cat" in command:
            return completed("", 1)
        if "settings get global private_dns_mode" in command:
            return completed(self.mode + "\n")
        if "settings get global private_dns_specifier" in command:
            return completed(self.specifier + "\n")
        if "settings put global private_dns_mode" in command:
            self.mode = arguments[-1]
            return completed()
        if "settings put global private_dns_specifier" in command:
            self.specifier = arguments[-1]
            return completed()
        if "settings delete global private_dns_mode" in command:
            self.mode = "null"
            return completed()
        if "settings delete global private_dns_specifier" in command:
            self.specifier = "null"
            return completed()
        return completed()


class FullDnsOverrideTest(unittest.TestCase):
    """An explicit --dns replaces the --full preset's DNS
    component: the composed config carries exactly one DNS
    intent, and the shared apply + verify sequence (the DNS
    block of the shell-level apply, then the end-of-run verify)
    completes against a fake store. Before the fix, --full
    --dns HOSTNAME composed dhcp_dns=True AND privacy_dns=HOST:
    the hostname apply persisted, then the dhcp-first verify
    expectation failed the run (Defect A)."""

    def compose_and_run(self, argv, store):
        arguments = parse(argv)
        intents = [
            arguments.dhcp_dns,
            arguments.privacy_dns is not None,
            arguments.restore_privacy_dns,
        ]
        self.assertEqual(sum(bool(intent) for intent in intents), 1, argv)
        config = SettingsConfig(
            privacy_dns=arguments.privacy_dns,
            dhcp_dns=arguments.dhcp_dns,
            restore_privacy_dns=arguments.restore_privacy_dns,
        )
        feature = make_settings_feature(config, adb_run=store.adb_run)
        with contextlib.redirect_stdout(io.StringIO()):
            if config.privacy_dns:
                feature.apply_privacy_dns()
            if config.dhcp_dns:
                feature.apply_dhcp_dns()
            if config.restore_privacy_dns:
                feature.restore_private_dns()
            feature.verify_privacy_dns()
        return arguments

    def test_full_dns_hostname_yields_the_hostname_intent(self) -> None:
        store = FakeDnsStore(mode="off", specifier="null")
        arguments = self.compose_and_run(
            ["--full", "--dns", "one.one.one.one"], store
        )
        self.assertEqual(arguments.privacy_dns, "one.one.one.one")
        self.assertFalse(arguments.dhcp_dns)
        self.assertEqual(store.mode, "hostname")
        self.assertEqual(store.specifier, "one.one.one.one")

    def test_full_dns_off_yields_the_dhcp_intent(self) -> None:
        store = FakeDnsStore(mode="hostname", specifier="one.one.one.one")
        arguments = self.compose_and_run(["--full", "--dns", "off"], store)
        self.assertTrue(arguments.dhcp_dns)
        self.assertIsNone(arguments.privacy_dns)
        self.assertEqual(store.mode, "off")
        self.assertEqual(store.specifier, "null")

    def test_full_alone_keeps_the_preset_dns_intent(self) -> None:
        store = FakeDnsStore(mode="hostname", specifier="one.one.one.one")
        arguments = self.compose_and_run(["--full"], store)
        self.assertTrue(arguments.dhcp_dns)
        self.assertIsNone(arguments.privacy_dns)
        self.assertEqual(store.mode, "off")
        self.assertEqual(store.specifier, "null")


class RestoreSurfaceTest(unittest.TestCase):
    def test_every_restore_name_maps_to_its_attribute(self) -> None:
        for name, attribute in cli_module.RESTORE_FLAG_MAP.items():
            with self.subTest(name=name):
                arguments = parse(["--restore", name])
                self.assertTrue(getattr(arguments, attribute))

    def test_restore_names_and_map_cover_each_other(self) -> None:
        self.assertEqual(
            set(cli_module.RESTORE_NAMES), set(cli_module.RESTORE_FLAG_MAP)
        )

    def test_several_restores_accumulate(self) -> None:
        arguments = parse(["--restore", "audio", "--restore", "dns"])
        self.assertTrue(arguments.restore_audio)
        self.assertTrue(arguments.restore_privacy_dns)

    def test_unknown_restore_name_is_rejected(self) -> None:
        self.assertIn("invalid choice", parse_error(["--restore", "nope"]))

    def test_old_restore_spellings_are_a_clean_break(self) -> None:
        for argv in (
            ["--restore-audio"],
            ["--restore-bloat"],
            ["--restore-remote-wipe"],
            ["--enable-updates"],
            ["--restore-presence-profile"],
            ["--restore-presence-fps"],
            ["--restore-adb-auth-timeout"],
            ["--restore-app-verifier"],
            ["--restore-camera-light"],
        ):
            with self.subTest(argv=argv):
                self.assertIn("unrecognized arguments", parse_error(argv))

    def test_new_gap_restores_reject_their_apply_counterparts(self) -> None:
        self.assertIn(
            "--autoroot cannot be combined with --restore autoroot",
            parse_error(["--autoroot", "--restore", "autoroot"]),
        )
        self.assertIn(
            "--remove-meta-accounts cannot be combined with "
            "--restore meta-authenticators",
            parse_error(
                ["--remove-meta-accounts", "--restore", "meta-authenticators"]
            ),
        )
        self.assertIn(
            "--system-theme-control cannot be combined with --restore theme",
            parse_error(
                ["--system-theme-control", "dark", "--restore", "theme"]
            ),
        )


class InternalActionIdsTest(unittest.TestCase):
    def test_requested_actions_keep_existing_ids_and_gain_restores(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                dhcp_dns=True,
                enable_updates=True,
                restore_autoroot=True,
                restore_wireless_adb=True,
                restore_theme=True,
                restore_meta_authenticators=True,
            )
        self.assertEqual(
            provisioner.requested_actions(),
            {
                "dhcp_dns": True,
                "enable_updates": True,
                "restore_autoroot": True,
                "restore_wireless_adb": True,
                "restore_theme": True,
                "restore_meta_authenticators": True,
            },
        )


class OtaPackageRecordTest(unittest.TestCase):
    """The updates restore replays recorded OTA package states
    instead of enabling unconditionally; no record keeps the
    factory-default (all enabled) behavior."""

    def make_provisioner(self, temporary: str) -> PortalProvisioner:
        return PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary)
        )

    def test_record_captures_enabled_disabled_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            pushed: dict[str, str] = {}
            with (
                mock.patch.object(
                    provisioner,
                    "package_sets",
                    return_value=({OTA_UI_PACKAGE}, set()),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=completed("", returncode=1),
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: pushed.update(
                        {remote: contents}
                    ),
                ),
            ):
                provisioner.record_ota_package_states()
            states = json.loads(pushed[OTA_PACKAGES_BACKUP_REMOTE])["packages"]
            self.assertEqual(states[OTA_UI_PACKAGE], "enabled")
            self.assertEqual(states[OTA_SETUP_PACKAGE], "absent")

    def test_enable_replays_the_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            record = json.dumps(
                {
                    "packages": {
                        OTA_UI_PACKAGE: "enabled",
                        OTA_SETUP_PACKAGE: "disabled",
                    }
                }
            )
            calls: list[list[str]] = []

            def fake_adb(args, timeout=None, check=False):
                calls.append(list(args))
                if args[:2] == ["shell", "cat"]:
                    return completed(record)
                return completed("new state: disabled-user")

            with (
                mock.patch.object(provisioner, "adb_run", side_effect=fake_adb),
                mock.patch.object(provisioner, "settle_package_state"),
            ):
                provisioner.enable_ota_packages()
            joined = [" ".join(call) for call in calls]
            self.assertTrue(
                any("pm enable" in call and OTA_UI_PACKAGE in call for call in joined)
            )
            self.assertTrue(
                any(
                    "pm disable-user" in call and OTA_SETUP_PACKAGE in call
                    for call in joined
                )
            )

    def test_enable_without_a_record_enables_everything(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            calls: list[list[str]] = []

            def fake_adb(args, timeout=None, check=False):
                calls.append(list(args))
                if args[:2] == ["shell", "cat"]:
                    return completed("", returncode=1)
                return completed("new state: enabled")

            with (
                mock.patch.object(provisioner, "adb_run", side_effect=fake_adb),
                mock.patch.object(provisioner, "settle_package_state"),
            ):
                provisioner.enable_ota_packages()
            joined = [" ".join(call) for call in calls]
            self.assertTrue(any("pm enable" in call for call in joined))
            self.assertFalse(any("pm disable-user" in call for call in joined))


def make_presence_feature(
    adb_run, push_text_atomic, theme: str | None = None
) -> PresenceFeature:
    return PresenceFeature(
        config=lambda: PresenceConfig(
            system_theme_control=theme, presence_fps_cap=None
        ),
        adb_run=adb_run,
        run=lambda *a, **k: completed(),
        target=lambda: None,
        log_dir=lambda: pathlib.Path("/tmp"),
        uid1000_path=lambda name: f"/data/portal-uid1000/{name}",
        install_apk_preserving_verifier=lambda *a, **k: None,
        verify_package_verifier_state=lambda *a, **k: None,
        settle_package_state=lambda *a, **k: None,
        push_text_atomic=push_text_atomic,
        package_sets=lambda: (set(), set()),
        logcat_watermark=lambda *a, **k: None,
        logcat_poll=lambda *a, **k: "",
        adb_framework_boot_installed_remote="/tmp/adb-framework",
    )


class SystemThemeRecordTest(unittest.TestCase):
    """Gap 5: the theme apply records ui_night_mode first (first
    record wins); the restore replays the record, and with no
    record deletes the key — the verified factory default."""

    def test_record_writes_the_current_value_once(self) -> None:
        pushed: dict[str, str] = {}
        calls: list[list[str]] = []

        def fake_adb(args, timeout=None, check=False):
            calls.append(list(args))
            if "test" in args:
                # Backup absent on the first record, present after.
                return completed("", returncode=0 if pushed else 1)
            if "settings" in args:
                return completed("2")
            return completed()

        feature = make_presence_feature(
            fake_adb,
            lambda contents, remote: pushed.update({remote: contents}),
        )
        feature.record_system_theme_original()
        feature.record_system_theme_original()
        self.assertEqual(
            json.loads(pushed[SYSTEM_THEME_BACKUP_REMOTE]),
            {"ui_night_mode": "2"},
        )
        puts = [c for c in calls if "settings" in c and "put" in c]
        self.assertEqual(puts, [])

    def test_restore_replays_a_recorded_value(self) -> None:
        # On a shell-uimode target (the harness target) the
        # recorded mode is restored through the uimode transport,
        # which writes the key itself — a bare settings put never
        # transitions the manager (Defect F).
        calls: list[list[str]] = []

        def fake_adb(args, timeout=None, check=False):
            calls.append(list(args))
            if "cat" in args:
                return completed(json.dumps({"ui_night_mode": "1"}))
            return completed()

        feature = make_presence_feature(fake_adb, lambda c, r: None)
        feature.restore_system_theme()
        self.assertIn(
            ["shell", "cmd", "uimode", "night", "no"],
            calls,
        )
        self.assertFalse(
            any(
                "settings" in call and "put" in call for call in calls
            )
        )

    def test_restore_without_a_record_deletes_the_key(self) -> None:
        calls: list[list[str]] = []

        def fake_adb(args, timeout=None, check=False):
            calls.append(list(args))
            return completed("", returncode=1)

        feature = make_presence_feature(fake_adb, lambda c, r: None)
        feature.restore_system_theme()
        self.assertIn(
            ["shell", "settings", "delete", "secure", "ui_night_mode"],
            calls,
        )

    def test_restore_of_a_recorded_absence_deletes_the_key(self) -> None:
        calls: list[list[str]] = []

        def fake_adb(args, timeout=None, check=False):
            calls.append(list(args))
            if "cat" in args:
                return completed(json.dumps({"ui_night_mode": None}))
            return completed()

        feature = make_presence_feature(fake_adb, lambda c, r: None)
        feature.restore_system_theme()
        self.assertIn(
            ["shell", "settings", "delete", "secure", "ui_night_mode"],
            calls,
        )


class SystemThemePreflightRecordOrderTest(unittest.TestCase):
    """Defect E side finding: the theme preflight APPLIES the
    theme as its already-configured probe, and the channel gate
    calls it before the stages path's own record step — so on
    the channel route the recorded-original tier could never
    engage, and a first channel apply overwrote the original
    before anyone recorded it. The preflight records the
    original at the apply point, before applying, so every
    route is covered."""

    def test_preflight_records_the_original_before_applying(
        self,
    ) -> None:
        events: list[str] = []
        pushed: dict[str, str] = {}
        live = {"night_mode": "1"}

        def fake_adb(args, timeout=None, check=False):
            del timeout, check
            if "test" in args:
                # Backup absent until the record pushes it.
                return completed("", returncode=0 if pushed else 1)
            if "uimode" in args:
                if args[-1] in {"yes", "no", "auto"}:
                    events.append("apply")
                    live["night_mode"] = "2" if args[-1] == "yes" else "1"
                    return completed()
                # Query form: report the manager state.
                return completed(
                    "Night mode: yes"
                    if live["night_mode"] == "2"
                    else "Night mode: no"
                )
            if "settings" in args and "get" in args:
                return completed(live["night_mode"])
            return completed()

        def push(contents, remote):
            events.append("record")
            pushed[remote] = contents

        feature = PresenceFeature(
            config=lambda: PresenceConfig(
                system_theme_control="dark", presence_fps_cap=None
            ),
            adb_run=fake_adb,
            run=lambda *a, **k: completed(),
            target=lambda: None,
            log_dir=lambda: pathlib.Path("/tmp"),
            uid1000_path=lambda name: f"/data/portal-uid1000/{name}",
            install_apk_preserving_verifier=lambda *a, **k: None,
            verify_package_verifier_state=lambda *a, **k: None,
            settle_package_state=lambda *a, **k: None,
            push_text_atomic=push,
            package_sets=lambda: (set(), set()),
            logcat_watermark=lambda *a, **k: None,
            logcat_poll=lambda *a, **k: "",
            adb_framework_boot_installed_remote="/tmp/adb-framework",
        )
        self.assertTrue(feature.system_theme_control_preflight())
        self.assertEqual(events, ["record", "apply"])
        self.assertEqual(
            json.loads(pushed[SYSTEM_THEME_BACKUP_REMOTE]),
            {"ui_night_mode": "1"},
        )


class FakeUimodeDevice:
    """Stateful model of the shell-uimode theme surface.

    The manager state and the ui_night_mode key are separate
    state, exactly as on device: settings put/delete move only
    the key; `cmd uimode night <arg>` moves the manager AND
    writes the key, but only on a real transition — a same-state
    call is a no-op that never rewrites the key (the Defect F
    mechanism, closure session 7)."""

    KEY_BY_MANAGER = {"auto": "0", "no": "1", "yes": "2"}

    def __init__(
        self,
        *,
        key: str | None = None,
        manager: str = "no",
        backup: str | None = None,
    ) -> None:
        self.key = key
        self.manager = manager
        self.backup = backup
        self.calls: list[list[str]] = []
        self.uimode_sets: list[str] = []

    def __call__(self, args, timeout=None, check=False):
        del timeout, check
        args = list(args)
        self.calls.append(args)
        if "cat" in args:
            if self.backup is None:
                return completed("", returncode=1)
            return completed(self.backup)
        if "uimode" in args:
            if args[-1] in self.KEY_BY_MANAGER:
                self.uimode_sets.append(args[-1])
                if args[-1] != self.manager:
                    self.manager = args[-1]
                    self.key = self.KEY_BY_MANAGER[args[-1]]
                return completed()
            return completed(f"Night mode: {self.manager}")
        if "settings" in args:
            if "get" in args:
                return completed(
                    self.key if self.key is not None else "null"
                )
            if "put" in args:
                self.key = args[-1]
                return completed()
            if "delete" in args:
                self.key = None
                return completed()
        return completed()


class SystemThemeUimodeDivergenceTest(unittest.TestCase):
    """Defect F: the theme restore moved only the ui_night_mode
    key, leaving UiModeManager wherever the last apply put it.
    The pair then verified on the key while diverged, and the
    next same-state apply no-oped against the manager and
    failed its key-based verify permanently."""

    def test_restore_to_absent_transitions_the_manager(self) -> None:
        device = FakeUimodeDevice(
            key="2",
            manager="yes",
            backup=json.dumps({"ui_night_mode": None}),
        )
        feature = make_presence_feature(device, lambda c, r: None)
        feature.restore_system_theme()
        # The manager is driven to the absent key's boot-time
        # default BEFORE the key is deleted, and the end state
        # verifies on both reads.
        self.assertEqual(device.uimode_sets, ["no"])
        self.assertIsNone(device.key)
        self.assertEqual(device.manager, "no")
        feature.verify_system_theme_restored()

    def test_restore_to_absent_without_a_record(self) -> None:
        device = FakeUimodeDevice(key="2", manager="yes", backup=None)
        feature = make_presence_feature(device, lambda c, r: None)
        feature.restore_system_theme()
        self.assertEqual(device.uimode_sets, ["no"])
        self.assertIsNone(device.key)
        self.assertEqual(device.manager, "no")
        feature.verify_system_theme_restored()

    def test_restore_of_recorded_dark_goes_through_the_transport(
        self,
    ) -> None:
        device = FakeUimodeDevice(
            key="1",
            manager="no",
            backup=json.dumps({"ui_night_mode": "2"}),
        )
        feature = make_presence_feature(device, lambda c, r: None)
        feature.restore_system_theme()
        self.assertEqual(device.uimode_sets, ["yes"])
        self.assertFalse(
            any(
                "settings" in call and "put" in call
                for call in device.calls
            )
        )
        self.assertEqual(device.key, "2")
        self.assertEqual(device.manager, "yes")
        feature.verify_system_theme_restored()

    def test_apply_heals_the_diverged_state(self) -> None:
        # The library unit's session-7 end state: key absent,
        # manager at night. A dark apply must force a real
        # transition (through the opposite state) so the
        # transport rewrites the key; a bare same-state call
        # would no-op and leave the key absent.
        device = FakeUimodeDevice(key=None, manager="yes")
        feature = make_presence_feature(
            device, lambda c, r: None, theme="dark"
        )
        feature.apply_system_theme_request()
        self.assertEqual(device.uimode_sets, ["no", "yes"])
        self.assertEqual(device.key, "2")
        self.assertEqual(device.manager, "yes")
        feature.verify_system_theme_control(wait_seconds=5)

    def test_the_pre_fix_restore_output_fails_verification(
        self,
    ) -> None:
        # Session 7 reproduced: the pre-fix restore's whole
        # effect was deleting the key under a night manager.
        # That end state must now fail verification as diverged.
        device = FakeUimodeDevice(
            key="2",
            manager="yes",
            backup=json.dumps({"ui_night_mode": None}),
        )
        device(["shell", "settings", "delete", "secure", "ui_night_mode"])
        feature = make_presence_feature(device, lambda c, r: None)
        with self.assertRaises(ProvisionError) as raised:
            feature.verify_system_theme_restored()
        self.assertIn("diverged", str(raised.exception))

    def test_apply_verification_fails_loudly_on_divergence(
        self,
    ) -> None:
        device = FakeUimodeDevice(key=None, manager="yes")
        feature = make_presence_feature(
            device, lambda c, r: None, theme="dark"
        )
        with self.assertRaises(ProvisionError) as raised:
            feature.verify_system_theme_control(wait_seconds=1)
        self.assertIn("diverged", str(raised.exception))


def make_settings_feature(config: SettingsConfig, **overrides) -> SettingsFeature:
    callbacks = dict(
        adb_run=lambda *a, **k: completed(),
        log_dir=pathlib.Path("/tmp"),
        target=lambda: None,
        config=lambda: config,
        ensure_adb_framework_enabled=lambda: None,
        push_text_atomic=lambda contents, remote: None,
        settle_package_state=lambda *a, **k: None,
        package_sets=lambda: (set(), set()),
        current_component_states=lambda: {},
        current_named_component_states=lambda components, **k: {},
        meta_accounts=lambda: [],
        disabled_meta_authenticators=lambda: set(),
        read_component_backup=lambda required=True: None,
        read_remote_wipe_backup=lambda required=True: None,
        ensure_remote_wipe_backup=lambda: {},
    )
    callbacks.update(overrides)
    return SettingsFeature(**callbacks)


class MetaAuthenticatorsRestoreTest(unittest.TestCase):
    """Gap 4: --restore meta-authenticators generates component
    actions that return the three authenticator components to
    their recorded states, or to enabled (factory default) when
    the component backup holds no record for them."""

    def capture_actions(self, feature: SettingsFeature) -> str:
        pushed: dict[str, str] = {}
        feature._push_text_atomic = lambda contents, remote: pushed.update(
            {remote: contents}
        )
        feature.prepare_component_actions()
        return next(iter(pushed.values()))

    def test_factory_default_enables_all_three(self) -> None:
        feature = make_settings_feature(
            SettingsConfig(restore_meta_authenticators=True)
        )
        contents = self.capture_actions(feature)
        for component in META_AUTHENTICATOR_COMPONENTS:
            # The jar validates each entry against
            # ComponentName.flattenToString(), so the actions
            # carry the flattened package/class form, not the
            # bare class name the backup keys on.
            self.assertIn(
                f"enable\t{META_AUTHENTICATOR_PACKAGE}/{component}",
                contents,
            )

    def test_recorded_states_are_replayed(self) -> None:
        recorded = {
            component: ("com.facebook.alohaservices.alohausers", "default")
            for component in META_AUTHENTICATOR_COMPONENTS
        }
        feature = make_settings_feature(
            SettingsConfig(restore_meta_authenticators=True),
            read_component_backup=lambda required=True: recorded,
        )
        contents = self.capture_actions(feature)
        for component in META_AUTHENTICATOR_COMPONENTS:
            self.assertIn(
                f"default\tcom.facebook.alohaservices.alohausers"
                f"/{component}",
                contents,
            )


if __name__ == "__main__":
    unittest.main()
