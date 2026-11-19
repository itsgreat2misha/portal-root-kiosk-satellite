# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.
#
# Phase M0 characterization tests (see the monolith-split plan): these
# pin the behaviours a later pure-move refactor could silently break --
# argument->config mapping for every CLI flag, state/backup file
# round-trips including byte-format stability, the exact marker
# strings emitted by each phase, and the guarantee that host-side
# failures surface before any reboot. No production code is changed
# by this file; every test passes against the unmodified tree.

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import provision_portal as provision_portal_module  # noqa: E402
from provision_portal import (  # noqa: E402
    ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
    ADB_AUTH_TIMEOUT_SETTING,
    ADB_ENABLED_SETTING,
    APP_VERIFIER_BACKUP_REMOTE,
    AUTOROOT_HELPER_PACKAGE,
    AUTOROOT_MAX_ATTEMPTS,
    AUTOROOT_REMOTE_DIR,
    CUSTOM_PAYLOAD_DST_REMOTE,
    CUSTOM_PAYLOAD_PORT,
    DEBLOAT_BACKUP_REMOTE,
    DEBLOAT_COMPONENT_BACKUP_REMOTE,
    DEBLOAT_PACKAGES,
    DEFAULT_CUSTOM_PAYLOAD_LOCAL,
    PRIVACY_BACKUP_REMOTE,
    PROVISIONER_VERSION,
    REMOTE_WIPE_BACKUP_REMOTE,
    REMOTE_WIPE_COMPONENTS,
    SHIZUKU_HELPER_PACKAGE,
    SHIZUKU_PACKAGE,
    SHIZUKU_VERSION,
    STATE_REMOTE,
    PortalProvisioner,
    ProvisionError,
    parse_args,
)
from meta_debloat_components import (  # noqa: E402
    DEBLOAT_COMPONENT_NAMES,
    DEBLOAT_COMPONENTS,
)
from portal_targets import TARGETS  # noqa: E402


SERIAL = "192.0.2.1:5555"
ALOHA = next(
    target for target in TARGETS if target.key == "portal-plus-aloha-1041515800015050"
)
TERRY = next(
    target for target in TARGETS if target.key == "portal-go-terry-5051355900018050"
)
RIPLEY = next(target for target in TARGETS if target.device == "ripley")


def parse(argv: list[str]):
    with mock.patch.object(sys, "argv", ["provision_portal.py", *argv]):
        return parse_args()


def parse_error(argv: list[str]) -> str:
    stderr = io.StringIO()
    with (
        mock.patch.object(sys, "argv", ["provision_portal.py", *argv]),
        contextlib.redirect_stderr(stderr),
    ):
        with unittest.TestCase().assertRaises(SystemExit):
            parse_args()
    return stderr.getvalue()


def make_provisioner(temporary: str, **kwargs) -> PortalProvisioner:
    return PortalProvisioner(SERIAL, 1, pathlib.Path(temporary), **kwargs)


def flag_aware_adb_run(state: dict | None = None, fallback_returncode: int = 1):
    """adb_run fake modelling the autoroot disable flag on a device
    whose /data/local/tmp is writable. provision() sets and restores
    that flag on every run (the re-run guard), so fakes that drive
    provision() must answer its commands; every other command gets
    fallback_returncode, matching the flat fakes used before."""
    if state is None:
        state = {"present": False, "content": ""}

    def adb_run(arguments, timeout=None, check=False):
        del timeout, check
        arguments = [str(argument) for argument in arguments]
        joined = " ".join(arguments)
        if "portal-autoroot.disable" not in joined:
            return subprocess.CompletedProcess(
                arguments, fallback_returncode, ""
            )
        if "test" in arguments:
            return subprocess.CompletedProcess(
                arguments,
                0 if state["present"] else 1,
                provision_portal_module.AUTOROOT_FLAG_PRESENT_TOKEN
                if state["present"]
                else provision_portal_module.AUTOROOT_FLAG_ABSENT_TOKEN,
            )
        if "cat" in arguments:
            if not state["present"]:
                return subprocess.CompletedProcess(arguments, 1, "")
            return subprocess.CompletedProcess(
                arguments, 0, state["content"]
            )
        if "rm" in arguments:
            state["present"] = False
            state["content"] = ""
            return subprocess.CompletedProcess(arguments, 0, "")
        # echo <token> > flag / touch flag: create it.
        state["present"] = True
        parts = joined.split()
        if "echo" in parts:
            state["content"] = parts[parts.index("echo") + 1]
        return subprocess.CompletedProcess(arguments, 0, "")

    return adb_run


class FakeRemoteFiles:
    """In-memory stand-in for the device's /data/local/tmp files.

    Implements just enough of adb_run's surface (cat / push / the
    chmod&&mv shell idiom used by the atomic writers) for the state
    and backup writers to round-trip through their real code paths.
    """

    def __init__(self) -> None:
        self.files: dict[str, str] = {}
        self.calls: list[list[str]] = []

    def adb_run(self, arguments, timeout=None, check=False):
        del timeout, check
        arguments = [str(argument) for argument in arguments]
        self.calls.append(list(arguments))
        if arguments[:2] == ["shell", "cat"] and len(arguments) == 3:
            remote = arguments[2]
            if remote in self.files:
                return subprocess.CompletedProcess(arguments, 0, self.files[remote])
            return subprocess.CompletedProcess(arguments, 1, "")
        if arguments[0] == "push":
            local, remote = arguments[1], arguments[2]
            self.files[remote] = pathlib.Path(local).read_text(encoding="utf-8")
            return subprocess.CompletedProcess(arguments, 0, "")
        if arguments[0] == "shell" and len(arguments) == 2 and "mv " in arguments[1]:
            tokens = shlex.split(arguments[1])
            source, destination = tokens[-2], tokens[-1]
            self.files[destination] = self.files.pop(source)
            return subprocess.CompletedProcess(arguments, 0, "")
        return subprocess.CompletedProcess(arguments, 0, "")


# ---------------------------------------------------------------------------
# Argument -> config mapping
# ---------------------------------------------------------------------------


class CliDefaultsTest(unittest.TestCase):
    def test_no_arguments_produces_the_exact_default_namespace(self) -> None:
        self.assertEqual(
            vars(parse([])),
            {
                "serial": None,
                "attempts": 12,
                "full": False,
                "restore": [],
                "persistent_wireless_adb": False,
                "disable_adb_auth_timeout": False,
                "restore_adb_auth_timeout": False,
                "restore_autoroot": False,
                "restore_wireless_adb": False,
                "restore_theme": False,
                "restore_meta_authenticators": False,
                # No action selected and no mode/backup: audio is the
                # default action.
                "audio": True,
                "restore_audio": False,
                "skip_build": False,
                "force": False,
                "shizuku": False,
                "remove_shizuku": False,
                "shizuku_apk": None,
                "custom_payload": None,
                "skip_shizuku_root": False,
                "autoroot": False,
                "verify_boots": 1,
                "system_theme_control": None,
                "allow_app_updates": False,
                "restore_app_verifier": False,
                "disable_updates": False,
                "enable_updates": False,
                "block_remote_wipe": False,
                "restore_remote_wipe": False,
                "disable_camera_light": False,
                "restore_camera_light": False,
                "debloat": False,
                "restore_bloat": False,
                "remove_meta_accounts": False,
                "optimize_presence": False,
                "presence_fps_cap": None,
                "dns": None,
                "privacy_dns": None,
                "dhcp_dns": False,
                "restore_privacy_dns": False,
                "status": False,
                "dry_run": False,
                "recover": False,
                "collect_diagnostics": False,
                "backup": None,
                "restore_presence_profile": False,
                "restore_presence_fps": False,
                "log_dir": None,
                "backup_only": False,
            },
        )

    def test_version_flag_prints_prog_and_version_then_exits_zero(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["provision_portal.py", "--version"]),
            contextlib.redirect_stdout(stdout),
        ):
            with self.assertRaises(SystemExit) as caught:
                parse_args()
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(
            stdout.getvalue(), f"provision_portal.py {PROVISIONER_VERSION}\n"
        )


class CliSingleFlagMappingTest(unittest.TestCase):
    # (argv tail, attribute, expected value, audio stays/becomes)
    # "audio" pins whether selecting this flag suppresses the default
    # audio action: flags that count as a selected action (or a mode)
    # suppress it; passive flags (serial, attempts, skip-build, ...)
    # leave the default in place.
    CASES = (
        (["--serial", "10.0.0.9:5555"], "serial", "10.0.0.9:5555", True),
        (["--attempts", "3"], "attempts", 3, True),
        (["--attempts", "100"], "attempts", 100, True),
        (["--skip-build"], "skip_build", True, True),
        (["--skip-shizuku-root"], "skip_shizuku_root", True, True),
        (["--verify-boots", "2"], "verify_boots", 2, True),
        (["--log-dir", "/tmp/logs"], "log_dir", pathlib.Path("/tmp/logs"), True),
        (["--persistent-wireless-adb"], "persistent_wireless_adb", True, False),
        (["--disable-adb-auth-timeout"], "disable_adb_auth_timeout", True, False),
        (["--restore", "adb-auth-timeout"], "restore_adb_auth_timeout", True, False),
        (["--audio"], "audio", True, True),
        (["--restore", "audio"], "restore_audio", True, False),
        (["--shizuku"], "shizuku", True, False),
        (["--remove-shizuku"], "remove_shizuku", True, False),
        (
            ["--shizuku", "--shizuku-apk", "/tmp/s.apk"],
            "shizuku_apk",
            pathlib.Path("/tmp/s.apk"),
            False,
        ),
        (["--allow-app-updates"], "allow_app_updates", True, False),
        (["--restore", "app-verifier"], "restore_app_verifier", True, False),
        (["--disable-updates"], "disable_updates", True, False),
        (["--restore", "updates"], "enable_updates", True, False),
        (["--block-remote-wipe"], "block_remote_wipe", True, False),
        (["--restore", "remote-wipe"], "restore_remote_wipe", True, False),
        (["--restore", "camera-light"], "restore_camera_light", True, False),
        (["--debloat"], "debloat", True, False),
        (["--restore", "bloat"], "restore_bloat", True, False),
        (["--remove-meta-accounts"], "remove_meta_accounts", True, False),
        (["--optimize-presence"], "optimize_presence", True, False),
        (["--restore", "presence"], "restore_presence_profile", True, False),
        (["--restore", "presence-fps"], "restore_presence_fps", True, False),
        (["--dns", "dns.example.com"], "privacy_dns", "dns.example.com", False),
        (["--dns", "off"], "dhcp_dns", True, False),
        (["--restore", "dns"], "restore_privacy_dns", True, False),
        (["--restore", "autoroot"], "restore_autoroot", True, False),
        (["--restore", "wireless-adb"], "restore_wireless_adb", True, False),
        (["--restore", "theme"], "restore_theme", True, False),
        (
            ["--restore", "meta-authenticators"],
            "restore_meta_authenticators",
            True,
            False,
        ),
        (["--full"], "disable_updates", True, True),
        (["--system-theme-control", "light"], "system_theme_control", "light", False),
        (["--system-theme-control", "dark"], "system_theme_control", "dark", False),
        (["--status"], "status", True, False),
        (["--dry-run"], "dry_run", True, False),
        (["--recover"], "recover", True, False),
    )

    def test_every_flag_maps_to_its_attribute(self) -> None:
        for argv, attribute, expected, audio in self.CASES:
            with self.subTest(argv=argv):
                arguments = parse(argv)
                self.assertEqual(getattr(arguments, attribute), expected)
                self.assertEqual(arguments.audio, audio, "default-audio rule")

    def test_custom_payload_bare_and_explicit(self) -> None:
        bare = parse(["--custom-payload"])
        self.assertEqual(bare.custom_payload, DEFAULT_CUSTOM_PAYLOAD_LOCAL)
        self.assertFalse(bare.audio)
        explicit = parse(["--custom-payload", "/tmp/daemon.bin"])
        self.assertEqual(explicit.custom_payload, pathlib.Path("/tmp/daemon.bin"))

    def test_backup_alone_sets_backup_only_and_suppresses_default_audio(
        self,
    ) -> None:
        arguments = parse(["--backup", "/tmp/backup"])
        self.assertEqual(arguments.backup, pathlib.Path("/tmp/backup"))
        self.assertTrue(arguments.backup_only)
        self.assertFalse(arguments.audio)

    def test_backup_with_a_mode_is_not_backup_only(self) -> None:
        # (--recover --backup is a parse error, pinned in
        # CliValidationTest.)
        for mode in ("--status", "--dry-run"):
            with self.subTest(mode=mode):
                arguments = parse([mode, "--backup", "/tmp/backup"])
                self.assertFalse(arguments.backup_only)

    def test_backup_with_an_action_is_not_backup_only(self) -> None:
        arguments = parse(["--audio", "--backup", "/tmp/backup"])
        self.assertFalse(arguments.backup_only)
        self.assertTrue(arguments.audio)

    def test_presence_fps_cap_implies_optimize_presence(self) -> None:
        for fps in (1, 5, 10):
            with self.subTest(fps=fps):
                arguments = parse(["--presence-fps-cap", str(fps)])
                self.assertEqual(arguments.presence_fps_cap, fps)
                self.assertTrue(arguments.optimize_presence)
                self.assertFalse(arguments.audio)

    def test_persistent_wireless_adb_implies_disable_adb_auth_timeout(
        self,
    ) -> None:
        arguments = parse(["--persistent-wireless-adb"])
        self.assertTrue(arguments.disable_adb_auth_timeout)
        self.assertFalse(arguments.restore_adb_auth_timeout)


class CliValidationTest(unittest.TestCase):
    # Pairs still enforced by argparse mutually exclusive groups.
    MUTUALLY_EXCLUSIVE = (
        ["--shizuku", "--remove-shizuku"],
        ["--status", "--dry-run"],
        ["--status", "--recover"],
        ["--dry-run", "--recover"],
    )

    # Apply/restore pairs for one feature, rejected by the shell's
    # own checks with these messages since the pairs moved onto the
    # unified --restore <name> surface.
    PAIR_ERRORS = (
        (
            ["--disable-adb-auth-timeout", "--restore", "adb-auth-timeout"],
            "--disable-adb-auth-timeout cannot be combined with "
            "--restore adb-auth-timeout",
        ),
        (
            ["--audio", "--restore", "audio"],
            "--audio cannot be combined with --restore audio",
        ),
        (
            ["--allow-app-updates", "--restore", "app-verifier"],
            "--allow-app-updates cannot be combined with "
            "--restore app-verifier",
        ),
        (
            ["--disable-updates", "--restore", "updates"],
            "--disable-updates cannot be combined with --restore updates",
        ),
        (
            ["--block-remote-wipe", "--restore", "remote-wipe"],
            "--block-remote-wipe cannot be combined with "
            "--restore remote-wipe",
        ),
        (
            ["--disable-camera-light", "--restore", "camera-light"],
            "--disable-camera-light cannot be combined with "
            "--restore camera-light",
        ),
        (
            ["--debloat", "--restore", "bloat"],
            "--debloat cannot be combined with --restore bloat",
        ),
        (
            ["--optimize-presence", "--restore", "presence"],
            "--optimize-presence cannot be combined with --restore presence",
        ),
        (
            ["--optimize-presence", "--restore", "presence-fps"],
            "--optimize-presence cannot be combined with "
            "--restore presence-fps",
        ),
        (
            ["--restore", "presence", "--restore", "presence-fps"],
            "--restore presence cannot be combined with "
            "--restore presence-fps",
        ),
        (
            ["--dns", "dns.example.com", "--restore", "dns"],
            "--dns cannot be combined with --restore dns",
        ),
        (
            ["--dns", "off", "--restore", "dns"],
            "--dns cannot be combined with --restore dns",
        ),
    )

    def test_mutually_exclusive_pairs_are_rejected(self) -> None:
        for argv in self.MUTUALLY_EXCLUSIVE:
            with self.subTest(argv=argv):
                self.assertIn("not allowed with argument", parse_error(argv))
        for argv, message in self.PAIR_ERRORS:
            with self.subTest(argv=argv):
                self.assertIn(message, parse_error(argv))

    def test_attempts_bounds(self) -> None:
        for value in ("0", "101"):
            with self.subTest(value=value):
                self.assertIn(
                    "--attempts must be between 1 and 100",
                    parse_error(["--attempts", value]),
                )
        self.assertIn("invalid int value", parse_error(["--attempts", "many"]))

    def test_verify_boots_choices(self) -> None:
        for value in ("0", "3"):
            with self.subTest(value=value):
                self.assertIn("invalid choice", parse_error(["--verify-boots", value]))

    def test_presence_fps_cap_bounds(self) -> None:
        for value in ("0", "11"):
            with self.subTest(value=value):
                self.assertIn(
                    "--presence-fps-cap must be between 1 and 10",
                    parse_error(["--presence-fps-cap", value]),
                )

    def test_presence_fps_cap_rejects_presence_rollbacks(self) -> None:
        for rollback in ("presence", "presence-fps"):
            with self.subTest(rollback=rollback):
                self.assertIn(
                    "--presence-fps-cap cannot be combined with a presence rollback",
                    parse_error(["--presence-fps-cap", "5", "--restore", rollback]),
                )

    def test_shizuku_apk_requires_shizuku(self) -> None:
        self.assertIn(
            "--shizuku-apk requires --shizuku",
            parse_error(["--shizuku-apk", "/tmp/s.apk"]),
        )

    def test_disable_camera_light_is_retired_at_parse_time(self) -> None:
        self.assertIn(
            "--disable-camera-light has been retired",
            parse_error(["--disable-camera-light"]),
        )

    def test_status_and_recover_reject_action_flags(self) -> None:
        self.assertIn(
            "--status cannot be combined with provisioning actions",
            parse_error(["--status", "--audio"]),
        )
        self.assertIn(
            "--recover resumes its saved action set",
            parse_error(["--recover", "--audio"]),
        )
        self.assertIn(
            "--recover cannot be combined with --backup",
            parse_error(["--recover", "--backup", "/tmp/b"]),
        )

    def test_persistent_wireless_adb_rejects_auth_timeout_restore(self) -> None:
        self.assertIn(
            "--persistent-wireless-adb cannot be combined with "
            "--restore adb-auth-timeout",
            parse_error(
                ["--persistent-wireless-adb", "--restore", "adb-auth-timeout"]
            ),
        )

    def test_autoroot_rejects_remove_shizuku(self) -> None:
        self.assertIn(
            "--autoroot cannot be combined with --remove-shizuku",
            parse_error(["--autoroot", "--remove-shizuku"]),
        )


class MainConfigMappingTest(unittest.TestCase):
    """--serial is enforced in main(), not parse_args(), so the
    argument->config mapping for the constructor is pinned through
    main() with a fake PortalProvisioner recording its arguments."""

    def run_main(self, argv, provision_side_effect=None):
        constructed: list = []

        class FakeProvisioner:
            def __init__(self, *args, **kwargs):
                constructed.append((args, kwargs))

            def provision(self):
                if provision_side_effect is not None:
                    raise provision_side_effect

        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["provision_portal.py", *argv]),
            mock.patch.object(
                provision_portal_module, "PortalProvisioner", FakeProvisioner
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = provision_portal_module.main()
        return result, constructed, stderr.getvalue()

    def test_main_maps_every_cli_flag_to_constructor_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = pathlib.Path(temporary) / "logs"
            result, constructed, _ = self.run_main(
                [
                    "--serial", SERIAL,
                    "--attempts", "7",
                    "--log-dir", str(log_dir),
                    "--persistent-wireless-adb",
                    "--audio",
                    "--skip-build",
                    "--shizuku",
                    "--shizuku-apk", "/tmp/shizuku.apk",
                    "--custom-payload", "/tmp/daemon.bin",
                    "--skip-shizuku-root",
                    "--autoroot",
                    "--verify-boots", "2",
                    "--system-theme-control", "dark",
                    "--allow-app-updates",
                    "--disable-updates",
                    "--block-remote-wipe",
                    "--debloat",
                    "--remove-meta-accounts",
                    "--presence-fps-cap", "4",
                    "--dns", "dns.example.com",
                    "--dry-run",
                    "--backup", "/tmp/backup.tar.gz",
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(len(constructed), 1)
        args, kwargs = constructed[0]
        self.assertEqual(args, (SERIAL, 7, log_dir))
        self.assertEqual(
            kwargs,
            {
                "audio": True,
                "restore_audio": False,
                "disable_updates": True,
                "enable_updates": False,
                "block_remote_wipe": True,
                "restore_remote_wipe": False,
                "debloat": True,
                "restore_bloat": False,
                "remove_meta_accounts": True,
                "optimize_presence": True,
                "restore_presence_profile": False,
                "presence_fps_cap": 4,
                "restore_presence_fps": False,
                "privacy_dns": "dns.example.com",
                "dhcp_dns": False,
                "restore_privacy_dns": False,
                "allow_app_updates": True,
                "restore_app_verifier": False,
                "shizuku": True,
                "remove_shizuku": False,
                "disable_camera_light": False,
                "restore_camera_light": False,
                "system_theme_control": "dark",
                "shizuku_apk": pathlib.Path("/tmp/shizuku.apk"),
                "custom_payload": pathlib.Path("/tmp/daemon.bin"),
                "skip_shizuku_root": True,
                "autoroot": True,
                "verify_boots": 2,
                "status_only": False,
                "dry_run": True,
                "collect_diagnostics": False,
                "backup_path": pathlib.Path("/tmp/backup.tar.gz"),
                "recover": False,
                "skip_build": True,
                "force": False,
                "persistent_wireless_adb": True,
                # Implied by --persistent-wireless-adb in parse_args.
                "disable_adb_auth_timeout": True,
                "restore_adb_auth_timeout": False,
                "restore_autoroot": False,
                "restore_wireless_adb": False,
                "restore_theme": False,
                "restore_meta_authenticators": False,
            },
        )

    def test_main_status_flag_maps_to_status_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, constructed, _ = self.run_main(
                [
                    "--serial", SERIAL,
                    "--status",
                    "--log-dir", str(pathlib.Path(temporary) / "logs"),
                ]
            )
        self.assertEqual(result, 0)
        _, kwargs = constructed[0]
        self.assertTrue(kwargs["status_only"])
        self.assertFalse(kwargs["dry_run"])

    def test_main_backup_only_maps_to_status_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, constructed, _ = self.run_main(
                [
                    "--serial", SERIAL,
                    "--backup", "/tmp/backup.tar.gz",
                    "--log-dir", str(pathlib.Path(temporary) / "logs"),
                ]
            )
        self.assertEqual(result, 0)
        _, kwargs = constructed[0]
        self.assertTrue(kwargs["status_only"])
        self.assertEqual(kwargs["backup_path"], pathlib.Path("/tmp/backup.tar.gz"))

    def test_main_without_serial_constructs_nothing_and_returns_2(self) -> None:
        result, constructed, stderr = self.run_main(["--audio"])
        self.assertEqual(result, 2)
        self.assertEqual(constructed, [])
        self.assertIn("--serial is required", stderr)

    def test_main_reports_provision_error_and_returns_1(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, _, stderr = self.run_main(
                [
                    "--serial", SERIAL,
                    "--audio",
                    "--log-dir", str(pathlib.Path(temporary) / "logs"),
                ],
                provision_side_effect=ProvisionError("boom"),
            )
        self.assertEqual(result, 1)
        self.assertIn("PROVISION_ERROR: boom", stderr)


class ConstructorConfigMappingTest(unittest.TestCase):
    def test_constructor_stores_every_config_attribute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = pathlib.Path(temporary)
            provisioner = PortalProvisioner(
                SERIAL,
                9,
                log_dir,
                audio=True,
                restore_audio=True,
                disable_updates=True,
                enable_updates=True,
                debloat=True,
                restore_bloat=True,
                block_remote_wipe=True,
                restore_remote_wipe=True,
                remove_meta_accounts=True,
                optimize_presence=True,
                restore_presence_profile=True,
                presence_fps_cap=6,
                restore_presence_fps=True,
                privacy_dns="dns.example.com",
                dhcp_dns=True,
                restore_privacy_dns=True,
                allow_app_updates=True,
                restore_app_verifier=True,
                shizuku=True,
                remove_shizuku=True,
                disable_camera_light=True,
                restore_camera_light=True,
                system_theme_control="dark",
                shizuku_apk=pathlib.Path("/tmp/s.apk"),
                custom_payload=pathlib.Path("/tmp/p.bin"),
                skip_shizuku_root=True,
                autoroot=True,
                verify_boots=2,
                status_only=True,
                dry_run=True,
                backup_path=pathlib.Path("/tmp/b"),
                recover=True,
                skip_build=True,
                restore_adb_auth_timeout=True,
                wireless_adb_only=True,
                adb_framework_only=True,
                meta_accounts_local_only=True,
                meta_accounts_auth_only=True,
                meta_accounts_finalize_only=True,
            )
            expected = {
                "serial": SERIAL,
                "attempts": 9,
                "log_dir": log_dir,
                "audio": True,
                "restore_audio": True,
                "disable_updates": True,
                "enable_updates": True,
                "debloat": True,
                "restore_bloat": True,
                "block_remote_wipe": True,
                "restore_remote_wipe": True,
                "remove_meta_accounts": True,
                "optimize_presence": True,
                "restore_presence_profile": True,
                "presence_fps_cap": 6,
                "restore_presence_fps": True,
                "privacy_dns": "dns.example.com",
                "dhcp_dns": True,
                "restore_privacy_dns": True,
                "allow_app_updates": True,
                "restore_app_verifier": True,
                "shizuku": True,
                "remove_shizuku": True,
                "disable_camera_light": True,
                "restore_camera_light": True,
                "system_theme_control": "dark",
                "shizuku_apk": pathlib.Path("/tmp/s.apk"),
                "custom_payload": pathlib.Path("/tmp/p.bin"),
                "skip_shizuku_root": True,
                "autoroot": True,
                "verify_boots": 2,
                "status_only": True,
                "dry_run": True,
                "backup_path": pathlib.Path("/tmp/b"),
                "recover": True,
                "skip_build": True,
                "restore_adb_auth_timeout": True,
                "wireless_adb_only": True,
                "adb_framework_only": True,
                "meta_accounts_local_only": True,
                "meta_accounts_auth_only": True,
                "meta_accounts_finalize_only": True,
            }
            for attribute, value in expected.items():
                self.assertEqual(getattr(provisioner, attribute), value, attribute)
            self.assertEqual(provisioner.adb, ["adb", "-s", SERIAL])
            self.assertIsNone(provisioner.target)

    def test_persistent_wireless_adb_forces_disable_adb_auth_timeout(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, persistent_wireless_adb=True
            )
            self.assertTrue(provisioner.persistent_wireless_adb)
            self.assertTrue(provisioner.disable_adb_auth_timeout)

    def test_constructor_rejects_verify_boots_outside_1_and_2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                ProvisionError, "--verify-boots must be 1 or 2"
            ):
                make_provisioner(temporary, verify_boots=3)

    def test_requested_actions_mapping_and_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                persistent_wireless_adb=True,
                audio=True,
                disable_updates=True,
                debloat=True,
                block_remote_wipe=True,
                remove_meta_accounts=True,
                optimize_presence=True,
                presence_fps_cap=4,
                privacy_dns="dns.example.com",
                allow_app_updates=True,
                shizuku=True,
                system_theme_control="light",
                custom_payload=pathlib.Path("/tmp/p.bin"),
            )
            actions = provisioner.requested_actions()
        self.assertEqual(
            actions,
            {
                "persistent_wireless_adb": True,
                # Forced on by persistent_wireless_adb in __init__.
                "disable_adb_auth_timeout": True,
                "audio": True,
                "disable_updates": True,
                "debloat": True,
                "block_remote_wipe": True,
                "remove_meta_accounts": True,
                "optimize_presence": True,
                "allow_app_updates": True,
                "shizuku": True,
                "privacy_dns": "dns.example.com",
                "presence_fps_cap": 4,
                "system_theme_control": "light",
                "custom_payload": "/tmp/p.bin",
            },
        )
        self.assertEqual(
            list(actions),
            [
                "persistent_wireless_adb",
                "disable_adb_auth_timeout",
                "audio",
                "disable_updates",
                "debloat",
                "block_remote_wipe",
                "remove_meta_accounts",
                "optimize_presence",
                "allow_app_updates",
                "shizuku",
                "privacy_dns",
                "presence_fps_cap",
                "system_theme_control",
                "custom_payload",
            ],
        )

    def test_requested_actions_empty_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(make_provisioner(temporary).requested_actions(), {})


# ---------------------------------------------------------------------------
# State-file and backup-file round-trips (byte-format stability)
# ---------------------------------------------------------------------------


class ProvisionStateRoundTripTest(unittest.TestCase):
    def build(self, temporary: str):
        provisioner = make_provisioner(temporary, audio=True)
        provisioner.target = TERRY
        remote = FakeRemoteFiles()
        fingerprint = TERRY.fingerprint

        def adb_run(arguments, timeout=None, check=False):
            if list(arguments)[:3] == ["shell", "getprop", "ro.build.fingerprint"]:
                return subprocess.CompletedProcess(arguments, 0, fingerprint + "\n")
            return remote.adb_run(arguments, timeout=timeout, check=check)

        return provisioner, remote, adb_run

    def test_write_then_read_state_is_identical_and_byte_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, remote, adb_run = self.build(temporary)
            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provisioner, "tool_revision", return_value="b265d23"
                ),
                mock.patch.object(
                    provisioner,
                    "selected_artifact_hashes",
                    return_value={"tools/provision_portal.py": "a" * 64},
                ),
                contextlib.redirect_stdout(stdout),
            ):
                provisioner.write_state("pending", "boot-1", None)
                local_bytes = (
                    provisioner.log_dir / "portal-provision-state-v1.json"
                ).read_bytes()
                state = provisioner.read_state()

            self.assertIsNotNone(state)
            assert state is not None
            updated_at = state.pop("updated_at")
            # updated_at is a live UTC ISO-8601 timestamp.
            parsed_stamp = provision_portal_module.dt.datetime.fromisoformat(
                str(updated_at)
            )
            self.assertIsNotNone(parsed_stamp.tzinfo)
            expected = {
                "schema": 1,
                "status": "pending",
                "updated_at": updated_at,
                "serial": SERIAL,
                "target": TERRY.key,
                "fingerprint": TERRY.fingerprint,
                "tool_revision": "b265d23",
                "artifact_sha256": {"tools/provision_portal.py": "a" * 64},
                "actions": {"audio": True},
                "verification": {"first_boot": "boot-1", "second_boot": None},
            }
            self.assertEqual(
                state,
                {
                    key: value
                    for key, value in expected.items()
                    if key != "updated_at"
                },
            )
            # Byte format: sorted keys, two-space indent, trailing \n,
            # and the device copy is byte-identical to the host copy.
            self.assertEqual(
                local_bytes,
                (json.dumps(expected, indent=2, sort_keys=True) + "\n").encode(),
            )
            self.assertEqual(remote.files[STATE_REMOTE].encode(), local_bytes)
            self.assertEqual(
                stat.S_IMODE(
                    (provisioner.log_dir / "portal-provision-state-v1.json").stat().st_mode
                ),
                0o600,
            )
            # Atomic publish: push to STATE_REMOTE + ".tmp", then a
            # single chmod 0600 && mv shell step.
            push_call = next(
                call for call in remote.calls if call[0] == "push"
            )
            self.assertEqual(push_call[2], STATE_REMOTE + ".tmp")
            move_call = next(
                call for call in remote.calls if call[0] == "shell" and "mv " in call[-1]
            )
            self.assertEqual(
                move_call[1],
                f"chmod 0600 {STATE_REMOTE}.tmp && "
                f"mv {STATE_REMOTE}.tmp {STATE_REMOTE}",
            )
            self.assertIn(
                f"STATE_MANIFEST status=pending path={STATE_REMOTE}",
                stdout.getvalue().splitlines(),
            )

    def test_read_state_absent_invalid_and_wrong_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)

            def adb_with(stdout: str, returncode: int = 0):
                return mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], returncode, stdout),
                )

            with adb_with("", returncode=1):
                self.assertIsNone(provisioner.read_state())
            with adb_with("{not json"):
                with self.assertRaisesRegex(
                    ProvisionError, "invalid device state manifest"
                ):
                    provisioner.read_state()
            with adb_with(json.dumps({"schema": 2, "status": "pending"})):
                with self.assertRaisesRegex(
                    ProvisionError, "unrecognized device state manifest"
                ):
                    provisioner.read_state()
            with adb_with(json.dumps(["not", "a", "dict"])):
                with self.assertRaisesRegex(
                    ProvisionError, "unrecognized device state manifest"
                ):
                    provisioner.read_state()

    def test_print_status_writes_status_json_with_the_same_bytes_it_prints(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            status = {"zeta": 1, "alpha": {"nested": [True, None]}}
            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "collect_status", return_value=status),
                contextlib.redirect_stdout(stdout),
            ):
                returned = provisioner.print_status()
            self.assertEqual(returned, status)
            rendered = json.dumps(status, indent=2, sort_keys=True)
            self.assertEqual(stdout.getvalue(), rendered + "\n")
            self.assertEqual(
                (provisioner.log_dir / "status.json").read_text(),
                rendered + "\n",
            )


class BackupBundleFormatTest(unittest.TestCase):
    def test_manifest_and_status_inside_the_bundle_are_byte_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            status = {"alpha": "x", "zeta": 1}
            destination = pathlib.Path(temporary) / "bundle.tar.gz"

            def adb_run(arguments, timeout=None, check=False):
                del timeout, check
                return subprocess.CompletedProcess(
                    arguments, 1 if arguments[0] == "pull" else 0, "device text\n"
                )

            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "collect_status", return_value=status),
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(provisioner, "tool_revision", return_value="rev9"),
                contextlib.redirect_stdout(stdout),
            ):
                result = provisioner.create_backup_bundle(destination)

            self.assertEqual(result, destination)
            self.assertIn(f"BACKUP_OK path={destination}", stdout.getvalue().splitlines())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            with tarfile.open(destination, "r:gz") as archive:
                members = {
                    member.name: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                }
            prefix = "portal-backup/"
            self.assertEqual(
                members[prefix + "status.json"],
                (json.dumps(status, indent=2, sort_keys=True) + "\n").encode(),
            )
            manifest = json.loads(members[prefix + "manifest.json"])
            self.assertEqual(
                members[prefix + "manifest.json"],
                (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
            )
            self.assertEqual(manifest["schema"], 1)
            self.assertEqual(manifest["serial"], SERIAL)
            self.assertEqual(manifest["tool_revision"], "rev9")
            provision_portal_module.dt.datetime.fromisoformat(manifest["created_at"])
            expected_files = {
                name[len(prefix):]
                for name in members
            }
            self.assertEqual(set(manifest["sha256"]), expected_files - {"manifest.json"})
            for name, digest in manifest["sha256"].items():
                self.assertEqual(
                    digest, hashlib.sha256(members[prefix + name]).hexdigest(), name
                )


class PrivateDnsBackupRoundTripTest(unittest.TestCase):
    def test_backup_bytes_and_restore_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, restore_privacy_dns=True)
            remote = FakeRemoteFiles()
            settings = {
                "private_dns_mode": "opportunistic",
                "private_dns_specifier": "dns.example.org",
            }

            def adb_run(arguments, timeout=None, check=False):
                if list(arguments)[:4] == ["shell", "settings", "get", "global"]:
                    return subprocess.CompletedProcess(
                        arguments, 0, settings[arguments[4]] + "\n"
                    )
                return remote.adb_run(arguments, timeout=timeout, check=check)

            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                provisioner.backup_private_dns()
            expected_backup = {
                "schema": 1,
                "mode": "opportunistic",
                "hostname": "dns.example.org",
            }
            # Byte format: indent=2, insertion order (no sort_keys).
            self.assertEqual(
                remote.files[PRIVACY_BACKUP_REMOTE],
                json.dumps(expected_backup, indent=2) + "\n",
            )
            # A second backup is a no-op: the first backup wins.
            settings["private_dns_mode"] = "hostname"
            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                provisioner.backup_private_dns()
            self.assertEqual(
                remote.files[PRIVACY_BACKUP_REMOTE],
                json.dumps(expected_backup, indent=2) + "\n",
            )
            # Restore replays exactly the saved values.
            calls: list[list[str]] = []

            def restore_adb(arguments, timeout=None, check=False):
                if list(arguments)[:2] == ["shell", "cat"]:
                    return subprocess.CompletedProcess(
                        arguments, 0, remote.files[PRIVACY_BACKUP_REMOTE]
                    )
                calls.append([str(a) for a in arguments])
                return subprocess.CompletedProcess(arguments, 0, "")

            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=restore_adb),
                contextlib.redirect_stdout(stdout),
            ):
                provisioner.restore_private_dns()
            self.assertEqual(
                calls,
                [
                    ["shell", "settings", "put", "global", "private_dns_mode", "opportunistic"],
                    ["shell", "settings", "put", "global", "private_dns_specifier", "dns.example.org"],
                ],
            )
            self.assertIn("PRIVACY_DNS_RESTORE_OK", stdout.getvalue().splitlines())

    def test_restore_deletes_settings_saved_as_null(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, restore_privacy_dns=True)
            backup = json.dumps({"schema": 1, "mode": "null", "hostname": ""})
            calls: list[list[str]] = []

            def adb_run(arguments, timeout=None, check=False):
                if list(arguments)[:2] == ["shell", "cat"]:
                    return subprocess.CompletedProcess(arguments, 0, backup)
                calls.append([str(a) for a in arguments])
                return subprocess.CompletedProcess(arguments, 0, "")

            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                provisioner.restore_private_dns()
            self.assertEqual(
                calls,
                [
                    ["shell", "settings", "delete", "global", "private_dns_mode"],
                    ["shell", "settings", "delete", "global", "private_dns_specifier"],
                ],
            )

    def test_restore_rejects_wrong_schema_and_incomplete_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, restore_privacy_dns=True)
            for payload, pattern in (
                (json.dumps({"schema": 9, "mode": "off", "hostname": "x"}), "unrecognized Private DNS backup"),
                (json.dumps({"schema": 1, "mode": "off"}), "Private DNS backup is incomplete"),
                ("{broken", "invalid Private DNS backup"),
            ):
                with self.subTest(payload=payload):
                    with mock.patch.object(
                        provisioner,
                        "adb_run",
                        return_value=subprocess.CompletedProcess([], 0, payload),
                    ):
                        with self.assertRaisesRegex(ProvisionError, pattern):
                            provisioner.restore_private_dns()


class PrivateDnsApplyTest(unittest.TestCase):
    """The shared apply sequence's DNS applies, driven end to end.

    Regression pin: apply_privacy_dns used to write the normalized
    hostname back into the frozen SettingsConfig and crashed with
    FrozenInstanceError after the live settings were already changed,
    so --dns <hostname> could not complete on any path. The off
    spelling never hit the assignment (its apply mutates nothing)
    and is pinned alongside for symmetry.
    """

    def _device(self, settings):
        remote = FakeRemoteFiles()

        def adb_run(arguments, timeout=None, check=False):
            arguments = [str(argument) for argument in arguments]
            if arguments[:4] == ["shell", "settings", "get", "global"]:
                return subprocess.CompletedProcess(
                    arguments, 0, settings.get(arguments[4], "null") + "\n"
                )
            if arguments[:4] == ["shell", "settings", "put", "global"]:
                settings[arguments[4]] = arguments[5]
                return subprocess.CompletedProcess(arguments, 0, "")
            if arguments[:4] == ["shell", "settings", "delete", "global"]:
                settings.pop(arguments[4], None)
                return subprocess.CompletedProcess(arguments, 0, "")
            return remote.adb_run(arguments, timeout=timeout, check=check)

        return adb_run

    def test_hostname_apply_through_the_shared_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            # The CLI hands the hostname over raw; normalization is
            # the apply's job.
            provisioner = make_provisioner(
                temporary, privacy_dns="One.One.One.One"
            )
            settings = {
                "private_dns_mode": "opportunistic",
                "private_dns_specifier": "dns.example.org",
            }
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    provisioner, "adb_run", side_effect=self._device(settings)
                ),
                contextlib.redirect_stdout(stdout),
            ):
                provisioner._apply_shell_level_state(
                    debloat_configured=False,
                    remote_wipe_configured=False,
                    defer_dns=False,
                )
                # The end-of-run verification reads the same raw flag
                # value and must agree with what the apply wrote.
                provisioner.verify_privacy_dns()
            self.assertEqual(
                settings,
                {
                    "private_dns_mode": "hostname",
                    "private_dns_specifier": "one.one.one.one",
                },
            )
            self.assertIn(
                "PRIVACY_DNS_OK action=strict mode=hostname "
                "hostname=one.one.one.one",
                stdout.getvalue().splitlines(),
            )

    def test_off_apply_through_the_shared_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, dhcp_dns=True)
            settings = {
                "private_dns_mode": "hostname",
                "private_dns_specifier": "one.one.one.one",
            }
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    provisioner, "adb_run", side_effect=self._device(settings)
                ),
                contextlib.redirect_stdout(stdout),
            ):
                provisioner._apply_shell_level_state(
                    debloat_configured=False,
                    remote_wipe_configured=False,
                    defer_dns=False,
                )
            self.assertEqual(settings, {"private_dns_mode": "off"})
            self.assertIn(
                "PRIVACY_DNS_OK action=network mode=off hostname=null",
                stdout.getvalue().splitlines(),
            )


class AdbAuthTimeoutBackupRoundTripTest(unittest.TestCase):
    def test_backup_bytes_and_read_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            captured: list[tuple[str, str]] = []

            def adb_run(arguments, timeout=None, check=False):
                del timeout, check
                if list(arguments)[:2] == ["shell", "cat"]:
                    return subprocess.CompletedProcess(arguments, 1, "")
                return subprocess.CompletedProcess(
                    arguments, 0, "604800\n"
                )

            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(
                        (contents, remote)
                    ),
                ),
            ):
                provisioner.backup_adb_auth_timeout()
            expected = json.dumps({"schema": 1, "value": "604800"}, indent=2) + "\n"
            self.assertEqual(
                captured, [(expected, ADB_AUTH_TIMEOUT_BACKUP_REMOTE)]
            )
            with mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess([], 0, expected),
            ):
                self.assertEqual(provisioner.read_adb_auth_timeout_backup(), "604800")

    def test_read_rejects_absent_malformed_and_out_of_domain_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            with mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess([], 1, ""),
            ):
                with self.assertRaisesRegex(ProvisionError, "backup is absent"):
                    provisioner.read_adb_auth_timeout_backup()
            for payload, pattern in (
                ("{broken", "invalid ADB authorization timeout backup"),
                (json.dumps({"schema": 2, "value": "0"}), "unrecognized ADB authorization timeout backup"),
                (json.dumps({"schema": 1, "value": "soon"}), "unrecognized ADB authorization timeout backup"),
                (json.dumps({"schema": 1, "value": 0}), "unrecognized ADB authorization timeout backup"),
            ):
                with self.subTest(payload=payload):
                    with mock.patch.object(
                        provisioner,
                        "adb_run",
                        return_value=subprocess.CompletedProcess([], 0, payload),
                    ):
                        with self.assertRaisesRegex(ProvisionError, pattern):
                            provisioner.read_adb_auth_timeout_backup()
            # "null" (setting absent) is a valid saved value.
            with mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps({"schema": 1, "value": "null"})
                ),
            ):
                self.assertEqual(provisioner.read_adb_auth_timeout_backup(), "null")


class AppVerifierBackupRoundTripTest(unittest.TestCase):
    BACKUP = {
        "schema": 2,
        "package_verifier_enable": "1",
        "meta_verifier_package_disabled": True,
    }

    def test_write_bytes_and_read_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            remote = FakeRemoteFiles()
            with mock.patch.object(
                provisioner, "adb_run", side_effect=remote.adb_run
            ):
                provisioner.write_app_verifier_backup(dict(self.BACKUP))
            # Byte format: indent=2, insertion order (no sort_keys).
            self.assertEqual(
                remote.files[APP_VERIFIER_BACKUP_REMOTE],
                json.dumps(self.BACKUP, indent=2) + "\n",
            )
            with mock.patch.object(
                provisioner, "adb_run", side_effect=remote.adb_run
            ):
                self.assertEqual(
                    provisioner.read_app_verifier_backup(), self.BACKUP
                )

    def test_schema_1_backup_is_upgraded_on_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            legacy = {"schema": 1, "package_verifier_enable": "0"}
            with mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(legacy)
                ),
            ):
                backup = provisioner.read_app_verifier_backup()
            self.assertEqual(backup["package_verifier_enable"], "0")
            # Schema 1 predates package-state management: the verifier
            # package is treated as never disabled.
            self.assertIs(backup["meta_verifier_package_disabled"], False)

    def test_read_rejects_wrong_schema_and_bad_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            for payload, pattern in (
                (json.dumps({"schema": 3, "package_verifier_enable": "1", "meta_verifier_package_disabled": False}), "unrecognized app-verifier backup"),
                (json.dumps({"schema": 2, "package_verifier_enable": "yes", "meta_verifier_package_disabled": False}), "app-verifier backup is incomplete"),
                (json.dumps({"schema": 2, "package_verifier_enable": "1"}), "app-verifier package backup is incomplete"),
                ("{broken", "invalid app-verifier backup"),
            ):
                with self.subTest(payload=payload):
                    with mock.patch.object(
                        provisioner,
                        "adb_run",
                        return_value=subprocess.CompletedProcess([], 0, payload),
                    ):
                        with self.assertRaisesRegex(ProvisionError, pattern):
                            provisioner.read_app_verifier_backup()


class TsvBackupRoundTripTest(unittest.TestCase):
    def test_debloat_backup_write_read_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, debloat=True)
            remote = FakeRemoteFiles()
            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=remote.adb_run),
                mock.patch.object(
                    provisioner,
                    "package_sets",
                    return_value=(set(DEBLOAT_PACKAGES), {DEBLOAT_PACKAGES[0]}),
                ),
                contextlib.redirect_stdout(stdout),
            ):
                states = provisioner.ensure_debloat_backup()
            expected_states = {
                package: (
                    "disabled" if package == DEBLOAT_PACKAGES[0] else "enabled"
                )
                for package in DEBLOAT_PACKAGES
            }
            self.assertEqual(states, expected_states)
            expected_contents = "# portal-debloat-backup-v1\n" + "".join(
                f"{package}\t{expected_states[package]}\n"
                for package in DEBLOAT_PACKAGES
            )
            self.assertEqual(remote.files[DEBLOAT_BACKUP_REMOTE], expected_contents)
            self.assertEqual(
                PortalProvisioner.parse_debloat_backup(expected_contents),
                expected_states,
            )
            self.assertIn(
                f"DEBLOAT_BACKUP_OK existing=0 path={DEBLOAT_BACKUP_REMOTE}",
                stdout.getvalue().splitlines(),
            )
            # Second run reuses the saved backup verbatim.
            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=remote.adb_run),
                mock.patch.object(
                    provisioner,
                    "package_sets",
                    side_effect=AssertionError("device re-read on reuse"),
                ),
                contextlib.redirect_stdout(stdout),
            ):
                self.assertEqual(provisioner.ensure_debloat_backup(), expected_states)
            self.assertIn(
                f"DEBLOAT_BACKUP_OK existing=1 path={DEBLOAT_BACKUP_REMOTE}",
                stdout.getvalue().splitlines(),
            )

    def test_component_backup_write_read_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, debloat=True)
            remote = FakeRemoteFiles()
            states = {
                component: (category, "default")
                for category, component in DEBLOAT_COMPONENTS
            }
            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=remote.adb_run),
                mock.patch.object(
                    provisioner, "current_component_states", return_value=states
                ),
                contextlib.redirect_stdout(stdout),
            ):
                saved = provisioner.ensure_component_backup()
            self.assertEqual(saved, states)
            expected_contents = (
                "# portal-debloat-components-backup-v1\n"
                + "".join(
                    f"{states[component][0]}\t{component}\tdefault\n"
                    for component in DEBLOAT_COMPONENT_NAMES
                )
            )
            self.assertEqual(
                remote.files[DEBLOAT_COMPONENT_BACKUP_REMOTE], expected_contents
            )
            self.assertEqual(
                PortalProvisioner.parse_component_backup(expected_contents), states
            )
            self.assertIn(
                "DEBLOAT_COMPONENT_BACKUP_OK existing=0 path="
                + DEBLOAT_COMPONENT_BACKUP_REMOTE,
                stdout.getvalue().splitlines(),
            )

    def test_remote_wipe_backup_write_read_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, block_remote_wipe=True)
            remote = FakeRemoteFiles()
            states = {component: "default" for component in REMOTE_WIPE_COMPONENTS}
            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=remote.adb_run),
                mock.patch.object(
                    provisioner,
                    "current_named_component_states",
                    return_value=states,
                ),
                contextlib.redirect_stdout(stdout),
            ):
                saved = provisioner.ensure_remote_wipe_backup()
            self.assertEqual(saved, states)
            expected_contents = (
                "# portal-remote-wipe-components-backup-v1\n"
                + "".join(
                    f"{component}\tdefault\n" for component in REMOTE_WIPE_COMPONENTS
                )
            )
            self.assertEqual(
                remote.files[REMOTE_WIPE_BACKUP_REMOTE], expected_contents
            )
            self.assertEqual(
                PortalProvisioner.parse_remote_wipe_backup(expected_contents),
                states,
            )
            self.assertIn(
                "REMOTE_WIPE_BACKUP_OK existing=0 path=" + REMOTE_WIPE_BACKUP_REMOTE,
                stdout.getvalue().splitlines(),
            )

    def test_tsv_parsers_reject_bad_headers_and_incomplete_files(self) -> None:
        with self.assertRaisesRegex(ProvisionError, "unrecognized Portal debloat backup"):
            PortalProvisioner.parse_debloat_backup("# something-else\n")
        with self.assertRaisesRegex(ProvisionError, "unrecognized component debloat backup"):
            PortalProvisioner.parse_component_backup("")
        with self.assertRaisesRegex(ProvisionError, "unrecognized remote-wipe backup"):
            PortalProvisioner.parse_remote_wipe_backup("# portal-debloat-backup-v1\n")
        incomplete = "# portal-remote-wipe-components-backup-v1\n" + (
            f"{REMOTE_WIPE_COMPONENTS[0]}\tdefault\n"
        )
        with self.assertRaisesRegex(ProvisionError, "remote-wipe backup is incomplete"):
            PortalProvisioner.parse_remote_wipe_backup(incomplete)


# ---------------------------------------------------------------------------
# Marker strings emitted by each phase (exact lines)
# ---------------------------------------------------------------------------


def stdout_lines(function, *args, **kwargs):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = function(*args, **kwargs)
    return result, buffer.getvalue().splitlines()


class TargetMarkerTest(unittest.TestCase):
    def adb_for(self, provisioner, target):
        properties = {
            "ro.build.fingerprint": target.fingerprint,
            "ro.product.device": target.device,
            "ro.product.model": target.model,
        }

        def adb_run(arguments, timeout=None, check=False):
            del timeout, check
            return subprocess.CompletedProcess(
                arguments, 0, properties[arguments[-1]] + "\n"
            )

        return mock.patch.object(provisioner, "adb_run", side_effect=adb_run)

    def test_target_ok_marker_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            with self.adb_for(provisioner, TERRY):
                found, lines = stdout_lines(provisioner.verify_target)
            self.assertEqual(found, TERRY)
            self.assertEqual(
                lines,
                [
                    f"TARGET_OK serial={SERIAL} target={TERRY.key} "
                    f"model={TERRY.model} device={TERRY.device} "
                    f"fingerprint={TERRY.fingerprint}"
                ],
            )

    def test_target_unsupported_marker_and_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)

            def adb_run(arguments, timeout=None, check=False):
                del timeout, check
                values = {
                    "ro.build.fingerprint": "unknown/fingerprint:1",
                    "ro.product.device": "unknown-device",
                    "ro.product.model": "Unknown Model",
                }
                return subprocess.CompletedProcess(
                    arguments, 0, values[arguments[-1]] + "\n"
                )

            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                found, lines = stdout_lines(
                    provisioner.verify_target, require_supported=False
                )
                self.assertIsNone(found)
                self.assertEqual(
                    lines,
                    [
                        f"TARGET_UNSUPPORTED serial={SERIAL} "
                        "model=Unknown Model device=unknown-device "
                        "fingerprint=unknown/fingerprint:1"
                    ],
                )
                with self.assertRaisesRegex(
                    ProvisionError,
                    "unsupported firmware; refusing build-specific kernel writes",
                ):
                    provisioner.verify_target()


class ProvisionOkMarkerTest(unittest.TestCase):
    def test_verify_across_boots_provision_ok_single_boot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            with (
                mock.patch.object(provisioner, "verify_requested_state") as verify,
                mock.patch.object(provisioner, "write_state") as write_state,
                mock.patch.object(provisioner, "reboot") as reboot,
            ):
                _, lines = stdout_lines(
                    provisioner.verify_across_two_reboots, first_boot="boot-A"
                )
            reboot.assert_not_called()
            verify.assert_called_once_with()
            write_state.assert_called_once_with("complete", "boot-A", "boot-A")
            self.assertEqual(
                lines,
                [
                    f"PROVISION_OK first_boot=boot-A second_boot=boot-A "
                    f"logs={provisioner.log_dir}"
                ],
            )

    def test_verify_across_boots_provision_ok_two_boots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, verify_boots=2)
            with (
                mock.patch.object(provisioner, "verify_requested_state") as verify,
                mock.patch.object(provisioner, "write_state") as write_state,
                mock.patch.object(
                    provisioner, "reboot", return_value=("boot-A", "boot-B")
                ),
            ):
                _, lines = stdout_lines(
                    provisioner.verify_across_two_reboots, first_boot="boot-A"
                )
            self.assertEqual(verify.call_count, 2)
            write_state.assert_called_once_with("complete", "boot-A", "boot-B")
            self.assertEqual(
                lines,
                [
                    "VERIFY_REBOOT starting",
                    f"PROVISION_OK first_boot=boot-A second_boot=boot-B "
                    f"logs={provisioner.log_dir}",
                ],
            )

    def test_provision_ok_reboots_zero_for_configured_system_theme(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, system_theme_control="dark"
            )
            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner,
                    "verify_target",
                    side_effect=lambda **_: setattr(provisioner, "target", TERRY),
                ),
                mock.patch.object(
                    provisioner, "adb_framework_boot_preflight", return_value=False
                ),
                mock.patch.object(
                    provisioner, "record_system_theme_original"
                ),
                mock.patch.object(
                    provisioner,
                    "system_theme_control_preflight",
                    return_value=True,
                ),
                mock.patch.object(provisioner, "write_state") as write_state,
                mock.patch.object(provisioner, "reboot") as reboot,
                mock.patch.object(
                    provisioner, "adb_run", side_effect=flag_aware_adb_run()
                ),
            ):
                _, lines = stdout_lines(provisioner.provision)
            reboot.assert_not_called()
            write_state.assert_called_once_with("complete")
            self.assertEqual(
                lines,
                [
                    "AUTOROOT_GUARD_ENGAGED prior=absent",
                    "PROVISION_OK reboots=0 system_theme=dark "
                    f"logs={provisioner.log_dir}",
                    "AUTOROOT_GUARD_RESTORED prior=absent",
                ],
            )


class VerifyMarkersTest(unittest.TestCase):
    def test_adb_framework_ok_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            with mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess([], 0, "1\n"),
            ):
                _, lines = stdout_lines(provisioner.verify_adb_framework_enabled)
            self.assertEqual(
                lines,
                [
                    f"ADB_FRAMEWORK_OK action=verified "
                    f"{ADB_ENABLED_SETTING}=1 prompts=enabled"
                ],
            )

    def test_adb_auth_timeout_ok_marker_disabled_and_restored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            with mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess([], 0, "0\n"),
            ):
                _, lines = stdout_lines(provisioner.verify_adb_auth_timeout)
            self.assertEqual(
                lines,
                [f"ADB_AUTH_TIMEOUT_OK action=disabled {ADB_AUTH_TIMEOUT_SETTING}=0"],
            )
            provisioner.restore_adb_auth_timeout = True
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, "604800\n"),
                ),
                mock.patch.object(
                    provisioner,
                    "read_adb_auth_timeout_backup",
                    return_value="604800",
                ),
            ):
                _, lines = stdout_lines(provisioner.verify_adb_auth_timeout)
            self.assertEqual(
                lines,
                [
                    f"ADB_AUTH_TIMEOUT_OK action=restored "
                    f"{ADB_AUTH_TIMEOUT_SETTING}=604800"
                ],
            )

    def test_app_updates_ok_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, allow_app_updates=True)
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, "0\n"),
                ),
                mock.patch.object(
                    provisioner,
                    "app_verifier_package_disabled",
                    return_value=True,
                ),
            ):
                _, lines = stdout_lines(provisioner.verify_app_verifier_setting)
            self.assertEqual(
                lines,
                [
                    "APP_UPDATES_OK action=updates-allowed "
                    "package_verifier_enable=0 meta_verifier_disabled=1"
                ],
            )

    def test_privacy_dns_ok_marker_strict_and_dhcp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, privacy_dns="dns.example.com"
            )

            def adb_with(mode: str, hostname: str):
                def adb_run(arguments, timeout=None, check=False):
                    del timeout, check
                    value = (
                        mode
                        if arguments[-1] == "private_dns_mode"
                        else hostname
                    )
                    return subprocess.CompletedProcess(arguments, 0, value + "\n")

                return mock.patch.object(
                    provisioner, "adb_run", side_effect=adb_run
                )

            with adb_with("hostname", "dns.example.com"):
                _, lines = stdout_lines(provisioner.verify_privacy_dns)
            self.assertEqual(
                lines,
                [
                    "PRIVACY_DNS_OK action=strict mode=hostname "
                    "hostname=dns.example.com"
                ],
            )
            provisioner.privacy_dns = None
            provisioner.dhcp_dns = True
            with adb_with("off", "null"):
                _, lines = stdout_lines(provisioner.verify_privacy_dns)
            self.assertEqual(
                lines,
                ["PRIVACY_DNS_OK action=network mode=off hostname=null"],
            )


class ExploitUsersMarkerTest(unittest.TestCase):
    def test_exploit_users_ok_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            provisioner.target = RIPLEY
            listing = (
                "Users:\n"
                "\tUserInfo{10:PortalRootSentinel-1:4c13} running\n"
                "\tUserInfo{11:PortalRootSentinel-2:4c13} running\n"
                "\tUserInfo{12:PortalRootSentinel-3:4c13} running\n"
            )
            with mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess([], 0, listing),
            ):
                _, lines = stdout_lines(provisioner.prepare_exploit_users)
            self.assertEqual(lines, ["EXPLOIT_USERS_OK ids=10,11,12 created=3"])
            self.assertEqual(provisioner.exploit_user_ids_runtime, (10, 11, 12))


class ShizukuMarkersTest(unittest.TestCase):
    def test_shizuku_payload_ok_marker_and_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            provisioner.target = ALOHA
            apk = pathlib.Path(temporary) / "shizuku.apk"
            apk.write_bytes(b"apk")

            def adb_run(arguments, timeout=None, check=False):
                del timeout, check
                joined = " ".join(str(a) for a in arguments)
                if "dumpsys" in arguments:
                    return subprocess.CompletedProcess(
                        arguments, 0, f"versionName={SHIZUKU_VERSION}\n"
                    )
                if "adbkey.pub" in joined:
                    return subprocess.CompletedProcess(
                        arguments, 0, "AAAAB3NzaC1 user@portal\n"
                    )
                if "adbkey" in joined:
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        "-----BEGIN PRIVATE KEY-----\nx\n"
                        "-----END PRIVATE KEY-----\n",
                    )
                return subprocess.CompletedProcess(arguments, 0, "")

            with (
                mock.patch.object(
                    provisioner, "resolve_shizuku_apk", return_value=apk
                ),
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(provisioner, "install_apk_preserving_verifier"),
                mock.patch.object(provisioner, "settle_package_state"),
                mock.patch.object(provisioner, "verify_package_verifier_state"),
            ):
                _, lines = stdout_lines(provisioner.install_shizuku_payload)
            self.assertEqual(
                lines,
                [
                    f"SHIZUKU_PAYLOAD_OK version={SHIZUKU_VERSION} "
                    f"helper={SHIZUKU_HELPER_PACKAGE} key_reused=1"
                ],
            )
            key_file = provisioner.log_dir / "portal-shizuku-adbkey.pub"
            self.assertEqual(key_file.read_text(), "AAAAB3NzaC1 user@portal\n")
            self.assertEqual(stat.S_IMODE(key_file.stat().st_mode), 0o600)

    def test_shizuku_root_ok_marker(self) -> None:
        # Same fake-device shape as ShizukuRootStartTest in
        # test_autoroot_flows.py, here pinning the emitted markers.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            provisioner.target = ALOHA
            pidof_calls = {"count": 0}

            def adb_run(args, timeout=None, check=False):
                del timeout, check
                if "dumpsys" in args:
                    return subprocess.CompletedProcess(
                        args,
                        0,
                        "    nativeLibraryDir=/data/app/~~x/"
                        "moe.shizuku.privileged.api-y/lib/arm64\n",
                        "",
                    )
                if "pm" in args and "path" in args:
                    return subprocess.CompletedProcess(
                        args,
                        0,
                        "package:/data/app/~~x/moe.shizuku.privileged.api-y/base.apk\n",
                        "",
                    )
                if args[:2] == ["shell", "pidof"]:
                    pidof_calls["count"] += 1
                    stdout = "" if pidof_calls["count"] == 1 else "12345"
                    return subprocess.CompletedProcess(args, 0, stdout, "")
                if "cat" in args and any("/proc/" in a for a in args):
                    return subprocess.CompletedProcess(
                        args, 0, "Name:\tshizuku_server\nUid:\t0\t0\t0\t0\n", ""
                    )
                return subprocess.CompletedProcess(args, 0, "", "")

            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provisioner, "daemon_exec", return_value=(0, "12345")
                ),
            ):
                _, lines = stdout_lines(provisioner.start_shizuku_as_root)
            self.assertIn(
                "SHIZUKU_ROOT_START exit=0 output='12345'", lines
            )
            self.assertIn("SHIZUKU_ROOT_OK pid=12345 uid=0", lines)


class CustomPayloadMarkerTest(unittest.TestCase):
    def test_custom_payload_ok_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                shizuku=True,
                custom_payload=pathlib.Path(temporary) / "daemon.bin",
            )
            provisioner.target = ALOHA
            provisioner.custom_payload.write_bytes(b"daemon")
            with (
                mock.patch.object(provisioner, "stage") as stage,
                mock.patch.object(
                    provisioner, "reboot", return_value=("boot-0", "boot-1")
                ) as reboot,
                mock.patch.object(provisioner, "wait_for_race_boot_window"),
                mock.patch.object(provisioner, "kaslr_base", return_value=0x1000),
                mock.patch.object(provisioner, "memstart", return_value=0x2000),
                mock.patch.object(provisioner, "exploit", return_value=True),
                mock.patch.object(provisioner, "verify_custom_payload"),
                mock.patch.object(
                    provisioner, "apply_post_payload_root_steps"
                ) as post_steps,
                mock.patch.object(provisioner, "write_state") as write_state,
            ):
                _, lines = stdout_lines(provisioner.apply_custom_payload)
            stage.assert_called_once_with()
            reboot.assert_called_once_with()
            post_steps.assert_called_once_with()
            write_state.assert_called_once_with("complete")
            self.assertIn("CUSTOM_PAYLOAD_ATTEMPT=1 preparing clean boot", lines)
            self.assertIn(
                "RUNTIME_ADDRESSES attempt=1 boot_id=boot-1 "
                "kaslr=0x1000 memstart=0x2000",
                lines,
            )
            self.assertIn(
                f"CUSTOM_PAYLOAD_OK payload={CUSTOM_PAYLOAD_DST_REMOTE} "
                f"port={CUSTOM_PAYLOAD_PORT} logs={provisioner.log_dir}",
                lines,
            )
            self.assertFalse(provisioner._in_custom_payload_phase)


class AutorootStagedMarkerTest(unittest.TestCase):
    # Mirrors AutorootStagingTest's harness in test_autoroot_flows.py,
    # here pinning the exact marker lines staging emits.
    def test_autoroot_staged_ok_and_companion_markers_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                shizuku=True,
                autoroot=True,
                custom_payload=pathlib.Path("daemon.bin"),
            )
            provisioner.target = ALOHA
            apk = pathlib.Path(temporary) / "helper.apk"
            apk.write_bytes(b"apk")
            runner = pathlib.Path(temporary) / "run.sh"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            pushes: dict[str, str] = {}

            def adb_run(args, timeout=None, check=False):
                del timeout, check
                if args[:3] == ["shell", "pm", "path"]:
                    return subprocess.CompletedProcess(
                        args, 0, "package:/data/app/~~s/base.apk\n", ""
                    )
                if args[:3] == ["shell", "test", "-f"]:
                    return subprocess.CompletedProcess(args, 0, "", "")
                if args and args[0] == "push":
                    local_path = pathlib.Path(args[1])
                    pushes[args[2]] = (
                        local_path.read_text(encoding="utf-8")
                        if local_path.is_file()
                        else ""
                    )
                    return subprocess.CompletedProcess(args, 0, "", "")
                if args and args[0] == "uninstall":
                    return subprocess.CompletedProcess(args, 0, "Success\n", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            with (
                mock.patch.object(
                    provision_portal_module, "AUTOROOT_HELPER_LOCAL", apk
                ),
                mock.patch.object(
                    provision_portal_module, "AUTOROOT_RUNNER_LOCAL", runner
                ),
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(provisioner, "install_apk_preserving_verifier"),
                mock.patch.object(provisioner, "settle_package_state"),
                mock.patch.object(
                    provisioner,
                    "package_sets",
                    return_value=({SHIZUKU_HELPER_PACKAGE}, set()),
                ),
            ):
                _, lines = stdout_lines(provisioner.stage_autoroot_payload)
            self.assertIn("AUTOROOT_HELPER_ACTIVATED first_install=1", lines)
            self.assertIn(
                "SHIZUKU_HELPER_REMOVED reason=autoroot-keypair-merged", lines
            )
            self.assertIn(
                f"AUTOROOT_STAGED_OK dir={AUTOROOT_REMOTE_DIR} "
                f"helper={AUTOROOT_HELPER_PACKAGE} "
                f"max_attempts={AUTOROOT_MAX_ATTEMPTS}",
                lines,
            )
            conf = pushes["/data/local/tmp/portal-autoroot/autoroot.conf"]
            self.assertEqual(
                conf,
                f"MAX_ATTEMPTS={AUTOROOT_MAX_ATTEMPTS}\n"
                "SESSION_WINDOW_SEC=3600\n"
                "SIMPLEPERF=/data/local/tmp/portal-simpleperf\n"
                "KASLR_OFFSETS="
                + ",".join(hex(o) for o in ALOHA.kaslr_pc_offsets)
                + "\n",
            )


class RecoverMarkersTest(unittest.TestCase):
    def run_recover(self, provisioner, state):
        with (
            mock.patch.object(provisioner, "read_state", return_value=state),
            mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess([], 0, ""),
            ),
            mock.patch.object(provisioner, "print_status"),
        ):
            return stdout_lines(provisioner.recover_actions)

    def test_recover_no_state_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            result, lines = self.run_recover(provisioner, None)
            self.assertFalse(result)
            self.assertEqual(lines, ["RECOVER_NO_STATE staged_files=cleaned"])

    def test_recover_completed_state_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            result, lines = self.run_recover(
                provisioner, {"schema": 1, "status": "complete", "actions": {}}
            )
            self.assertFalse(result)
            self.assertEqual(lines, ["RECOVER_STATE status=complete action=status"])

    def test_recover_resume_marker_and_action_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            state = {
                "schema": 1,
                "status": "pending",
                "actions": {
                    "audio": True,
                    "privacy_dns": "dns.example.com",
                    "presence_fps_cap": 5,
                    "system_theme_control": "dark",
                },
            }
            result, lines = self.run_recover(provisioner, state)
            self.assertTrue(result)
            self.assertEqual(
                lines,
                [
                    "RECOVER_RESUME actions=audio,presence_fps_cap,"
                    "privacy_dns,system_theme_control"
                ],
            )
            self.assertTrue(provisioner.audio)
            self.assertEqual(provisioner.privacy_dns, "dns.example.com")
            self.assertEqual(provisioner.presence_fps_cap, 5)
            self.assertEqual(provisioner.system_theme_control, "dark")

    def test_recover_rejects_unknown_actions_and_bad_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            for actions, pattern in (
                ({"teleport": True}, "unsupported recovery action: teleport"),
                ({"audio": "yes"}, "invalid recovery value for audio"),
                ({"presence_fps_cap": 99}, "invalid presence_fps_cap recovery value"),
                ({"privacy_dns": 42}, "invalid privacy_dns recovery value"),
                ({"system_theme_control": "automatic"}, "invalid system_theme_control recovery value"),
            ):
                with self.subTest(actions=actions):
                    state = {"schema": 1, "status": "pending", "actions": actions}
                    with (
                        mock.patch.object(
                            provisioner, "read_state", return_value=state
                        ),
                        mock.patch.object(
                            provisioner,
                            "adb_run",
                            return_value=subprocess.CompletedProcess([], 0, ""),
                        ),
                    ):
                        with self.assertRaisesRegex(ProvisionError, pattern):
                            provisioner.recover_actions()
            with (
                mock.patch.object(
                    provisioner,
                    "read_state",
                    return_value={"schema": 1, "status": "pending", "actions": []},
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "pending state has no action map"
                ):
                    provisioner.recover_actions()


class DryRunReportTest(unittest.TestCase):
    def test_dry_run_line_format_and_report_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            with mock.patch.object(
                provision_portal_module.shutil, "which", return_value="/bin/tool"
            ):
                _, lines = stdout_lines(provisioner.dry_run_report, {})
            expected = {
                "actions": {},
                "current": {
                    "audio": None,
                    "updates": None,
                    "debloat": None,
                    "remote_wipe": None,
                    "meta_accounts_remaining": None,
                    "presence": None,
                    # Dict-typed sections pass through as dicts; an
                    # empty status yields empty dicts here, not None.
                    "privacy_dns": {},
                    "app_updates": {},
                    "shizuku": {},
                    "system_theme_control": {},
                    "camera_light": {},
                    "adb_auth_timeout_disabled": None,
                    "adb_authorization_prompts_enabled": None,
                    "adb_framework_boot_persistence_verified": None,
                },
                "requires_exploit": False,
                "minimum_reboots": 0,
                "host_tools": {
                    "adb": True,
                    "git": True,
                    "make": True,
                    "python3": True,
                },
                "build_outputs": {},
                "will_modify_device": False,
            }
            self.assertEqual(
                lines, ["DRY_RUN " + json.dumps(expected, sort_keys=True)]
            )


# ---------------------------------------------------------------------------
# Failure ordering: host-side failures surface before any reboot
#
# The family around ShizukuCliTest
# .test_download_failure_is_reported_before_any_reboot in
# test_provision_portal_cli.py: every host-side validation that
# provision() (and the phase entry points) performs before the first
# exploit/install reboot must fail without a single reboot call, and
# -- for the provision() pre-reboot block -- before the "pending"
# state manifest is written.
# ---------------------------------------------------------------------------


class FailureBeforeRebootTest(unittest.TestCase):
    def run_provision_expecting_failure(self, provisioner, pattern: str):
        """Drive provision() with the device seams mocked; return the
        reboot/write_state mocks so callers can assert they never ran."""
        reboot = mock.Mock(name="reboot")
        write_state = mock.Mock(name="write_state")
        with (
            mock.patch.object(provisioner, "connect"),
            mock.patch.object(
                provisioner,
                "verify_target",
                side_effect=lambda **_: setattr(provisioner, "target", TERRY),
            ),
            mock.patch.object(
                provisioner, "adb_framework_boot_preflight", return_value=False
            ),
            mock.patch(
                "provision_portal.android_build_environment", return_value={}
            ),
            mock.patch.object(
                provisioner,
                "adb_run",
                side_effect=flag_aware_adb_run(),
            ),
            mock.patch.object(provisioner, "reboot", reboot),
            mock.patch.object(provisioner, "write_state", write_state),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(ProvisionError, pattern),
        ):
            provisioner.provision()
        return reboot, write_state

    def test_missing_explicit_shizuku_apk_fails_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                shizuku=True,
                shizuku_apk=pathlib.Path(temporary) / "no-such.apk",
            )
            reboot, write_state = self.run_provision_expecting_failure(
                provisioner, "Shizuku APK does not exist"
            )
            reboot.assert_not_called()
            write_state.assert_not_called()

    def test_shizuku_download_failure_fails_before_any_reboot(self) -> None:
        # The real resolve_shizuku_apk, with the network call failing:
        # the download error must surface from provision() before any
        # reboot and before the pending manifest is written.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            reboot = mock.Mock(name="reboot")
            write_state = mock.Mock(name="write_state")
            with (
                mock.patch.dict(os.environ, {"HOME": temporary}),
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner,
                    "verify_target",
                    side_effect=lambda **_: setattr(provisioner, "target", TERRY),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_framework_boot_preflight",
                    return_value=False,
                ),
                mock.patch(
                    "provision_portal.android_build_environment", return_value={}
                ),
                mock.patch.object(provisioner, "reboot", reboot),
                mock.patch.object(provisioner, "write_state", write_state),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=flag_aware_adb_run()
                ),
                mock.patch(
                    "provision_portal.urllib.request.urlretrieve",
                    side_effect=OSError("host is offline"),
                ),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(
                    ProvisionError,
                    "Shizuku APK download failed on the host computer",
                ),
            ):
                provisioner.provision()
            reboot.assert_not_called()
            write_state.assert_not_called()

    def test_shizuku_checksum_mismatch_fails_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)

            def fake_download(url, destination):
                pathlib.Path(destination).write_bytes(b"not the pinned apk")
                return destination, None

            # Drive provision() manually: this case needs urlretrieve
            # patched, which the shared helper does not do.
            reboot = mock.Mock(name="reboot")
            write_state = mock.Mock(name="write_state")
            with (
                mock.patch.dict(os.environ, {"HOME": temporary}),
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner,
                    "verify_target",
                    side_effect=lambda **_: setattr(provisioner, "target", TERRY),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_framework_boot_preflight",
                    return_value=False,
                ),
                mock.patch(
                    "provision_portal.android_build_environment", return_value={}
                ),
                mock.patch.object(provisioner, "reboot", reboot),
                mock.patch.object(provisioner, "write_state", write_state),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=flag_aware_adb_run()
                ),
                mock.patch(
                    "provision_portal.urllib.request.urlretrieve",
                    side_effect=fake_download,
                ),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(
                    ProvisionError, "official Shizuku APK checksum mismatch"
                ),
            ):
                provisioner.provision()
            reboot.assert_not_called()
            write_state.assert_not_called()
            # The rejected download is cleaned out of the cache.
            cache = pathlib.Path(temporary) / ".cache" / "portal-root"
            self.assertEqual(list(cache.iterdir()), [])

    def test_invalid_shizuku_apk_zip_fails_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bogus = pathlib.Path(temporary) / "bogus.apk"
            bogus.write_bytes(b"this is not a zip archive")
            provisioner = make_provisioner(
                temporary, shizuku=True, shizuku_apk=bogus
            )
            reboot, write_state = self.run_provision_expecting_failure(
                provisioner, "invalid Shizuku APK"
            )
            reboot.assert_not_called()
            write_state.assert_not_called()

    def test_build_environment_failure_fails_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, audio=True)
            reboot = mock.Mock(name="reboot")
            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner,
                    "verify_target",
                    side_effect=lambda **_: setattr(provisioner, "target", TERRY),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_framework_boot_preflight",
                    return_value=False,
                ),
                mock.patch(
                    "provision_portal.android_build_environment",
                    side_effect=ProvisionError(
                        "no Portal changes were made: no Android SDK found"
                    ),
                ),
                mock.patch.object(provisioner, "reboot", reboot),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=flag_aware_adb_run()
                ),
                mock.patch.object(
                    provisioner, "resolve_shizuku_apk"
                ) as resolve,
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(ProvisionError, "no Portal changes were made"),
            ):
                provisioner.provision()
            reboot.assert_not_called()
            resolve.assert_not_called()

    def test_unsupported_target_fails_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            reboot = mock.Mock(name="reboot")

            def adb_run(arguments, timeout=None, check=False):
                del timeout, check
                arguments = [str(argument) for argument in arguments]
                if (
                    "portal-autoroot.disable" in " ".join(arguments)
                    and "test" in arguments
                ):
                    # The guard's flag probe: answer present, so
                    # the run reaches the target check it is about.
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        provision_portal_module.AUTOROOT_FLAG_PRESENT_TOKEN,
                    )
                return subprocess.CompletedProcess(
                    arguments, 0, "unknown-value\n"
                )

            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(provisioner, "reboot", reboot),
                mock.patch(
                    "provision_portal.android_build_environment", return_value={}
                ) as build_env,
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(ProvisionError, "unsupported firmware"),
            ):
                provisioner.provision()
            reboot.assert_not_called()
            build_env.assert_not_called()

    def test_retired_camera_light_flag_fails_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_camera_light=True)
            reboot, write_state = self.run_provision_expecting_failure(
                provisioner,
                "--disable-camera-light has been retired",
            )
            reboot.assert_not_called()
            write_state.assert_not_called()

    def test_missing_custom_payload_fails_before_stage_and_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                custom_payload=pathlib.Path(temporary) / "missing-daemon",
            )
            provisioner.target = ALOHA
            with (
                mock.patch.object(provisioner, "stage") as stage,
                mock.patch.object(provisioner, "reboot") as reboot,
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "custom payload not found"
                ):
                    provisioner.apply_custom_payload()
            stage.assert_not_called()
            reboot.assert_not_called()

    def test_custom_payload_requires_target_and_configuration_first(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, custom_payload=pathlib.Path(temporary) / "daemon"
            )
            with self.assertRaisesRegex(
                ProvisionError, "target must be selected before custom payload"
            ):
                provisioner.apply_custom_payload()
            provisioner.target = ALOHA
            provisioner.custom_payload = None
            with self.assertRaisesRegex(
                ProvisionError, "custom payload was not configured"
            ):
                provisioner.apply_custom_payload()

    def test_stage_missing_build_output_fails_before_any_push(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            provisioner.target = TERRY
            with mock.patch.object(provisioner, "adb_run") as adb_run:
                with self.assertRaisesRegex(
                    ProvisionError, "missing build output"
                ):
                    provisioner.stage()
            adb_run.assert_not_called()

    def test_standard_install_stage_failure_precedes_first_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, audio=True)
            provisioner.target = TERRY
            with (
                mock.patch.object(provisioner, "prepare_exploit_users"),
                mock.patch.object(
                    provisioner,
                    "stage",
                    side_effect=ProvisionError("missing build output: preload"),
                ),
                mock.patch.object(provisioner, "reboot") as reboot,
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(ProvisionError, "missing build output"),
            ):
                provisioner.run_standard_install(use_exploit_sentinel=False)
            reboot.assert_not_called()

    def test_autoroot_staging_missing_helper_fails_before_any_adb(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, shizuku=True, autoroot=True
            )
            provisioner.target = ALOHA
            missing = pathlib.Path(temporary) / "no-helper.apk"
            with (
                mock.patch.object(
                    provision_portal_module, "AUTOROOT_HELPER_LOCAL", missing
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    side_effect=AssertionError("adb used before validation"),
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "missing autoroot helper build output"
                ):
                    provisioner.stage_autoroot_payload()

    def test_autoroot_staging_missing_runner_fails_before_any_adb(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, shizuku=True, autoroot=True
            )
            provisioner.target = ALOHA
            helper = pathlib.Path(temporary) / "helper.apk"
            helper.write_bytes(b"apk")
            missing = pathlib.Path(temporary) / "no-run.sh"
            with (
                mock.patch.object(
                    provision_portal_module, "AUTOROOT_HELPER_LOCAL", helper
                ),
                mock.patch.object(
                    provision_portal_module, "AUTOROOT_RUNNER_LOCAL", missing
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    side_effect=AssertionError("adb used before validation"),
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "missing autoroot runner script"
                ):
                    provisioner.stage_autoroot_payload()


if __name__ == "__main__":
    unittest.main()
