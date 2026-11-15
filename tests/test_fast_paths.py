#!/usr/bin/env python3
# Copyright (c) 2026 itsgreat2misha
# SPDX-License-Identifier: Apache-2.0
"""Re-run fast paths: the already-provisioned no-op exit, the
root-channel apply path for drifted state, and --force.

The no-op and channel decisions are pure functions of the recorded
state manifest plus cheap live spot-checks, so they are tested as
decision tables: each condition failing individually must block the
fast path, and all conditions holding must allow it. The channel
apply itself is sequenced from the same idempotent shell-level
applies the race run uses; those are replaced with recorders here so
the tests pin the decision, the sequencing, the manifest rewrite,
and the fall-back-to-race-run behaviour rather than re-testing each
apply (each has its own coverage).
"""

from __future__ import annotations

import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[1] / "tools")
)

from portal_targets import TARGETS  # noqa: E402
from provision_portal import (  # noqa: E402
    PortalProvisioner,
    ProvisionError,
    parse_args,
)

SERIAL = "192.0.2.1:5555"
ALOHA = next(
    target for target in TARGETS if target.key == "portal-plus-aloha-1041515800015050"
)
STATE_REMOTE = "/data/local/tmp/portal-provision-state-v1.json"

DOCUMENTED = dict(
    audio=True,
    disable_updates=True,
    debloat=True,
    block_remote_wipe=True,
    remove_meta_accounts=True,
    disable_adb_auth_timeout=True,
    privacy_dns="family.cloudflare-dns.com",
    dhcp_dns=True,
    allow_app_updates=True,
    shizuku=True,
    autoroot=True,
    custom_payload=pathlib.Path("tools/exploit/build/portal-daemon"),
)


def make_provisioner(temporary: str, **kwargs) -> PortalProvisioner:
    provisioner = PortalProvisioner(
        SERIAL, 12, pathlib.Path(temporary), **kwargs
    )
    provisioner.target = ALOHA
    return provisioner


def completed(args, stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args, returncode, stdout, "")


class FakeDevice:
    """adb fake modelling a healthy provisioned device: root-mode
    Shizuku answering, sentinel + autoroot helper installed, the
    staged simpleperf present, wireless ADB persisted."""

    def __init__(self) -> None:
        self.shizuku_uid = "0"
        self.shizuku_running = True
        self.sentinel = True
        self.helper = True
        self.simpleperf = True
        self.port = "5555"
        self.audio_marker = True
        self.audio_artifact = True
        self.aiservice = True

    def adb_run(self, arguments, timeout=None, check=False):
        del timeout, check
        command = " ".join(str(argument) for argument in arguments)
        if "pidof shizuku_server" in command:
            return completed(
                arguments, "4242\n" if self.shizuku_running else ""
            )
        if "/proc/4242/status" in command:
            return completed(
                arguments, f"Name:\tshizuku_server\nUid:\t{self.shizuku_uid}\t0\t0\t0\n"
            )
        if "pm path dev.portal.exploitsentinel" in command:
            return completed(
                arguments,
                "package:/data/app/sentinel/base.apk\n" if self.sentinel else "",
            )
        if "pm path dev.portal.autoroothelper" in command:
            return completed(
                arguments,
                "package:/data/app/helper/base.apk\n" if self.helper else "",
            )
        if "test -f /data/local/tmp/portal-simpleperf" in command:
            return completed(arguments, "", 0 if self.simpleperf else 1)
        if (
            "test -f /data/local/tmp/portal-audio-backup/installed-v1"
            in command
        ):
            return completed(arguments, "", 0 if self.audio_marker else 1)
        if "test -f /data/local/tmp/libportal_audio_persist.so" in command:
            return completed(
                arguments, "", 0 if self.audio_artifact else 1
            )
        if "test -f /data/local/tmp/portal-audio-ctl.jar" in command:
            return completed(
                arguments, "", 0 if self.audio_artifact else 1
            )
        if "pidof com.facebook.portal.aiservice" in command:
            if self.aiservice:
                return completed(arguments, "2703\n")
            return completed(arguments, "", 1)
        if "getprop persist.adb.tcp.port" in command:
            return completed(arguments, self.port + "\n")
        return completed(arguments, "", 1)


def good_state(provisioner: PortalProvisioner) -> dict:
    return {
        "schema": 1,
        "status": "complete",
        "fingerprint": ALOHA.fingerprint,
        "target": ALOHA.key,
        "tool_revision": provisioner.tool_revision(),
        "actions": dict(provisioner.requested_actions()),
        "artifact_sha256": dict(provisioner.selected_artifact_hashes()),
        "first_boot": "boot-a",
        "second_boot": "boot-a",
        "updated_unix": 1,
    }


def eligible_provisioner(temporary: str, **overrides):
    """A documented-set provisioner on a healthy fake device with
    every bootstrap preflight reporting already-configured."""
    kwargs = dict(DOCUMENTED)
    kwargs.update(overrides)
    provisioner = make_provisioner(temporary, **kwargs)
    device = FakeDevice()
    provisioner.adb_run = device.adb_run
    provisioner.adb_framework_boot_configured = True
    for name in (
        "audio_preflight",
        "audio_channel_preflight",
        "ota_preflight",
        "meta_accounts_preflight",
        "debloat_preflight",
        "remote_wipe_preflight",
    ):
        setattr(provisioner, name, lambda: True)
    return provisioner, device


class NoopBlockerTest(unittest.TestCase):
    def test_all_conditions_hold(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, **DOCUMENTED)
            self.assertIsNone(provisioner._noop_blocker(good_state(provisioner)))

    def test_each_condition_failing_individually_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, **DOCUMENTED)
            cases = []
            state = good_state(provisioner)
            state["status"] = "pending"
            cases.append((state, "status-pending"))
            state = good_state(provisioner)
            state["tool_revision"] = "deadbeef"
            cases.append((state, "tool-revision"))
            state = good_state(provisioner)
            state["fingerprint"] = "other/build"
            cases.append((state, "fingerprint"))
            state = good_state(provisioner)
            del state["actions"]["debloat"]
            cases.append((state, "actions-debloat"))
            state = good_state(provisioner)
            state["actions"]["privacy_dns"] = "other.example.com"
            cases.append((state, "actions-privacy_dns"))
            state = good_state(provisioner)
            state["artifact_sha256"]["tools/provision_portal.py"] = "0" * 64
            cases.append((state, "artifact-"))
            for state, prefix in cases:
                with self.subTest(prefix=prefix):
                    blocker = provisioner._noop_blocker(state)
                    self.assertIsNotNone(blocker)
                    self.assertTrue(blocker.startswith(prefix), blocker)

    def test_subset_request_still_noops(self) -> None:
        """A run asking for fewer actions than were applied no-ops:
        the provisioner has no un-apply semantics."""
        with tempfile.TemporaryDirectory() as temporary:
            full = make_provisioner(temporary, **DOCUMENTED)
            state = good_state(full)
            subset = make_provisioner(temporary, audio=True)
            self.assertIsNone(subset._noop_blocker(state))

    def test_superset_recorded_actions_still_noops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, audio=True)
            state = good_state(provisioner)
            state["actions"]["debloat"] = True
            state["actions"]["autoroot"] = True
            self.assertIsNone(provisioner._noop_blocker(state))

    def test_unselected_recorded_artifact_is_ignored(self) -> None:
        """A recorded hash for an artifact this run does not select
        (it belongs to an unrequested action) must not block the
        no-op — regression: this only shows on machines where the
        other actions' build outputs actually exist."""
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, audio=True)
            state = good_state(provisioner)
            state["artifact_sha256"]["exploit/build/not-selected.jar"] = (
                "f" * 64
            )
            self.assertIsNone(provisioner._noop_blocker(state))


class RootSetupBlockerTest(unittest.TestCase):
    def test_healthy_device_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            self.assertIsNone(provisioner._root_setup_blocker())

    def test_each_live_check_failing_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, device = eligible_provisioner(temporary)
            device.shizuku_running = False
            self.assertEqual(provisioner._root_setup_blocker(), "shizuku-root")
            device.shizuku_running = True
            device.shizuku_uid = "1000"
            self.assertEqual(provisioner._root_setup_blocker(), "shizuku-root")
            device.shizuku_uid = "0"
            device.sentinel = False
            self.assertEqual(
                provisioner._root_setup_blocker(), "sentinel-missing"
            )
            device.sentinel = True
            device.helper = False
            self.assertEqual(
                provisioner._root_setup_blocker(), "autoroot-helper-missing"
            )


class ChannelBlockerTest(unittest.TestCase):
    def test_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            self.assertIsNone(
                provisioner._channel_blocker(good_state(provisioner))
            )

    def test_pending_manifest_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            state = good_state(provisioner)
            state["status"] = "pending"
            self.assertEqual(
                provisioner._channel_blocker(state), "status-pending"
            )

    def test_each_bootstrap_drift_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, device = eligible_provisioner(temporary)
            state = good_state(provisioner)
            provisioner.audio_channel_preflight = lambda: False
            self.assertEqual(
                provisioner._channel_blocker(state), "audio-not-configured"
            )
            provisioner.audio_channel_preflight = lambda: True
            provisioner.ota_preflight = lambda: False
            self.assertEqual(
                provisioner._channel_blocker(state), "ota-not-configured"
            )
            provisioner.ota_preflight = lambda: True
            device.simpleperf = False
            self.assertEqual(
                provisioner._channel_blocker(state), "simpleperf-missing"
            )
            device.simpleperf = True
            device.port = ""
            self.assertEqual(
                provisioner._channel_blocker(state), "wireless-adb-bootstrap"
            )

    def test_race_owned_actions_block(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for overrides, expected in (
                ({"restore_audio": True}, "restore-audio"),
                ({"remove_shizuku": True}, "remove-shizuku"),
                ({"enable_updates": True}, "enable-updates"),
                ({"restore_camera_light": True}, "restore-camera-light"),
                ({"disable_camera_light": True}, "retired-camera-light"),
            ):
                with self.subTest(expected=expected):
                    provisioner, _device = eligible_provisioner(
                        temporary, **overrides
                    )
                    self.assertEqual(
                        provisioner._channel_blocker(
                            good_state(provisioner)
                        ),
                        expected,
                    )


class AudioChannelPreflightTest(unittest.TestCase):
    """The channel eligibility audio check must be boot-age
    independent: durable marker + staged persist artifact + the
    aiservice process alive now, with no logcat consultation (the
    logcat probe in audio_preflight rotates away on long uptimes —
    Run 33 step 1). Each signal missing must decline, sending the
    run to the race fallback."""

    def _provisioner(self, temporary: str, device: FakeDevice):
        provisioner = make_provisioner(temporary, **DOCUMENTED)
        provisioner.adb_run = device.adb_run
        provisioner.adb_framework_boot_configured = True
        for name in (
            "ota_preflight",
            "meta_accounts_preflight",
            "debloat_preflight",
            "remote_wipe_preflight",
        ):
            setattr(provisioner, name, lambda: True)
        return provisioner

    def test_healthy_install_eligible_without_logcat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = FakeDevice()
            provisioner = self._provisioner(temporary, device)

            def no_logcat(*args, **kwargs):
                raise AssertionError("eligibility consulted logcat")

            provisioner.logcat_poll = no_logcat
            provisioner.logcat_watermark = no_logcat
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner.audio_channel_preflight())
                self.assertIsNone(
                    provisioner._channel_blocker(
                        good_state(provisioner)
                    )
                )
            self.assertIn(
                "AUDIO_CHANNEL_PREFLIGHT installed=1 staged=1 "
                "aiservice=1 action=skip",
                stdout.getvalue(),
            )

    def test_marker_present_but_aiservice_not_live_declines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = FakeDevice()
            device.aiservice = False
            provisioner = self._provisioner(temporary, device)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertFalse(provisioner.audio_channel_preflight())
                self.assertEqual(
                    provisioner._channel_blocker(
                        good_state(provisioner)
                    ),
                    "audio-not-configured",
                )
            self.assertIn("action=decline", stdout.getvalue())

    def test_marker_present_but_artifact_missing_declines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = FakeDevice()
            device.audio_artifact = False
            provisioner = self._provisioner(temporary, device)
            with redirect_stdout(io.StringIO()):
                self.assertFalse(provisioner.audio_channel_preflight())

    def test_nothing_staged_declines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = FakeDevice()
            device.audio_marker = False
            provisioner = self._provisioner(temporary, device)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertFalse(provisioner.audio_channel_preflight())
            self.assertIn(
                "AUDIO_CHANNEL_PREFLIGHT installed=0", stdout.getvalue()
            )


class ChannelApplyTest(unittest.TestCase):
    def tearDown(self) -> None:
        patched = getattr(self, "_patched", None)
        if patched is not None:
            import provision_portal as pp_module

            (
                pp_module.android_build_environment,
                pp_module.build,
            ) = patched
            self._patched = None

    def _instrument(self, provisioner: PortalProvisioner) -> list:
        calls: list = []
        # Host-side build machinery is out of scope for the channel
        # decision tests; the applies below are the device surface.
        import provision_portal as pp_module

        self._patched = (
            pp_module.android_build_environment,
            pp_module.build,
        )
        pp_module.android_build_environment = lambda target: None
        pp_module.build = lambda **kwargs: calls.append("build")
        provisioner.resolve_shizuku_apk = lambda: pathlib.Path("s.apk")
        for name in (
            "apply_debloat",
            "disable_ota_packages",
            "disable_adb_authorization_timeout",
            "apply_privacy_dns",
            "apply_dhcp_dns",
            "allow_third_party_app_updates",
            "prepare_component_actions",
            "install_shizuku_payload",
            "prepare_exploit_sentinel",
            "stage_autoroot_payload",
            "verify_requested_state",
        ):
            setattr(
                provisioner,
                name,
                (lambda recorded: lambda *a, **k: calls.append(recorded))(
                    name
                ),
            )
        verify_kwargs: list = []

        def record_verify(*args, **kwargs):
            calls.append("verify_requested_state")
            verify_kwargs.append(kwargs)

        provisioner.verify_requested_state = record_verify
        self._verify_kwargs = verify_kwargs
        states: list = []
        provisioner.write_state = lambda status, **k: states.append(status)
        self._states = states
        return calls

    def test_channel_apply_rewrites_manifest_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            calls = self._instrument(provisioner)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                handled = provisioner._apply_via_channel("actions-dhcp_dns")
            self.assertTrue(handled)
            output = stdout.getvalue()
            self.assertIn("PROVISION_CHANNEL_ENGAGED reason=actions-dhcp_dns", output)
            self.assertIn("PROVISION_CHANNEL_OK", output)
            self.assertIn("apply_dhcp_dns", calls)
            self.assertIn("stage_autoroot_payload", calls)
            self.assertIn("verify_requested_state", calls)
            self.assertEqual(self._verify_kwargs, [{"via_channel": True}])
            self.assertEqual(self._states, ["pending", "complete"])

    def test_channel_failure_falls_back_without_completing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            calls = self._instrument(provisioner)

            def boom() -> None:
                raise ProvisionError("simulated apply failure")

            provisioner.stage_autoroot_payload = boom
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                handled = provisioner._apply_via_channel("artifact-x")
            self.assertFalse(handled)
            self.assertIn("PROVISION_CHANNEL_FALLBACK", stdout.getvalue())
            self.assertEqual(self._states, ["pending"])


class VerifyRequestedStateAudioTest(unittest.TestCase):
    """The channel apply's final verification runs on the device's
    current boot, however old, so its audio check must use the
    boot-age-independent signal; the race path's verification keeps
    the fresh-boot logcat probe (verify_watchdog)."""

    def _provisioner(self, temporary: str):
        provisioner = make_provisioner(temporary, audio=True)
        watchdog_calls: list = []
        provisioner.verify_watchdog = lambda *a, **k: watchdog_calls.append(
            True
        )
        self._watchdog_calls = watchdog_calls
        return provisioner

    def test_channel_verify_uses_durable_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            provisioner.audio_channel_preflight = lambda: True
            with redirect_stdout(io.StringIO()):
                provisioner.verify_requested_state(via_channel=True)
            self.assertEqual(self._watchdog_calls, [])

    def test_channel_verify_declining_signal_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            provisioner.audio_channel_preflight = lambda: False
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError):
                    provisioner.verify_requested_state(via_channel=True)
            self.assertEqual(self._watchdog_calls, [])

    def test_race_verify_keeps_logcat_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)

            def no_channel_signal():
                raise AssertionError("race verify used the channel signal")

            provisioner.audio_channel_preflight = no_channel_signal
            with redirect_stdout(io.StringIO()):
                provisioner.verify_requested_state()
            self.assertEqual(self._watchdog_calls, [True])


class RunFastPathTest(unittest.TestCase):
    def test_noop_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            provisioner.read_state = lambda: good_state(provisioner)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertIn("PROVISION_NOOP", stdout.getvalue())

    def test_pending_manifest_falls_through(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            state = good_state(provisioner)
            state["status"] = "pending"
            provisioner.read_state = lambda: state
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertFalse(provisioner._run_fast_path())
            output = stdout.getvalue()
            self.assertIn("PROVISION_NOOP_SKIP reason=status-pending", output)
            self.assertIn("PROVISION_CHANNEL_SKIP reason=status-pending", output)

    def test_missing_manifest_falls_through_silently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            provisioner.read_state = lambda: None
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertFalse(provisioner._run_fast_path())
            self.assertEqual(stdout.getvalue(), "")

    def test_drifted_state_takes_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _device = eligible_provisioner(temporary)
            state = good_state(provisioner)
            del state["actions"]["dhcp_dns"]
            provisioner.read_state = lambda: state
            applied: list = []
            provisioner._apply_via_channel = (
                lambda reason: applied.append(reason) or True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertEqual(applied, ["actions-dhcp_dns"])
            self.assertIn(
                "PROVISION_NOOP_SKIP reason=actions-dhcp_dns",
                stdout.getvalue(),
            )


class ForceTest(unittest.TestCase):
    def test_force_flag_parses(self) -> None:
        with unittest.mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--serial", SERIAL, "--force"],
        ):
            arguments = parse_args()
        self.assertTrue(arguments.force)

    def test_force_bypasses_apk_install_skip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for force, expected_package in ((False, "pkg"), (True, None)):
                with self.subTest(force=force):
                    provisioner = make_provisioner(
                        temporary, force=force
                    )
                    seen: list = []
                    provisioner.shizuku_feature.install_apk_preserving_verifier = (  # noqa: E501
                        lambda apk, tag, package=None: seen.append(package)
                    )
                    provisioner.install_apk_preserving_verifier(
                        pathlib.Path("x.apk"), "tag", "pkg"
                    )
                    self.assertEqual(seen, [expected_package])


if __name__ == "__main__":
    unittest.main()
