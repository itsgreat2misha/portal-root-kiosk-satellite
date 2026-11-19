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
        # The documented set records dhcp_dns, whose end state is
        # Private DNS off with no specifier.
        self.dns_mode = "off"
        self.dns_specifier = "null"

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
        if "settings get global private_dns_mode" in command:
            return completed(arguments, self.dns_mode + "\n")
        if "settings get global private_dns_specifier" in command:
            return completed(arguments, self.dns_specifier + "\n")
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
            # A missing staged simpleperf no longer blocks the channel
            # path: autoroot staging pushes it on demand.
            self.assertIsNone(provisioner._channel_blocker(state))
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
        pp_module.android_build_environment = lambda target, **_kwargs: None
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


class ChannelManifestMergeTest(unittest.TestCase):
    """The channel path applies a delta; its completion write must
    merge into the recorded manifest, not replace it with the
    delta's own record. Gate session, Nov 19, 2026: a bare
    --dns channel run shrank a full record (11 actions, the
    autoroot key hash) to the DNS action alone, and the next
    --full run lost the OTA posture trust that reads
    disable_updates from the record and had to race."""

    def _prior_record(self, temporary: str) -> dict:
        full = make_provisioner(temporary, **DOCUMENTED)
        actions = dict(full.requested_actions())
        hashes = dict(full.selected_artifact_hashes())
        hashes["prior/only-artifact.bin"] = "prior-only-digest"
        return {
            "schema": 1,
            "status": "complete",
            "target": ALOHA.key,
            "fingerprint": ALOHA.fingerprint,
            "tool_revision": "prior-revision",
            "actions": actions,
            "artifact_sha256": hashes,
            "autoroot_key_sha256": "prior-key-hash",
            "desired_state": {"alohausers_package": "disabled"},
            "verification": {
                "first_boot": "boot-a",
                "second_boot": "boot-a",
            },
        }

    def _write(self, provisioner: PortalProvisioner, **kwargs) -> dict:
        captured: dict = {}

        def fake_write_state(status, **state_kwargs):
            captured["status"] = status
            captured.update(state_kwargs)

        with (
            unittest.mock.patch.object(
                provisioner,
                "adb_run",
                return_value=completed([], ALOHA.fingerprint + "\n"),
            ),
            unittest.mock.patch.object(
                provisioner.run_state, "write_state", fake_write_state
            ),
            redirect_stdout(io.StringIO()),
        ):
            provisioner.write_state("complete", **kwargs)
        return captured

    def _manifest(self, captured: dict) -> dict:
        manifest = {
            "schema": 1,
            "status": captured["status"],
            "target": captured["target_key"],
            "fingerprint": captured["fingerprint"],
            "tool_revision": captured["tool_revision"],
            "artifact_sha256": captured["artifact_sha256"],
            "actions": captured["actions"],
            "verification": {
                "first_boot": captured["first_boot"],
                "second_boot": captured["second_boot"],
            },
        }
        if captured["autoroot_key_sha256"] is not None:
            manifest["autoroot_key_sha256"] = captured[
                "autoroot_key_sha256"
            ]
        if captured["desired_state"]:
            manifest["desired_state"] = captured["desired_state"]
        return manifest

    def test_delta_completion_merges_into_prior_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            delta = make_provisioner(
                temporary, privacy_dns="one.one.one.one"
            )
            delta._start_state = prior
            run_hashes = delta.selected_artifact_hashes()
            captured = self._write(delta, merge_prior=True)
            actions = captured["actions"]
            # Every prior action survives; the delta's action wins.
            # One exception by design (Defect D record hygiene): the
            # prior record carries the pre-#64 DNS pair, and the
            # delta's hostname completion drops the dhcp sibling so
            # the record carries only the intent it established.
            for name, value in prior["actions"].items():
                if name in ("privacy_dns", "dhcp_dns"):
                    continue
                self.assertEqual(actions[name], value, name)
            self.assertEqual(actions["privacy_dns"], "one.one.one.one")
            self.assertNotIn("dhcp_dns", actions)
            self.assertEqual(len(actions), len(prior["actions"]) - 1)
            # Hashes merge per key the same way.
            hashes = captured["artifact_sha256"]
            self.assertEqual(
                hashes["prior/only-artifact.bin"], "prior-only-digest"
            )
            for name, digest in run_hashes.items():
                self.assertEqual(hashes[name], digest, name)
            # The recorded key hash survives a run that staged
            # nothing; desired state and the verification boots
            # carry over; the revision follows the completing run.
            self.assertEqual(
                captured["autoroot_key_sha256"], "prior-key-hash"
            )
            self.assertEqual(
                captured["desired_state"],
                {"alohausers_package": "disabled"},
            )
            self.assertEqual(captured["first_boot"], "boot-a")
            self.assertEqual(captured["second_boot"], "boot-a")
            self.assertEqual(
                captured["tool_revision"], delta.tool_revision()
            )
            self.assertNotEqual(captured["tool_revision"], "prior-revision")

    def test_merged_record_keeps_full_run_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            delta = make_provisioner(
                temporary, privacy_dns="one.one.one.one"
            )
            delta._start_state = prior
            merged = self._manifest(self._write(delta, merge_prior=True))
            shrunken = self._manifest(self._write(delta))
            # The later full run carries the delta's intent as its
            # only DNS intent (the post-#64 composition shape): the
            # merged record, which dropped the dhcp sibling under
            # the Defect D hygiene, satisfies it.
            full, _device = eligible_provisioner(
                temporary, privacy_dns="one.one.one.one", dhcp_dns=False
            )
            # Force the OTA clause onto the recorded-posture trust:
            # the live preflight reads unconfigured in the posture
            # by design, so only the record can satisfy it.
            full.ota_preflight = lambda: False
            self.assertIsNone(full._noop_blocker(merged))
            self.assertIsNone(full._channel_blocker(merged))
            # The pre-fix record shape fails both gates exactly as
            # observed live: the no-op gate misses recorded actions
            # and the channel gate loses the OTA posture trust.
            self.assertTrue(
                full._noop_blocker(shrunken).startswith("actions-")
            )
            self.assertEqual(
                full._channel_blocker(shrunken), "ota-not-configured"
            )

    def test_restaged_autoroot_records_the_new_key_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            delta = make_provisioner(
                temporary, privacy_dns="one.one.one.one"
            )
            delta._start_state = prior
            delta.staged_autoroot_key_sha256 = "new-key-hash"
            captured = self._write(delta, merge_prior=True)
            self.assertEqual(
                captured["autoroot_key_sha256"], "new-key-hash"
            )

    def test_unmerged_completion_write_replaces_as_before(self) -> None:
        # The merge is opt-in per call site (the channel completion
        # write and the subset completion exits pass merge_prior);
        # a write_state call without the flag keeps the historical
        # replace semantics pinned here.
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            delta = make_provisioner(
                temporary, privacy_dns="one.one.one.one"
            )
            delta._start_state = prior
            captured = self._write(delta)
            self.assertEqual(
                captured["actions"], {"privacy_dns": "one.one.one.one"}
            )
            self.assertIsNone(captured["autoroot_key_sha256"])
            self.assertNotIn(
                "prior/only-artifact.bin", captured["artifact_sha256"]
            )



class SubsetStagesManifestMergeTest(unittest.TestCase):
    """The stages path's single-action early-complete exits are
    subset completions too: like the channel path's completion
    write, they must merge into the recorded manifest instead of
    replacing it with the subset's own record (a presence-only or
    theme-only run does not un-apply everything else). Driven
    through the presence-only exit, whose completion write fires
    unconditionally once presence reads already-configured; the
    other subset exits share the same write_state call shape."""

    def _prior_record(self, temporary: str, status: str = "complete") -> dict:
        full = make_provisioner(temporary, **DOCUMENTED)
        actions = dict(full.requested_actions())
        hashes = dict(full.selected_artifact_hashes())
        hashes["prior/only-artifact.bin"] = "prior-only-digest"
        return {
            "schema": 1,
            "status": status,
            "target": ALOHA.key,
            "fingerprint": ALOHA.fingerprint,
            "tool_revision": "prior-revision",
            "actions": actions,
            "artifact_sha256": hashes,
            "autoroot_key_sha256": "prior-key-hash",
            "desired_state": {"alohausers_package": "disabled"},
            "verification": {
                "first_boot": "boot-a",
                "second_boot": "boot-a",
            },
        }

    def _drive_presence_exit(self, temporary: str, prior: dict):
        provisioner = make_provisioner(
            temporary, optimize_presence=True, skip_build=True
        )
        writes: list = []

        def fake_run_state_write(status, **kwargs):
            writes.append((status, kwargs))

        def fake_adb_run(arguments, timeout=None, check=False):
            del timeout, check
            command = " ".join(str(argument) for argument in arguments)
            if "getprop ro.build.fingerprint" in command:
                return completed(arguments, ALOHA.fingerprint + "\n")
            if "getprop persist.adb.tcp.port" in command:
                return completed(arguments, "5555\n")
            return completed(arguments, "", 1)

        provisioner.adb_run = fake_adb_run
        provisioner.read_state = lambda: prior
        provisioner.verify_target = lambda *args, **kwargs: None
        provisioner._observe_start_package_state = lambda: None
        provisioner.adb_framework_boot_preflight = lambda: False
        provisioner._run_fast_path = lambda: False
        provisioner.sync_ota_nodemon_autoroot_conf = lambda: None
        provisioner.sync_drift_conf_keys = lambda: None
        provisioner.presence_preflight = lambda: True
        stdout = io.StringIO()
        with (
            unittest.mock.patch.object(
                provisioner.run_state, "write_state", fake_run_state_write
            ),
            redirect_stdout(stdout),
        ):
            provisioner._provision_stages()
        return provisioner, writes, stdout.getvalue()

    def test_presence_only_completion_merges_into_prior_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            provisioner, writes, output = self._drive_presence_exit(
                temporary, prior
            )
            self.assertIn(
                "PROVISION_ALREADY_COMPLETE actions=optimize_presence",
                output,
            )
            self.assertIn("STATE_MANIFEST_MERGED", output)
            self.assertEqual(
                [status for status, _kwargs in writes],
                ["pending", "complete"],
            )
            captured = writes[-1][1]
            # Every prior action survives; the run's own action is
            # added, and the hashes merge per key the same way.
            actions = captured["actions"]
            for name, value in prior["actions"].items():
                self.assertEqual(actions[name], value, name)
            self.assertEqual(actions["optimize_presence"], True)
            self.assertEqual(len(actions), len(prior["actions"]) + 1)
            hashes = captured["artifact_sha256"]
            self.assertEqual(
                hashes["prior/only-artifact.bin"], "prior-only-digest"
            )
            for name, digest in provisioner.selected_artifact_hashes().items():
                self.assertEqual(hashes[name], digest, name)
            # The recorded key hash, desired state and verification
            # boots carry over; the revision follows this run.
            self.assertEqual(
                captured["autoroot_key_sha256"], "prior-key-hash"
            )
            self.assertEqual(
                captured["desired_state"],
                {"alohausers_package": "disabled"},
            )
            self.assertEqual(captured["first_boot"], "boot-a")
            self.assertEqual(captured["second_boot"], "boot-a")
            self.assertEqual(
                captured["tool_revision"], provisioner.tool_revision()
            )

    def test_presence_only_completion_replaces_noncomplete_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary, status="pending")
            _provisioner, writes, output = self._drive_presence_exit(
                temporary, prior
            )
            self.assertNotIn("STATE_MANIFEST_MERGED", output)
            captured = writes[-1][1]
            self.assertEqual(
                captured["actions"], {"optimize_presence": True}
            )
            self.assertIsNone(captured["autoroot_key_sha256"])
            self.assertNotIn(
                "prior/only-artifact.bin", captured["artifact_sha256"]
            )


class PayloadTerminalManifestMergeTest(unittest.TestCase):
    """The custom-payload phase's terminal write ends a
    payload-only invocation: it must merge into the recorded
    manifest like the other subset completions instead of
    shrinking it to the payload action alone."""

    def _prior_record(self, temporary: str, status: str = "complete") -> dict:
        full = make_provisioner(temporary, **DOCUMENTED)
        actions = dict(full.requested_actions())
        hashes = dict(full.selected_artifact_hashes())
        hashes["prior/only-artifact.bin"] = "prior-only-digest"
        return {
            "schema": 1,
            "status": status,
            "target": ALOHA.key,
            "fingerprint": ALOHA.fingerprint,
            "tool_revision": "prior-revision",
            "actions": actions,
            "artifact_sha256": hashes,
            "autoroot_key_sha256": "prior-key-hash",
            "desired_state": {"alohausers_package": "disabled"},
            "verification": {
                "first_boot": "boot-a",
                "second_boot": "boot-a",
            },
        }

    def _drive_payload(self, temporary: str, prior: dict):
        payload = pathlib.Path(temporary) / "payload.bin"
        payload.write_bytes(b"payload")
        provisioner = make_provisioner(
            temporary, custom_payload=payload, skip_build=True
        )
        provisioner._start_state = prior
        writes: list = []

        def fake_run_state_write(status, **kwargs):
            writes.append((status, kwargs))

        def fake_adb_run(arguments, timeout=None, check=False):
            del timeout, check
            command = " ".join(str(argument) for argument in arguments)
            if "getprop ro.build.fingerprint" in command:
                return completed(arguments, ALOHA.fingerprint + "\n")
            return completed(arguments, "", 1)

        provisioner.adb_run = fake_adb_run
        provisioner.stage = lambda: None
        provisioner.reboot = lambda: ("boot-0", "boot-1")
        provisioner.kaslr_base = lambda attempt: 0x1000
        provisioner.memstart = lambda attempt: 0x2000
        provisioner.wait_for_race_boot_window = lambda attempt: None
        provisioner.exploit = lambda *args, **kwargs: True
        provisioner.verify_custom_payload = lambda *args, **kwargs: None
        provisioner._apply_recorded_posture = lambda: None
        provisioner.apply_post_payload_root_steps = lambda: None
        stdout = io.StringIO()
        with (
            unittest.mock.patch.object(
                provisioner.run_state, "write_state", fake_run_state_write
            ),
            redirect_stdout(stdout),
        ):
            provisioner.apply_custom_payload()
        return provisioner, payload, writes, stdout.getvalue()

    def test_payload_terminal_write_merges_into_prior_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            _provisioner, payload, writes, output = self._drive_payload(
                temporary, prior
            )
            self.assertIn("CUSTOM_PAYLOAD_OK", output)
            self.assertIn("STATE_MANIFEST_MERGED", output)
            self.assertEqual(
                [status for status, _kwargs in writes], ["complete"]
            )
            captured = writes[-1][1]
            # Every prior action survives; the run's own payload
            # action wins over the recorded one.
            actions = captured["actions"]
            for name, value in prior["actions"].items():
                if name == "custom_payload":
                    continue
                self.assertEqual(actions[name], value, name)
            self.assertEqual(actions["custom_payload"], str(payload))
            self.assertEqual(len(actions), len(prior["actions"]))
            hashes = captured["artifact_sha256"]
            self.assertEqual(
                hashes["prior/only-artifact.bin"], "prior-only-digest"
            )
            self.assertEqual(
                captured["autoroot_key_sha256"], "prior-key-hash"
            )
            self.assertEqual(captured["first_boot"], "boot-a")
            self.assertEqual(captured["second_boot"], "boot-a")

    def test_payload_terminal_write_replaces_noncomplete_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary, status="pending")
            _provisioner, payload, writes, output = self._drive_payload(
                temporary, prior
            )
            self.assertNotIn("STATE_MANIFEST_MERGED", output)
            captured = writes[-1][1]
            self.assertEqual(
                captured["actions"], {"custom_payload": str(payload)}
            )
            self.assertIsNone(captured["autoroot_key_sha256"])
            self.assertNotIn(
                "prior/only-artifact.bin", captured["artifact_sha256"]
            )

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


class DnsDevice:
    """adb fake modelling the Private DNS settings store and the
    on-device first-value backup file."""

    def __init__(self, mode="off", specifier="null", backup=True):
        self.mode = mode
        self.specifier = specifier
        self.backup = backup
        self.writes: list = []

    def adb_run(self, arguments, timeout=None, check=False):
        del timeout, check
        command = " ".join(str(argument) for argument in arguments)
        if "settings get global private_dns_mode" in command:
            return completed(arguments, self.mode + "\n")
        if "settings get global private_dns_specifier" in command:
            return completed(arguments, self.specifier + "\n")
        if "settings put global private_dns_mode" in command:
            self.mode = arguments[-1]
            self.writes.append(("mode", self.mode))
            return completed(arguments)
        if "settings put global private_dns_specifier" in command:
            self.specifier = arguments[-1]
            self.writes.append(("specifier", self.specifier))
            return completed(arguments)
        if "settings delete global private_dns_mode" in command:
            self.mode = "null"
            self.writes.append(("mode", "null"))
            return completed(arguments)
        if "settings delete global private_dns_specifier" in command:
            self.specifier = "null"
            self.writes.append(("specifier", "null"))
            return completed(arguments)
        if "portal-private-dns-before-v1.json" in command and "cat" in command:
            if not self.backup:
                return completed(arguments, "", 1)
            return completed(
                arguments,
                json.dumps(
                    {"schema": 1, "mode": "off", "hostname": "null"}
                ),
            )
        return completed(arguments, "", 0)


class RecordedDnsInvariantTest(unittest.TestCase):
    """Phase C2: the Private DNS end-state invariant. The manifest
    records the desired end state; every later run compares the
    live state to the record, and drift is repaired, never passed
    over — including by the no-op exit."""

    def _provisioner(self, temporary: str, device: DnsDevice, **kwargs):
        provisioner = make_provisioner(temporary, **kwargs)
        provisioner.adb_run = device.adb_run
        return provisioner

    def test_expectation_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary, DnsDevice())
            expect = provisioner._recorded_dns_expectation
            self.assertEqual(
                expect({"actions": {"dhcp_dns": True}}), ("off", "null")
            )
            self.assertEqual(
                expect({"actions": {"privacy_dns": "Family.Example.com"}}),
                ("hostname", "family.example.com"),
            )
            self.assertIsNone(expect({"actions": {"audio": True}}))
            self.assertIsNone(expect({"actions": {}}))
            self.assertIsNone(expect(None))
            self.assertIsNone(expect({}))
            provisioner.read_private_dns_backup = lambda: {
                "schema": 1,
                "mode": "hostname",
                "hostname": "dns.example.org",
            }
            self.assertEqual(
                expect({"actions": {"restore_privacy_dns": True}}),
                ("hostname", "dns.example.org"),
            )
            provisioner.read_private_dns_backup = lambda: None
            self.assertIsNone(
                expect({"actions": {"restore_privacy_dns": True}})
            )

    def test_verify_repairs_recorded_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = DnsDevice(mode="hostname", specifier="one.one.one.one")
            provisioner = self._provisioner(temporary, device)
            provisioner._start_state = {"actions": {"dhcp_dns": True}}
            provisioner._start_state_captured = True
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                provisioner.verify_requested_state()
            self.assertEqual(device.mode, "off")
            self.assertEqual(device.specifier, "null")
            output = stdout.getvalue()
            self.assertIn("PRIVACY_DNS_DRIFT", output)
            self.assertIn("PRIVACY_DNS_REPAIRED", output)

    def test_verify_channel_repairs_recorded_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = DnsDevice(mode="hostname", specifier="one.one.one.one")
            provisioner = self._provisioner(temporary, device)
            provisioner._start_state = {"actions": {"dhcp_dns": True}}
            provisioner._start_state_captured = True
            with redirect_stdout(io.StringIO()):
                provisioner.verify_requested_state(via_channel=True)
            self.assertEqual(device.mode, "off")
            self.assertEqual(device.specifier, "null")

    def test_verify_passes_when_recorded_state_holds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = DnsDevice()
            provisioner = self._provisioner(temporary, device)
            provisioner._start_state = {"actions": {"dhcp_dns": True}}
            provisioner._start_state_captured = True
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                provisioner.verify_requested_state()
            self.assertEqual(device.writes, [])
            self.assertIn("PRIVACY_DNS_RECORDED_OK", stdout.getvalue())

    def test_verify_skips_when_nothing_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = DnsDevice(mode="hostname", specifier="one.one.one.one")
            provisioner = self._provisioner(temporary, device)
            provisioner._start_state = {"actions": {"audio": True}}
            provisioner._start_state_captured = True
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                provisioner.verify_requested_state()
            self.assertEqual(device.writes, [])
            self.assertNotIn("PRIVACY_DNS", stdout.getvalue())

    def test_deferred_apply_flushes_instead_of_invariant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = DnsDevice(mode="hostname", specifier="one.one.one.one")
            provisioner = self._provisioner(temporary, device, dhcp_dns=True)
            provisioner._start_state = {"actions": {"dhcp_dns": True}}
            provisioner._start_state_captured = True
            provisioner._dns_apply_deferred = True
            applied: list = []
            provisioner.apply_dhcp_dns = lambda: applied.append("dhcp")
            provisioner.verify_privacy_dns = lambda: applied.append("verify")
            with redirect_stdout(io.StringIO()):
                provisioner.verify_requested_state()
            self.assertEqual(applied, ["dhcp", "verify"])
            self.assertFalse(provisioner._dns_apply_deferred)
            self.assertEqual(device.writes, [])

    def test_noop_blocked_by_dns_drift_takes_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, device = eligible_provisioner(temporary)
            device.dns_mode = "hostname"
            device.dns_specifier = "one.one.one.one"
            provisioner.read_state = lambda: good_state(provisioner)
            applied: list = []
            provisioner._apply_via_channel = (
                lambda reason: applied.append(reason) or True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertEqual(applied, ["dns-drift"])
            self.assertEqual(
                provisioner._dns_repair_expectation, ("off", "null")
            )
            output = stdout.getvalue()
            self.assertIn("PRIVACY_DNS_DRIFT", output)
            self.assertIn("PROVISION_NOOP_SKIP reason=dns-drift", output)
            self.assertNotIn("PROVISION_NOOP reason=", output)


class RequestedDnsIntentGateTest(unittest.TestCase):
    """Defect D (closure session 3, Nov 19, 2026): a recorded
    manifest carrying BOTH DNS intents — a pre-PR #64 pair the
    PR #65/#66 merges preserve — resolves dhcp-first in the
    recorded-expectation readers, so a bare --dns HOSTNAME run
    whose record happened to hold that same hostname compared
    live state against "off", matched the live-off device, and
    no-oped: an explicit request silently ignored. When a run
    carries a DNS intent of its own, the fast path's drift
    evaluation must judge live state against the REQUESTED
    intent; runs carrying no intent keep the recorded pair's
    dhcp-first resolution exactly as before."""

    def _stale_pair_state(self, provisioner) -> dict:
        state = good_state(provisioner)
        # The pre-#64 pair: both intents in one record.
        state["actions"]["dhcp_dns"] = True
        state["actions"]["privacy_dns"] = "one.one.one.one"
        return state

    def test_explicit_hostname_request_detects_drift_over_stale_pair(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, device = eligible_provisioner(
                temporary, privacy_dns="one.one.one.one", dhcp_dns=False
            )
            device.dns_mode = "off"
            device.dns_specifier = "null"
            provisioner.read_state = lambda: self._stale_pair_state(
                provisioner
            )
            applied: list = []
            provisioner._apply_via_channel = (
                lambda reason: applied.append(reason) or True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertEqual(applied, ["dns-drift"])
            self.assertEqual(
                provisioner._dns_repair_expectation,
                ("hostname", "one.one.one.one"),
            )
            output = stdout.getvalue()
            self.assertIn("PRIVACY_DNS_DRIFT", output)
            self.assertIn("requested_mode=hostname", output)
            self.assertIn("PROVISION_NOOP_SKIP reason=dns-drift", output)
            self.assertNotIn("PROVISION_NOOP reason=", output)

    def test_explicit_hostname_request_noops_when_live_matches_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, device = eligible_provisioner(
                temporary, privacy_dns="one.one.one.one", dhcp_dns=False
            )
            device.dns_mode = "hostname"
            device.dns_specifier = "one.one.one.one"
            provisioner.read_state = lambda: self._stale_pair_state(
                provisioner
            )
            applied: list = []
            provisioner._apply_via_channel = (
                lambda reason: applied.append(reason) or True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertEqual(applied, [])
            self.assertIn("PROVISION_NOOP reason=", stdout.getvalue())

    def test_explicit_off_request_noop_stands_over_stale_pair(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, device = eligible_provisioner(
                temporary, privacy_dns=None, dhcp_dns=True
            )
            device.dns_mode = "off"
            device.dns_specifier = "null"
            provisioner.read_state = lambda: self._stale_pair_state(
                provisioner
            )
            applied: list = []
            provisioner._apply_via_channel = (
                lambda reason: applied.append(reason) or True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertEqual(applied, [])
            self.assertIn("PROVISION_NOOP reason=", stdout.getvalue())

    def test_full_preset_shape_against_stale_pair_behaves_as_today(
        self,
    ) -> None:
        # --full with no explicit --dns composes to the preset's
        # dhcp intent alone; against the stale pair its verdicts
        # are the recorded pair's dhcp-first verdicts: live off
        # no-ops, live on the recorded hostname is drift toward
        # off (the preset's intent and the pair's dhcp-first
        # resolution coincide, so nothing changes).
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, device = eligible_provisioner(
                temporary, privacy_dns=None, dhcp_dns=True
            )
            provisioner.read_state = lambda: self._stale_pair_state(
                provisioner
            )
            applied: list = []
            provisioner._apply_via_channel = (
                lambda reason: applied.append(reason) or True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertEqual(applied, [])
            self.assertIn("PROVISION_NOOP reason=", stdout.getvalue())
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, device = eligible_provisioner(
                temporary, privacy_dns=None, dhcp_dns=True
            )
            device.dns_mode = "hostname"
            device.dns_specifier = "one.one.one.one"
            provisioner.read_state = lambda: self._stale_pair_state(
                provisioner
            )
            applied = []
            provisioner._apply_via_channel = (
                lambda reason: applied.append(reason) or True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertEqual(applied, ["dns-drift"])
            self.assertEqual(
                provisioner._dns_repair_expectation, ("off", "null")
            )


class DnsRecordHygieneTest(unittest.TestCase):
    """Defect D, record side: a completion write that establishes
    a DNS intent must record ONLY that intent. The PR #65/#66
    merges preserve prior actions per key, so without an active
    drop the pre-#64 pair (dhcp_dns + privacy_dns in one record)
    survives every later DNS run forever, and the dhcp-first
    readers keep shadowing the intent the last run established.
    With the drop, a dual-intent record converges on its next
    DNS completion."""

    def _prior_record(self, temporary: str) -> dict:
        full = make_provisioner(temporary, **DOCUMENTED)
        actions = dict(full.requested_actions())
        # DOCUMENTED composes both intents: the stale pair.
        assert actions.get("dhcp_dns") is True
        assert isinstance(actions.get("privacy_dns"), str)
        return {
            "schema": 1,
            "status": "complete",
            "target": ALOHA.key,
            "fingerprint": ALOHA.fingerprint,
            "tool_revision": "prior-revision",
            "actions": actions,
            "artifact_sha256": dict(full.selected_artifact_hashes()),
            "autoroot_key_sha256": "prior-key-hash",
            "desired_state": {"alohausers_package": "disabled"},
            "verification": {
                "first_boot": "boot-a",
                "second_boot": "boot-a",
            },
        }

    def _write(self, provisioner: PortalProvisioner, **kwargs) -> dict:
        captured: dict = {}

        def fake_write_state(status, **state_kwargs):
            captured["status"] = status
            captured.update(state_kwargs)

        with (
            unittest.mock.patch.object(
                provisioner,
                "adb_run",
                return_value=completed([], ALOHA.fingerprint + "\n"),
            ),
            unittest.mock.patch.object(
                provisioner.run_state, "write_state", fake_write_state
            ),
            redirect_stdout(io.StringIO()),
        ):
            provisioner.write_state("complete", **kwargs)
        return captured

    def test_hostname_completion_drops_the_dhcp_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            delta = make_provisioner(
                temporary, privacy_dns="one.one.one.one"
            )
            delta._start_state = prior
            captured = self._write(delta, merge_prior=True)
            actions = captured["actions"]
            self.assertEqual(actions["privacy_dns"], "one.one.one.one")
            self.assertNotIn("dhcp_dns", actions)
            self.assertNotIn("restore_privacy_dns", actions)
            # Unrelated prior actions still merge through.
            for name, value in prior["actions"].items():
                if name in ("dhcp_dns", "privacy_dns"):
                    continue
                self.assertEqual(actions[name], value, name)
            self.assertEqual(
                captured["autoroot_key_sha256"], "prior-key-hash"
            )

    def test_off_completion_drops_the_privacy_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            delta = make_provisioner(temporary, dhcp_dns=True)
            delta._start_state = prior
            captured = self._write(delta, merge_prior=True)
            actions = captured["actions"]
            self.assertEqual(actions["dhcp_dns"], True)
            self.assertNotIn("privacy_dns", actions)
            self.assertNotIn("restore_privacy_dns", actions)
            for name, value in prior["actions"].items():
                if name in ("dhcp_dns", "privacy_dns"):
                    continue
                self.assertEqual(actions[name], value, name)

    def test_non_dns_completion_keeps_the_recorded_pair(self) -> None:
        # A delta that establishes no DNS intent must not touch
        # the recorded DNS actions: the merge preserves them, and
        # convergence is the next DNS run's job, not this one's.
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior_record(temporary)
            delta = make_provisioner(temporary, audio=True)
            delta._start_state = prior
            captured = self._write(delta, merge_prior=True)
            actions = captured["actions"]
            self.assertEqual(actions["dhcp_dns"], True)
            self.assertEqual(
                actions["privacy_dns"],
                prior["actions"]["privacy_dns"],
            )


class RestoreGateTest(unittest.TestCase):
    """Defect E, gate side: a restore records an operation, not a
    state. Closure session 6, Nov 19, 2026: --restore theme
    completed and its merged write recorded restore_theme; a
    channel --system-theme-control dark apply then set the live
    ui_night_mode to 2; a second --restore theme returned
    PROVISION_NOOP by record alone and never executed, leaving
    the live value at 2. A requested operation must always
    execute and verify its live end state, so the no-op gate
    never satisfies one from the record. The Shizuku removal is
    the same operation-not-state shape and is pinned with the
    restores."""

    # Constructor kwarg -> the action key it records: every
    # restore the CLI exposes, plus the Shizuku removal.
    OPERATIONS = {
        "restore_adb_auth_timeout": "restore_adb_auth_timeout",
        "restore_audio": "restore_audio",
        "enable_updates": "enable_updates",
        "restore_bloat": "restore_bloat",
        "restore_remote_wipe": "restore_remote_wipe",
        "restore_presence_profile": "restore_presence_profile",
        "restore_presence_fps": "restore_presence_fps",
        "restore_privacy_dns": "restore_privacy_dns",
        "restore_app_verifier": "restore_app_verifier",
        "restore_camera_light": "restore_camera_light",
        "restore_autoroot": "restore_autoroot",
        "restore_wireless_adb": "restore_wireless_adb",
        "restore_theme": "restore_theme",
        "restore_meta_authenticators": "restore_meta_authenticators",
        "remove_shizuku": "remove_shizuku",
    }

    def test_recorded_operation_never_satisfies_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for kwarg, action in self.OPERATIONS.items():
                with self.subTest(action=action):
                    provisioner = make_provisioner(
                        temporary, **{kwarg: True}
                    )
                    state = good_state(provisioner)
                    self.assertEqual(
                        state["actions"].get(action), True
                    )
                    self.assertEqual(
                        provisioner._noop_blocker(state),
                        f"actions-{action}",
                    )

    def test_repeat_restore_theme_executes_instead_of_nooping(
        self,
    ) -> None:
        """The live failure shape at the fast path: the record
        carries restore_theme from the first restore, so the
        repeat request must route onward to execute (here, the
        channel) instead of printing PROVISION_NOOP."""
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, restore_theme=True
            )
            device = FakeDevice()
            provisioner.adb_run = device.adb_run
            provisioner.read_state = lambda: good_state(provisioner)
            applied: list = []
            provisioner._apply_via_channel = (
                lambda reason: applied.append(reason) or True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertTrue(provisioner._run_fast_path())
            self.assertEqual(applied, ["actions-restore_theme"])
            self.assertIn(
                "PROVISION_NOOP_SKIP reason=actions-restore_theme",
                stdout.getvalue(),
            )
            self.assertNotIn(
                "PROVISION_NOOP reason", stdout.getvalue()
            )

    def test_apply_only_record_satisfaction_unchanged(self) -> None:
        """Control: requests carrying no operation keep the
        record-only satisfaction exactly as before."""
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, **DOCUMENTED)
            self.assertIsNone(
                provisioner._noop_blocker(good_state(provisioner))
            )


class RestoreRecordHygieneTest(unittest.TestCase):
    """Defect E, record side: mirroring the Defect D DNS family
    drop, a completion that records one side of an apply/restore
    pair drops the other side from the merged record, so the
    record never carries the contradictory pair (closure session
    6 left system_theme_control: "dark" beside restore_theme:
    true). The DNS pair is the family's own mechanism and stays
    pinned by DnsRecordHygieneTest; autoroot's apply side is the
    staging flag rather than an action key and is pinned
    separately below."""

    # (apply kwargs, apply action, restore kwargs, restore action)
    PAIRS = (
        ({"audio": True}, "audio",
         {"restore_audio": True}, "restore_audio"),
        ({"disable_updates": True}, "disable_updates",
         {"enable_updates": True}, "enable_updates"),
        ({"debloat": True}, "debloat",
         {"restore_bloat": True}, "restore_bloat"),
        ({"block_remote_wipe": True}, "block_remote_wipe",
         {"restore_remote_wipe": True}, "restore_remote_wipe"),
        ({"remove_meta_accounts": True}, "remove_meta_accounts",
         {"restore_meta_authenticators": True},
         "restore_meta_authenticators"),
        ({"optimize_presence": True}, "optimize_presence",
         {"restore_presence_profile": True},
         "restore_presence_profile"),
        ({"presence_fps_cap": 5}, "presence_fps_cap",
         {"restore_presence_fps": True}, "restore_presence_fps"),
        ({"allow_app_updates": True}, "allow_app_updates",
         {"restore_app_verifier": True}, "restore_app_verifier"),
        ({"disable_adb_auth_timeout": True},
         "disable_adb_auth_timeout",
         {"restore_adb_auth_timeout": True},
         "restore_adb_auth_timeout"),
        ({"disable_camera_light": True}, "disable_camera_light",
         {"restore_camera_light": True}, "restore_camera_light"),
        ({"persistent_wireless_adb": True},
         "persistent_wireless_adb",
         {"restore_wireless_adb": True}, "restore_wireless_adb"),
        ({"system_theme_control": "dark"}, "system_theme_control",
         {"restore_theme": True}, "restore_theme"),
        ({"shizuku": True}, "shizuku",
         {"remove_shizuku": True}, "remove_shizuku"),
    )

    def _prior(self, actions: dict) -> dict:
        return {
            "schema": 1,
            "status": "complete",
            "target": ALOHA.key,
            "fingerprint": ALOHA.fingerprint,
            "tool_revision": "prior-revision",
            "actions": dict(actions),
            "artifact_sha256": {},
            "autoroot_key_sha256": "prior-key-hash",
            "desired_state": {"alohausers_package": "disabled"},
            "verification": {
                "first_boot": "boot-a",
                "second_boot": "boot-a",
            },
        }

    def _write(self, provisioner: PortalProvisioner, **kwargs) -> dict:
        captured: dict = {}

        def fake_write_state(status, **state_kwargs):
            captured["status"] = status
            captured.update(state_kwargs)

        with (
            unittest.mock.patch.object(
                provisioner,
                "adb_run",
                return_value=completed([], ALOHA.fingerprint + "\n"),
            ),
            unittest.mock.patch.object(
                provisioner.run_state, "write_state", fake_write_state
            ),
            redirect_stdout(io.StringIO()),
        ):
            provisioner.write_state("complete", **kwargs)
        return captured

    @staticmethod
    def _unrelated(pair_actions: tuple) -> str:
        for candidate in ("audio", "debloat", "shizuku"):
            if candidate not in pair_actions:
                return candidate
        raise AssertionError("no unrelated candidate left")

    def test_apply_completion_drops_the_recorded_restore(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for apply_kwargs, apply_action, _, restore_action in (
                self.PAIRS
            ):
                with self.subTest(pair=apply_action):
                    unrelated = self._unrelated(
                        (apply_action, restore_action)
                    )
                    prior = self._prior(
                        {restore_action: True, unrelated: True}
                    )
                    delta = make_provisioner(
                        temporary, **apply_kwargs
                    )
                    delta._start_state = prior
                    actions = self._write(delta, merge_prior=True)[
                        "actions"
                    ]
                    self.assertIn(apply_action, actions)
                    self.assertNotIn(restore_action, actions)
                    self.assertEqual(actions[unrelated], True)

    def test_restore_completion_drops_the_recorded_apply(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for (
                _,
                apply_action,
                restore_kwargs,
                restore_action,
            ) in self.PAIRS:
                with self.subTest(pair=restore_action):
                    apply_value = (
                        "dark"
                        if apply_action == "system_theme_control"
                        else 5
                        if apply_action == "presence_fps_cap"
                        else True
                    )
                    unrelated = self._unrelated(
                        (apply_action, restore_action)
                    )
                    prior = self._prior(
                        {apply_action: apply_value, unrelated: True}
                    )
                    delta = make_provisioner(
                        temporary, **restore_kwargs
                    )
                    delta._start_state = prior
                    actions = self._write(delta, merge_prior=True)[
                        "actions"
                    ]
                    self.assertEqual(actions[restore_action], True)
                    self.assertNotIn(apply_action, actions)
                    self.assertEqual(actions[unrelated], True)

    def test_autoroot_completion_drops_the_recorded_restore(
        self,
    ) -> None:
        """Autoroot's apply side is the staging request itself,
        not an action key: a completion from a run that staged
        autoroot drops a recorded restore_autoroot the same way."""
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior(
                {"restore_autoroot": True, "audio": True}
            )
            delta = make_provisioner(temporary, autoroot=True)
            delta._start_state = prior
            actions = self._write(delta, merge_prior=True)["actions"]
            self.assertNotIn("restore_autoroot", actions)
            self.assertEqual(actions["audio"], True)

    def test_unrelated_completion_keeps_the_recorded_pair(
        self,
    ) -> None:
        # A delta that establishes neither side of a pair must
        # not touch the recorded pair: the merge preserves it,
        # and convergence is that pair's next run's job (the
        # DnsRecordHygieneTest non-DNS pin, generalized).
        with tempfile.TemporaryDirectory() as temporary:
            prior = self._prior(
                {
                    "system_theme_control": "dark",
                    "restore_theme": True,
                }
            )
            delta = make_provisioner(temporary, audio=True)
            delta._start_state = prior
            actions = self._write(delta, merge_prior=True)["actions"]
            self.assertEqual(actions["system_theme_control"], "dark")
            self.assertEqual(actions["restore_theme"], True)


class SharedApplySequenceTest(unittest.TestCase):
    """Phase C2 item 1: the stages path and the channel path run
    one shared shell-level apply sequence. These tests pin the
    order, the two skip sources, and the stages path's DNS defer."""

    SEQUENCE_KWARGS = dict(
        debloat=True,
        restore_bloat=True,
        block_remote_wipe=True,
        restore_remote_wipe=True,
        disable_updates=True,
        disable_adb_auth_timeout=True,
        restore_adb_auth_timeout=True,
        privacy_dns="family.example.com",
        dhcp_dns=True,
        restore_privacy_dns=True,
        allow_app_updates=True,
        restore_app_verifier=True,
    )
    APPLIES = (
        "apply_debloat",
        "restore_debloat",
        "ensure_remote_wipe_backup",
        "read_remote_wipe_backup",
        "disable_ota_packages",
        "disable_adb_authorization_timeout",
        "restore_adb_authorization_timeout",
        "apply_privacy_dns",
        "apply_dhcp_dns",
        "restore_private_dns",
        "allow_third_party_app_updates",
        "restore_app_verifier_setting",
        "prepare_component_actions",
    )

    def _instrumented(self, temporary: str):
        provisioner = make_provisioner(temporary, **self.SEQUENCE_KWARGS)
        calls: list = []
        for name in self.APPLIES:
            setattr(
                provisioner,
                name,
                (lambda recorded: lambda *a, **k: calls.append(recorded))(
                    name
                ),
            )
        provisioner.needs_uid1000_payload = lambda: False
        provisioner.needs_component_ctl = lambda: True
        return provisioner, calls

    def test_full_sequence_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, calls = self._instrumented(temporary)
            provisioner._apply_shell_level_state(
                debloat_configured=False,
                remote_wipe_configured=False,
                defer_dns=False,
            )
            self.assertEqual(calls, list(self.APPLIES))
            self.assertFalse(provisioner._dns_apply_deferred)

    def test_configured_skips_and_dns_defer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, calls = self._instrumented(temporary)
            provisioner._apply_shell_level_state(
                debloat_configured=True,
                remote_wipe_configured=True,
                defer_dns=True,
            )
            self.assertEqual(
                calls,
                [
                    name
                    for name in self.APPLIES
                    if name
                    not in (
                        "apply_debloat",
                        "ensure_remote_wipe_backup",
                        "apply_privacy_dns",
                        "apply_dhcp_dns",
                        "restore_private_dns",
                    )
                ],
            )
            self.assertTrue(provisioner._dns_apply_deferred)


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
        # --force bypasses only the byte-identical skip, via the
        # skip_if_identical flag; the package itself always goes
        # through, because it also gates the signature-mismatch
        # retry (nulling it disarmed the retry for every install in
        # a force run — the autoroot staging install hit that on a
        # stale old-keystore helper, Nov 17, 2026).
        with tempfile.TemporaryDirectory() as temporary:
            for force, expected_skip in ((False, True), (True, False)):
                with self.subTest(force=force):
                    provisioner = make_provisioner(
                        temporary, force=force
                    )
                    seen: list = []
                    provisioner.shizuku_feature.install_apk_preserving_verifier = (  # noqa: E501
                        lambda apk, tag, package=None, *, skip_if_identical=True: seen.append(  # noqa: E501
                            (package, skip_if_identical)
                        )
                    )
                    provisioner.install_apk_preserving_verifier(
                        pathlib.Path("x.apk"), "tag", "pkg"
                    )
                    self.assertEqual(seen, [("pkg", expected_skip)])


class ShizukuEndStateDevice:
    """adb fake modelling the finished autoroot end state: the
    Shizuku package installed, its server live as uid 0, the
    standalone helper package ABSENT (removed by the flow itself
    after the keypair merge), sentinel + autoroot helper present.
    The install-phase verify_shizuku() can never pass on this
    state; the channel end-state check must."""

    def __init__(self) -> None:
        self.shizuku_uid = "0"
        self.shizuku_running = True
        self.shizuku_package = True

    def adb_run(self, arguments, timeout=None, check=False):
        del timeout, check
        command = " ".join(str(argument) for argument in arguments)
        if "pm path moe.shizuku.privileged.api" in command:
            return completed(
                arguments,
                "package:/data/app/shizuku/base.apk\n"
                if self.shizuku_package
                else "",
            )
        if "pm path dev.portal.exploitsentinel" in command:
            return completed(
                arguments, "package:/data/app/sentinel/base.apk\n"
            )
        if "pm path dev.portal.autoroothelper" in command:
            return completed(
                arguments, "package:/data/app/helper/base.apk\n"
            )
        if "pidof shizuku_server" in command:
            return completed(
                arguments, "4242\n" if self.shizuku_running else ""
            )
        if "/proc/4242/status" in command:
            return completed(
                arguments,
                f"Name:\tshizuku_server\nUid:\t{self.shizuku_uid}\t0\t0\t0\n",
            )
        if "pm list packages" in command:
            return completed(
                arguments,
                "package:moe.shizuku.privileged.api\n"
                "package:dev.portal.autoroothelper\n",
            )
        if "ps -A" in command:
            user = "root" if self.shizuku_uid == "0" else "shell"
            return completed(
                arguments,
                f"{user} 4242 1 0 0 0 0 S shizuku_server\n"
                if self.shizuku_running
                else "",
            )
        if "dumpsys package dev.portal.shizukuhelper" in command:
            return completed(arguments, "")
        return completed(arguments, "", 1)


class VerifyShizukuChannelTest(unittest.TestCase):
    """The channel Shizuku verification asserts the finished
    autoroot end state (package installed, server uid 0, root
    setup identities present) instead of the install-phase
    startup state (standalone helper present, server as shell)."""

    def _provisioner(self, temporary: str, device: ShizukuEndStateDevice):
        provisioner = make_provisioner(
            temporary, shizuku=True, autoroot=True
        )
        provisioner.adb_run = device.adb_run
        return provisioner

    def test_end_state_passes_channel_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShizukuEndStateDevice()
            provisioner = self._provisioner(temporary, device)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                provisioner.verify_shizuku_channel()
            self.assertIn(
                "SHIZUKU_OK privilege=root", stdout.getvalue()
            )

    def test_end_state_fails_the_old_phase_check(self) -> None:
        """The same device state must FAIL the race path's
        install-phase assertion — that mismatch is the defect
        class this audit fixes."""
        with tempfile.TemporaryDirectory() as temporary:
            device = ShizukuEndStateDevice()
            provisioner = self._provisioner(temporary, device)
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError):
                    provisioner.shizuku_feature.verify_shizuku(
                        wait_seconds=1
                    )

    def test_server_wrong_uid_declines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShizukuEndStateDevice()
            device.shizuku_uid = "2000"
            provisioner = self._provisioner(temporary, device)
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError):
                    provisioner.verify_shizuku_channel()

    def test_server_absent_declines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShizukuEndStateDevice()
            device.shizuku_running = False
            provisioner = self._provisioner(temporary, device)
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError):
                    provisioner.verify_shizuku_channel()

    def test_shizuku_package_absent_declines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShizukuEndStateDevice()
            device.shizuku_package = False
            provisioner = self._provisioner(temporary, device)
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError):
                    provisioner.verify_shizuku_channel()

    def test_dispatch_channel_vs_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            calls: list = []
            provisioner.verify_shizuku = lambda *a, **k: calls.append(
                "race"
            )
            provisioner.verify_shizuku_channel = lambda: calls.append(
                "channel"
            )
            with redirect_stdout(io.StringIO()):
                provisioner.verify_requested_state(via_channel=True)
                provisioner.verify_requested_state()
            self.assertEqual(calls, ["channel", "race"])


class PresenceEndStateDevice:
    """adb fake modelling a live presence runtime on an old boot:
    the pipeline is running (aiservice pid, active camera client,
    CAMERA appop allow, analysis/ROI frame markers in the current
    logcat, pose metrics + frame processor in dumpsys) and the
    durable profile marker is present — but NONE of the
    config-load-time logcat evidence (settings_config.xml profile
    keys, full-scene marker, FPS/activation lines) exists, because
    it rotated away. The race-path profile verification needs
    that evidence; the channel verification must not."""

    def __init__(self) -> None:
        self.marker = True
        self.fps_marker = "5"

    def adb_run(self, arguments, timeout=None, check=False):
        del timeout, check
        command = " ".join(str(argument) for argument in arguments)
        if (
            "test -f /data/local/tmp/portal-presence-backup/installed-v1"
            in command
        ):
            return completed(arguments, "", 0 if self.marker else 1)
        if "cat /data/local/tmp/portal-presence-backup/fps-cap-v1" in command:
            return completed(arguments, self.fps_marker + "\n")
        if "pidof com.facebook.portal.aiservice" in command:
            return completed(arguments, "2703\n")
        if "dumpsys media.camera" in command:
            return completed(
                arguments,
                "Active Camera Clients:\n"
                "Client Package Name: com.facebook.portal.aiservice\n",
            )
        if "cmd appops get" in command:
            return completed(arguments, "CAMERA: allow\n")
        if "logcat" in command:
            return completed(
                arguments,
                "Frame available for analysis stream\n"
                "Frame available for roi stream\n",
            )
        if "dumpsys activity service" in command:
            return completed(
                arguments,
                "[ PoseEstimatorManagerMetrics ]\n"
                "10 ms - 20 ms: 3\n"
                "[ AlohaFrameProcessor ]\nloaded\n"
                "[ AiCameramanController ]\n",
            )
        return completed(arguments, "", 1)


class VerifyPresenceChannelTest(unittest.TestCase):
    """The channel presence verification asserts durable markers
    (installed profile marker, fps-cap marker) plus the live
    pipeline subset, instead of the race verify's config-load
    logcat evidence."""

    def _provisioner(self, temporary: str, device: PresenceEndStateDevice, **kwargs):
        provisioner = make_provisioner(temporary, **kwargs)
        provisioner.adb_run = device.adb_run
        return provisioner

    def test_live_runtime_with_marker_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = PresenceEndStateDevice()
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                provisioner.verify_presence_runtime_channel()
            self.assertIn(
                "PRESENCE_RUNTIME_OK", stdout.getvalue()
            )
            self.assertIn("profile=durable-marker", stdout.getvalue())

    def test_marker_absent_declines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = PresenceEndStateDevice()
            device.marker = False
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError):
                    provisioner.verify_presence_runtime_channel()

    def test_fps_cap_marker_mismatch_declines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = PresenceEndStateDevice()
            device.fps_marker = "3"
            provisioner = self._provisioner(
                temporary, device, presence_fps_cap=5
            )
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError):
                    provisioner.verify_presence_runtime_channel(
                        expected_analysis_fps=5
                    )

    def test_fps_cap_marker_match_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = PresenceEndStateDevice()
            provisioner = self._provisioner(
                temporary, device, presence_fps_cap=5
            )
            with redirect_stdout(io.StringIO()):
                provisioner.verify_presence_runtime_channel(
                    expected_analysis_fps=5
                )

    def test_dispatch_channel_vs_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, optimize_presence=True
            )
            calls: list = []
            provisioner.verify_presence_runtime = (
                lambda *a, **k: calls.append("race")
            )
            provisioner.verify_presence_runtime_channel = (
                lambda *a, **k: calls.append(("channel", k))
            )
            with redirect_stdout(io.StringIO()):
                provisioner.verify_requested_state(via_channel=True)
                provisioner.verify_requested_state()
            self.assertEqual(calls[0][0], "channel")
            self.assertEqual(
                calls[0][1],
                {
                    "expected_analysis_fps": None,
                    "require_marker": True,
                },
            )
            self.assertEqual(calls[1], "race")


class ShutterPresenceDevice:
    """adb fake for the shutter-aware presence verification: the
    lens cover state, aiservice process, CAMERA appop, durable
    profile evidence (installed marker / config-load logcat lines)
    and the FPS cap marker are each independently switchable. The
    streaming evidence is modelled as present, so with the cover
    open the live check passes on its first sample."""

    PROFILE_KEYS = (
        "enable_cv_background_detector_v2",
        "enable_hardware_cropping",
        "enable_liveness_metric",
        "enable_color_based_reid",
        "enable_face_rec_based_reid_v3",
    )

    def __init__(self) -> None:
        self.shutter: str | None = "1"
        self.pid = "2703"
        self.appop_allow = True
        self.marker = False
        self.profile_lines = True
        self.fps_marker = "5"

    def _logs(self) -> str:
        lines = []
        if self.profile_lines:
            lines += [
                f"settings_config.xml {key} false"
                for key in self.PROFILE_KEYS
            ]
        lines += [
            "Disabled hardware cropping",
            "Frame available for analysis stream",
            "Frame available for roi stream",
        ]
        return "\n".join(lines) + "\n"

    def adb_run(self, arguments, timeout=None, check=False):
        del timeout, check
        command = " ".join(str(argument) for argument in arguments)
        if "dumpsys platform_state_service" in command:
            if self.shutter is None:
                return completed(arguments, "platform state unavailable\n")
            return completed(arguments, f"shutter_state={self.shutter}\n")
        if (
            "test -f /data/local/tmp/portal-presence-backup/installed-v1"
            in command
        ):
            return completed(arguments, "", 0 if self.marker else 1)
        if "fps-cap-v1" in command or "presence-fps" in command:
            return completed(arguments, self.fps_marker + "\n")
        if "pidof com.facebook.portal.aiservice" in command:
            if not self.pid:
                return completed(arguments, "", 1)
            return completed(arguments, self.pid + "\n")
        if "dumpsys media.camera" in command:
            return completed(
                arguments,
                "Active Camera Clients:\n"
                "Client Package Name: com.facebook.portal.aiservice\n"
                "com.facebook.alohasdk.dewarp_crop_rect.x_start:\n"
                "[0.0]\n"
                "com.facebook.alohasdk.dewarp_crop_rect.y_start:\n"
                "[0.0]\n"
                "com.facebook.alohasdk.dewarp_crop_rect.width:\n"
                "[4032.0]\n",
            )
        if "cmd appops get" in command:
            return completed(
                arguments,
                "CAMERA: allow\n" if self.appop_allow else "CAMERA: deny\n",
            )
        if "logcat" in command:
            return completed(arguments, self._logs())
        if "dumpsys activity service" in command:
            return completed(
                arguments,
                "[ PoseEstimatorManagerMetrics ]\n"
                "10 ms - 20 ms: 3\n"
                "[ AlohaFrameProcessor ]\nloaded\n"
                "[ AiCameramanController ]\n",
            )
        if "ps -T" in command:
            return completed(arguments, "main\n")
        return completed(arguments, "", 0)


class ShutterAwarePresenceTest(unittest.TestCase):
    """With the camera lens cover closed the presence pipeline is
    off by design (it configures, starts, and pauses without ever
    opening the camera), so the streaming verification can never
    pass. The verification reads the shutter state first: covered
    units verify their durable end state and return a distinct
    deferred outcome; durable failures still fail; open units run
    the live check unchanged. A deferred verification is recorded
    in the manifest as "deferred" (the OTA "unverified" pattern),
    so the no-op gate refuses to treat it as verified and a later
    run with the cover open re-attempts the streaming check."""

    def _provisioner(self, temporary: str, device: ShutterPresenceDevice, **kwargs):
        provisioner = make_provisioner(temporary, **kwargs)
        provisioner.adb_run = device.adb_run
        return provisioner

    def test_closed_shutter_durable_good_defers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                outcome = provisioner.verify_presence_runtime(
                    require_profile=True, wait_seconds=5
                )
            self.assertEqual(outcome, "deferred")
            self.assertTrue(provisioner.presence_deferred)
            self.assertIn(
                "PRESENCE_VERIFY_DEFERRED reason=shutter_closed",
                stdout.getvalue(),
            )
            self.assertNotIn("PRESENCE_RUNTIME_OK", stdout.getvalue())

    def test_closed_shutter_profile_evidenced_by_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.profile_lines = False
            device.marker = True
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            with redirect_stdout(io.StringIO()):
                outcome = provisioner.verify_presence_runtime(
                    require_profile=True, wait_seconds=5
                )
            self.assertEqual(outcome, "deferred")

    def test_closed_shutter_appop_denied_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.appop_allow = False
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError) as raised:
                    provisioner.verify_presence_runtime(
                        require_profile=True, wait_seconds=5
                    )
            self.assertIn("camera-appop-not-allow", str(raised.exception))
            self.assertFalse(provisioner.presence_deferred)

    def test_closed_shutter_aiservice_down_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.pid = ""
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError) as raised:
                    provisioner.verify_presence_runtime(
                        require_profile=True, wait_seconds=5
                    )
            self.assertIn("aiservice-not-running", str(raised.exception))
            self.assertFalse(provisioner.presence_deferred)

    def test_closed_shutter_profile_not_evidenced_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.profile_lines = False
            device.marker = False
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError) as raised:
                    provisioner.verify_presence_runtime(
                        require_profile=True, wait_seconds=5
                    )
            self.assertIn("profile-not-evidenced", str(raised.exception))
            self.assertFalse(provisioner.presence_deferred)

    def test_closed_shutter_fps_cap_durable_good_defers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            provisioner = self._provisioner(
                temporary, device, presence_fps_cap=5
            )
            with redirect_stdout(io.StringIO()):
                outcome = provisioner.verify_presence_runtime(
                    require_profile=True,
                    expected_analysis_fps=5,
                    wait_seconds=5,
                )
            self.assertEqual(outcome, "deferred")
            self.assertTrue(provisioner.presence_deferred)

    def test_closed_shutter_fps_cap_marker_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.fps_marker = "3"
            provisioner = self._provisioner(
                temporary, device, presence_fps_cap=5
            )
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError) as raised:
                    provisioner.verify_presence_runtime(
                        require_profile=True,
                        expected_analysis_fps=5,
                        wait_seconds=5,
                    )
            self.assertIn(
                "fps-cap-marker-mismatch", str(raised.exception)
            )
            self.assertFalse(provisioner.presence_deferred)

    def test_open_shutter_live_verification_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.shutter = "0"
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                outcome = provisioner.verify_presence_runtime(
                    require_profile=True, wait_seconds=5
                )
            self.assertEqual(outcome, "verified")
            self.assertIn("PRESENCE_RUNTIME_OK", stdout.getvalue())
            self.assertFalse(provisioner.presence_deferred)

    def test_shutter_unreadable_falls_back_to_live(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.shutter = None
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            with redirect_stdout(io.StringIO()):
                outcome = provisioner.verify_presence_runtime(
                    require_profile=True, wait_seconds=5
                )
            self.assertEqual(outcome, "verified")
            self.assertFalse(provisioner.presence_deferred)

    def test_channel_closed_shutter_defers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.marker = True
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                outcome = provisioner.verify_presence_runtime_channel()
            self.assertEqual(outcome, "deferred")
            self.assertTrue(provisioner.presence_deferred)
            self.assertIn(
                "PRESENCE_VERIFY_DEFERRED reason=shutter_closed "
                "path=channel",
                stdout.getvalue(),
            )

    def test_channel_closed_shutter_service_down_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            device.marker = True
            device.pid = ""
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(ProvisionError) as raised:
                    provisioner.verify_presence_runtime_channel()
            self.assertIn("aiservice-not-running", str(raised.exception))
            self.assertFalse(provisioner.presence_deferred)

    def test_preflight_closed_shutter_skips_as_deferred(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            device = ShutterPresenceDevice()
            provisioner = self._provisioner(
                temporary, device, optimize_presence=True
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                configured = provisioner.presence_preflight()
            self.assertTrue(configured)
            self.assertIn(
                "PRESENCE_PREFLIGHT action=skip profile=durable "
                "deferred=shutter_closed",
                stdout.getvalue(),
            )
            self.assertTrue(provisioner.presence_deferred)

    def _recorded_actions(self, temporary: str, deferred: bool) -> dict:
        provisioner = make_provisioner(temporary, optimize_presence=True)
        provisioner.adb_run = (
            lambda arguments, timeout=None, check=False: completed(
                arguments, ALOHA.fingerprint + "\n"
            )
        )
        provisioner.presence_deferred = deferred
        writes: list = []
        with unittest.mock.patch.object(
            provisioner.run_state,
            "write_state",
            lambda status, **kwargs: writes.append((status, kwargs)),
        ):
            provisioner.write_state("complete")
        return writes[-1][1]["actions"]

    def test_deferred_verification_records_deferred_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            actions = self._recorded_actions(temporary, deferred=True)
            self.assertEqual(actions["optimize_presence"], "deferred")
            actions = self._recorded_actions(temporary, deferred=False)
            self.assertEqual(actions["optimize_presence"], True)

    def test_deferred_record_blocks_noop_until_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, optimize_presence=True
            )
            state = {
                "status": "complete",
                "tool_revision": provisioner.tool_revision(),
                "target": ALOHA.key,
                "fingerprint": ALOHA.fingerprint,
                "actions": {"optimize_presence": "deferred"},
                "artifact_sha256": {},
            }
            self.assertEqual(
                provisioner._noop_blocker(state),
                "actions-optimize_presence",
            )
            state["actions"] = {"optimize_presence": True}
            self.assertIsNone(provisioner._noop_blocker(state))


if __name__ == "__main__":
    unittest.main()
