#!/usr/bin/env python3
# Copyright (c) 2026 itsgreat2misha
# SPDX-License-Identifier: Apache-2.0
"""Verification at the end (Phase C3-B): a bootstrap phase's
deferred failure is judged against the device's end state, not at
the point in the run's ordering where the phase happened to run.

Pins:
- the re-judgment seam inside report_deferred_failures(): a stale
  OTA bootstrap verification failure clears when ota_preflight()
  passes against the end state, and is confirmed (manifest records
  the action unverified, the run still fails) when it does not;
- the posture judgment (owner decision, Nov 18, 2026): when the run
  ends in the alohausers-disabled posture, the OTA item is judged
  by the posture criteria instead of override provenance, which
  the posture makes impossible by design — all four criteria true
  judges it done, any one false leaves it unverified, and the
  judgment never applies while alohausers is enabled;
- the raise defers past a pending custom payload phase, and a
  provisional judgment may clear a failure but never confirms one;
- the payload-only path reports deferred failures at its end (it
  used to return without reporting at all);
- the manifest correction: a completed manifest that claimed the
  OTA action done is re-written as unverified by the final
  judgment, preserving the recorded verification boots;
- singleton runs keep fail-fast bootstrap behaviour.
"""

from __future__ import annotations

import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[1] / "tools")
)

from portal_targets import TARGETS  # noqa: E402
from provision_portal import PortalProvisioner, ProvisionError  # noqa: E402

SERIAL = "192.0.2.1:5555"
ALOHA = next(
    target for target in TARGETS if target.key == "portal-plus-aloha-1041515800015050"
)
VERIFY_ENTRY = (
    "disable_updates: the dedicated Aloha OTA bootstrap did not verify"
)


def make_provisioner(temporary: str, **kwargs) -> PortalProvisioner:
    provisioner = PortalProvisioner(
        SERIAL, 12, pathlib.Path(temporary), **kwargs
    )
    provisioner.target = ALOHA
    return provisioner


def completed(args, stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args, returncode, stdout, "")


def deferred_provisioner(temporary: str, **kwargs) -> PortalProvisioner:
    kwargs.setdefault("disable_updates", True)
    kwargs.setdefault("audio", True)
    provisioner = make_provisioner(temporary, **kwargs)
    provisioner.deferred_phase_failures = [VERIFY_ENTRY]
    return provisioner


class RejudgmentTest(unittest.TestCase):
    def test_clears_when_end_state_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = deferred_provisioner(temporary)
            provisioner.ota_preflight = lambda: True
            output = io.StringIO()
            with redirect_stdout(output):
                provisioner.report_deferred_failures()
            self.assertEqual(provisioner.deferred_phase_failures, [])
            self.assertFalse(provisioner.ota_unverified)
            self.assertIn(
                "OTA_DEFERRED_FAILURE_CLEARED", output.getvalue()
            )

    def test_unconfirmed_stays_unverified_and_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = deferred_provisioner(temporary)
            provisioner.ota_preflight = lambda: False
            provisioner.alohausers_package_disabled = lambda: False
            provisioner.read_state = lambda: None
            with self.assertRaises(ProvisionError):
                provisioner.report_deferred_failures()
            self.assertEqual(
                provisioner.deferred_phase_failures, [VERIFY_ENTRY]
            )
            self.assertTrue(provisioner.ota_unverified)

    def test_non_verification_entry_is_not_rejudged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = deferred_provisioner(temporary)
            provisioner.deferred_phase_failures = [
                "disable_updates: provisioning failed after 12 attempts"
            ]
            calls = []
            provisioner.ota_preflight = lambda: calls.append(1) or True
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(
                ProvisionError
            ):
                provisioner.report_deferred_failures()
            self.assertEqual(calls, [])
            self.assertNotIn(
                "OTA_DEFERRED_FAILURE_CLEARED", output.getvalue()
            )
            self.assertFalse(provisioner.ota_unverified)


class PostureJudgmentTest(unittest.TestCase):
    def posture_provisioner(self, temporary: str) -> PortalProvisioner:
        provisioner = deferred_provisioner(temporary)
        provisioner.ota_preflight = lambda: False
        provisioner.alohausers_package_disabled = lambda: True
        provisioner._ota_nodemon_conf_staged = lambda: True
        provisioner._ota_override_present = lambda: True
        provisioner.ota_nodemon_set_this_run = True
        provisioner.adb_run = (
            lambda arguments, timeout=None, check=False: completed(
                arguments, "\n"
            )
        )
        return provisioner

    def test_all_criteria_true_judges_done(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.posture_provisioner(temporary)
            output = io.StringIO()
            with redirect_stdout(output):
                provisioner.report_deferred_failures()
            self.assertEqual(provisioner.deferred_phase_failures, [])
            self.assertFalse(provisioner.ota_unverified)
            self.assertIn(
                "OTA_POSTURE_JUDGED result=done", output.getvalue()
            )
            self.assertIn(
                "nodemon_source=set-this-run", output.getvalue()
            )

    def test_nodemon_from_current_boot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.posture_provisioner(temporary)
            provisioner.ota_nodemon_set_this_run = False
            provisioner.adb_run = (
                lambda arguments, timeout=None, check=False: completed(
                    arguments, "true\n"
                )
            )
            output = io.StringIO()
            with redirect_stdout(output):
                provisioner.report_deferred_failures()
            self.assertEqual(provisioner.deferred_phase_failures, [])
            self.assertIn(
                "nodemon_source=current-boot", output.getvalue()
            )

    def test_each_criterion_false_leaves_unverified(self) -> None:
        cases = {
            "conf": {"_ota_nodemon_conf_staged": lambda: False},
            "nodemon": {"ota_nodemon_set_this_run": False},
            "override": {"_ota_override_present": lambda: False},
        }
        for name, overrides in cases.items():
            with self.subTest(criterion=name), tempfile.TemporaryDirectory() as temporary:
                provisioner = self.posture_provisioner(temporary)
                for attribute, value in overrides.items():
                    setattr(provisioner, attribute, value)
                output = io.StringIO()
                with redirect_stdout(output), self.assertRaises(
                    ProvisionError
                ):
                    provisioner.report_deferred_failures()
                self.assertTrue(provisioner.ota_unverified)
                self.assertIn(
                    "OTA_POSTURE_JUDGED result=unverified",
                    output.getvalue(),
                )

    def test_not_applied_while_alohausers_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.posture_provisioner(temporary)
            provisioner.alohausers_package_disabled = lambda: False
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(
                ProvisionError
            ):
                provisioner.report_deferred_failures()
            self.assertTrue(provisioner.ota_unverified)
            self.assertNotIn("OTA_POSTURE_JUDGED", output.getvalue())


class OverridePresenceTest(unittest.TestCase):
    def test_daemon_answers_present(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            provisioner.daemon_exec = lambda command, timeout=40: (0, "")
            self.assertTrue(provisioner._ota_override_present())

    def test_daemon_refusal_falls_back_to_install_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            provisioner.daemon_exec = lambda command, timeout=40: (1, "")
            self.assertFalse(provisioner._ota_override_present())
            provisioner._ota_install_verified_this_run = True
            self.assertTrue(provisioner._ota_override_present())

    def test_daemon_down_falls_back_to_install_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)

            def down(command, timeout=40):
                raise ConnectionRefusedError("no daemon")

            provisioner.daemon_exec = down
            self.assertFalse(provisioner._ota_override_present())
            provisioner._ota_install_verified_this_run = True
            self.assertTrue(provisioner._ota_override_present())


class PayloadDeferralTest(unittest.TestCase):
    def test_raise_deferred_past_pending_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = deferred_provisioner(temporary)
            provisioner.ota_preflight = lambda: False
            provisioner.alohausers_package_disabled = lambda: False
            provisioner.read_state = lambda: None
            provisioner._payload_phase_pending = True
            # Provisional judgment: no raise, and it must not
            # confirm the failure either.
            provisioner.report_deferred_failures()
            self.assertFalse(provisioner.ota_unverified)
            self.assertEqual(
                provisioner.deferred_phase_failures, [VERIFY_ENTRY]
            )
            provisioner._payload_phase_pending = False
            with self.assertRaises(ProvisionError):
                provisioner.report_deferred_failures()
            self.assertTrue(provisioner.ota_unverified)

    def test_provisional_judgment_may_clear(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = deferred_provisioner(temporary)
            provisioner.ota_preflight = lambda: True
            provisioner._payload_phase_pending = True
            provisioner.report_deferred_failures()
            self.assertEqual(provisioner.deferred_phase_failures, [])

    def test_payload_branch_reports_at_its_end(self) -> None:
        """Wiring pin: _provision_stages sets the pending flag from
        the run's payload request and makes a final report in the
        payload branch, after the payload apply — the payload-only
        path used to return without reporting at all."""
        source = (
            pathlib.Path(__file__).resolve().parents[1]
            / "tools"
            / "provision_portal.py"
        ).read_text(encoding="utf-8")
        stages = source.split("def _provision_stages", 1)[1].split(
            "\ndef keystore_certificate_sha256", 1
        )[0]
        self.assertIn(
            "_payload_phase_pending = self.custom_payload is not None",
            stages,
        )
        payload_branch = stages.split(
            "if self.custom_payload is not None:", 1
        )[1]
        clear = payload_branch.index("_payload_phase_pending = False")
        report = payload_branch.index(
            "report_deferred_failures()", clear
        )
        self.assertLess(clear, report)


class ManifestCorrectionTest(unittest.TestCase):
    def unverified_provisioner(self, temporary: str, state) -> PortalProvisioner:
        provisioner = deferred_provisioner(temporary)
        provisioner.ota_preflight = lambda: False
        provisioner.alohausers_package_disabled = lambda: False
        provisioner.read_state = lambda: state
        provisioner.writes = []
        provisioner.write_state = lambda status, fb=None, sb=None: (
            provisioner.writes.append((status, fb, sb))
        )
        return provisioner

    def test_correction_rewrites_claiming_manifest(self) -> None:
        state = {
            "status": "complete",
            "actions": {"disable_updates": True, "audio": True},
            "verification": {"first_boot": "b1", "second_boot": "b2"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.unverified_provisioner(temporary, state)
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(
                ProvisionError
            ):
                provisioner.report_deferred_failures()
            self.assertEqual(
                provisioner.writes, [("complete", "b1", "b2")]
            )
            self.assertIn("OTA_MANIFEST_CORRECTED", output.getvalue())

    def test_no_correction_when_already_unverified(self) -> None:
        state = {
            "status": "complete",
            "actions": {"disable_updates": "unverified"},
            "verification": {"first_boot": "b1", "second_boot": "b2"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.unverified_provisioner(temporary, state)
            with self.assertRaises(ProvisionError):
                provisioner.report_deferred_failures()
            self.assertEqual(provisioner.writes, [])

    def test_no_correction_when_manifest_not_complete(self) -> None:
        state = {
            "status": "pending",
            "actions": {"disable_updates": True},
            "verification": {"first_boot": None, "second_boot": None},
        }
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.unverified_provisioner(temporary, state)
            with self.assertRaises(ProvisionError):
                provisioner.report_deferred_failures()
            self.assertEqual(provisioner.writes, [])


class BootstrapGuardTest(unittest.TestCase):
    def test_singleton_run_keeps_fail_fast(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            with self.assertRaises(ProvisionError):
                with provisioner.bootstrap_guard("disable_updates"):
                    raise ProvisionError("boom")
            self.assertEqual(provisioner.deferred_phase_failures, [])

    def test_multi_action_run_defers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, disable_updates=True, audio=True
            )
            with provisioner.bootstrap_guard("disable_updates"):
                raise ProvisionError("boom")
            self.assertEqual(
                provisioner.deferred_phase_failures,
                ["disable_updates: boom"],
            )


if __name__ == "__main__":
    unittest.main()
