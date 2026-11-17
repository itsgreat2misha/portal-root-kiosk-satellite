# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Re-run guard: provision() sets the autoroot disable flag itself
and restores the state it found on every exit path, so re-running
the provisioner on an already-provisioned device cannot collide
with the device's own live autoroot session (Run 32)."""

from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import provision_portal as provision_portal_module  # noqa: E402
from provision_portal import (  # noqa: E402
    AUTOROOT_DISABLE_FLAG_REMOTE,
    AUTOROOT_FLAG_ABSENT_TOKEN,
    AUTOROOT_FLAG_PRESENT_TOKEN,
    AUTOROOT_GUARD_TOKEN,
    PortalProvisioner,
    ProvisionError,
)

SERIAL = "192.0.2.1:5555"


class FakeFlagDevice:
    """Stateful adb_run fake for the autoroot disable flag file.

    All non-flag commands fail with rc=1. Failure injection:
    fail_set (the guard's create never lands), fail_rm (removal
    never lands), dark (every flag command reports an adb transport
    error, as a wedged device does), disrupt_probes (the Run 34
    shape: that many initial flag probes after disruption starts
    return a bare non-zero with no token while rm/touch never
    land, as commands issued into an adbd restart do; the
    disruption is armed by setting the attribute mid-run)."""

    def __init__(
        self,
        present: bool = False,
        content: str = "",
        fail_set: bool = False,
        fail_rm: bool = False,
        dark: bool = False,
    ) -> None:
        self.present = present
        self.content = content
        self.fail_set = fail_set
        self.fail_rm = fail_rm
        self.dark = dark
        self.disrupt_probes = 0
        self.flag_commands: list[str] = []

    def adb_run(self, arguments, timeout=None, check=False):
        del timeout, check
        arguments = [str(argument) for argument in arguments]
        joined = " ".join(arguments)
        if AUTOROOT_DISABLE_FLAG_REMOTE not in joined:
            return subprocess.CompletedProcess(arguments, 1, "")
        self.flag_commands.append(joined)
        if self.dark:
            return subprocess.CompletedProcess(
                arguments, 1, "error: device offline"
            )
        if self.disrupt_probes > 0:
            if "test" in arguments:
                self.disrupt_probes -= 1
                return subprocess.CompletedProcess(arguments, 1, "")
            # rm / touch / echo issued into the disruption are lost.
            return subprocess.CompletedProcess(arguments, 1, "")
        if "test" in arguments:
            return subprocess.CompletedProcess(
                arguments,
                0 if self.present else 1,
                AUTOROOT_FLAG_PRESENT_TOKEN
                if self.present
                else AUTOROOT_FLAG_ABSENT_TOKEN,
            )
        if "cat" in arguments:
            if not self.present:
                return subprocess.CompletedProcess(arguments, 1, "")
            return subprocess.CompletedProcess(
                arguments, 0, self.content
            )
        if "rm" in arguments:
            if not self.fail_rm:
                self.present = False
                self.content = ""
            return subprocess.CompletedProcess(arguments, 0, "")
        # echo <token> > flag / touch flag.
        if not self.fail_set:
            self.present = True
            parts = joined.split()
            if "echo" in parts:
                self.content = parts[parts.index("echo") + 1]
        return subprocess.CompletedProcess(arguments, 0, "")


class AutorootGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        provision_portal_module._autoroot_guard_depth = 0
        # The restore's retry delays ride out a real adbd restart;
        # the fakes answer instantly, so collapse them to zero.
        delays = mock.patch.object(
            provision_portal_module,
            "AUTOROOT_GUARD_RESTORE_DELAYS",
            (0.0, 0.0, 0.0, 0.0),
        )
        delays.start()
        self.addCleanup(delays.stop)

    def tearDown(self) -> None:
        provision_portal_module._autoroot_guard_depth = 0

    def make_provisioner(self, temporary: str, **kwargs) -> PortalProvisioner:
        return PortalProvisioner(
            SERIAL, 1, pathlib.Path(temporary), **kwargs
        )

    def drive(self, provisioner, device, stages):
        """Run provision() with connect and the stage body stubbed."""
        stdout = io.StringIO()
        with (
            mock.patch.object(provisioner, "connect"),
            mock.patch.object(
                provisioner, "adb_run", side_effect=device.adb_run
            ),
            mock.patch.object(
                provisioner, "_provision_stages", side_effect=stages
            ) as stages_mock,
            contextlib.redirect_stdout(stdout),
        ):
            provisioner.provision()
        return stages_mock, stdout.getvalue()

    def test_success_sets_then_restores_absent_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice()
            seen = {}

            def stages():
                seen["present_during"] = device.present
                seen["content_during"] = device.content

            _, output = self.drive(provisioner, device, stages)
            self.assertTrue(seen["present_during"])
            self.assertEqual(seen["content_during"], AUTOROOT_GUARD_TOKEN)
            self.assertFalse(device.present)
            self.assertIn("AUTOROOT_GUARD_ENGAGED prior=absent", output)
            self.assertIn("AUTOROOT_GUARD_RESTORED prior=absent", output)

    def test_failure_exit_restores_absent_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice()

            def stages():
                raise ProvisionError("stage boom")

            with self.assertRaisesRegex(ProvisionError, "stage boom"):
                self.drive(provisioner, device, stages)
            self.assertFalse(device.present)

    def test_preset_user_flag_stays_set_and_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice(present=True, content="")
            seen = {}

            def stages():
                seen["present_during"] = device.present

            _, output = self.drive(provisioner, device, stages)
            self.assertTrue(seen["present_during"])
            self.assertTrue(device.present)
            self.assertEqual(device.content, "")
            self.assertIn("AUTOROOT_GUARD_ENGAGED prior=present", output)
            self.assertIn("AUTOROOT_GUARD_RESTORED prior=present", output)

    def test_leftover_guard_flag_is_treated_as_own(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice(
                present=True, content=AUTOROOT_GUARD_TOKEN
            )
            _, output = self.drive(provisioner, device, lambda: None)
            self.assertFalse(device.present)
            self.assertIn(
                "AUTOROOT_GUARD_ENGAGED prior=absent leftover=1", output
            )
            self.assertIn("AUTOROOT_GUARD_RESTORED prior=absent", output)

    def test_engage_failure_refuses_before_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice(fail_set=True)
            stages = mock.Mock(name="stages")
            with self.assertRaisesRegex(
                ProvisionError, "could not set the autoroot disable flag"
            ):
                self.drive(provisioner, device, stages)
            stages.assert_not_called()
            self.assertEqual(
                provision_portal_module._autoroot_guard_depth, 0
            )

    def test_nested_provision_does_not_release_early(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = self.make_provisioner(temporary)
            inner = self.make_provisioner(temporary)
            device = FakeFlagDevice()
            seen = {}

            def inner_stages():
                seen["present_in_inner"] = device.present

            def outer_stages():
                with (
                    mock.patch.object(inner, "connect"),
                    mock.patch.object(
                        inner, "adb_run", side_effect=device.adb_run
                    ),
                    mock.patch.object(
                        inner,
                        "_provision_stages",
                        side_effect=inner_stages,
                    ),
                ):
                    inner.provision()
                seen["present_after_inner"] = device.present

            self.drive(outer, device, outer_stages)
            self.assertTrue(seen["present_in_inner"])
            self.assertTrue(seen["present_after_inner"])
            self.assertFalse(device.present)
            self.assertEqual(
                provision_portal_module._autoroot_guard_depth, 0
            )

    def test_restore_failure_on_success_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice(fail_rm=True)
            stdout = io.StringIO()
            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=device.adb_run
                ),
                mock.patch.object(provisioner, "_provision_stages"),
                contextlib.redirect_stdout(stdout),
                self.assertRaisesRegex(
                    ProvisionError, "AUTOROOT_GUARD_RESTORE_FAILED"
                ),
            ):
                provisioner.provision()
            self.assertTrue(device.present)

    def test_restore_failure_on_failure_does_not_mask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice(fail_rm=True)
            stdout = io.StringIO()

            def stages():
                raise ProvisionError("stage boom")

            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=device.adb_run
                ),
                mock.patch.object(
                    provisioner, "_provision_stages", side_effect=stages
                ),
                contextlib.redirect_stdout(stdout),
                self.assertRaisesRegex(ProvisionError, "stage boom"),
            ):
                provisioner.provision()
            self.assertIn(
                "AUTOROOT_GUARD_RESTORE_FAILED", stdout.getvalue()
            )

    def test_dark_device_restore_warns_without_masking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice()
            stdout = io.StringIO()

            def stages():
                device.dark = True
                raise ProvisionError("device wedged")

            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=device.adb_run
                ),
                mock.patch.object(
                    provisioner, "_provision_stages", side_effect=stages
                ),
                contextlib.redirect_stdout(stdout),
                self.assertRaisesRegex(ProvisionError, "device wedged"),
            ):
                provisioner.provision()
            self.assertIn(
                "AUTOROOT_GUARD_RESTORE_FAILED", stdout.getvalue()
            )

    def test_disrupted_restore_never_claims_restored(self) -> None:
        """The Run 34 shape: the release's rm is lost in an adbd
        disruption and its probes come back with no token at all.
        The old exit-code check printed AUTOROOT_GUARD_RESTORED
        over a flag that was still on disk; the restore must now
        report failure, and the run's own error stays unmasked."""
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice()
            stdout = io.StringIO()

            def stages():
                device.disrupt_probes = 99
                raise ProvisionError("device wedged")

            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=device.adb_run
                ),
                mock.patch.object(
                    provisioner, "_provision_stages", side_effect=stages
                ),
                contextlib.redirect_stdout(stdout),
                self.assertRaisesRegex(ProvisionError, "device wedged"),
            ):
                provisioner.provision()
            output = stdout.getvalue()
            self.assertIn("AUTOROOT_GUARD_RESTORE_FAILED", output)
            self.assertNotIn("AUTOROOT_GUARD_RESTORED", output)
            self.assertTrue(device.present)

    def test_disrupted_restore_recovers_within_the_window(self) -> None:
        """The same disruption, clearing after two probes: the
        bounded retry re-applies the rm once the transport answers
        again, and RESTORED is printed only over a verified absent
        flag."""
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary)
            device = FakeFlagDevice()

            def stages():
                device.disrupt_probes = 2

            _, output = self.drive(provisioner, device, stages)
            self.assertIn("AUTOROOT_GUARD_RESTORED prior=absent", output)
            self.assertFalse(device.present)

    def test_status_only_never_touches_the_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(
                temporary, status_only=True
            )
            device = FakeFlagDevice()
            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=device.adb_run
                ),
                mock.patch.object(provisioner, "verify_target"),
                mock.patch.object(provisioner, "print_status"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                provisioner.provision()
            self.assertEqual(device.flag_commands, [])
            self.assertFalse(device.present)


if __name__ == "__main__":
    unittest.main()
