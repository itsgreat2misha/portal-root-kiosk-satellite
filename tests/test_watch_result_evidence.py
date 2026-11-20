# SPDX-License-Identifier: Apache-2.0
# Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
# See LICENSE and NOTICE.

from __future__ import annotations

import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from portal_targets import TARGETS  # noqa: E402
from provision_portal import PortalProvisioner, ProvisionError  # noqa: E402


WATCH_RESULT_REMOTE = "/data/local/tmp/ghostlock-watch-result.txt"
BOOT_ID_REMOTE = "/proc/sys/kernel/random/boot_id"
BOOT_ID = "12345678-1234-1234-1234-123456789012"


def _completed(returncode: int = 0, stdout: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, "")


class _EvidenceDevice:
    """adb_run stand-in answering the two evidence reads by path.

    Each read is either a CompletedProcess to return or an exception
    instance to raise; every call is recorded so tests can pin that
    the evidence read happens before the attempt's reboot.
    """

    def __init__(self, watch_result, boot_id) -> None:
        self.watch_result = watch_result
        self.boot_id = boot_id
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=None, check=False):
        args = [str(arg) for arg in args]
        self.calls.append(args)
        if args[:2] == ["shell", "cat"] and len(args) == 3:
            if args[2] == WATCH_RESULT_REMOTE:
                return self._answer(self.watch_result)
            if args[2] == BOOT_ID_REMOTE:
                return self._answer(self.boot_id)
        return _completed(0, "")

    @staticmethod
    def _answer(behavior):
        if isinstance(behavior, BaseException):
            raise behavior
        return behavior

    def index_of(self, needle: str) -> int:
        for index, call in enumerate(self.calls):
            if needle in " ".join(call):
                return index
        return -1


def _exploit_with_device(
    provisioner: PortalProvisioner,
    device: _EvidenceDevice,
    script: str,
    output: io.StringIO,
) -> bool:
    """Run exploit() against a child process running a Python script
    (sys.executable, not /bin/sh, so the suite runs on Windows too)."""
    real_popen = subprocess.Popen

    def fake_popen(*args: object, **kwargs: object):
        return real_popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )

    with (
        mock.patch.object(provisioner, "adb_run", device),
        mock.patch(
            "provision_portal.subprocess.Popen", side_effect=fake_popen
        ),
        mock.patch.object(sys, "stdout", output),
    ):
        return provisioner.exploit(0x1000, 0x2000, 1)


class WatchResultEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        # terry never takes the cipher watch-result recovery path, so
        # the only watch-result read in these runs is the evidence
        # capture itself.
        self.terry = next(
            target for target in TARGETS if target.device == "terry"
        )

    def _provisioner(self, temporary: str) -> PortalProvisioner:
        provisioner = PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary)
        )
        provisioner.target = self.terry
        return provisioner

    def test_failed_attempt_logs_present_file_and_parsed_step(self) -> None:
        device = _EvidenceDevice(
            watch_result=_completed(
                0, "WATCH_CFI_OK=0 STEP=30 ERRNO=13 ROOT=0 RSTEP=0 RERR=0"
            ),
            boot_id=_completed(0, BOOT_ID + "\n"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            output = io.StringIO()
            result = _exploit_with_device(
                provisioner,
                device,
                "import sys; print('attempt output', flush=True); "
                "sys.exit(3)",
                output,
            )

        self.assertFalse(result)
        self.assertIn(
            "WATCH_RESULT_EVIDENCE attempt=1 present=1 step=30 "
            f"boot_id={BOOT_ID}",
            output.getvalue(),
        )
        # The capture is read before the reboot that ends the attempt.
        self.assertGreaterEqual(device.index_of(WATCH_RESULT_REMOTE), 0)
        self.assertLess(
            device.index_of(WATCH_RESULT_REMOTE), device.index_of("reboot")
        )

    def test_failed_attempt_logs_absent_file(self) -> None:
        device = _EvidenceDevice(
            watch_result=_completed(1, ""),
            boot_id=_completed(0, BOOT_ID + "\n"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            output = io.StringIO()
            result = _exploit_with_device(
                provisioner,
                device,
                "import sys; print('attempt output', flush=True); "
                "sys.exit(3)",
                output,
            )

        self.assertFalse(result)
        self.assertIn(
            "WATCH_RESULT_EVIDENCE attempt=1 present=0 step=none "
            f"boot_id={BOOT_ID}",
            output.getvalue(),
        )

    def test_failed_attempt_survives_evidence_read_errors(self) -> None:
        device = _EvidenceDevice(
            watch_result=ProvisionError("transport down"),
            boot_id=ProvisionError("transport down"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            output = io.StringIO()
            result = _exploit_with_device(
                provisioner,
                device,
                "import sys; print('attempt output', flush=True); "
                "sys.exit(3)",
                output,
            )

        self.assertFalse(result)
        self.assertIn(
            "WATCH_RESULT_EVIDENCE attempt=1 present=0 step=none "
            "boot_id=unknown",
            output.getvalue(),
        )
        # The run is unaffected: the attempt still ends with its reboot.
        self.assertGreaterEqual(device.index_of("reboot"), 0)

    def test_successful_attempt_logs_no_evidence(self) -> None:
        device = _EvidenceDevice(
            watch_result=_completed(
                0, "WATCH_CFI_OK=1 STEP=0 ERRNO=0 ROOT=1 RSTEP=0 RERR=0"
            ),
            boot_id=_completed(0, BOOT_ID + "\n"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            output = io.StringIO()
            result = _exploit_with_device(
                provisioner,
                device,
                "print('provision actions complete ok=1', flush=True)",
                output,
            )

        self.assertTrue(result)
        self.assertNotIn("WATCH_RESULT_EVIDENCE", output.getvalue())


if __name__ == "__main__":
    unittest.main()
