# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

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

import device_session as device_session_module  # noqa: E402

from device_session import DeviceSession, ProvisionError  # noqa: E402
from provision_portal import PortalProvisioner  # noqa: E402


OLD_BOOT = "11111111-1111-1111-1111-111111111111"
NEW_BOOT = "22222222-2222-2222-2222-222222222222"
NOTICE = "WAITING_FOR_ADB test notice: enable ADB in the Debug menu"


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _ok_run(arguments, timeout=None, check=False):
    del timeout, check
    return subprocess.CompletedProcess(arguments, 0, "")


def _scripted_session(failures_before_answer: int, notice=NOTICE):
    """A DeviceSession whose probe fails N times, then reports NEW_BOOT."""
    session = DeviceSession(
        "192.0.2.1:5555",
        wait_notice=(lambda: notice) if notice is not None else None,
    )
    calls = {"count": 0}

    def adb_run(arguments, timeout=None, check=False):
        del timeout, check
        calls["count"] += 1
        if calls["count"] <= failures_before_answer:
            return subprocess.CompletedProcess(arguments, 1, "")
        return subprocess.CompletedProcess(arguments, 0, f"1\n{NEW_BOOT}\n")

    return session, adb_run


class ConnectAfterRebootWaitNoticeTest(unittest.TestCase):
    def _run_wait(self, session, adb_run, wait_seconds=600):
        output = io.StringIO()
        with (
            mock.patch.object(session, "run", side_effect=_ok_run),
            mock.patch.object(session, "adb_run", side_effect=adb_run),
            mock.patch.object(device_session_module, "time", _FakeClock()),
            contextlib.redirect_stdout(output),
        ):
            try:
                result = session.connect_after_reboot(
                    OLD_BOOT, wait_seconds=wait_seconds
                )
                error = None
            except ProvisionError as exc:
                result, error = None, exc
        return result, error, output.getvalue()

    def test_notice_printed_while_unanswered_then_device_returns(self) -> None:
        session, adb_run = _scripted_session(failures_before_answer=8)
        result, error, output = self._run_wait(session, adb_run)
        self.assertIsNone(error)
        self.assertEqual(result, NEW_BOOT)
        self.assertIn(NOTICE, output)

    def test_timeout_error_names_debug_menu_action(self) -> None:
        session, adb_run = _scripted_session(failures_before_answer=10**9)
        result, error, output = self._run_wait(session, adb_run, wait_seconds=30)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        self.assertIn("Debug menu", str(error))
        self.assertIn(NOTICE, output)

    def test_no_notice_when_callback_stays_silent(self) -> None:
        session, adb_run = _scripted_session(
            failures_before_answer=8, notice=None
        )
        result, error, output = self._run_wait(session, adb_run)
        self.assertIsNone(error)
        self.assertEqual(result, NEW_BOOT)
        self.assertNotIn("WAITING_FOR_ADB", output)

    def test_no_notice_when_device_returns_promptly(self) -> None:
        session, adb_run = _scripted_session(failures_before_answer=1)
        result, error, output = self._run_wait(session, adb_run)
        self.assertIsNone(error)
        self.assertEqual(result, NEW_BOOT)
        self.assertNotIn(NOTICE, output)


class ProvisionerWaitNoticeGatingTest(unittest.TestCase):
    def test_notice_only_until_wireless_adb_persistent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            self.assertIsNone(provisioner._adb_wait_notice())
            provisioner.persist_wireless_adb = True
            notice = provisioner._adb_wait_notice()
            self.assertIsNotNone(notice)
            self.assertIn("WAITING_FOR_ADB", notice)
            self.assertIn("Debug menu", notice)
            provisioner._wireless_adb_verified = True
            self.assertIsNone(provisioner._adb_wait_notice())


if __name__ == "__main__":
    unittest.main()
