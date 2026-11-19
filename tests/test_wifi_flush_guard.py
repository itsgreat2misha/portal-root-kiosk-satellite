# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Flush-and-age guard for host race attempts (F1, 2026-11-19).

Every boot auto-connects WiFi within seconds; the connection makes
system_server update the saved-network record and schedule an
asynchronous WifiConfigStore write. Host race boots die young and
uncleanly (attempt panics, watchdog cuts, the runner's unconditional
post-attempt reboot) inside that write's flush window, and repeated
episodes lost the library unit's saved network outright. The guard
therefore runs before every host race attempt: the boot must be at
least RACE_BOOT_MIN_AGE_SECONDS old, and the runner syncs before the
attempt starts. The runner also syncs before every reboot it issues
(DeviceSession.reboot and the exploit runner's post-attempt reboot).

When the uptime read does not answer, the guard fails toward
waiting: it counts its own observation time on the same boot id as a
lower bound on the boot's age and waits the full window out. These
tests pin that behavior with a fake clock and a scripted device, and
pin the wiring (both attempt loops guard before exploit; sync
precedes each issued reboot) by source shape.
"""

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

from device_session import DeviceSession, ProvisionError  # noqa: E402
from provision_portal import (  # noqa: E402
    PortalProvisioner,
    RACE_BOOT_MIN_AGE_SECONDS,
)


UPTIME_REMOTE = "/proc/uptime"
BOOT_ID_REMOTE = "/proc/sys/kernel/random/boot_id"
OLD_BOOT = "11111111-1111-1111-1111-111111111111"
NEW_BOOT = "22222222-2222-2222-2222-222222222222"


def _completed(returncode: int = 0, stdout: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, "")


class _FakeClock:
    """monotonic()/sleep() stand-in: sleep advances the clock."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class _GuardDevice:
    """adb_run stand-in answering the guard's reads.

    uptime is a callable returning the boot age in seconds, or None
    to simulate an unanswered read; boot_id is a callable returning
    the current boot id. Every call is recorded in order.
    """

    def __init__(self, uptime, boot_id=lambda: OLD_BOOT) -> None:
        self._uptime = uptime
        self._boot_id = boot_id
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=None, check=False):
        del timeout, check
        args = [str(arg) for arg in args]
        self.calls.append(args)
        if args == ["shell", "cat", UPTIME_REMOTE]:
            age = self._uptime()
            if age is None:
                return _completed(1, "")
            return _completed(0, f"{age:.2f} 1000.00\n")
        if args == ["shell", "cat", BOOT_ID_REMOTE]:
            return _completed(0, self._boot_id() + "\n")
        return _completed(0, "")

    def count(self, needle: list[str]) -> int:
        return sum(1 for call in self.calls if call == needle)


def _run_guard(device: _GuardDevice, clock: _FakeClock) -> str:
    with tempfile.TemporaryDirectory() as temporary:
        provisioner = PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary)
        )
        output = io.StringIO()
        with (
            mock.patch.object(provisioner, "adb_run", device),
            mock.patch.object(provision_portal_module, "time", clock),
            contextlib.redirect_stdout(output),
        ):
            provisioner.wait_for_race_boot_window(3)
        return output.getvalue()


class RaceBootWindowGuardTest(unittest.TestCase):
    def test_min_age_is_120_seconds(self) -> None:
        self.assertEqual(RACE_BOOT_MIN_AGE_SECONDS, 120)

    def test_old_boot_proceeds_without_waiting_and_syncs(self) -> None:
        clock = _FakeClock()
        device = _GuardDevice(uptime=lambda: 200.0)
        output = _run_guard(device, clock)
        self.assertEqual(clock.sleeps, [])
        self.assertEqual(device.count(["shell", "sync"]), 1)
        self.assertEqual(device.calls[-1], ["shell", "sync"])
        self.assertIn(
            "WIFI_FLUSH_GUARD attempt=3 boot_age_seconds=200 synced=1",
            output,
        )
        self.assertNotIn("WIFI_FLUSH_GUARD_WAIT", output)

    def test_boot_exactly_at_minimum_age_proceeds(self) -> None:
        clock = _FakeClock()
        device = _GuardDevice(uptime=lambda: 120.0)
        output = _run_guard(device, clock)
        self.assertEqual(clock.sleeps, [])
        self.assertEqual(device.count(["shell", "sync"]), 1)
        self.assertIn("boot_age_seconds=120 synced=1", output)

    def test_young_boot_waits_the_shortfall_then_syncs(self) -> None:
        clock = _FakeClock()
        device = _GuardDevice(uptime=lambda: 30.0 + clock.now)
        output = _run_guard(device, clock)
        self.assertEqual(sum(clock.sleeps), 90.0)
        self.assertIn(
            "WIFI_FLUSH_GUARD_WAIT attempt=3 boot_age_seconds=30 "
            "required=120",
            output,
        )
        self.assertIn(
            "WIFI_FLUSH_GUARD attempt=3 boot_age_seconds=120 synced=1",
            output,
        )
        # The sync is issued only after the boot has aged out.
        self.assertEqual(device.calls[-1], ["shell", "sync"])
        self.assertEqual(device.count(["shell", "sync"]), 1)

    def test_unanswered_uptime_waits_the_full_window(self) -> None:
        # Fail toward waiting: with no age source, the guard counts
        # its own observation time on the same boot and waits the
        # whole window rather than skipping the guard.
        clock = _FakeClock()
        device = _GuardDevice(uptime=lambda: None)
        output = _run_guard(device, clock)
        self.assertEqual(sum(clock.sleeps), 120.0)
        self.assertIn("boot_age_seconds=unknown", output)
        self.assertEqual(device.count(["shell", "sync"]), 1)
        self.assertIn(
            "WIFI_FLUSH_GUARD attempt=3 boot_age_seconds=unknown "
            "synced=1",
            output,
        )

    def test_unanswered_uptime_boot_change_restarts_the_wait(self) -> None:
        # A different boot id mid-wait means a new, young boot: the
        # observation lower bound restarts with it.
        clock = _FakeClock()
        device = _GuardDevice(
            uptime=lambda: None,
            boot_id=lambda: OLD_BOOT if clock.now < 60 else NEW_BOOT,
        )
        _run_guard(device, clock)
        self.assertEqual(sum(clock.sleeps), 180.0)
        self.assertEqual(device.count(["shell", "sync"]), 1)


class SessionRebootSyncTest(unittest.TestCase):
    def _session(self, sync_error: bool = False):
        session = DeviceSession("192.0.2.1:5555")
        calls: list[list[str]] = []

        def adb_run(args, timeout=None, check=False):
            del timeout, check
            args = [str(arg) for arg in args]
            calls.append(args)
            if args == ["shell", "cat", BOOT_ID_REMOTE]:
                return _completed(0, OLD_BOOT + "\n")
            if args == ["shell", "sync"] and sync_error:
                raise ProvisionError("device did not answer sync")
            return _completed(0, "")

        return session, adb_run, calls

    def test_sync_precedes_the_issued_reboot(self) -> None:
        session, adb_run, calls = self._session()
        with (
            mock.patch.object(session, "adb_run", side_effect=adb_run),
            mock.patch.object(
                session, "connect_after_reboot", return_value=NEW_BOOT
            ),
        ):
            before, after = session.reboot()
        self.assertEqual((before, after), (OLD_BOOT, NEW_BOOT))
        self.assertLess(
            calls.index(["shell", "sync"]), calls.index(["reboot"])
        )

    def test_reboot_proceeds_when_sync_is_unanswered(self) -> None:
        session, adb_run, calls = self._session(sync_error=True)
        with (
            mock.patch.object(session, "adb_run", side_effect=adb_run),
            mock.patch.object(
                session, "connect_after_reboot", return_value=NEW_BOOT
            ),
        ):
            before, after = session.reboot()
        self.assertEqual((before, after), (OLD_BOOT, NEW_BOOT))
        self.assertIn(["reboot"], calls)


class GuardWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (ROOT / "tools" / "provision_portal.py").read_text(
            encoding="utf-8"
        )

    @staticmethod
    def _between(source: str, start: str, end: str) -> str:
        return source[source.index(start) : source.index(end)]

    def test_install_loop_guards_before_exploit(self) -> None:
        body = self._between(
            self.source, "def run_standard_install", "def provision"
        )
        self.assertLess(
            body.index("wait_for_race_boot_window(attempt)"),
            body.index("exploit_ok = self.exploit("),
        )

    def test_payload_loop_guards_before_exploit(self) -> None:
        body = self._between(
            self.source,
            "def apply_custom_payload",
            "def verify_custom_payload",
        )
        self.assertLess(
            body.index("wait_for_race_boot_window(attempt)"),
            body.index("self.exploit("),
        )

    def test_exploit_syncs_before_its_post_attempt_reboot(self) -> None:
        body = self._between(
            self.source, "def exploit(", "def apply_custom_payload"
        )
        tail = body[body.index("INSTALL_ATTEMPT_RESULT") :]
        self.assertLess(
            tail.index('"shell", "sync"'), tail.index('["reboot"]')
        )


if __name__ == "__main__":
    unittest.main()
