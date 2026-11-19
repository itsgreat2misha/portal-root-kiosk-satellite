# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Flush-and-age guard for on-device attempts (F1, 2026-11-19).

Every boot auto-connects WiFi within seconds; the connection makes
system_server update the saved-network record and schedule an
asynchronous WifiConfigStore write. On-device attempt boots die
young and uncleanly (race panics, watchdog cuts, the clean-attempt
reboot) inside that write's flush window, the same loss the host
loops caused. The helper therefore waits for the boot to reach
BootFlushGuard.MIN_BOOT_AGE_MS and syncs before an attempt starts,
and syncs again before the clean-attempt reboot.

The policy itself is pure Java (BootFlushGuard). When a JDK is
available these tests compile and execute the real decision table;
the source-shape tests always run and pin the wiring: the guard runs
before the attempt is counted and before the failure budget's
in-progress mark is written (so the 300 s verdict watchdog and the
budget accounting are undisturbed), and the clean-attempt reboot
syncs first.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER_SRC = ROOT / "autoroot-helper" / "src" / "dev" / "portal" / "autoroothelper"
GUARD_JAVA = HELPER_SRC / "BootFlushGuard.java"
SERVICE_JAVA = HELPER_SRC / "AutorootService.java"
WATCHDOG_JAVA = HELPER_SRC / "AttemptWatchdog.java"


HARNESS = """
package dev.portal.autoroothelper;

public final class BootFlushGuardHarness {
    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    public static void main(String[] args) {
        check(BootFlushGuard.MIN_BOOT_AGE_MS == 120_000L,
                "minimum boot age is not 120 s");
        // Unknown age fails toward waiting the full window.
        check(BootFlushGuard.remainingWaitMs(-1L) == 120_000L,
                "unknown age does not wait the full window");
        check(!BootFlushGuard.attemptMayStart(-1L),
                "attempt may start at unknown age");
        // The wait is the shortfall to the minimum age, floored at 0.
        check(BootFlushGuard.remainingWaitMs(0L) == 120_000L,
                "wait at boot instant");
        check(BootFlushGuard.remainingWaitMs(60_000L) == 60_000L,
                "wait at half the minimum age");
        check(BootFlushGuard.remainingWaitMs(119_999L) == 1L,
                "wait just before the minimum age");
        check(BootFlushGuard.remainingWaitMs(120_000L) == 0L,
                "wait at the minimum age");
        check(BootFlushGuard.remainingWaitMs(3_600_000L) == 0L,
                "wait on an old boot");
        check(!BootFlushGuard.attemptMayStart(0L),
                "attempt may start at the boot instant");
        check(!BootFlushGuard.attemptMayStart(119_999L),
                "attempt may start just before the minimum age");
        check(BootFlushGuard.attemptMayStart(120_000L),
                "attempt may not start at the minimum age");
        check(BootFlushGuard.attemptMayStart(600_000L),
                "attempt may not start on an old boot");
        System.out.println("BOOT_FLUSH_GUARD_HARNESS_OK");
    }
}
"""


@unittest.skipUnless(
    shutil.which("javac") and shutil.which("java"),
    "no JDK available to execute the Java decision table",
)
class BootFlushGuardDecisionTableTest(unittest.TestCase):
    def test_decision_table_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_dir = (
                pathlib.Path(temporary) / "dev" / "portal" / "autoroothelper"
            )
            package_dir.mkdir(parents=True)
            (package_dir / "BootFlushGuard.java").write_text(
                GUARD_JAVA.read_text(encoding="utf-8"), encoding="utf-8"
            )
            (package_dir / "BootFlushGuardHarness.java").write_text(
                HARNESS, encoding="utf-8"
            )
            compile_result = subprocess.run(
                [
                    "javac",
                    "-d",
                    temporary,
                    str(package_dir / "BootFlushGuard.java"),
                    str(package_dir / "BootFlushGuardHarness.java"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [
                    "java",
                    "-cp",
                    temporary,
                    "dev.portal.autoroothelper.BootFlushGuardHarness",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertIn("BOOT_FLUSH_GUARD_HARNESS_OK", run_result.stdout)


class BootFlushGuardWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = GUARD_JAVA.read_text(encoding="utf-8")
        self.service = SERVICE_JAVA.read_text(encoding="utf-8")
        self.watchdog = WATCHDOG_JAVA.read_text(encoding="utf-8")

    def test_policy_shape(self) -> None:
        self.assertIn("MIN_BOOT_AGE_MS = 120_000L", self.guard)
        self.assertIn("bootAgeMs < 0L", self.guard)
        self.assertIn("Math.max(0L, MIN_BOOT_AGE_MS - bootAgeMs)", self.guard)
        self.assertIn("bootAgeMs >= MIN_BOOT_AGE_MS", self.guard)

    def test_service_waits_on_boot_age_and_syncs(self) -> None:
        self.assertIn("BootFlushGuard.remainingWaitMs", self.service)
        self.assertIn("SystemClock.elapsedRealtime()", self.service)
        method = self.service[
            self.service.index("private boolean waitForBootFlushWindow") :
            self.service.index("private void rebootForCleanAttempt")
        ]
        self.assertIn('shell("sync")', method)
        self.assertIn("stopRequested", method)

    def test_guard_runs_before_attempt_count_and_budget_mark(self) -> None:
        # The guard's call site sits ahead of both the attempt count
        # and the failure budget's in-progress mark, so a stop during
        # the wait disturbs neither the budget accounting nor the
        # watchdog structure built around the attempt.
        call = self.service.index("if (!waitForBootFlushWindow())")
        self.assertLess(call, self.service.index("attempts++;"))
        self.assertLess(
            call, self.service.index("budget.attemptStarted")
        )

    def test_clean_attempt_reboot_syncs_first(self) -> None:
        method = self.service[
            self.service.index("private void rebootForCleanAttempt") :
            self.service.index("// ---- discovery")
        ]
        self.assertLess(
            method.index('shell("sync")'), method.index('shell("reboot")')
        )

    def test_watchdog_and_runner_timeout_undisturbed(self) -> None:
        self.assertIn("CUTOFF_MS = 300_000L", self.watchdog)
        self.assertIn("600000", self.service)
        self.assertIn("AttemptWatchdog.shouldCut", self.service)


if __name__ == "__main__":
    unittest.main()
