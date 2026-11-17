# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Autoroot cross-boot failure budget (2026-11-17).

The per-attempt watchdogs and the per-session cap bound a single
boot; a deterministic mid-attempt crash or freeze otherwise loops
forever across boots. The budget counts only truly incomplete
attempts - the service writes an in-progress mark when an attempt
starts and a verdict when one completes (win or clean loss), so a
later boot that finds the mark still set knows the attempt never
completed. At 5 consecutive incomplete boots the service stands
down, posts a persistent notification, and waits for the user to
re-enable it on the device (or for a host re-stage).

One accounting refinement is pinned here too: a clean loss whose
reboot outran the service's verdict write is recovered from the
race's own verdict in attempt.log (the mark records the attempt's
log offset, and a fail verdict found there counts the attempt as
completed), so only attempts that left no verdict anywhere count.

The accounting itself is pure Java (FailureBudget). When a JDK is
available these tests compile and execute the real decision
table; the source-shape tests always run and pin the wiring: the
mark/verdict points in the service, the stand-down gate ahead of
any racing, the notification, the on-device re-enable, and the
host-side report.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER_SRC = ROOT / "autoroot-helper" / "src" / "dev" / "portal" / "autoroothelper"
BUDGET_JAVA = HELPER_SRC / "FailureBudget.java"
SERVICE_JAVA = HELPER_SRC / "AutorootService.java"
ACTIVITY_JAVA = HELPER_SRC / "AutorootActivity.java"


HARNESS = """
package dev.portal.autoroothelper;

public final class BudgetHarness {
    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    // One verdict-less boot against a budget whose previous
    // attempt died mid-flight: mark, then the next boot accounts.
    private static void incompleteBoot(FailureBudget budget) {
        budget.attemptStarted(-1);
        budget.accountBoot();
    }

    public static void main(String[] args) {
        check(FailureBudget.THRESHOLD == 5, "threshold is not 5");

        // A fresh budget (what a host re-stage leaves behind: the
        // state file is deleted) starts clean.
        FailureBudget fresh = new FailureBudget(0, false, false, -1);
        check(fresh.incompleteStreak() == 0, "fresh streak not 0");
        check(!fresh.attemptOpen(), "fresh budget has an open mark");
        check(!fresh.stoodDown(), "fresh budget stood down");
        check(!fresh.accountBoot(), "quiet boot changed fresh state");

        // Clean losses never increment: five boots, each starting
        // and completing an attempt (a win or a clean loss - the
        // accounting cannot and must not distinguish them).
        FailureBudget clean = new FailureBudget(0, false, false, -1);
        for (int i = 0; i < 5; i++) {
            check(!clean.accountBoot(), "clean boot counted");
            clean.attemptStarted(-1);
            clean.attemptCompleted();
            check(clean.incompleteStreak() == 0,
                    "clean loss incremented the streak");
            check(!clean.stoodDown(), "clean losses stood down");
        }

        // A verdict-less boot increments by exactly one and
        // consumes the mark.
        FailureBudget died = new FailureBudget(0, false, false, -1);
        died.attemptStarted(-1);
        check(died.accountBoot(), "verdict-less boot not counted");
        check(died.incompleteStreak() == 1, "streak not 1");
        check(!died.attemptOpen(), "mark not consumed at boot");
        check(!died.stoodDown(), "stood down at 1");
        check(!died.accountBoot(), "consumed mark counted twice");
        check(died.incompleteStreak() == 1, "streak moved on recount");

        // A completed attempt resets the streak.
        incompleteBoot(died);
        check(died.incompleteStreak() == 2, "streak not 2");
        died.attemptStarted(-1);
        died.attemptCompleted();
        check(died.incompleteStreak() == 0,
                "completed attempt did not reset the streak");
        incompleteBoot(died);
        check(died.incompleteStreak() == 1,
                "streak not 1 after reset plus one incomplete");

        // A loss verdict recovered from attempt.log counts the
        // attempt as completed: the mark clears, the streak
        // resets, and the recorded offset is consumed with the
        // mark, so the same verdict can never be applied twice.
        FailureBudget recovered = new FailureBudget(0, false, false, -1);
        incompleteBoot(recovered);
        incompleteBoot(recovered);
        check(recovered.incompleteStreak() == 2, "streak not 2");
        recovered.attemptStarted(4096);
        check(recovered.openLogOffset() == 4096,
                "log offset not recorded with the mark");
        check(recovered.accountBoot(true),
                "recovered loss verdict changed nothing");
        check(recovered.incompleteStreak() == 0,
                "recovered loss verdict did not reset the streak");
        check(!recovered.attemptOpen(),
                "recovered verdict left the mark open");
        check(recovered.openLogOffset() == -1,
                "recovered verdict did not consume the offset");
        check(!recovered.accountBoot(true),
                "stale verdict applied with no open attempt");
        check(recovered.incompleteStreak() == 0,
                "stale verdict moved the streak");

        // An open mark whose log holds no verdict still counts,
        // offset or not: the recovery is scoped, not a blanket
        // pardon for every open mark.
        recovered.attemptStarted(8192);
        check(recovered.accountBoot(false),
                "verdict-less mark with an offset not counted");
        check(recovered.incompleteStreak() == 1, "streak not 1");
        check(recovered.openLogOffset() == -1,
                "counted mark did not consume the offset");

        // Completing an attempt and re-enabling both clear the
        // recorded offset along with the mark.
        recovered.attemptStarted(123);
        recovered.attemptCompleted();
        check(recovered.openLogOffset() == -1,
                "completion kept the log offset");
        recovered.attemptStarted(456);
        recovered.reenable();
        check(recovered.openLogOffset() == -1,
                "re-enable kept the log offset");

        // Five consecutive incomplete boots stand down; four do
        // not.
        FailureBudget loop = new FailureBudget(0, false, false, -1);
        incompleteBoot(loop);
        check(!loop.stoodDown(), "stood down at 1");
        incompleteBoot(loop);
        incompleteBoot(loop);
        incompleteBoot(loop);
        check(loop.incompleteStreak() == 4, "streak not 4");
        check(!loop.stoodDown(), "stood down at 4");
        incompleteBoot(loop);
        check(loop.incompleteStreak() == 5, "streak not 5");
        check(loop.stoodDown(), "not stood down at 5");
        // The stand-down persists across quiet boots.
        check(!loop.accountBoot(), "quiet stood-down boot changed state");
        check(loop.stoodDown(), "stand-down did not persist");

        // Re-enable clears the counter and the stand-down, and the
        // budget re-arms: 5 more incomplete boots stand down again.
        loop.reenable();
        check(loop.incompleteStreak() == 0, "re-enable kept the streak");
        check(!loop.attemptOpen(), "re-enable kept an open mark");
        check(!loop.stoodDown(), "re-enable kept the stand-down");
        incompleteBoot(loop);
        incompleteBoot(loop);
        incompleteBoot(loop);
        incompleteBoot(loop);
        check(!loop.stoodDown(), "re-armed budget stood down at 4");
        incompleteBoot(loop);
        check(loop.stoodDown(), "re-armed budget did not stand down");

        System.out.println("BUDGET_HARNESS_OK");
    }
}
"""


@unittest.skipUnless(
    shutil.which("javac") and shutil.which("java"),
    "no JDK available to execute the Java decision table",
)
class FailureBudgetDecisionTableTest(unittest.TestCase):
    def test_decision_table_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_dir = (
                pathlib.Path(temporary) / "dev" / "portal" / "autoroothelper"
            )
            package_dir.mkdir(parents=True)
            (package_dir / "FailureBudget.java").write_text(
                BUDGET_JAVA.read_text(encoding="utf-8"), encoding="utf-8"
            )
            (package_dir / "BudgetHarness.java").write_text(
                HARNESS, encoding="utf-8"
            )
            compile_result = subprocess.run(
                [
                    "javac",
                    "-d",
                    temporary,
                    str(package_dir / "FailureBudget.java"),
                    str(package_dir / "BudgetHarness.java"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["java", "-cp", temporary, "dev.portal.autoroothelper.BudgetHarness"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertIn("BUDGET_HARNESS_OK", run_result.stdout)


class FailureBudgetWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.budget = BUDGET_JAVA.read_text(encoding="utf-8")
        self.service = SERVICE_JAVA.read_text(encoding="utf-8")
        self.activity = ACTIVITY_JAVA.read_text(encoding="utf-8")

    def test_threshold_and_state_keys(self) -> None:
        self.assertIn("THRESHOLD = 5", self.budget)
        # The budget state lives in the autoroot state file, under
        # its own keys - alongside, not as, the disable flag.
        self.assertIn('KEY_STREAK = "budget_streak"', self.budget)
        self.assertIn('KEY_OPEN = "budget_open"', self.budget)
        self.assertIn('KEY_STOOD_DOWN = "budget_stood_down"', self.budget)
        self.assertIn('KEY_LOG_OFFSET = "budget_log_offset"', self.budget)
        self.assertNotIn("portal-autoroot.disable", self.budget)

    def test_threshold_prose_says_five_everywhere(self) -> None:
        # Every user-facing or documented surface of the threshold
        # moved from 3 to 5 with the constant; nothing still says 3.
        self.assertIn("last 5 boots", self.activity)
        self.assertIn("5 more bad boots", self.activity)
        self.assertNotIn("last 3 boots", self.activity)
        self.assertNotIn("3 more bad boots", self.activity)
        self.assertIn("after 5 in a row", self.service)
        self.assertNotIn("after 3 in a row", self.service)
        self.assertNotIn("after 3 more incomplete", self.service)
        provisioner = (ROOT / "tools" / "provision_portal.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("After 5 consecutive verdict-less", provisioner)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("After 5 such boots", readme)
        self.assertIn("after 5 more bad boots", readme)
        self.assertNotIn("After 3 such boots", readme)

    def test_accounting_and_gate_run_before_any_racing(self) -> None:
        account = self.service.index("budget.accountBoot(lossVerdictRecovered)")
        gate = self.service.index("if (budget.stoodDown())")
        mark = self.service.index("budget.attemptStarted(attemptLogSizeForBudget())")
        race = self.service.index("runAttemptWithWatchdog(kaslr")
        self.assertLess(account, gate)
        self.assertLess(gate, mark)
        self.assertLess(mark, race)
        # The stood-down return publishes the phase the activity
        # renders and refreshes the notification.
        self.assertIn('publishStatus("STOOD_DOWN"', self.service)

    def test_loss_verdict_recovery_is_wired(self) -> None:
        # The accounting consults attempt.log for the open
        # attempt's own race verdict, scoped to the offset recorded
        # with the mark, and only a fail verdict recovers.
        self.assertIn("attemptVerdict(budget.openLogOffset())", self.service)
        self.assertIn("AttemptWatchdog.VERDICT_FAIL", self.service)
        self.assertIn("loss verdict recovered", self.service)
        # The offset is persisted with the budget state and loaded
        # back, so the recovery survives the reboot between the
        # attempt and its accounting.
        self.assertIn("FailureBudget.KEY_LOG_OFFSET", self.service)
        # An unmeasurable offset disables recovery for the attempt
        # rather than consulting the log from a guessed position.
        self.assertIn("attemptLogSizeForBudget()", self.service)

    def test_verdict_recorded_on_controlled_exits(self) -> None:
        # Every controlled exit after the mark records the verdict
        # through the one helper: discovery stop/failure, post-
        # attempt stop, daemon wait stop, win, clean loss, the two
        # root-already-active paths, plus the helper's own overload.
        self.assertGreaterEqual(self.service.count("completeBudgetAttempt("), 8)
        self.assertIn("budget.attemptCompleted()", self.service)
        # A service-level exception also closes an open attempt (the
        # device did not crash; the process caught the failure).
        self.assertIn("completeOpenAttemptAfterError()", self.service)

    def test_notification_is_persistent_and_opens_the_helper(self) -> None:
        self.assertIn("NotificationManager", self.service)
        self.assertIn("createNotificationChannel", self.service)
        self.assertIn(".setOngoing(true)", self.service)
        self.assertIn("PendingIntent.getActivity", self.service)
        self.assertIn("AutorootActivity.class", self.service)
        self.assertIn("crashed or froze", self.service)
        # Kept while stood down: refreshed from persisted state at
        # every service start, cancelled only when not stood down.
        self.assertIn("refreshStandDownNotification()", self.service)
        self.assertIn("manager.cancel(NOTIFY_ID_STOOD_DOWN)", self.service)

    def test_user_reenable_clears_and_restarts(self) -> None:
        self.assertIn("ACTION_REENABLE", self.service)
        self.assertIn('"dev.portal.autoroothelper.REENABLE"', self.service)
        self.assertIn("handleReenable", self.service)
        self.assertIn("budget.reenable()", self.service)
        # The helper screen offers the re-enable only while stood
        # down and states the risk next to it.
        self.assertIn("AutorootService.ACTION_REENABLE", self.activity)
        self.assertIn("Re-enable autoroot", self.activity)
        self.assertIn("at your own", self.activity)
        self.assertIn("PREF_STOOD_DOWN", self.activity)

    def test_host_reports_stand_down_and_restage_clears_it(self) -> None:
        provisioner = (ROOT / "tools" / "provision_portal.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("_report_autoroot_stood_down", provisioner)
        self.assertIn('values.get("budget_stood_down") == "1"', provisioner)
        self.assertIn("AUTOROOT_STOOD_DOWN streak=", provisioner)
        # A host re-stage deletes the state file the budget lives
        # in, which is what clears the stand-down from the host.
        payload = (ROOT / "tools" / "features" / "payload.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('f"{AUTOROOT_REMOTE_DIR}/state"', payload)


if __name__ == "__main__":
    unittest.main()
