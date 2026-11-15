# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Recovery fail-fast watchdog (2026-11-14; post-verdict 2026-11-15).

Timeout-class recovery attempts (no race verdict, hanging to the
600 s runner timeout) were ~47% of recovery wall-clock in Runs
21-27. The watchdog in AutorootService cuts an attempt at 300 s
when no WATCH_CFI_OK verdict has appeared in attempt.log; a WIN
verdict is never cut, however long its collection runs (wins
conclude at the timeout edge by design).

Post-verdict extension (Run 30 evidence): an attempt can write a
FAIL verdict (~55 s in) and then hang to the full 600 s anyway.
A fail-verdict attempt may be cut once the grace period since
the verdict has elapsed AND the root daemon is known-absent; a
fail verdict with the daemon present is never cut.

The policy itself is pure Java (AttemptWatchdog). When a JDK is
available these tests compile and execute the real decision
table; the source-shape tests always run and pin the wiring:
cutoff value, marker, kill mechanism, and recovery-only scope.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER_SRC = ROOT / "autoroot-helper" / "src" / "dev" / "portal" / "autoroothelper"
WATCHDOG_JAVA = HELPER_SRC / "AttemptWatchdog.java"
SERVICE_JAVA = HELPER_SRC / "AutorootService.java"


HARNESS = """
package dev.portal.autoroothelper;

public final class WatchdogHarness {
    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    public static void main(String[] args) {
        // No verdict: cut only at/after the 300 s cutoff.
        check(!AttemptWatchdog.shouldCut(0L, false), "cut at 0s");
        check(!AttemptWatchdog.shouldCut(244_000L, false), "cut at slowest fast fail");
        check(!AttemptWatchdog.shouldCut(299_999L, false), "cut just before cutoff");
        check(AttemptWatchdog.shouldCut(300_000L, false), "no cut at cutoff");
        check(AttemptWatchdog.shouldCut(600_000L, false), "no cut at old timeout");
        // Verdict seen early: NEVER cut, even past the old timeout.
        check(!AttemptWatchdog.shouldCut(300_000L, true), "cut a verdicted attempt");
        check(!AttemptWatchdog.shouldCut(600_000L, true), "cut a timeout-edge win");
        check(!AttemptWatchdog.shouldCut(900_000L, true), "cut a long collection");
        // Verdict detection keys on the marker text.
        check(AttemptWatchdog.verdictIn("WATCH_CFI_OK=1 STEP=0 ERRNO=0 ROOT=1 x"),
                "win verdict not detected");
        check(AttemptWatchdog.verdictIn("noise\\nWATCH_CFI_OK=0 STEP=151 ERRNO=13"),
                "fail verdict not detected");
        check(!AttemptWatchdog.verdictIn("AUTOROOT_ATTEMPT attempt=3 kaslr=0x0"),
                "banner mistaken for verdict");
        check(!AttemptWatchdog.verdictIn(""), "empty log mistaken for verdict");
        check(!AttemptWatchdog.verdictIn(null), "null log mistaken for verdict");
        check(AttemptWatchdog.CUTOFF_MS == 300_000L, "cutoff is not 300 s");
        // Verdict values: win = 1, fail = 0, absent = -1; last wins.
        check(AttemptWatchdog.verdictValue("WATCH_CFI_OK=1 STEP=0") == 1,
                "win verdict value wrong");
        check(AttemptWatchdog.verdictValue("WATCH_CFI_OK=0 STEP=151") == 0,
                "fail verdict value wrong");
        check(AttemptWatchdog.verdictValue("no verdict here") == -1,
                "missing verdict value wrong");
        check(AttemptWatchdog.verdictValue(null) == -1,
                "null log verdict value wrong");
        check(AttemptWatchdog.verdictValue("WATCH_CFI_OK=0 x WATCH_CFI_OK=1") == 1,
                "last verdict should govern");
        // Post-verdict policy: fail verdict + daemon absent cuts
        // only at/after the grace period; daemon present never cuts.
        check(!AttemptWatchdog.shouldCutFailVerdict(0L, true),
                "fail cut at verdict instant");
        check(!AttemptWatchdog.shouldCutFailVerdict(29_999L, true),
                "fail cut inside grace");
        check(AttemptWatchdog.shouldCutFailVerdict(30_000L, true),
                "no fail cut at grace end, daemon absent");
        check(AttemptWatchdog.shouldCutFailVerdict(549_000L, true),
                "no fail cut late, daemon absent");
        check(!AttemptWatchdog.shouldCutFailVerdict(30_000L, false),
                "fail cut with daemon present");
        check(!AttemptWatchdog.shouldCutFailVerdict(900_000L, false),
                "fail cut late with daemon present");
        check(AttemptWatchdog.FAIL_GRACE_MS == 30_000L, "grace is not 30 s");
        System.out.println("WATCHDOG_HARNESS_OK");
    }
}
"""


@unittest.skipUnless(
    shutil.which("javac") and shutil.which("java"),
    "no JDK available to execute the Java decision table",
)
class WatchdogDecisionTableTest(unittest.TestCase):
    def test_decision_table_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_dir = (
                pathlib.Path(temporary) / "dev" / "portal" / "autoroothelper"
            )
            package_dir.mkdir(parents=True)
            (package_dir / "AttemptWatchdog.java").write_text(
                WATCHDOG_JAVA.read_text(encoding="utf-8"), encoding="utf-8"
            )
            (package_dir / "WatchdogHarness.java").write_text(
                HARNESS, encoding="utf-8"
            )
            compile_result = subprocess.run(
                [
                    "javac",
                    "-d",
                    temporary,
                    str(package_dir / "AttemptWatchdog.java"),
                    str(package_dir / "WatchdogHarness.java"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["java", "-cp", temporary, "dev.portal.autoroothelper.WatchdogHarness"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertIn("WATCHDOG_HARNESS_OK", run_result.stdout)


class WatchdogWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.watchdog = WATCHDOG_JAVA.read_text(encoding="utf-8")
        self.service = SERVICE_JAVA.read_text(encoding="utf-8")

    def test_cutoff_is_300s_and_marker_is_the_race_verdict(self) -> None:
        self.assertIn("CUTOFF_MS = 300_000L", self.watchdog)
        self.assertIn('VERDICT_MARKER = "WATCH_CFI_OK="', self.watchdog)
        self.assertIn("!verdictSeen && elapsedMs >= CUTOFF_MS", self.watchdog)

    def test_post_verdict_policy_shape(self) -> None:
        # Grace period and the daemon-absence condition are part
        # of the policy, and the service only consults the
        # post-verdict cut on a FAIL verdict, reusing the existing
        # daemon check (daemonServingRoot) for known-absence.
        self.assertIn("FAIL_GRACE_MS = 30_000L", self.watchdog)
        self.assertIn("daemonAbsent && sinceFailVerdictMs >= FAIL_GRACE_MS",
                      self.watchdog)
        self.assertIn("AttemptWatchdog.shouldCutFailVerdict", self.service)
        self.assertIn("AttemptWatchdog.VERDICT_FAIL", self.service)
        self.assertIn("daemonServingRoot()", self.service)
        self.assertIn("fail verdict, daemon absent", self.service)
        self.assertIn("but daemon present; not cutting", self.service)

    def test_service_polls_attempt_log_and_cuts_via_tracked_client(self) -> None:
        self.assertIn("runAttemptWithWatchdog", self.service)
        self.assertIn("AttemptWatchdog.shouldCut", self.service)
        # The verdict check is scoped to bytes written since this
        # attempt started (attempt.log is append-only across
        # attempts), never the whole historical log.
        self.assertIn("attemptLogSize()", self.service)
        self.assertIn('"tail -c +" + (attemptLogOffset + 1)', self.service)
        # The cut uses the existing tracked-client teardown (the
        # stop path's kill mechanism), not a new kill channel.
        self.assertIn("client.close()", self.service)

    def test_attempt_timeout_and_provision_path_unchanged(self) -> None:
        # The 600 s runner timeout stays; the watchdog only stops
        # an attempt EARLIER when it has produced no verdict.
        self.assertIn("600000", self.service)
        # Recovery-only scope: the host provisioner (provision
        # path) must not reference the watchdog at all.
        provisioner = (ROOT / "tools" / "provision_portal.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("AttemptWatchdog", provisioner)
        self.assertNotIn("fail-fast cutoff", provisioner)


if __name__ == "__main__":
    unittest.main()
