# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Post-attempt orphan sweep + bounded Shizuku handoff (Phase C1).

Twice in the 2026-11-17 posture sessions a winning attempt's
process tree wedged (spinning once, ptrace-stopped once) and held
the recovery handoff for ~13 minutes until the processes exited
on their own; Run 33 saw the same starvation from a pair of
spinning orphans, cleared within ~90 s once they were killed by
hand. The service now sweeps the attempt's leftover tree after
every attempt's verdict, and the handoff wait is bounded by a
wall-clock deadline with a re-sweep and exactly one retry.

Snapshot column (2026-11-18, found by the C1b win-stall sweep's
first live run against a live tree): the sweep's ps snapshot
must use the NAME column. This device's toybox ps prints the
executable name in COMM - the /system/bin/true host reports as
"toybox" - so a COMM snapshot never matches the policy's task
names and the kill set was always empty against a real wedge.

The kill-set policy is pure Java (OrphanSweep). When a JDK is
available these tests compile and execute the real decision
table; the source-shape tests always run and pin the wiring:
the post-attempt sweep point, the daemon/Shizuku exclusions,
the handoff deadline, and the single retry.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER_SRC = ROOT / "autoroot-helper" / "src" / "dev" / "portal" / "autoroothelper"
SWEEP_JAVA = HELPER_SRC / "OrphanSweep.java"
SERVICE_JAVA = HELPER_SRC / "AutorootService.java"
MANIFEST_XML = ROOT / "autoroot-helper" / "AndroidManifest.xml"


HARNESS = """
package dev.portal.autoroothelper;

import java.util.List;

public final class SweepHarness {
    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    private static void checkSet(String ps, int selfPid, String label,
            int... expected) {
        List<Integer> actual = OrphanSweep.selectKillPids(ps, selfPid);
        check(actual.size() == expected.length,
                label + ": size " + actual.size() + " != " + expected.length
                        + " (" + actual + ")");
        for (int i = 0; i < expected.length; i++) {
            check(actual.get(i) == expected[i],
                    label + ": element " + i + " " + actual.get(i)
                            + " != " + expected[i]);
        }
    }

    public static void main(String[] args) {
        // A wedged winning attempt: the true host, its ptrace
        // children, the root daemon hanging off the same tree
        // (excluded, and its own child not traversed), an
        // unrelated shell and the service itself.
        String wedged = "PID PPID NAME\\n"
                + "1 0 init\\n"
                + "900 1 sh\\n"
                + "1000 900 true\\n"
                + "1001 1000 true\\n"
                + "1002 1000 sleep\\n"
                + "1003 1001 gdbserver\\n"
                + "1100 1000 portal-root-dae\\n"
                + "1101 1100 portal-root-dae\\n"
                + "1200 1 shizuku_server\\n"
                + "2000 1 dev.portal.autoroothelper\\n";
        checkSet(wedged, 2000, "wedged tree", 1000, 1001, 1002, 1003);

        // Clean attempt: no true processes at all, nothing to do.
        String clean = "PID PPID NAME\\n"
                + "1 0 init\\n"
                + "1200 1 shizuku_server\\n"
                + "1300 1 portal-root-dae\\n";
        checkSet(clean, 2000, "clean tree");

        // A leftover true whose only child is the daemon: the
        // daemon survives, the host does not.
        String daemonChild = "100 1 true\\n"
                + "101 100 portal-root-daemon\\n";
        checkSet(daemonChild, 999, "daemon child", 100);

        // The service's own pid is never selected, even named true.
        String selfTrue = "300 1 true\\n" + "301 300 sh\\n";
        checkSet(selfTrue, 300, "self named true");

        // Malformed input selects nothing and never throws.
        checkSet("", 1, "empty");
        checkSet(null, 1, "null");
        checkSet("garbage line\\n1 2\\n", 1, "malformed");
        System.out.println("SWEEP_HARNESS_OK");
    }
}
"""


@unittest.skipUnless(
    shutil.which("javac") and shutil.which("java"),
    "no JDK available to execute the Java decision table",
)
class SweepDecisionTableTest(unittest.TestCase):
    def test_decision_table_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_dir = (
                pathlib.Path(temporary) / "dev" / "portal" / "autoroothelper"
            )
            package_dir.mkdir(parents=True)
            (package_dir / "OrphanSweep.java").write_text(
                SWEEP_JAVA.read_text(encoding="utf-8"), encoding="utf-8"
            )
            (package_dir / "SweepHarness.java").write_text(
                HARNESS, encoding="utf-8"
            )
            compile_result = subprocess.run(
                [
                    "javac",
                    "-d",
                    temporary,
                    str(package_dir / "OrphanSweep.java"),
                    str(package_dir / "SweepHarness.java"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["java", "-cp", temporary, "dev.portal.autoroothelper.SweepHarness"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertIn("SWEEP_HARNESS_OK", run_result.stdout)


class SweepWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sweep = SWEEP_JAVA.read_text(encoding="utf-8")
        self.service = SERVICE_JAVA.read_text(encoding="utf-8")

    def test_policy_exclusions(self) -> None:
        self.assertIn('HOST_COMM = "true"', self.sweep)
        self.assertIn('DAEMON_COMM_PREFIX = "portal-root-d"', self.sweep)
        self.assertIn('SHIZUKU_COMM = "shizuku_server"', self.sweep)
        self.assertIn("pid <= 1", self.sweep)
        self.assertIn("pid == selfPid", self.sweep)

    def test_sweep_runs_after_every_attempt(self) -> None:
        # The sweep point sits between the watchdog's return and
        # the post-attempt daemon wait, so wins and losses alike
        # hand a clean process table to whatever comes next.
        attempt_at = self.service.index("runAttemptWithWatchdog(kaslr")
        sweep_at = self.service.index('sweepAttemptOrphans("post-attempt")')
        daemon_wait_at = self.service.index("boolean up = false;")
        self.assertLess(attempt_at, sweep_at)
        self.assertLess(sweep_at, daemon_wait_at)
        self.assertIn("kill -9", self.service)
        # The snapshot column is NAME, never COMM: this device's
        # toybox ps prints the executable name in COMM ("toybox"
        # for the /system/bin/true host), so a COMM snapshot can
        # never match the policy's task names (found live by the
        # C1b win-stall sweep, 2026-11-18).
        self.assertIn('shell("ps -A -o pid,ppid,name")', self.service)
        self.assertNotIn('shell("ps -A -o pid,ppid,comm")', self.service)

    def test_handoff_is_bounded_with_one_retry(self) -> None:
        self.assertIn("HANDOFF_WAIT_MS = 120_000L", self.service)
        self.assertIn(
            "while (System.currentTimeMillis() < deadlineMs)", self.service
        )
        wrapper = self.service[
            self.service.index("private boolean finishShizukuHandoff()") :
            self.service.index("// ---- root daemon")
        ]
        self.assertEqual(wrapper.count("ensureShizukuRoot()"), 2)
        self.assertIn('sweepAttemptOrphans("handoff-retry")', wrapper)
        # Both handoff call sites go through the bounded wrapper;
        # the only direct ensureShizukuRoot call left is inside it.
        self.assertEqual(self.service.count("if (ensureShizukuRoot())"), 1)
        self.assertEqual(self.service.count("finishShizukuHandoff()"), 3)

    def test_helper_version_bumped(self) -> None:
        manifest = MANIFEST_XML.read_text(encoding="utf-8")
        self.assertIn('android:versionCode="15"', manifest)
        self.assertIn('android:versionName="1.14"', manifest)


if __name__ == "__main__":
    unittest.main()
