# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Per-boot build gate for autoroot (2026-11-22).

The staged runner and its offsets are build-specific, so at staging
time the provisioner records the build fingerprint it staged for in
autoroot.conf, and on every boot the helper compares it against
Build.FINGERPRINT before any rooting attempt. On a mismatch it makes
no attempts, persists the stood-down state, and surfaces it
(notification, helper status naming the build found, and a log the
host --status can read). It resumes when the build matches again or
the unit is re-staged.

The comparison itself is pure Java (BuildGate). When a JDK is
available these tests compile and execute the real decision table;
the source-shape tests always run and pin the wiring: the staging
record, the gate ahead of every root path in the service, the
persisted state and its surfaces, and the host --status report.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import provision_portal  # noqa: E402
from provision_portal import PortalProvisioner  # noqa: E402
from portal_targets import TARGETS  # noqa: E402


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER_SRC = ROOT / "autoroot-helper" / "src" / "dev" / "portal" / "autoroothelper"
GATE_JAVA = HELPER_SRC / "BuildGate.java"
SERVICE_JAVA = HELPER_SRC / "AutorootService.java"
ACTIVITY_JAVA = HELPER_SRC / "AutorootActivity.java"

OLD = "Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys"
NEW = "Facebook/omni_prod/omni:10/QKQ1.210213.001/3051392000021050:user/prod-keys"


HARNESS = """
package dev.portal.autoroothelper;

public final class GateHarness {
    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    public static void main(String[] args) {
        String oldBuild =
                "Facebook/omni_prod/omni:10/QKQ1.210213.001/3051355900018050:user/prod-keys";
        String newBuild =
                "Facebook/omni_prod/omni:10/QKQ1.210213.001/3051392000021050:user/prod-keys";

        // The recorded keys are the contract with the staged conf,
        // the state file and the host --status report.
        check("EXPECTED_FINGERPRINT".equals(BuildGate.CONF_KEY),
                "conf key changed");
        check("build_gate_stood_down".equals(BuildGate.KEY_STOOD_DOWN),
                "stood-down key changed");
        check("build_gate_expected".equals(BuildGate.KEY_EXPECTED),
                "expected key changed");
        check("build_gate_found".equals(BuildGate.KEY_FOUND),
                "found key changed");

        // A matching build runs; surrounding whitespace from the
        // conf file does not matter.
        check(BuildGate.matches(oldBuild, oldBuild), "match refused");
        check(!BuildGate.stoodDown(oldBuild, oldBuild),
                "match stood down");
        check(BuildGate.matches("  " + oldBuild + " ", oldBuild),
                "padded expectation refused");

        // A different build stands down.
        check(!BuildGate.matches(oldBuild, newBuild),
                "mismatch allowed");
        check(BuildGate.stoodDown(oldBuild, newBuild),
                "mismatch did not stand down");

        // No recorded expectation (staged before the gate existed)
        // is ungated, whatever the live build is.
        check(!BuildGate.hasExpectation(null), "null is an expectation");
        check(!BuildGate.hasExpectation(""), "empty is an expectation");
        check(!BuildGate.hasExpectation("  "), "blank is an expectation");
        check(BuildGate.matches(null, newBuild), "null expectation gated");
        check(BuildGate.matches("", newBuild), "empty expectation gated");
        check(!BuildGate.stoodDown(null, newBuild),
                "null expectation stood down");

        // A recorded expectation with an unreadable live build
        // fails closed.
        check(!BuildGate.matches(oldBuild, null),
                "unreadable build allowed");
        check(BuildGate.stoodDown(oldBuild, null),
                "unreadable build did not stand down");

        System.out.println("GATE_HARNESS_OK");
    }
}
"""


@unittest.skipUnless(
    shutil.which("javac") and shutil.which("java"),
    "no JDK available to execute the Java decision table",
)
class BuildGateDecisionTableTest(unittest.TestCase):
    def test_decision_table_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_dir = (
                pathlib.Path(temporary) / "dev" / "portal" / "autoroothelper"
            )
            package_dir.mkdir(parents=True)
            (package_dir / "BuildGate.java").write_text(
                GATE_JAVA.read_text(encoding="utf-8"), encoding="utf-8"
            )
            (package_dir / "GateHarness.java").write_text(
                HARNESS, encoding="utf-8"
            )
            compile_result = subprocess.run(
                [
                    "javac",
                    "-d",
                    temporary,
                    str(package_dir / "BuildGate.java"),
                    str(package_dir / "GateHarness.java"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["java", "-cp", temporary, "dev.portal.autoroothelper.GateHarness"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertIn("GATE_HARNESS_OK", run_result.stdout)


class BuildGateWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = GATE_JAVA.read_text(encoding="utf-8")
        self.service = SERVICE_JAVA.read_text(encoding="utf-8")
        self.activity = ACTIVITY_JAVA.read_text(encoding="utf-8")
        self.payload = (ROOT / "tools" / "features" / "payload.py").read_text(
            encoding="utf-8"
        )
        self.provisioner = (ROOT / "tools" / "provision_portal.py").read_text(
            encoding="utf-8"
        )

    def test_staging_records_the_expected_fingerprint(self) -> None:
        # The staged autoroot.conf carries the fingerprint of the
        # target this staging selected, rendered with the conf.
        self.assertIn(
            'f"EXPECTED_FINGERPRINT={self._target().fingerprint}\\n"',
            self.payload,
        )
        self.assertIn('CONF_KEY = "EXPECTED_FINGERPRINT"', self.gate)

    def test_gate_runs_before_any_rooting_attempt(self) -> None:
        gate = self.service.index("BuildGate.stoodDown(expectedBuild, foundBuild)")
        conf_read = self.service.index("Map<String, String> conf = readKeyValues(CONF);")
        root_up = self.service.index("if (shizukuServingRoot())")
        race = self.service.index("runAttemptWithWatchdog(kaslr")
        self.assertLess(conf_read, gate)
        self.assertLess(gate, root_up)
        self.assertLess(gate, race)
        # The comparison is against the live build of this boot.
        self.assertIn("String foundBuild = Build.FINGERPRINT;", self.service)
        self.assertIn("conf.get(BuildGate.CONF_KEY)", self.service)

    def test_mismatch_persists_and_surfaces_the_stand_down(self) -> None:
        # Persisted in the state file under the gate's own keys.
        self.assertIn("gateState.put(BuildGate.KEY_STOOD_DOWN, \"1\")", self.service)
        self.assertIn("gateState.put(BuildGate.KEY_EXPECTED,", self.service)
        self.assertIn("gateState.put(BuildGate.KEY_FOUND,", self.service)
        self.assertIn("writeState(gateState);", self.service)
        # A log line the host --status can read, naming both builds.
        self.assertIn(
            'logFile("build gate stood down expected=" + expectedBuild',
            self.service,
        )
        # Helper status naming the build found.
        self.assertIn('publishStatus("BUILD_MISMATCH"', self.service)
        self.assertIn('"unsupported build " + foundBuild', self.service)
        self.assertIn('case "BUILD_MISMATCH":', self.activity)
        # A persistent notification naming the build found.
        self.assertIn("postBuildGateNotification(found)", self.service)
        self.assertIn("NOTIFY_ID_BUILD_GATE = 2", self.service)
        self.assertIn('" unsupported build (" + foundBuild', self.service)
        self.assertIn(".setOngoing(true)", self.service)

    def test_match_clears_a_persisted_stand_down(self) -> None:
        # The gate is re-evaluated every boot: on a match the
        # persisted keys and the notification are cleared, so the
        # unit resumes without a host run.
        self.assertIn("clearBuildGateState();", self.service)
        self.assertIn("state.remove(BuildGate.KEY_STOOD_DOWN);", self.service)
        self.assertIn("state.remove(BuildGate.KEY_FOUND);", self.service)
        self.assertIn('"build gate cleared: build matches again"', self.service)
        # Staging deletes the state file (the re-stage resume path),
        # which drops the gate keys with the rest of the state.
        self.assertIn('f"{AUTOROOT_REMOTE_DIR}/state"', self.payload)

    def test_status_reports_the_gate(self) -> None:
        self.assertIn('"autoroot": {', self.provisioner)
        self.assertIn('"expected_fingerprint": autoroot_conf_values.get(', self.provisioner)
        self.assertIn('"EXPECTED_FINGERPRINT"', self.provisioner)
        self.assertIn('"build_gate_stood_down"', self.provisioner)
        self.assertIn('"build_gate_expected"', self.provisioner)
        self.assertIn('"build_gate_found"', self.provisioner)
        # The service log is read so its build-gate lines surface.
        self.assertIn('f"{AUTOROOT_REMOTE_DIR}/service.log"', self.provisioner)
        self.assertIn('if "build gate" in line', self.provisioner)


OMNI = next(
    target for target in TARGETS if target.key == "portal-mini-omni-3051355900018050"
)


class BuildGateStatusTest(unittest.TestCase):
    """--status reads the staged expectation, the persisted gate
    state, and the service log's build-gate lines."""

    def collect(self, files: dict[str, str]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            provisioner.target = OMNI

            def adb_run(args, timeout=None, check=False):
                if args[:2] == ["shell", "cat"] and args[2] in files:
                    return subprocess.CompletedProcess(
                        args, 0, files[args[2]], ""
                    )
                if args[:2] == ["shell", "cat"]:
                    return subprocess.CompletedProcess(args, 1, "", "")
                return subprocess.CompletedProcess(args, 0, "", "")

            with mock.patch.object(
                provisioner, "adb_run", side_effect=adb_run
            ):
                return provisioner.collect_status()

    def test_status_reports_a_stood_down_gate(self) -> None:
        status = self.collect(
            {
                "/data/local/tmp/portal-autoroot/autoroot.conf": (
                    "MAX_ATTEMPTS=8\n"
                    f"EXPECTED_FINGERPRINT={OLD}\n"
                ),
                "/data/local/tmp/portal-autoroot/state": (
                    "build_gate_stood_down=1\n"
                    f"build_gate_expected={OLD}\n"
                    f"build_gate_found={NEW}\n"
                ),
                "/data/local/tmp/portal-autoroot/service.log": (
                    "1700000000 attempt 1 of 8 boot=abc\n"
                    f"1700000100 build gate stood down expected={OLD} found={NEW}\n"
                ),
            }
        )
        autoroot = status["autoroot"]
        self.assertEqual(autoroot["expected_fingerprint"], OLD)
        gate = autoroot["build_gate"]
        self.assertTrue(gate["stood_down"])
        self.assertEqual(gate["expected"], OLD)
        self.assertEqual(gate["found"], NEW)
        self.assertEqual(len(gate["log"]), 1)
        self.assertIn("build gate stood down", gate["log"][0])

    def test_status_reports_no_gate_when_nothing_is_staged(self) -> None:
        status = self.collect({})
        autoroot = status["autoroot"]
        self.assertIsNone(autoroot["expected_fingerprint"])
        gate = autoroot["build_gate"]
        self.assertFalse(gate["stood_down"])
        self.assertIsNone(gate["expected"])
        self.assertIsNone(gate["found"])
        self.assertEqual(gate["log"], [])


if __name__ == "__main__":
    unittest.main()
