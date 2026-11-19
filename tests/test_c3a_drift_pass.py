# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Phase C3-A (2026-11-18): the per-boot recorded-state drift pass
and its host companions.

Five surfaces are pinned:

- DriftPolicy, the helper's pure per-item decision table, compiled
  and executed when a JDK is available; the service wiring is
  pinned by source shape either way (three root-established exits,
  the pass before the daemon window closes, no failure-budget
  state writes inside the pass, the host-run disable flag still
  returning before any exit).
- The manifest's additive desired_state record: a run records the
  alohausers-disabled posture only when it removes Meta accounts
  AND started with the package disabled; unrelated runs preserve
  an earlier record.
- The staged autoroot.conf keys (DNS_MODE / DNS_SPECIFIER /
  ALOHAUSERS_DISABLED) with the OTA_NODEMON preserve/sync
  discipline, at staging time and in the later-run sync.
- The posture no-op trust gap from C3-B validation: a manifest
  whose disable_updates completion was recorded under the posture
  judgment is trusted by the channel gate and the channel-path
  OTA verification instead of re-deriving OTA from a config dump
  that reads unconfigured by design in the posture; and the
  Private DNS no-op gate confirms a lone mismatching sample with
  one re-read before calling it drift (the run-8 refusal was a
  single disagreeing read on a device verified minutes earlier).
- The fast-path gates' posture trust for a completion recorded
  "unverified" by a win-less run's posture judgment (Phase D
  closure, 2026-11-19): otad.nodemon is per-boot and win-set, so
  on a boot where autoroot has not won no live OTA proof can
  pass, and both the no-op gate and the channel OTA clause
  refused the finished device into a race. The gates now stand
  in with the posture criteria a win-less boot CAN read (the
  recorded posture, the staged conf's OTA_NODEMON, the package
  actually disabled); the end-of-run judgment itself is
  unchanged and still fails the same device.
- The conf syncs after an autoroot restore (Defect I, Phase D
  closure session 12, 2026-11-19): the restore removes the whole
  staging directory, the syncs' unchecked cat read surfaced its
  error text as config lines, and the rewrite pushed into the
  removed directory, where adb push cannot create directories.
  The syncs now share a read that treats a failed read as no
  staged config and a write that creates the directory first;
  the pins run both syncs and the restore-then-reprovision
  sequence against a fake device filesystem.
- The posture bootstrap (Defect J, Phase D closure session 13,
  2026-11-19): desired_state keyed only off the start state
  under --remove-meta-accounts, so a run starting from a
  drifted (enabled) device recorded nothing and the posture
  was unreachable through the tool. A run that stages the OTA
  posture now establishes it at the end-of-run posture step,
  and a completing run whose end state is the disabled posture
  records the desire from its own end state; a run ending
  enabled records nothing.
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

import provision_portal  # noqa: E402
from provision_portal import PortalProvisioner, ProvisionError  # noqa: E402
from portal_targets import TARGETS  # noqa: E402
from features.payload import PayloadConfig, PayloadFeature  # noqa: E402
from features.settings import (  # noqa: E402
    META_AUTHENTICATOR_COMPONENTS,
    SettingsFeature,
)

import test_fast_paths  # noqa: E402

HELPER_SRC = ROOT / "autoroot-helper" / "src" / "dev" / "portal" / "autoroothelper"
POLICY_JAVA = HELPER_SRC / "DriftPolicy.java"
SERVICE_JAVA = HELPER_SRC / "AutorootService.java"

ALOHA = next(
    target for target in TARGETS if target.key == "portal-plus-aloha-1041515800015050"
)
OMNI = next(
    target for target in TARGETS if target.key == "portal-mini-omni-3051355900018050"
)
CONF_REMOTE = "/data/local/tmp/portal-autoroot/autoroot.conf"
RUN_SH_REMOTE = "/data/local/tmp/portal-autoroot/run.sh"
BASE_CONF = (
    "MAX_ATTEMPTS=8\n"
    "SESSION_WINDOW_SEC=3600\n"
    "SIMPLEPERF=/data/local/tmp/portal-simpleperf\n"
    "KASLR_OFFSETS=0x3354\n"
)
POSTURE_STATE = {
    "status": "complete",
    "actions": {"disable_updates": True},
    "desired_state": {"alohausers_package": "disabled"},
}


def make_provisioner(temporary: str, target=ALOHA, **kwargs) -> PortalProvisioner:
    provisioner = PortalProvisioner(
        "192.0.2.1:5555", 1, pathlib.Path(temporary), **kwargs
    )
    provisioner.target = target
    return provisioner


def completed(args, stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args, returncode, stdout, "")


HARNESS = """
package dev.portal.autoroothelper;

public final class DriftHarness {
    private static void check(boolean condition, String label) {
        if (!condition) {
            throw new AssertionError(label);
        }
    }

    public static void main(String[] args) {
        // DNS: nothing recorded -> nothing enforced.
        check(DriftPolicy.dnsAction(null, null, "off", "null")
                == DriftPolicy.NONE, "dns unrecorded must be NONE");
        // DNS: recorded state holds, across absent spellings.
        check(DriftPolicy.dnsAction("off", "null", "off", "null")
                == DriftPolicy.NONE, "dns match must be NONE");
        check(DriftPolicy.dnsAction("off", null, "off", "")
                == DriftPolicy.NONE, "dns absent spellings must match");
        check(DriftPolicy.dnsAction("hostname", "one.one.one.one",
                "hostname", "one.one.one.one") == DriftPolicy.NONE,
                "dns hostname match must be NONE");
        // DNS: drift repairs through the loopback shell.
        check(DriftPolicy.dnsAction("off", "null", "hostname",
                "one.one.one.one") == DriftPolicy.REPAIR_VIA_SHELL,
                "dns drift must repair via shell");
        check(DriftPolicy.dnsAction("hostname", "one.one.one.one",
                "hostname", "dns.google") == DriftPolicy.REPAIR_VIA_SHELL,
                "dns specifier drift must repair via shell");
        // DNS: an unreadable live state is reported, never written blind.
        check(DriftPolicy.dnsAction("off", "null", null, null)
                == DriftPolicy.REPORT_ONLY,
                "dns unreadable must be REPORT_ONLY");

        // alohausers: no desire or already disabled -> no-op.
        check(DriftPolicy.alohausersAction(false, false, true)
                == DriftPolicy.NONE, "aloha no desire must be NONE");
        check(DriftPolicy.alohausersAction(true, true, false)
                == DriftPolicy.NONE, "aloha already disabled must be NONE");
        // Drift with the daemon window live repairs through it.
        check(DriftPolicy.alohausersAction(true, false, true)
                == DriftPolicy.REPAIR_VIA_DAEMON,
                "aloha drift with daemon must repair via daemon");
        // Drift without it waits for the next win: report only.
        check(DriftPolicy.alohausersAction(true, false, false)
                == DriftPolicy.REPORT_ONLY,
                "aloha drift without daemon must be REPORT_ONLY");

        // nodemon: check-only, always.
        check(DriftPolicy.nodemonAction(false, false) == DriftPolicy.NONE,
                "nodemon unstaged must be NONE");
        check(DriftPolicy.nodemonAction(true, true) == DriftPolicy.NONE,
                "nodemon set must be NONE");
        check(DriftPolicy.nodemonAction(true, false)
                == DriftPolicy.REPORT_ONLY,
                "nodemon staged but unset must be REPORT_ONLY");

        check("null".equals(DriftPolicy.normalize(null)), "normalize null");
        check("null".equals(DriftPolicy.normalize("  ")), "normalize blank");
        check("off".equals(DriftPolicy.normalize(" off ")), "normalize trims");

        System.out.println("DRIFT_HARNESS_OK");
    }
}
"""


@unittest.skipUnless(
    shutil.which("javac") and shutil.which("java"),
    "no JDK available to execute the Java decision table",
)
class DriftPolicyDecisionTableTest(unittest.TestCase):
    def test_decision_table_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_dir = (
                pathlib.Path(temporary) / "dev" / "portal" / "autoroothelper"
            )
            package_dir.mkdir(parents=True)
            (package_dir / "DriftPolicy.java").write_text(
                POLICY_JAVA.read_text(encoding="utf-8"), encoding="utf-8"
            )
            (package_dir / "DriftHarness.java").write_text(
                HARNESS, encoding="utf-8"
            )
            compile_result = subprocess.run(
                [
                    "javac",
                    "-d",
                    temporary,
                    str(package_dir / "DriftPolicy.java"),
                    str(package_dir / "DriftHarness.java"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["java", "-cp", temporary, "dev.portal.autoroothelper.DriftHarness"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertIn("DRIFT_HARNESS_OK", run_result.stdout)


class DriftPassWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = SERVICE_JAVA.read_text(encoding="utf-8")

    def test_pass_runs_at_all_three_root_exits(self) -> None:
        # One definition plus three call sites: the already-root
        # exit (shell channel only) and the two win exits (daemon
        # window still open).
        self.assertEqual(self.service.count("enforceRecordedState("), 4)
        self.assertEqual(self.service.count("enforceRecordedState(false, conf)"), 1)
        self.assertEqual(self.service.count("enforceRecordedState(true, conf)"), 2)

    def test_pass_precedes_daemon_close_on_the_win_exit(self) -> None:
        win = self.service.index("if (up) {")
        window = self.service[win : win + 1200]
        handoff = window.index("finishShizukuHandoff()")
        drift = window.index("enforceRecordedState(true, conf)")
        stop = window.index("stopDaemon()")
        self.assertLess(handoff, drift)
        self.assertLess(drift, stop)

    def test_pass_never_touches_the_budget_state(self) -> None:
        start = self.service.index("private void enforceRecordedState")
        end = self.service.index("// ---- plumbing", start)
        body = self.service[start:end]
        self.assertNotIn("writeState(", body)
        self.assertNotIn("FailureBudget", body)
        self.assertNotIn("readKeyValues(STATE)", body)

    def test_host_run_flag_returns_before_any_exit(self) -> None:
        flag_return = self.service.index("disabled by flag")
        first_call = self.service.index("enforceRecordedState(false, conf)")
        self.assertLess(flag_return, first_call)

    def test_channels_match_the_proven_walls(self) -> None:
        # DNS through the loopback shell, the package through the
        # daemon, nodemon read-only: the three channel shapes the
        # on-device walls allow, no invented fourth channel.
        self.assertIn('shell("settings get global " + key)', self.service)
        self.assertIn('"pm disable --user 0 " + ALOHAUSERS_PACKAGE', self.service)
        self.assertIn('reason=no-post-win-channel', self.service)


class DesiredStateRecordingTest(unittest.TestCase):
    def provisioner(self, temporary: str, **kwargs) -> PortalProvisioner:
        return make_provisioner(temporary, **kwargs)

    def test_posture_run_records_the_desire(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary, remove_meta_accounts=True)
            provisioner._alohausers_disabled_at_start = True
            self.assertEqual(
                provisioner._desired_state(),
                {"alohausers_package": "disabled"},
            )

    def test_run_starting_enabled_records_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary, remove_meta_accounts=True)
            provisioner._alohausers_disabled_at_start = False
            self.assertEqual(provisioner._desired_state(), {})

    def test_unrelated_run_preserves_an_earlier_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            provisioner._start_state = {
                "desired_state": {"alohausers_package": "disabled"}
            }
            self.assertEqual(
                provisioner._desired_state(),
                {"alohausers_package": "disabled"},
            )

    def test_removal_run_starting_enabled_drops_an_earlier_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary, remove_meta_accounts=True)
            provisioner._start_state = {
                "desired_state": {"alohausers_package": "disabled"}
            }
            provisioner._alohausers_disabled_at_start = False
            self.assertEqual(provisioner._desired_state(), {})

    def test_omni_never_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(
                temporary, target=OMNI, remove_meta_accounts=True
            )
            provisioner._alohausers_disabled_at_start = True
            self.assertEqual(provisioner._desired_state(), {})

    def test_write_state_carries_the_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary, remove_meta_accounts=True)
            provisioner._alohausers_disabled_at_start = True
            captured: dict = {}
            provisioner.adb_run = lambda *a, **k: completed(
                a, "fingerprint\n"
            )
            with mock.patch.object(
                provisioner.run_state,
                "write_state",
                side_effect=lambda status, **kw: captured.update(kw),
            ):
                provisioner.write_state("complete")
            self.assertEqual(
                captured.get("desired_state"),
                {"alohausers_package": "disabled"},
            )


class StagingDesiredTest(unittest.TestCase):
    """The PayloadFeature resolvers behind the staged conf keys."""

    def feature(
        self,
        *,
        target=ALOHA,
        conf: str = "",
        desired: dict | None = None,
        backup: dict | None = None,
        **config_kwargs,
    ) -> PayloadFeature:
        config = PayloadConfig(
            shizuku=True,
            skip_shizuku_root=False,
            autoroot=True,
            disable_updates=False,
            enable_updates=False,
            disable_camera_light=False,
            restore_camera_light=False,
            restore_presence_fps=False,
            restore_presence_profile=False,
            presence_fps_cap=None,
            **config_kwargs,
        )
        return PayloadFeature(
            config=lambda: config,
            adb_run=lambda args, **k: completed(args, conf),
            target=lambda: target,
            install_apk_preserving_verifier=lambda *a, **k: None,
            verify_package_verifier_state=lambda *a, **k: None,
            settle_package_state=lambda *a, **k: None,
            package_sets=lambda: (set(), set()),
            push_text_atomic=lambda *a, **k: None,
            build_exploit_environment=lambda *a, **k: None,
            uid1000_path=lambda name: name,
            compile_camera_light_host_speed=lambda *a, **k: None,
            start_shizuku_as_root=lambda *a, **k: None,
            stage_autoroot_payload=lambda *a, **k: None,
            stage_simpleperf=lambda *a, **k: None,
            presence_fps_action_requested=lambda: False,
            stop_root_daemon=lambda *a, **k: None,
            authorized_shizuku_key=lambda: None,
            read_saved_shizuku_key_marker=lambda: None,
            read_private_dns_backup=lambda required=True: backup,
            desired_state=lambda: desired or {},
            autoroot_helper_local=lambda: pathlib.Path("helper.apk"),
            autoroot_runner_local=lambda: pathlib.Path("run.sh"),
            adb_framework_boot_installed_remote="installed",
        )

    def test_dhcp_dns_records_off(self) -> None:
        self.assertEqual(
            self.feature(dhcp_dns=True)._dns_desired(), ("off", "null")
        )

    def test_privacy_dns_records_hostname_lowercased(self) -> None:
        self.assertEqual(
            self.feature(privacy_dns="One.One.One.One")._dns_desired(),
            ("hostname", "one.one.one.one"),
        )

    def test_unrequested_dns_preserves_staged_keys(self) -> None:
        feature = self.feature(
            conf=BASE_CONF + "DNS_MODE=hostname\nDNS_SPECIFIER=dns.google\n"
        )
        self.assertEqual(feature._dns_desired(), ("hostname", "dns.google"))

    def test_unrequested_dns_without_keys_records_nothing(self) -> None:
        self.assertIsNone(self.feature(conf=BASE_CONF)._dns_desired())

    def test_restore_resolves_from_the_backup(self) -> None:
        feature = self.feature(
            restore_privacy_dns=True,
            backup={"mode": "hostname", "hostname": "dns.google"},
        )
        self.assertEqual(feature._dns_desired(), ("hostname", "dns.google"))

    def test_restore_without_backup_records_nothing(self) -> None:
        feature = self.feature(restore_privacy_dns=True, backup=None)
        self.assertIsNone(feature._dns_desired())

    def test_alohausers_desire_from_the_record(self) -> None:
        feature = self.feature(desired={"alohausers_package": "disabled"})
        self.assertTrue(feature._alohausers_disabled_desired())

    def test_alohausers_preserves_a_staged_key(self) -> None:
        feature = self.feature(conf=BASE_CONF + "ALOHAUSERS_DISABLED=1\n")
        self.assertTrue(feature._alohausers_disabled_desired())

    def test_alohausers_absent_everywhere_is_false(self) -> None:
        self.assertFalse(self.feature(conf=BASE_CONF)._alohausers_disabled_desired())

    def test_alohausers_never_on_omni(self) -> None:
        feature = self.feature(
            target=OMNI, desired={"alohausers_package": "disabled"}
        )
        self.assertFalse(feature._alohausers_disabled_desired())

    def test_conf_render_carries_the_keys(self) -> None:
        payload = (ROOT / "tools" / "features" / "payload.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('conf += f"DNS_MODE={dns[0]}\\nDNS_SPECIFIER={dns[1]}\\n"', payload)
        self.assertIn('conf += "ALOHAUSERS_DISABLED=1\\n"', payload)


class DriftConfSyncTest(unittest.TestCase):
    """Later runs rewrite the staged drift keys in place."""

    def run_sync(self, provisioner, existing_conf: str, staged: bool = True):
        pushes: dict[str, str] = {}

        def adb_run(args, timeout=None, check=False):
            if args[:3] == ["shell", "test", "-f"] and args[3] == RUN_SH_REMOTE:
                return completed(args, returncode=0 if staged else 1)
            if args[:3] == ["shell", "cat", CONF_REMOTE]:
                return completed(args, existing_conf)
            if args and args[0] == "push":
                local_path = pathlib.Path(args[1])
                pushes[args[2]] = (
                    local_path.read_text(encoding="utf-8")
                    if local_path.is_file()
                    else ""
                )
                return completed(args)
            return completed(args)

        stdout = io.StringIO()
        with (
            mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
            contextlib.redirect_stdout(stdout),
        ):
            provisioner.sync_drift_conf_keys()
        return pushes, stdout.getvalue()

    def test_dns_change_rewrites_the_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, dhcp_dns=True)
            pushes, output = self.run_sync(
                provisioner,
                BASE_CONF + "DNS_MODE=hostname\nDNS_SPECIFIER=dns.google\n",
            )
        self.assertEqual(
            pushes[CONF_REMOTE + ".tmp"],
            BASE_CONF + "DNS_MODE=off\nDNS_SPECIFIER=null\n",
        )
        self.assertIn("DRIFT_CONF_SYNC item=private_dns", output)

    def test_posture_run_adds_the_package_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, remove_meta_accounts=True)
            provisioner._alohausers_disabled_at_start = True
            pushes, output = self.run_sync(provisioner, BASE_CONF)
        self.assertEqual(
            pushes[CONF_REMOTE + ".tmp"], BASE_CONF + "ALOHAUSERS_DISABLED=1\n"
        )
        self.assertIn("DRIFT_CONF_SYNC item=alohausers value=1", output)

    def test_removal_run_starting_enabled_clears_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, remove_meta_accounts=True)
            provisioner._alohausers_disabled_at_start = False
            pushes, output = self.run_sync(
                provisioner, BASE_CONF + "ALOHAUSERS_DISABLED=1\n"
            )
        self.assertEqual(pushes[CONF_REMOTE + ".tmp"], BASE_CONF)
        self.assertIn("DRIFT_CONF_SYNC item=alohausers value=0", output)

    def test_unrelated_run_touches_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            pushes, output = self.run_sync(
                provisioner, BASE_CONF + "ALOHAUSERS_DISABLED=1\n"
            )
        self.assertEqual(pushes, {})
        self.assertEqual(output, "")


STAGING_DIR = "/data/local/tmp/portal-autoroot"


class FakeStagingDevice:
    """A minimal device filesystem for the staged autoroot dir.

    Models the three behaviors Defect I (2026-11-19) turned on:
    cat of a missing file fails with its error text on stdout
    (the command runner merges stderr there), adb push cannot
    create a missing parent directory (secure_mkdirs is refused
    on these devices), and the autoroot restore removes the
    staging directory wholesale (rm -rf in payload.py)."""

    def __init__(self, staged_conf: str | None = BASE_CONF) -> None:
        self.dirs = {"/data/local/tmp"}
        self.files: dict[str, str] = {}
        self.calls: list[list[str]] = []
        if staged_conf is not None:
            self.dirs.add(STAGING_DIR)
            self.files[RUN_SH_REMOTE] = "#!/bin/sh\n"
            self.files[CONF_REMOTE] = staged_conf

    def adb_run(self, args, timeout=None, check=False):
        self.calls.append(list(args))
        result = self._dispatch(args)
        if check and result.returncode != 0:
            raise ProvisionError(
                f"command failed ({result.returncode}): {args}\n{result.stdout}"
            )
        return result

    def _dispatch(self, args):
        if args[:3] == ["shell", "test", "-f"]:
            return completed(args, returncode=0 if args[3] in self.files else 1)
        if args[:2] == ["shell", "cat"]:
            path = args[2]
            if path in self.files:
                return completed(args, self.files[path])
            return completed(
                args,
                f"cat: {path}: No such file or directory\n",
                returncode=1,
            )
        if args[:3] == ["shell", "mkdir", "-p"]:
            self.dirs.add(args[3])
            return completed(args)
        if args[:3] == ["shell", "rm", "-rf"]:
            target = args[3]
            self.dirs.discard(target)
            for path in [
                p for p in self.files if p.startswith(target + "/")
            ]:
                del self.files[path]
            return completed(args)
        if args and args[0] == "push":
            local_path, remote = pathlib.Path(args[1]), args[2]
            if remote.rsplit("/", 1)[0] not in self.dirs:
                return completed(
                    args,
                    "adb: error: failed to copy: remote secure_mkdirs "
                    "failed: Operation not permitted\n",
                    returncode=1,
                )
            self.files[remote] = (
                local_path.read_text(encoding="utf-8")
                if local_path.is_file()
                else ""
            )
            return completed(args)
        if args[0] == "shell" and isinstance(args[1], str) and "mv " in args[1]:
            tokens = args[1].replace("&&", " ").split()
            index = tokens.index("mv")
            self.files[tokens[index + 2]] = self.files.pop(tokens[index + 1])
            return completed(args)
        return completed(args)


class DriftConfSyncMissingDirTest(unittest.TestCase):
    """Defect I: the conf syncs write into a directory only
    staging creates and the autoroot restore removes."""

    def run_on_device(self, provisioner, device, call) -> None:
        with (
            mock.patch.object(provisioner, "adb_run", side_effect=device.adb_run),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            call(provisioner)

    def test_drift_sync_write_creates_a_missing_staging_directory(self) -> None:
        device = FakeStagingDevice()
        device.dirs.discard(STAGING_DIR)
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, autoroot=True, dhcp_dns=True
            )
            self.run_on_device(
                provisioner, device, lambda p: p.sync_drift_conf_keys()
            )
        self.assertIn(STAGING_DIR, device.dirs)
        self.assertEqual(
            device.files[CONF_REMOTE],
            BASE_CONF + "DNS_MODE=off\nDNS_SPECIFIER=null\n",
        )
        mkdir_at = next(
            i
            for i, call in enumerate(device.calls)
            if call[:3] == ["shell", "mkdir", "-p"] and call[3] == STAGING_DIR
        )
        push_at = next(
            i for i, call in enumerate(device.calls) if call[0] == "push"
        )
        self.assertLess(mkdir_at, push_at)

    def test_nodemon_sync_write_creates_a_missing_staging_directory(
        self,
    ) -> None:
        device = FakeStagingDevice()
        device.dirs.discard(STAGING_DIR)
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, autoroot=True, disable_updates=True
            )
            self.run_on_device(
                provisioner,
                device,
                lambda p: p.sync_ota_nodemon_autoroot_conf(),
            )
        self.assertIn(STAGING_DIR, device.dirs)
        self.assertEqual(
            device.files[CONF_REMOTE], BASE_CONF + "OTA_NODEMON=1\n"
        )

    def test_restore_then_reprovision_sequence(self) -> None:
        device = FakeStagingDevice()
        # The autoroot restore's own removal (payload.py's rm -rf).
        device.adb_run(["shell", "rm", "-rf", STAGING_DIR])
        self.assertNotIn(CONF_REMOTE, device.files)
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                autoroot=True,
                dhcp_dns=True,
                disable_updates=True,
            )
            # The early conf syncs of the re-provision run: nothing
            # staged, so nothing to sync, and no write may be
            # attempted into the removed directory (pre-fix the
            # nodemon sync rewrote cat's error text and the push
            # died on the missing directory).
            self.run_on_device(
                provisioner,
                device,
                lambda p: p.sync_ota_nodemon_autoroot_conf(),
            )
            self.run_on_device(
                provisioner, device, lambda p: p.sync_drift_conf_keys()
            )
            self.assertNotIn(CONF_REMOTE, device.files)
            # The staging write the run performs later succeeds.
            device.adb_run(["shell", "mkdir", "-p", STAGING_DIR])
            with mock.patch.object(
                provisioner, "adb_run", side_effect=device.adb_run
            ):
                provisioner.push_text_atomic(
                    BASE_CONF + "OTA_NODEMON=1\n", CONF_REMOTE
                )
        self.assertEqual(
            device.files[CONF_REMOTE], BASE_CONF + "OTA_NODEMON=1\n"
        )


class PostureTrustTest(unittest.TestCase):
    """The recorded posture judgment is trusted, not re-derived."""

    def test_trust_predicate(self) -> None:
        trusted = PortalProvisioner._recorded_posture_ota_trusted
        self.assertTrue(trusted(POSTURE_STATE))
        self.assertFalse(trusted({"actions": {"disable_updates": True}}))
        self.assertFalse(
            trusted(
                {
                    "actions": {"disable_updates": "unverified"},
                    "desired_state": {"alohausers_package": "disabled"},
                }
            )
        )
        self.assertFalse(trusted(None))
        self.assertFalse(trusted({}))

    def channel_provisioner(self, temporary: str) -> PortalProvisioner:
        provisioner = make_provisioner(temporary, disable_updates=True)
        provisioner.adb_run = lambda *a, **k: completed(a, "5555\n")
        provisioner._root_setup_blocker = lambda: None
        provisioner.ota_preflight = lambda: False
        return provisioner

    def test_channel_gate_trusts_the_posture_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.channel_provisioner(temporary)
            self.assertIsNone(provisioner._channel_blocker(POSTURE_STATE))

    def test_channel_gate_still_refuses_without_the_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.channel_provisioner(temporary)
            state = {"status": "complete", "actions": {"disable_updates": True}}
            self.assertEqual(
                provisioner._channel_blocker(state), "ota-not-configured"
            )

    def ota_provisioner(self, temporary: str, *, posture_holds: bool):
        provisioner = make_provisioner(temporary, disable_updates=True)
        provisioner._start_state = POSTURE_STATE

        def adb_run(args, timeout=None, check=False):
            command = " ".join(str(a) for a in args)
            if "pm list packages -d" in command:
                return completed(
                    args,
                    "package:com.facebook.aloha.otaui\n"
                    "package:com.facebook.aloha.alohaotasetup\n",
                )
            if "getprop otad.nodemon" in command:
                return completed(args, "true\n")
            if "cat" in command and "autoroot.conf" in command:
                return completed(args, BASE_CONF + "OTA_NODEMON=1\n")
            return completed(args, "")

        provisioner.adb_run = adb_run
        provisioner.alohausers_package_disabled = lambda: posture_holds
        provisioner._ota_override_present = lambda: True
        provisioner.read_ota_config = lambda wait_seconds=0: ({}, "")
        return provisioner

    def test_channel_verify_uses_the_posture_criteria(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.ota_provisioner(temporary, posture_holds=True)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                provisioner.verify_ota_block(wait_seconds=1, via_channel=True)
            self.assertIn("OTA_POSTURE_OK", stdout.getvalue())

    def test_channel_verify_falls_back_when_posture_broken(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.ota_provisioner(temporary, posture_holds=False)
            with self.assertRaises(ProvisionError):
                provisioner.verify_ota_block(wait_seconds=1, via_channel=True)

    def test_race_verify_never_uses_the_posture_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.ota_provisioner(temporary, posture_holds=True)
            with self.assertRaises(ProvisionError):
                provisioner.verify_ota_block(wait_seconds=1)


class OtaGatingPostureTrustTest(unittest.TestCase):
    """The fast-path gates trust the recorded posture for a
    completion a win-less run recorded "unverified".

    The live shape (Phase D closure session, 2026-11-19): a
    channel run on a boot where autoroot had not won ended with
    the posture judgment unverified — nodemon unset, the override
    unobservable — and its merged manifest recorded
    disable_updates "unverified". The next --full run's no-op
    gate refused on that action and its channel gate refused on
    ota-not-configured, so the finished device raced. The gates
    now apply the posture criteria a win-less boot can read; the
    record-based trust above cannot cover this shape because it
    requires a recorded plain done."""

    def gating_provisioner(
        self,
        temporary: str,
        *,
        conf_staged: bool = True,
        package_disabled: bool = True,
    ) -> PortalProvisioner:
        provisioner = test_fast_paths.make_provisioner(
            temporary, **test_fast_paths.DOCUMENTED
        )
        provisioner._ota_nodemon_conf_staged = lambda: conf_staged
        provisioner.alohausers_package_disabled = (
            lambda: package_disabled
        )
        return provisioner

    def channel_provisioner(
        self,
        temporary: str,
        *,
        conf_staged: bool = True,
        package_disabled: bool = True,
    ) -> PortalProvisioner:
        provisioner, _device = test_fast_paths.eligible_provisioner(
            temporary
        )
        provisioner.ota_preflight = lambda: False
        provisioner._ota_nodemon_conf_staged = lambda: conf_staged
        provisioner.alohausers_package_disabled = (
            lambda: package_disabled
        )
        return provisioner

    @staticmethod
    def unverified_posture_state(provisioner) -> dict:
        state = test_fast_paths.good_state(provisioner)
        state["actions"]["disable_updates"] = "unverified"
        state["desired_state"] = {"alohausers_package": "disabled"}
        return state

    def test_noop_gate_trusts_the_unverified_posture_record(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.gating_provisioner(temporary)
            state = self.unverified_posture_state(provisioner)
            self.assertIsNone(provisioner._noop_blocker(state))

    def test_channel_gate_trusts_the_unverified_posture_record(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.channel_provisioner(temporary)
            state = self.unverified_posture_state(provisioner)
            self.assertIsNone(provisioner._channel_blocker(state))

    def test_each_precondition_removed_returns_the_blocker(
        self,
    ) -> None:
        variants = (
            ("no-posture-record", {}, True, True),
            (
                "posture-record-enabled",
                {"desired_state": {"alohausers_package": "enabled"}},
                True,
                True,
            ),
            ("conf-not-staged", None, False, True),
            ("package-not-disabled", None, True, False),
        )
        for label, state_override, conf_staged, package_disabled in (
            variants
        ):
            with self.subTest(precondition=label):
                with tempfile.TemporaryDirectory() as temporary:
                    provisioner = self.gating_provisioner(
                        temporary,
                        conf_staged=conf_staged,
                        package_disabled=package_disabled,
                    )
                    state = self.unverified_posture_state(provisioner)
                    if state_override is not None:
                        if state_override:
                            state.update(state_override)
                        else:
                            del state["desired_state"]
                    self.assertEqual(
                        provisioner._noop_blocker(state),
                        "actions-disable_updates",
                    )
                    channel = self.channel_provisioner(
                        temporary,
                        conf_staged=conf_staged,
                        package_disabled=package_disabled,
                    )
                    self.assertEqual(
                        channel._channel_blocker(state),
                        "ota-not-configured",
                    )

    def test_non_posture_record_is_unaffected(self) -> None:
        """Live reads holding is not enough on its own: without
        the recorded posture the unverified action blocks both
        gates exactly as before."""
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.gating_provisioner(temporary)
            state = self.unverified_posture_state(provisioner)
            del state["desired_state"]
            self.assertEqual(
                provisioner._noop_blocker(state),
                "actions-disable_updates",
            )
            channel = self.channel_provisioner(temporary)
            self.assertEqual(
                channel._channel_blocker(state), "ota-not-configured"
            )

    def test_posture_judgment_itself_is_unchanged(self) -> None:
        """The trust is gating-only: the end-of-run posture
        judgment still fails a device whose nodemon is unset and
        whose override is unobserved, even with every gating
        precondition holding — a run that applies OTA records
        nothing verified from the trust path."""
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, disable_updates=True
            )
            provisioner.alohausers_package_disabled = lambda: True
            provisioner._ota_nodemon_conf_staged = lambda: True
            provisioner._ota_override_present = lambda: False
            provisioner.adb_run = lambda args, **k: completed(args, "")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(provisioner._judge_ota_posture())


class MetaPostureTrustTest(unittest.TestCase):
    """The channel gate's meta-accounts clause trusts the recorded
    posture the way the OTA clause does: the preflight's
    already_clean requires the alohausers package NOT disabled, so
    it is unreachable on a posture device even when the removal's
    end state holds. The record overrides only the package clause;
    the preflight's live reads must still hold."""

    def channel_provisioner(
        self,
        temporary: str,
        *,
        accounts_absent: bool,
        package_disabled: bool,
        authenticators_disabled: bool,
    ) -> PortalProvisioner:
        provisioner = make_provisioner(temporary, remove_meta_accounts=True)
        provisioner.adb_run = lambda *a, **k: completed(a, "5555\n")
        provisioner.adb_framework_boot_configured = True
        provisioner._root_setup_blocker = lambda: None

        def preflight() -> bool:
            provisioner.meta_accounts_absent = accounts_absent
            provisioner.meta_accounts_package_disabled = package_disabled
            return False

        provisioner.meta_accounts_preflight = preflight
        provisioner.disabled_meta_authenticators = lambda: (
            set(META_AUTHENTICATOR_COMPONENTS)
            if authenticators_disabled
            else set()
        )
        return provisioner

    def test_posture_record_satisfies_the_meta_clause(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.channel_provisioner(
                temporary,
                accounts_absent=True,
                package_disabled=True,
                authenticators_disabled=True,
            )
            self.assertIsNone(provisioner._channel_blocker(POSTURE_STATE))

    def test_same_live_reads_without_the_record_still_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.channel_provisioner(
                temporary,
                accounts_absent=True,
                package_disabled=True,
                authenticators_disabled=True,
            )
            state = {"status": "complete", "actions": {}}
            self.assertEqual(
                provisioner._channel_blocker(state), "meta-accounts-not-clean"
            )

    def test_posture_record_with_accounts_present_still_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.channel_provisioner(
                temporary,
                accounts_absent=False,
                package_disabled=True,
                authenticators_disabled=True,
            )
            self.assertEqual(
                provisioner._channel_blocker(POSTURE_STATE),
                "meta-accounts-not-clean",
            )

    def test_posture_record_with_authenticators_live_still_refuses(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.channel_provisioner(
                temporary,
                accounts_absent=True,
                package_disabled=True,
                authenticators_disabled=False,
            )
            self.assertEqual(
                provisioner._channel_blocker(POSTURE_STATE),
                "meta-accounts-not-clean",
            )


class DnsGateConfirmReadTest(unittest.TestCase):
    """The run-8 shape: one disagreeing sample is not drift."""

    STATE = {"actions": {"dhcp_dns": True}}

    def provisioner(self, temporary: str, readings: list) -> PortalProvisioner:
        provisioner = make_provisioner(temporary)
        provisioner.read_private_dns_state = mock.Mock(side_effect=readings)
        return provisioner

    def test_single_bad_sample_is_not_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(
                temporary, [("hostname", "one.one.one.one"), ("off", "null")]
            )
            with mock.patch.object(time, "sleep", lambda *_: None):
                self.assertIsNone(provisioner._dns_drift(self.STATE))
            self.assertEqual(provisioner.read_private_dns_state.call_count, 2)

    def test_matching_first_sample_reads_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary, [("off", "null")])
            self.assertIsNone(provisioner._dns_drift(self.STATE))
            self.assertEqual(provisioner.read_private_dns_state.call_count, 1)

    def test_confirmed_drift_reports_with_live_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(
                temporary,
                [("hostname", "one.one.one.one"), ("hostname", "one.one.one.one")],
            )
            with mock.patch.object(time, "sleep", lambda *_: None):
                self.assertEqual(
                    provisioner._dns_drift(self.STATE), ("off", "null")
                )
            self.assertEqual(
                provisioner._dns_drift_live, ("hostname", "one.one.one.one")
            )

    def test_unreadable_on_both_reads_still_counts_as_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(
                temporary,
                [ProvisionError("io"), ProvisionError("io")],
            )
            with mock.patch.object(time, "sleep", lambda *_: None):
                self.assertEqual(
                    provisioner._dns_drift(self.STATE), ("off", "null")
                )
            self.assertIsNone(provisioner._dns_drift_live)


class PostureDriftNoopTest(unittest.TestCase):
    """A re-enabled alohausers package blocks the no-op exit."""

    def test_posture_drift_predicate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            provisioner.alohausers_package_disabled = lambda: False
            self.assertEqual(
                provisioner._posture_drift(POSTURE_STATE), "alohausers-enabled"
            )
            provisioner.alohausers_package_disabled = lambda: True
            self.assertIsNone(provisioner._posture_drift(POSTURE_STATE))
            self.assertIsNone(provisioner._posture_drift({"status": "complete"}))

    def fast_path(self, temporary: str, *, package_disabled: bool):
        provisioner, device = test_fast_paths.eligible_provisioner(temporary)
        state = test_fast_paths.good_state(provisioner)
        state["desired_state"] = {"alohausers_package": "disabled"}
        provisioner.read_state = lambda: state
        provisioner.alohausers_package_disabled = lambda: package_disabled
        applied: list[str] = []
        provisioner._apply_via_channel = lambda blocker: (
            applied.append(blocker) or True
        )
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = provisioner._run_fast_path()
        return result, applied, stdout.getvalue()

    def test_posture_holding_still_noops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, applied, output = self.fast_path(
                temporary, package_disabled=True
            )
        self.assertTrue(result)
        self.assertEqual(applied, [])
        self.assertIn("PROVISION_NOOP", output)

    def test_posture_drift_routes_to_the_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, applied, output = self.fast_path(
                temporary, package_disabled=False
            )
        self.assertTrue(result)
        self.assertEqual(applied, ["alohausers-enabled"])
        self.assertNotIn("PROVISION_NOOP ", output)


class PostureApplyTest(unittest.TestCase):
    """The end-of-run posture apply through the payload daemon."""

    def provisioner(self, temporary: str, *, disabled: bool):
        provisioner = make_provisioner(
            temporary,
            remove_meta_accounts=True,
            custom_payload=provision_portal.DEFAULT_CUSTOM_PAYLOAD_LOCAL,
        )
        provisioner._alohausers_disabled_at_start = True
        state = {"disabled": disabled}
        commands: list[str] = []

        def daemon_exec(command: str, timeout: int = 40):
            commands.append(command)
            state["disabled"] = True
            return 0, "done"

        provisioner.daemon_exec = daemon_exec
        provisioner.alohausers_package_disabled = lambda: state["disabled"]
        return provisioner, state, commands

    def test_apply_disables_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _state, commands = self.provisioner(
                temporary, disabled=False
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                provisioner._apply_recorded_posture()
            self.assertIn("ALOHAUSERS_POSTURE_APPLIED", stdout.getvalue())
            self.assertEqual(len(commands), 1)
            self.assertIn("pm disable", commands[0])
            self.assertEqual(provisioner.deferred_phase_failures, [])

    def test_already_disabled_is_a_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _state, commands = self.provisioner(
                temporary, disabled=True
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                provisioner._apply_recorded_posture()
            self.assertIn("ALOHAUSERS_POSTURE_OK", stdout.getvalue())
            self.assertEqual(commands, [])

    def test_failed_apply_is_deferred_not_silent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _state, _commands = self.provisioner(
                temporary, disabled=False
            )
            provisioner.daemon_exec = lambda command, timeout=40: (1, "nope")
            with contextlib.redirect_stdout(io.StringIO()):
                provisioner._apply_recorded_posture()
            self.assertEqual(len(provisioner.deferred_phase_failures), 1)
            self.assertIn(
                "alohausers_posture", provisioner.deferred_phase_failures[0]
            )

    def test_no_recorded_desire_no_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _state, commands = self.provisioner(
                temporary, disabled=False
            )
            provisioner._alohausers_disabled_at_start = False
            with contextlib.redirect_stdout(io.StringIO()):
                provisioner._apply_recorded_posture()
            self.assertEqual(commands, [])


class PostureBootstrapTest(unittest.TestCase):
    """Defect J: the end-of-run posture step establishes the
    posture for a run that stages it, and the desired-state
    record follows the run's own end state."""

    def provisioner(self, temporary: str, *, disabled: bool, daemon_ok: bool = True):
        provisioner = make_provisioner(
            temporary,
            remove_meta_accounts=True,
            disable_updates=True,
            autoroot=True,
            custom_payload=provision_portal.DEFAULT_CUSTOM_PAYLOAD_LOCAL,
        )
        provisioner._alohausers_disabled_at_start = False
        state = {"disabled": disabled}
        commands: list[str] = []

        def daemon_exec(command: str, timeout: int = 40):
            commands.append(command)
            if daemon_ok:
                state["disabled"] = True
                return 0, "done"
            return 1, "nope"

        provisioner.daemon_exec = daemon_exec
        provisioner.alohausers_package_disabled = lambda: state["disabled"]
        provisioner._ota_nodemon_conf_staged = lambda: True
        return provisioner, state, commands

    def test_drifted_full_run_records_from_its_end_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _state, commands = self.provisioner(
                temporary, disabled=False
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                provisioner._apply_recorded_posture()
            self.assertIn("ALOHAUSERS_POSTURE_APPLIED", stdout.getvalue())
            self.assertEqual(len(commands), 1)
            self.assertIn("pm disable", commands[0])
            self.assertEqual(provisioner.deferred_phase_failures, [])
            # The desire is recorded from the run's own end state,
            # although the run started enabled and no earlier
            # record exists.
            self.assertEqual(
                provisioner._desired_state(),
                {"alohausers_package": "disabled"},
            )
            # And the staging resolver renders the staged conf's
            # ALOHAUSERS_DISABLED key from that record.
            feature = StagingDesiredTest().feature(
                desired=provisioner._desired_state()
            )
            self.assertTrue(feature._alohausers_disabled_desired())

    def test_drifted_run_finding_the_package_disabled_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _state, commands = self.provisioner(
                temporary, disabled=True
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                provisioner._apply_recorded_posture()
            self.assertIn("ALOHAUSERS_POSTURE_OK", stdout.getvalue())
            self.assertEqual(commands, [])
            self.assertEqual(
                provisioner._desired_state(),
                {"alohausers_package": "disabled"},
            )

    def test_run_ending_enabled_records_no_posture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _state, _commands = self.provisioner(
                temporary, disabled=False, daemon_ok=False
            )
            with contextlib.redirect_stdout(io.StringIO()):
                provisioner._apply_recorded_posture()
            self.assertEqual(len(provisioner.deferred_phase_failures), 1)
            self.assertIn(
                "alohausers_posture", provisioner.deferred_phase_failures[0]
            )
            # No false posture claim: the run ends enabled and
            # records no disabled desire.
            self.assertEqual(provisioner._desired_state(), {})

    def test_no_daemon_channel_records_no_posture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner, _state, commands = self.provisioner(
                temporary, disabled=False
            )
            provisioner.custom_payload = pathlib.Path("other-payload.bin")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                provisioner._apply_recorded_posture()
            self.assertIn("ALOHAUSERS_POSTURE_DEFERRED", stdout.getvalue())
            self.assertEqual(commands, [])
            self.assertEqual(provisioner._desired_state(), {})

    def test_completion_write_records_the_end_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            provisioner.alohausers_package_disabled = lambda: True
            provisioner._ota_nodemon_conf_staged = lambda: True
            captured: dict = {}
            provisioner.adb_run = lambda *a, **k: completed(
                a, "fingerprint\n"
            )
            with mock.patch.object(
                provisioner.run_state,
                "write_state",
                side_effect=lambda status, **kw: captured.update(kw),
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    provisioner.write_state("complete")
            self.assertEqual(
                captured.get("desired_state"),
                {"alohausers_package": "disabled"},
            )

    def test_completion_write_ending_enabled_records_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            provisioner.alohausers_package_disabled = lambda: False
            provisioner._ota_nodemon_conf_staged = lambda: True
            captured: dict = {}
            provisioner.adb_run = lambda *a, **k: completed(
                a, "fingerprint\n"
            )
            with mock.patch.object(
                provisioner.run_state,
                "write_state",
                side_effect=lambda status, **kw: captured.update(kw),
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    provisioner.write_state("complete")
            self.assertIsNone(captured.get("desired_state"))


class MetaVerifyPostureTest(unittest.TestCase):
    """verify_meta_accounts_removed accepts the recorded posture."""

    def feature(self, *, desired_disabled: bool) -> SettingsFeature:
        def adb_run(args, timeout=None, check=False):
            return completed(
                args, "package:com.facebook.alohaservices.alohausers\n"
            )

        feature = SettingsFeature(
            adb_run=adb_run,
            log_dir=pathlib.Path(tempfile.gettempdir()),
            target=lambda: ALOHA,
            config=lambda: None,
            ensure_adb_framework_enabled=lambda: None,
            push_text_atomic=lambda *a, **k: None,
            settle_package_state=lambda *a, **k: None,
            package_sets=lambda: (set(), set()),
            current_component_states=lambda: {},
            current_named_component_states=lambda components: {},
            meta_accounts=lambda: [],
            disabled_meta_authenticators=lambda: set(
                META_AUTHENTICATOR_COMPONENTS
            ),
            read_component_backup=lambda required=True: None,
            read_remote_wipe_backup=lambda required=True: None,
            ensure_remote_wipe_backup=lambda: {},
            alohausers_desired_disabled=lambda: desired_disabled,
        )
        feature.verify_retained_platform = lambda **k: None
        return feature

    def test_disabled_package_passes_under_the_posture(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.feature(desired_disabled=True).verify_meta_accounts_removed()
        self.assertIn("alohausers=disabled-posture", stdout.getvalue())

    def test_disabled_package_still_fails_without_the_posture(self) -> None:
        with self.assertRaises(ProvisionError):
            self.feature(desired_disabled=False).verify_meta_accounts_removed()


if __name__ == "__main__":
    unittest.main()
