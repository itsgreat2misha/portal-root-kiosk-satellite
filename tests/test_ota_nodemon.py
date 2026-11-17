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

import provision_portal  # noqa: E402
from provision_portal import PortalProvisioner  # noqa: E402
from portal_targets import TARGETS  # noqa: E402


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


def make_provisioner(temporary: str, target=ALOHA, **kwargs) -> PortalProvisioner:
    provisioner = PortalProvisioner(
        "192.0.2.1:5555", 1, pathlib.Path(temporary), **kwargs
    )
    provisioner.target = target
    return provisioner


def completed(args, stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args, returncode, stdout, "")


class PostPayloadNodemonTest(unittest.TestCase):
    """The in-run set: daemon EXEC + independent getprop read-back."""

    def run_steps(self, provisioner, daemon_result, getprop_value: str):
        def adb_run(args, timeout=None, check=False):
            if args[:3] == ["shell", "getprop", "otad.nodemon"]:
                return completed(args, getprop_value + "\n")
            return completed(args)

        stdout = io.StringIO()
        with (
            mock.patch.object(
                provisioner.payload_feature,
                "daemon_exec",
                return_value=daemon_result,
            ) as daemon_exec,
            mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
            contextlib.redirect_stdout(stdout),
        ):
            provisioner.apply_post_payload_root_steps()
        return daemon_exec, stdout.getvalue()

    def test_set_and_marker_on_aloha_disable_updates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            daemon_exec, output = self.run_steps(provisioner, (0, ""), "true")
        daemon_exec.assert_called_once_with("setprop otad.nodemon true")
        self.assertIn("OTA_NODEMON_SET property=otad.nodemon value=true", output)

    def test_readback_mismatch_reports_failure_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            daemon_exec, output = self.run_steps(provisioner, (0, ""), "false")
        daemon_exec.assert_called_once_with("setprop otad.nodemon true")
        self.assertIn("OTA_NODEMON_SET_FAILED", output)
        self.assertIn("value='false'", output)

    def test_daemon_failure_reports_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            _daemon_exec, output = self.run_steps(provisioner, (1, ""), "true")
        self.assertIn("OTA_NODEMON_SET_FAILED", output)
        self.assertIn("exit=1", output)

    def test_skipped_without_disable_updates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            daemon_exec, output = self.run_steps(provisioner, (0, ""), "true")
        daemon_exec.assert_not_called()
        self.assertNotIn("OTA_NODEMON", output)

    def test_skipped_on_omni(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, target=OMNI, disable_updates=True
            )
            daemon_exec, output = self.run_steps(provisioner, (0, ""), "true")
        daemon_exec.assert_not_called()
        self.assertNotIn("OTA_NODEMON", output)


class AutorootConfNodemonTest(unittest.TestCase):
    """The staged autoroot.conf OTA_NODEMON key."""

    def build_provisioner(self, temporary: str, target=ALOHA, **kwargs):
        provisioner = make_provisioner(
            temporary,
            target=target,
            shizuku=True,
            autoroot=True,
            custom_payload=pathlib.Path("daemon.bin"),
            **kwargs,
        )
        apk = pathlib.Path(temporary) / "helper.apk"
        apk.write_bytes(b"apk")
        runner = pathlib.Path(temporary) / "run.sh"
        runner.write_text("#!/bin/sh\n", encoding="utf-8")
        for patcher in (
            mock.patch.object(provision_portal, "AUTOROOT_HELPER_LOCAL", apk),
            mock.patch.object(provision_portal, "AUTOROOT_RUNNER_LOCAL", runner),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        return provisioner

    def run_staging(self, provisioner, existing_conf: str):
        pushes: dict[str, str] = {}

        def adb_run(args, timeout=None, check=False):
            if args[:3] == ["shell", "pm", "path"]:
                return completed(args, "package:/data/app/~~s/base.apk\n")
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
            if args and args[0] == "uninstall":
                return completed(args, "Success\n")
            return completed(args)

        with (
            mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
            mock.patch.object(provisioner, "install_apk_preserving_verifier"),
            mock.patch.object(provisioner, "settle_package_state"),
            mock.patch.object(
                provisioner, "package_sets", return_value=(set(), set())
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            provisioner.stage_autoroot_payload()
        return pushes[CONF_REMOTE]

    def test_disable_updates_stages_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary, disable_updates=True)
            conf = self.run_staging(provisioner, "")
        self.assertIn("OTA_NODEMON=1\n", conf)

    def test_no_updates_request_leaves_the_key_out(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary)
            conf = self.run_staging(provisioner, BASE_CONF)
        self.assertNotIn("OTA_NODEMON", conf)

    def test_no_updates_request_preserves_a_staged_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary)
            conf = self.run_staging(provisioner, BASE_CONF + "OTA_NODEMON=1\n")
        self.assertIn("OTA_NODEMON=1\n", conf)

    def test_enable_updates_clears_a_staged_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary, enable_updates=True)
            conf = self.run_staging(provisioner, BASE_CONF + "OTA_NODEMON=1\n")
        self.assertNotIn("OTA_NODEMON", conf)

    def test_omni_never_stages_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(
                temporary, target=OMNI, disable_updates=True
            )
            conf = self.run_staging(provisioner, "")
        self.assertNotIn("OTA_NODEMON", conf)


class NodemonConfSyncTest(unittest.TestCase):
    """Later updates-state runs rewrite the staged key in place."""

    def run_sync(self, provisioner, existing_conf: str, staged: bool = True):
        pushes: dict[str, str] = {}
        calls: list[list[str]] = []

        def adb_run(args, timeout=None, check=False):
            calls.append(args)
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
            provisioner.sync_ota_nodemon_autoroot_conf()
        return pushes, calls, stdout.getvalue()

    def test_enable_updates_removes_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, enable_updates=True)
            pushes, _calls, output = self.run_sync(
                provisioner, BASE_CONF + "OTA_NODEMON=1\n"
            )
        self.assertEqual(pushes[CONF_REMOTE + ".tmp"], BASE_CONF)
        self.assertIn("OTA_NODEMON_CONF_SYNC value=0", output)

    def test_disable_updates_adds_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            pushes, _calls, output = self.run_sync(provisioner, BASE_CONF)
        self.assertEqual(
            pushes[CONF_REMOTE + ".tmp"], BASE_CONF + "OTA_NODEMON=1\n"
        )
        self.assertIn("OTA_NODEMON_CONF_SYNC value=1", output)

    def test_no_change_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            pushes, _calls, output = self.run_sync(
                provisioner, BASE_CONF + "OTA_NODEMON=1\n"
            )
        self.assertEqual(pushes, {})
        self.assertNotIn("OTA_NODEMON_CONF_SYNC", output)

    def test_no_updates_request_touches_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            pushes, calls, _output = self.run_sync(
                provisioner, BASE_CONF + "OTA_NODEMON=1\n"
            )
        self.assertEqual(pushes, {})
        self.assertEqual(calls, [])

    def test_unstaged_device_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, enable_updates=True)
            pushes, _calls, _output = self.run_sync(
                provisioner, BASE_CONF + "OTA_NODEMON=1\n", staged=False
            )
        self.assertEqual(pushes, {})

    def test_omni_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, target=OMNI, enable_updates=True
            )
            pushes, calls, _output = self.run_sync(
                provisioner, BASE_CONF + "OTA_NODEMON=1\n"
            )
        self.assertEqual(pushes, {})
        self.assertEqual(calls, [])


class NodemonStatusTest(unittest.TestCase):
    def test_status_reports_the_property(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)

            def adb_run(args, timeout=None, check=False):
                if args[:3] == ["shell", "getprop", "otad.nodemon"]:
                    return completed(args, "true\n")
                if args[:2] == ["shell", "cat"]:
                    # Backup/state files signal absence with a
                    # failing cat, not with empty contents.
                    return completed(args, returncode=1)
                return completed(args)

            with mock.patch.object(
                provisioner, "adb_run", side_effect=adb_run
            ):
                status = provisioner.collect_status()
        self.assertEqual(status["updates"]["nodemon"], "true")


if __name__ == "__main__":
    unittest.main()
