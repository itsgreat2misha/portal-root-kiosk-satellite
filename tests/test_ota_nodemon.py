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


class NodemonEnvGatingTest(unittest.TestCase):
    """GHOSTLOCK_OTA_NODEMON phase gating in build_exploit_environment.

    The key may appear only in the standard-install attempts, whose
    action child clones init's credential (no per-phase credential
    source, no preserved shell domain): the only context the
    property service accepts otad.nodemon writes from. The dedicated
    OTA phase clones the OTA installer credential, the backend phase
    clones system_server, and the payload phase preserves the shell
    domain, so the key stays out of all three.
    """

    def build_environment(self, provisioner):
        calls: list[list[str]] = []

        def adb_run(arguments, timeout=None, check=False):
            del timeout, check
            calls.append(arguments)
            value = (
                "1204" if arguments[:2] == ["shell", "pidof"] else "1000"
            )
            return completed(arguments, value + "\n")

        with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
            environment = provisioner.build_exploit_environment(
                0x1000, 0x2000, 1
            )
        return environment, calls

    def test_combined_aloha_env_carries_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, audio=True, disable_updates=True
            )
            environment, calls = self.build_environment(provisioner)
        self.assertEqual(environment["GHOSTLOCK_OTA_NODEMON"], "1")
        self.assertNotIn("GHOSTLOCK_ACTION_CREDENTIAL_PID", environment)
        self.assertNotIn("GHOSTLOCK_ACTION_PRESERVE_SELINUX", environment)
        self.assertFalse(
            any(call[:2] == ["shell", "pidof"] for call in calls),
            "combined attempts must not resolve a credential identity",
        )
        # Sanity: the combined environment really was built, with
        # the run's other actions present.
        self.assertEqual(environment["GHOSTLOCK_AUDIO_PERSIST"], "1")

    def test_dedicated_ota_phase_env_omits_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, disable_updates=True)
            environment, calls = self.build_environment(provisioner)
        self.assertIn(["shell", "pidof", "installd"], calls)
        self.assertEqual(environment["GHOSTLOCK_OTA_BLOCK"], "1")
        self.assertNotIn("GHOSTLOCK_OTA_NODEMON", environment)

    def test_backend_phase_env_omits_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, disable_updates=True, ota_backend_value="true"
            )
            environment, _calls = self.build_environment(provisioner)
        self.assertEqual(environment["GHOSTLOCK_OTA_BACKEND_VALUE"], "true")
        self.assertNotIn("GHOSTLOCK_OTA_NODEMON", environment)

    def test_payload_phase_env_omits_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                disable_updates=True,
                custom_payload=pathlib.Path("daemon.bin"),
            )
            provisioner._in_custom_payload_phase = True
            environment, _calls = self.build_environment(provisioner)
        self.assertEqual(environment["GHOSTLOCK_CUSTOM_PAYLOAD"], "1")
        self.assertEqual(
            environment["GHOSTLOCK_ACTION_PRESERVE_SELINUX"], "1"
        )
        self.assertNotIn("GHOSTLOCK_OTA_NODEMON", environment)

    def test_omni_env_omits_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, target=OMNI, audio=True, disable_updates=True
            )
            environment, _calls = self.build_environment(provisioner)
        self.assertNotIn("GHOSTLOCK_OTA_NODEMON", environment)

    def test_no_disable_updates_omits_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, audio=True)
            environment, _calls = self.build_environment(provisioner)
        self.assertNotIn("GHOSTLOCK_OTA_NODEMON", environment)


class NodemonNativeActionTest(unittest.TestCase):
    """The native action's context contract, pinned in source."""

    def test_action_markers_and_dispatch(self) -> None:
        fops = (ROOT / "exploit/src/fops.c").read_text(encoding="utf-8")
        self.assertIn("OTA_NODEMON_SET property=%s value=true", fops)
        self.assertIn("OTA_NODEMON_SET_FAILED", fops)
        self.assertIn('getenv("GHOSTLOCK_OTA_NODEMON")', fops)
        self.assertIn("spawn_configfs_nodemon_child()", fops)
        self.assertIn("install_nodemon_child_context(fd)", fops)
        self.assertIn("collect_configfs_nodemon_child()", fops)

    def test_child_context_helper_clears_the_phase_entries(self) -> None:
        root = (ROOT / "exploit/src/root.c").read_text(encoding="utf-8")
        self.assertIn("run_ota_nodemon_action()", root)
        helper = root[root.index("int install_nodemon_child_context"):]
        for name in (
            "GHOSTLOCK_ADBD_PID",
            "GHOSTLOCK_ACTION_CREDENTIAL_PID",
            "GHOSTLOCK_ACTION_PRESERVE_SELINUX",
            "GHOSTLOCK_ACTION_EXPECT_UID",
        ):
            self.assertIn(name, helper)


class NodemonRunnerTest(unittest.TestCase):
    """The staged runner turns the conf key into the payload env key."""

    def test_runner_exports_the_key_from_the_conf(self) -> None:
        runner = (ROOT / "autoroot-helper" / "run.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "grep -q '^OTA_NODEMON=1$' \"$DIR/autoroot.conf\"", runner
        )
        self.assertIn("export GHOSTLOCK_OTA_NODEMON=1", runner)
        # The conf is read before the env files are sourced (after
        # sourcing, every command runs under the exploit preload),
        # and the export lands inside the attempt subshell.
        conf_read = runner.index('"$DIR/autoroot.conf"')
        env_source = runner.index('. "$ENV_FILE"')
        export = runner.index("export GHOSTLOCK_OTA_NODEMON=1")
        self.assertLess(conf_read, env_source)
        self.assertLess(env_source, export)


class NodemonHelperRemovalTest(unittest.TestCase):
    """The helper's shell-domain setprop re-assert is gone: the
    property service refuses the write from that domain, so the
    re-assert only ever logged refusals."""

    def test_helper_no_longer_sets_the_property(self) -> None:
        service = (
            ROOT
            / "autoroot-helper/src/dev/portal/autoroothelper"
            / "AutorootService.java"
        ).read_text(encoding="utf-8")
        self.assertNotIn("reassertOtaNodemon", service)
        self.assertNotIn("setprop otad.nodemon", service)


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
