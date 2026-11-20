# SPDX-License-Identifier: Apache-2.0
# Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
# See LICENSE and NOTICE.

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import provision_portal as provision_portal_module  # noqa: E402

from provision_portal import (  # noqa: E402
    DIAGNOSTICS_PRELOAD_REMOTE,
    PROVISIONER_VERSION,
    PortalProvisioner,
    parse_args,
)
from portal_targets import TARGETS  # noqa: E402


UNSUPPORTED_FINGERPRINT = (
    "Facebook/omni_prod/omni:10/QKQ1.210213.001/"
    "3051392000014050:user/prod-keys"
)


def _completed(returncode: int = 0, stdout: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, "")


class _FakeDiagnosticsDevice:
    """adb_run stand-in for an unsupported omni build."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args, timeout=None, check=False):
        args = [str(arg) for arg in args]
        self.calls.append(args)
        if args[:2] == ["shell", "getprop"] and len(args) == 3:
            values = {
                "ro.build.fingerprint": UNSUPPORTED_FINGERPRINT,
                "ro.product.device": "omni",
                "ro.product.model": "PortalMini",
                "persist.sys.mobileconfigutil.usePlatformMobileConfig": (
                    "true"
                ),
            }
            return _completed(0, values.get(args[2], "") + "\n")
        if args == ["shell", "getprop"]:
            return _completed(
                0, "[ro.product.device]: [omni]\n[ro.product.model]: "
                "[PortalMini]\n"
            )
        if args == ["shell", "uname", "-a"]:
            return _completed(
                0,
                "Linux localhost 4.9.227-perf+ #1 SMP PREEMPT "
                "Mon Sep 22 00:00:00 UTC 2026 aarch64\n",
            )
        if args == ["shell", "cat", "/proc/version"]:
            return _completed(0, "Linux version 4.9.227-perf+\n")
        if args == ["shell", "nproc"]:
            return _completed(0, "8\n")
        if args == ["shell", "head", "-n", "100", "/proc/cpuinfo"]:
            return _completed(0, "processor\t: 0\n")
        if args == ["shell", "pm", "list", "packages"]:
            return _completed(
                0,
                "package:com.facebook.aloha.otaui\n"
                "package:com.facebook.aloha.platformmobileconfig\n"
                "package:com.android.settings\n",
            )
        if args == ["shell", "dumpsys", "activity", "services"]:
            return _completed(
                0,
                "  * ServiceRecord MobileConfigService\n"
                "  * ServiceRecord OtherService\n",
            )
        if args == ["shell", "bugreportz", "-p"]:
            return _completed(0, "OK:/data/local/tmp/bugreport-x.zip\n")
        if args[0] == "pull":
            local = pathlib.Path(args[2])
            with zipfile.ZipFile(local, "w") as archive:
                archive.writestr(
                    "bugreport-omni.txt",
                    "memory : 0xffffffc000000000 - 0xffffffc080000000\n",
                )
            return _completed(0, "1 file pulled\n")
        if args[0] == "push":
            return _completed(0, "1 file pushed\n")
        if args[:1] == ["shell"] and "GHOSTLOCK_DIAG_PAGE_PREP_ONLY=1" in (
            args[1] if len(args) > 1 else ""
        ):
            return _completed(
                0,
                "page collisions verified 7/7\n"
                "KernelSnitch mm_struct leak failed\n",
            )
        if args == ["shell", "base64", "/proc/config.gz"]:
            return _completed(1, "")
        if args == ["shell", "head", "-c", "65536", "/proc/kallsyms"]:
            return _completed(
                0, "0000000000000000 t _text\n0000000000000000 T _stext\n"
            )
        if args[:2] == ["shell", "rm"]:
            return _completed(0, "")
        raise AssertionError(f"unexpected adb call: {args}")


class CollectDiagnosticsTest(unittest.TestCase):
    def test_unsupported_build_produces_bundle(self) -> None:
        omni = next(
            target for target in TARGETS if target.device == "omni"
        )
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            log_dir = temporary_path / "logs"
            fake_root = temporary_path / "repo"
            preload = fake_root / "exploit" / "build" / omni.preload_name
            preload.parent.mkdir(parents=True)
            preload.write_bytes(b"fake preload")
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, log_dir, collect_diagnostics=True
            )
            device = _FakeDiagnosticsDevice()
            provisioner.adb_run = device  # type: ignore[method-assign]
            output = io.StringIO()
            with (
                mock.patch.object(
                    provision_portal_module, "ROOT", fake_root
                ),
                mock.patch.object(sys, "stdout", output),
            ):
                target = provisioner.verify_target(
                    require_supported=False
                )
                bundle_path = provisioner.collect_diagnostics_bundle()

            self.assertIsNone(target)
            self.assertTrue(bundle_path.is_file())
            self.assertIn("TARGET_UNSUPPORTED", output.getvalue())
            self.assertIn("DIAGNOSTICS_OK bundle=", output.getvalue())
            # The pushed diagnostic preload is removed again.
            self.assertIn(
                ["shell", "rm", "-f", DIAGNOSTICS_PRELOAD_REMOTE],
                device.calls,
            )
            with zipfile.ZipFile(bundle_path) as archive:
                names = set(archive.namelist())
                manifest = json.loads(archive.read("manifest.json"))
                packages = archive.read(
                    "mobileconfig-packages.txt"
                ).decode()
            self.assertTrue(
                {
                    "manifest.json",
                    "getprop.txt",
                    "uname.txt",
                    "proc-version.txt",
                    "nproc.txt",
                    "cpuinfo.txt",
                    "mobileconfig-backend.txt",
                    "mobileconfig-packages.txt",
                    "mobileconfig-services.txt",
                    "bugreport.zip",
                    "page-prep-diag.txt",
                    "proc-kallsyms.txt",
                }
                <= names
            )
            # config.gz is not readable at shell privilege: attempted,
            # recorded, and absent from the bundle.
            self.assertNotIn("proc-config.gz", names)
            self.assertEqual(manifest["kind"], "portal-diagnostics")
            self.assertEqual(
                manifest["tool_version"], PROVISIONER_VERSION
            )
            self.assertEqual(manifest["model"], "PortalMini")
            self.assertEqual(manifest["device"], "omni")
            self.assertEqual(
                manifest["fingerprint"], UNSUPPORTED_FINGERPRINT
            )
            self.assertIsNone(manifest["supported_target"])
            self.assertEqual(manifest["sibling_target"], omni.key)
            items = manifest["items"]
            self.assertEqual(items["getprop"]["status"], "collected")
            self.assertEqual(items["bugreport"]["status"], "collected")
            self.assertEqual(
                items["page_prep_diag"]["status"], "collected"
            )
            self.assertIn(
                "FAILED", items["page_prep_diag"]["detail"]
            )
            self.assertEqual(
                items["mobileconfig_backend"]["status"], "collected"
            )
            self.assertIn(
                "usePlatformMobileConfig=true",
                items["mobileconfig_backend"]["detail"],
            )
            self.assertEqual(
                items["proc_config_gz"]["status"], "attempted"
            )
            self.assertIn(
                "platformmobileconfig", packages
            )
            self.assertNotIn("com.android.settings", packages)

    def test_provision_routes_to_diagnostics_without_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                collect_diagnostics=True,
            )
            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner, "verify_target", return_value=None
                ) as verify,
                mock.patch.object(
                    provisioner, "collect_diagnostics_bundle"
                ) as collect,
                mock.patch.object(
                    provisioner,
                    "_engage_autoroot_guard",
                    side_effect=AssertionError("guard must not engage"),
                ),
            ):
                provisioner.provision()
            verify.assert_called_once_with(require_supported=False)
            collect.assert_called_once_with()


class CollectDiagnosticsCliTest(unittest.TestCase):
    def parse(self, argv):
        with mock.patch.object(
            sys, "argv", ["provision_portal.py", *argv]
        ):
            return parse_args()

    def test_flag_parses_and_does_not_default_to_audio(self) -> None:
        arguments = self.parse(["--collect-diagnostics"])

        self.assertTrue(arguments.collect_diagnostics)
        self.assertFalse(arguments.audio)

    def test_flag_rejects_provisioning_actions(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            self.parse(["--collect-diagnostics", "--audio"])

    def test_flag_is_mutually_exclusive_with_status(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            self.parse(["--collect-diagnostics", "--status"])


def _exploit_with_process(
    provisioner: PortalProvisioner, script: str, output: io.StringIO
) -> bool:
    """Run exploit() against a child process running a Python script.

    The child is sys.executable, not /bin/sh, so the suite exercises
    the attempt loop on hosts without a POSIX shell (Windows)."""
    real_popen = subprocess.Popen

    def fake_popen(*args: object, **kwargs: object):
        return real_popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )

    with (
        mock.patch.object(
            provisioner,
            "adb_run",
            return_value=_completed(0, ""),
        ),
        mock.patch(
            "provision_portal.subprocess.Popen", side_effect=fake_popen
        ),
        mock.patch.object(sys, "stdout", output),
    ):
        return provisioner.exploit(0x1000, 0x2000, 1)


class ExploitAttemptClassificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.terry = next(
            target for target in TARGETS if target.device == "terry"
        )

    def _provisioner(self, temporary: str) -> PortalProvisioner:
        provisioner = PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary)
        )
        provisioner.target = self.terry
        return provisioner

    def test_mm_struct_leak_failure_is_classified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            output = io.StringIO()
            result = _exploit_with_process(
                provisioner,
                "import time; "
                "print('KernelSnitch mm_struct leak failed', flush=True); "
                "time.sleep(30)",
                output,
            )

            self.assertFalse(result)
            text = output.getvalue()
            self.assertIn(
                "INSTALL_ATTEMPT_RESULT attempt=1 success=0 "
                "early_failure=1",
                text,
            )
            self.assertIn("end=failure-marker", text)

    def test_attempt_exit_logs_returncode_and_eof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            output = io.StringIO()
            result = _exploit_with_process(
                provisioner,
                "import sys; print('attempt output', flush=True); "
                "sys.exit(3)",
                output,
            )

            self.assertFalse(result)
            self.assertIn(
                "INSTALL_ATTEMPT_EXIT attempt=1 returncode=3 end=eof",
                output.getvalue(),
            )
            attempt_log = (
                pathlib.Path(temporary) / "attempt-1.log"
            ).read_text()
            self.assertIn("INSTALL_ATTEMPT_EXIT", attempt_log)

    def test_attempt_exit_logs_deadline(self) -> None:
        class AdvancingClock:
            def __init__(self) -> None:
                self.now = 0.0

            def monotonic(self) -> float:
                self.now += 120.0
                return self.now

            def sleep(self, seconds: float) -> None:
                pass

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            output = io.StringIO()
            real_popen = subprocess.Popen

            def fake_popen(*args: object, **kwargs: object):
                return real_popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                )

            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=_completed(0, ""),
                ),
                mock.patch(
                    "provision_portal.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch.object(
                    provision_portal_module, "time", AdvancingClock()
                ),
                mock.patch.object(sys, "stdout", output),
            ):
                result = provisioner.exploit(0x1000, 0x2000, 1)

            self.assertFalse(result)
            self.assertRegex(
                output.getvalue(),
                r"INSTALL_ATTEMPT_EXIT attempt=1 returncode=-?\d+ "
                r"end=deadline",
            )


if __name__ == "__main__":
    unittest.main()
