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
from provision_portal import (  # noqa: E402
    SHIZUKU_HELPER_PACKAGE,
    PortalProvisioner,
    ProvisionError,
    build,
    parse_args,
)
from portal_targets import TARGETS  # noqa: E402


ALOHA = next(
    target for target in TARGETS if target.key == "portal-plus-aloha-1041515800015050"
)


def make_provisioner(temporary: str, **kwargs) -> PortalProvisioner:
    provisioner = PortalProvisioner(
        "192.0.2.1:5555", 1, pathlib.Path(temporary), **kwargs
    )
    provisioner.target = ALOHA
    return provisioner


class AutorootCliTest(unittest.TestCase):
    def test_autoroot_and_payload_flags_parse(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            [
                "provision_portal.py",
                "--shizuku",
                "--autoroot",
                "--custom-payload",
                "daemon.bin",
            ],
        ):
            arguments = parse_args()
        self.assertTrue(arguments.shizuku)
        self.assertTrue(arguments.autoroot)
        self.assertFalse(arguments.skip_shizuku_root)

    def test_skip_shizuku_root_flag_parses(self) -> None:
        with mock.patch.object(
            sys, "argv", ["provision_portal.py", "--skip-shizuku-root"]
        ):
            arguments = parse_args()
        self.assertTrue(arguments.skip_shizuku_root)

    def test_autoroot_build_includes_helper_make(self) -> None:
        with (
            mock.patch(
                "provision_portal.android_build_environment", return_value={}
            ),
            mock.patch(
                "provision_portal.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as run,
        ):
            build(
                target=ALOHA,
                build_audio=False,
                build_account=False,
                build_components=False,
                build_shizuku=False,
                build_autoroot=True,
                build_presence=False,
                build_uid1000=False,
                build_sentinel=False,
            )
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(
            ["make", "-C", str(ROOT / "autoroot-helper"), "all"], commands
        )

    def test_staging_requires_a_selected_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                shizuku=True,
                autoroot=True,
            )
            with self.assertRaisesRegex(
                ProvisionError, "target must be selected before autoroot"
            ):
                provisioner.stage_autoroot_payload()

    def test_staging_requires_shizuku(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, autoroot=True)
            with mock.patch.object(
                provisioner, "adb_run", side_effect=AssertionError("adb used")
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "--autoroot requires --shizuku"
                ):
                    provisioner.stage_autoroot_payload()


class ExploitEnvironmentPhaseGateTest(unittest.TestCase):
    """The environment gates that keep phase-specific actions out of the
    wrong exploit phase (two live regressions: won races discarded as
    misses because an action ran in a phase where it could only fail)."""

    def build_env(self, provisioner, attempt: int = 1):
        # The builder finishes by removing the previous attempt's watch
        # result file on the device; that adb call is not under test here.
        with mock.patch.object(
            provisioner,
            "adb_run",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ):
            return provisioner.build_exploit_environment(
                0xFFFFFF8000000000, 0xFFFFFFC000000000, attempt
            )

    def test_authorize_key_present_outside_payload_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                shizuku=True,
                custom_payload=pathlib.Path("daemon.bin"),
            )
            environment = self.build_env(provisioner)
        self.assertEqual(environment["GHOSTLOCK_SHIZUKU_AUTHORIZE_KEY"], "1")
        self.assertNotIn("GHOSTLOCK_CUSTOM_PAYLOAD", environment)

    def test_authorize_key_absent_inside_payload_phase(self) -> None:
        # Regression (2026-11-03): carrying the key-authorization action
        # into custom-payload attempts made it fail after the payload
        # started, flipped the verdict to WATCH_CFI_OK=0, and discarded
        # roughly fifty won races as misses.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                shizuku=True,
                custom_payload=pathlib.Path("daemon.bin"),
            )
            provisioner._in_custom_payload_phase = True
            environment = self.build_env(provisioner)
        self.assertNotIn("GHOSTLOCK_SHIZUKU_AUTHORIZE_KEY", environment)

    def test_payload_keys_present_only_inside_payload_phase(self) -> None:
        # Regression (2026-11-04 Run 12): in the combined flow the
        # payload action leaked into standard install attempts and every
        # won install race was discarded the same way.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary,
                shizuku=True,
                custom_payload=pathlib.Path("daemon.bin"),
            )
            provisioner._in_custom_payload_phase = True
            environment = self.build_env(provisioner)
        self.assertEqual(environment["GHOSTLOCK_CUSTOM_PAYLOAD"], "1")
        self.assertIn("GHOSTLOCK_CUSTOM_PAYLOAD_SRC", environment)
        self.assertIn("GHOSTLOCK_CUSTOM_PAYLOAD_DST", environment)
        self.assertIn("GHOSTLOCK_LOCK_REPAIR", environment)

    def test_attempt_parity_geometry(self) -> None:
        # The on-device runner replays exactly these two geometries:
        # odd attempts use the base geometry, even attempts the retry
        # geometry, matching host-side retries.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary)
            odd = self.build_env(provisioner, attempt=1)
            even = self.build_env(provisioner, attempt=2)
        self.assertEqual(odd["GHOSTLOCK_KGSL_RECLAIM"], "8192")
        self.assertEqual(odd["GHOSTLOCK_MM_RECYCLE_SLABS"], "40")
        self.assertEqual(even["GHOSTLOCK_KGSL_RECLAIM"], "4096")
        self.assertEqual(even["GHOSTLOCK_MM_RECYCLE_SLABS"], "20")
        self.assertEqual(odd["GHOSTLOCK_KASLR_BASE"], "0xffffff8000000000")


class FakeSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.sent = b""

    def settimeout(self, _timeout) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, _size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *args) -> bool:
        return False


class DaemonExecTest(unittest.TestCase):
    def run_exec(self, chunks: list[bytes], command: str = "id"):
        fake = FakeSocket(chunks)
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            with mock.patch(
                "provision_portal.socket.create_connection", return_value=fake
            ):
                result = provisioner.daemon_exec(command)
        return result, fake

    def test_exec_parses_output_and_zero_exit(self) -> None:
        (code, output), fake = self.run_exec(
            [b"hello\nworld\nEXIT 0\nEND\n"], "echo hello"
        )
        self.assertEqual(code, 0)
        self.assertEqual(output, "hello\nworld")
        self.assertEqual(fake.sent, b"EXEC echo hello\n")

    def test_exec_propagates_nonzero_exit(self) -> None:
        (code, output), _ = self.run_exec([b"oops\nEXIT 3\nEND\n"])
        self.assertEqual(code, 3)
        self.assertEqual(output, "oops")

    def test_exec_defaults_to_exit_1_without_exit_line(self) -> None:
        (code, output), _ = self.run_exec([b"data\nEND\n"])
        self.assertEqual(code, 1)
        self.assertEqual(output, "data")

    def test_exec_reassembles_split_frames(self) -> None:
        (code, output), _ = self.run_exec(
            [b"par", b"tial\nEXIT 0\n", b"END\n"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(output, "partial")


DUMPSYS_NATIVE = (
    "    nativeLibraryDir=/data/app/~~x/moe.shizuku.privileged.api-y/lib/arm64\n"
    "    primaryCpuAbi=arm64-v8a\n"
)
DUMPSYS_LEGACY = (
    "    legacyNativeLibraryDir=/data/app/~~x/moe.shizuku.privileged.api-y/lib\n"
    "    primaryCpuAbi=arm64-v8a\n"
)
DUMPSYS_EMPTY = "    primaryCpuAbi=arm64-v8a\n"


class ShizukuRootStartTest(unittest.TestCase):
    def run_start(self, dumpsys_text: str):
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            pidof_calls = {"count": 0}

            def adb_run(args, timeout=None, check=False):
                joined = " ".join(args)
                if "dumpsys" in args:
                    return subprocess.CompletedProcess(args, 0, dumpsys_text, "")
                if "pm" in args and "path" in args:
                    return subprocess.CompletedProcess(
                        args,
                        0,
                        "package:/data/app/~~x/moe.shizuku.privileged.api-y/base.apk\n",
                        "",
                    )
                if args[:2] == ["shell", "pidof"]:
                    pidof_calls["count"] += 1
                    stdout = "" if pidof_calls["count"] == 1 else "12345"
                    return subprocess.CompletedProcess(args, 0, stdout, "")
                if "cat" in args and "/proc/" in joined:
                    return subprocess.CompletedProcess(
                        args, 0, "Name:\tshizuku_server\nUid:\t0\t0\t0\t0\n", ""
                    )
                return subprocess.CompletedProcess(args, 0, "", "")

            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provisioner, "daemon_exec", return_value=(0, "12345")
                ) as daemon_exec,
            ):
                provisioner.start_shizuku_as_root()
            return daemon_exec

    def test_native_library_dir_resolution(self) -> None:
        daemon_exec = self.run_start(DUMPSYS_NATIVE)
        command = daemon_exec.call_args.args[0]
        self.assertIn(
            "/data/app/~~x/moe.shizuku.privileged.api-y/lib/arm64/libshizuku.so",
            command,
        )
        self.assertIn(
            "--apk='/data/app/~~x/moe.shizuku.privileged.api-y/base.apk'", command
        )
        # Regression (2026-11-03 Run 10): the kill must use pidof only.
        # "pkill -f shizuku_server" matches the EXEC shell's own command
        # line and kills it before the starter runs.
        self.assertIn("pidof shizuku_server", command)
        self.assertNotIn("pkill", command)

    def test_legacy_library_dir_resolution_android9(self) -> None:
        # Android 9 dumps carry only legacyNativeLibraryDir (the
        # extraction root); the starter lives in its per-ABI subdir.
        daemon_exec = self.run_start(DUMPSYS_LEGACY)
        command = daemon_exec.call_args.args[0]
        self.assertIn(
            "/data/app/~~x/moe.shizuku.privileged.api-y/lib/arm64/libshizuku.so",
            command,
        )

    def test_unresolvable_starter_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)

            def adb_run(args, timeout=None, check=False):
                return subprocess.CompletedProcess(args, 0, DUMPSYS_EMPTY, "")

            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                with self.assertRaisesRegex(
                    ProvisionError, "could not resolve Shizuku nativeLibraryDir"
                ):
                    provisioner.start_shizuku_as_root()


class PostPayloadRootStepsTest(unittest.TestCase):
    def run_steps(self, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, **kwargs)
            with (
                mock.patch.object(provisioner, "start_shizuku_as_root") as start,
                mock.patch.object(provisioner, "stage_autoroot_payload") as stage,
            ):
                provisioner.apply_post_payload_root_steps()
            return start, stage

    def test_shizuku_root_runs_by_default(self) -> None:
        start, stage = self.run_steps(shizuku=True)
        start.assert_called_once_with()
        stage.assert_not_called()

    def test_skip_flag_suppresses_shizuku_root(self) -> None:
        start, stage = self.run_steps(shizuku=True, skip_shizuku_root=True)
        start.assert_not_called()
        stage.assert_not_called()

    def test_autoroot_stages_after_payload(self) -> None:
        start, stage = self.run_steps(shizuku=True, autoroot=True)
        start.assert_called_once_with()
        stage.assert_called_once_with()


class AutorootStagingTest(unittest.TestCase):
    def run_staging(self, provisioner, package_sets_value):
        pushes: dict[str, str] = {}

        def adb_run(args, timeout=None, check=False):
            if args[:3] == ["shell", "pm", "path"]:
                return subprocess.CompletedProcess(
                    args, 0, "package:/data/app/~~s/base.apk\n", ""
                )
            if args[:3] == ["shell", "test", "-f"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            if args and args[0] == "push":
                local, remote = args[1], args[2]
                local_path = pathlib.Path(local)
                pushes[remote] = (
                    local_path.read_text(encoding="utf-8")
                    if local_path.is_file()
                    else ""
                )
                return subprocess.CompletedProcess(args, 0, "", "")
            if args and args[0] == "uninstall":
                return subprocess.CompletedProcess(args, 0, "Success\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        stdout = io.StringIO()
        with (
            mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
            mock.patch.object(provisioner, "install_apk_preserving_verifier"),
            mock.patch.object(provisioner, "settle_package_state"),
            mock.patch.object(
                provisioner, "package_sets", return_value=package_sets_value
            ),
            contextlib.redirect_stdout(stdout),
        ):
            provisioner.stage_autoroot_payload()
        return pushes, stdout.getvalue()

    def build_provisioner(self, temporary: str) -> PortalProvisioner:
        provisioner = make_provisioner(
            temporary,
            shizuku=True,
            autoroot=True,
            custom_payload=pathlib.Path("daemon.bin"),
        )
        apk = pathlib.Path(temporary) / "helper.apk"
        apk.write_bytes(b"apk")
        runner = pathlib.Path(temporary) / "run.sh"
        runner.write_text("#!/bin/sh\n", encoding="utf-8")
        patchers = (
            mock.patch.object(
                provision_portal, "AUTOROOT_HELPER_LOCAL", apk
            ),
            mock.patch.object(
                provision_portal, "AUTOROOT_RUNNER_LOCAL", runner
            ),
        )
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        return provisioner

    def test_credential_environment_is_refused(self) -> None:
        # Fail-closed: an environment carrying a live per-boot credential
        # identity (pid/uid) must never be frozen into the on-device
        # runner's env files.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary)
            with mock.patch.object(
                provisioner,
                "build_exploit_environment",
                return_value={"GHOSTLOCK_ACTION_CREDENTIAL_PID": "4242"},
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "cannot stage this run"
                ):
                    self.run_staging(provisioner, (set(), set()))

    def test_staging_renders_envs_conf_and_removes_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary)
            pushes, output = self.run_staging(
                provisioner, ({SHIZUKU_HELPER_PACKAGE}, set())
            )
        odd = pushes["/data/local/tmp/portal-autoroot/env-odd.sh"]
        even = pushes["/data/local/tmp/portal-autoroot/env-even.sh"]
        self.assertIn("export GHOSTLOCK_KGSL_RECLAIM=8192", odd)
        self.assertIn("export GHOSTLOCK_MM_RECYCLE_SLABS=40", odd)
        self.assertIn("export GHOSTLOCK_KGSL_RECLAIM=4096", even)
        self.assertIn("export GHOSTLOCK_MM_RECYCLE_SLABS=20", even)
        # Per-boot addresses are discovered on-device, never frozen in.
        self.assertNotIn("GHOSTLOCK_KASLR_BASE", odd)
        self.assertNotIn("GHOSTLOCK_P0_MEMSTART", odd)
        conf = next(
            content
            for remote, content in pushes.items()
            if remote.endswith("autoroot.conf")
        )
        self.assertIn("MAX_ATTEMPTS=8", conf)
        self.assertIn("SESSION_WINDOW_SEC=3600", conf)
        # The shizuku helper is removed once the autoroot helper holds
        # its own copy of the keypair.
        self.assertIn("SHIZUKU_HELPER_REMOVED", output)
        self.assertIn("AUTOROOT_STAGED_OK", output)


if __name__ == "__main__":
    unittest.main()


import tempfile


class VerifyBootsTests(unittest.TestCase):
    def _provisioner(self, verify_boots):
        obj = PortalProvisioner.__new__(PortalProvisioner)
        obj.verify_boots = verify_boots
        obj.persist_wireless_adb = False
        obj.target = None
        obj.log_dir = pathlib.Path(tempfile.mkdtemp())
        state = {'cur': 'boot-A', 'reboots': 0, 'verifies': 0, 'written': None}

        def fake_reboot():
            old = state['cur']
            state['cur'] = old + 'x'
            state['reboots'] += 1
            return old, state['cur']

        def fake_verify():
            state['verifies'] += 1

        def fake_write_state(status, first=None, second=None):
            state['written'] = (status, first, second)

        obj.reboot = fake_reboot
        obj.verify_requested_state = fake_verify
        obj.write_state = fake_write_state
        obj.adb_framework_boot_install_requested = lambda: False
        return obj, state

    def test_one_boot_skips_second_verification_reboot(self):
        obj, st = self._provisioner(1)
        obj.verify_across_two_reboots(first_boot='boot-A')
        self.assertEqual(st['reboots'], 0)
        self.assertEqual(st['verifies'], 1)
        self.assertEqual(st['written'], ('complete', 'boot-A', 'boot-A'))

    def test_one_boot_after_initial_reboot(self):
        obj, st = self._provisioner(1)
        obj.verify_across_two_reboots()
        self.assertEqual(st['reboots'], 1)
        self.assertEqual(st['verifies'], 1)
        self.assertEqual(st['written'][0], 'complete')
        self.assertEqual(st['written'][1], st['written'][2])

    def test_two_boots_unchanged(self):
        obj, st = self._provisioner(2)
        obj.verify_across_two_reboots(first_boot='boot-A')
        self.assertEqual(st['reboots'], 1)
        self.assertEqual(st['verifies'], 2)
        self.assertEqual(st['written'], ('complete', 'boot-A', 'boot-Ax'))

    def test_verify_boots_cli(self):
        with mock.patch.object(sys, 'argv', ['provision_portal.py']):
            self.assertEqual(parse_args().verify_boots, 2)
        with mock.patch.object(
            sys, 'argv', ['provision_portal.py', '--verify-boots', '1']
        ):
            self.assertEqual(parse_args().verify_boots, 1)


class DaemonStopTest(unittest.TestCase):
    def run_stop(self, chunks: list[bytes]) -> FakeSocket:
        fake = FakeSocket(chunks)
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                '192.0.2.1:5555', 1, pathlib.Path(temporary)
            )
            with mock.patch(
                'provision_portal.socket.create_connection', return_value=fake
            ):
                provisioner.stop_root_daemon()
        return fake

    def test_stop_sends_stop_and_accepts_bye(self) -> None:
        fake = self.run_stop([b'BYE\n'])
        self.assertEqual(fake.sent, b'STOP\n')

    def test_stop_rejects_wrong_responder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                '192.0.2.1:5555', 1, pathlib.Path(temporary)
            )
            fake = FakeSocket([b'ERR unknown-command\nEND\n'])
            with mock.patch(
                'provision_portal.socket.create_connection', return_value=fake
            ):
                with self.assertRaises(ProvisionError):
                    provisioner.stop_root_daemon()


class PostPayloadDaemonStopTest(unittest.TestCase):
    def run_steps(self, *, shizuku, skip, autoroot, start_raises=False):
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                '192.0.2.1:5555', 1, pathlib.Path(temporary)
            )
        provisioner.shizuku = shizuku
        provisioner.skip_shizuku_root = skip
        provisioner.autoroot = autoroot
        calls: list[str] = []

        def start() -> None:
            calls.append('start')
            if start_raises:
                raise ProvisionError('boom')

        provisioner.start_shizuku_as_root = start
        provisioner.stage_autoroot_payload = lambda: calls.append('stage')
        provisioner.stop_root_daemon = lambda: calls.append('stop')
        return provisioner, calls

    def test_stop_after_handoff_and_staging(self) -> None:
        provisioner, calls = self.run_steps(
            shizuku=True, skip=False, autoroot=True
        )
        provisioner.apply_post_payload_root_steps()
        self.assertEqual(calls, ['start', 'stage', 'stop'])

    def test_no_stop_when_shizuku_root_skipped(self) -> None:
        provisioner, calls = self.run_steps(
            shizuku=True, skip=True, autoroot=True
        )
        provisioner.apply_post_payload_root_steps()
        self.assertEqual(calls, ['stage'])

    def test_no_stop_without_shizuku(self) -> None:
        provisioner, calls = self.run_steps(
            shizuku=False, skip=False, autoroot=False
        )
        provisioner.apply_post_payload_root_steps()
        self.assertEqual(calls, [])

    def test_no_stop_when_handoff_fails(self) -> None:
        provisioner, calls = self.run_steps(
            shizuku=True, skip=False, autoroot=False, start_raises=True
        )
        with self.assertRaises(ProvisionError):
            provisioner.apply_post_payload_root_steps()
        self.assertEqual(calls, ['start'])
