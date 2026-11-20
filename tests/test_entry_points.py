# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Entry-point ergonomics pins (simplification package): serial
resolution, the adb-missing preflight, bundle self-detection, the
pre-flight run summary + confirmation, and first-connect
diagnostics."""

from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import cli as cli_module  # noqa: E402
import device_session as device_session_module  # noqa: E402

from device_session import DeviceSession, ProvisionError  # noqa: E402
from provision_portal import PortalProvisioner  # noqa: E402


CONFIG = cli_module.CliConfig(
    version="0.0-test",
    default_custom_payload=pathlib.Path("/nonexistent/payload"),
    shizuku_version="test",
    banner="TEST BANNER",
)


def resolve(serial, devices=()):
    namespace = types.SimpleNamespace(serial=serial)
    with mock.patch.object(
        cli_module, "_adb_devices", return_value=list(devices)
    ):
        return cli_module._resolve_serial(namespace)


class SerialResolutionTest(unittest.TestCase):
    def test_bare_ipv4_gains_the_default_port(self) -> None:
        serial, error = resolve("192.0.2.1")
        self.assertEqual(serial, "192.0.2.1:5555")
        self.assertIsNone(error)

    def test_full_serial_passes_through(self) -> None:
        self.assertEqual(resolve("192.0.2.1:5555")[0], "192.0.2.1:5555")
        self.assertEqual(resolve("USB12345")[0], "USB12345")

    def test_single_connected_device_is_auto_selected(self) -> None:
        serial, error = resolve(None, [("192.0.2.9:5555", "device")])
        self.assertEqual(serial, "192.0.2.9:5555")
        self.assertIsNone(error)

    def test_no_device_is_an_error_listing_what_adb_sees(self) -> None:
        serial, error = resolve(None, [])
        self.assertIsNone(serial)
        self.assertIn("--serial is required", error)
        self.assertIn("none", error)

    def test_unauthorized_only_is_not_auto_selected(self) -> None:
        serial, error = resolve(None, [("192.0.2.9:5555", "unauthorized")])
        self.assertIsNone(serial)
        self.assertIn("unauthorized", error)

    def test_two_devices_are_listed_not_guessed(self) -> None:
        serial, error = resolve(
            None,
            [("192.0.2.9:5555", "device"), ("USB12345", "device")],
        )
        self.assertIsNone(serial)
        self.assertIn("192.0.2.9:5555", error)
        self.assertIn("USB12345", error)


class MainEntryTest(unittest.TestCase):
    def run_main(self, argv, which="/usr/bin/adb", tree=None):
        constructed = []

        class FakeProvisioner:
            def __init__(self, *args, **kwargs):
                constructed.append((args, kwargs))

            def provision(self):
                return None

        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(sys, "argv", ["provision_portal.py", *argv])
            )
            stack.enter_context(
                mock.patch.object(cli_module.shutil, "which", return_value=which)
            )
            stack.enter_context(contextlib.redirect_stderr(stderr))
            if tree is not None:
                stack.enter_context(
                    mock.patch.object(
                        cli_module, "__file__", str(tree / "tools" / "cli.py")
                    )
                )
            result = cli_module.main(CONFIG, FakeProvisioner)
        return result, constructed, stderr.getvalue()

    def test_missing_adb_is_a_human_error_before_any_work(self) -> None:
        result, constructed, stderr = self.run_main(
            ["--serial", "192.0.2.1:5555", "--status"], which=None
        )
        self.assertEqual(result, 2)
        self.assertEqual(constructed, [])
        self.assertIn("adb was not found on your PATH", stderr)
        self.assertIn("platform-tools", stderr)

    def test_bare_ip_serial_reaches_the_factory_with_port(self) -> None:
        result, constructed, _ = self.run_main(
            ["--serial", "192.0.2.1", "--status"]
        )
        self.assertEqual(result, 0)
        self.assertEqual(constructed[0][0][0], "192.0.2.1:5555")

    def test_extracted_bundle_is_the_default_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = pathlib.Path(temporary)
            (tree / "tools").mkdir()
            (tree / "bundle-manifest.json").write_text("{}")
            result, constructed, stderr = self.run_main(
                ["--serial", "192.0.2.1:5555", "--status"], tree=tree
            )
        self.assertEqual(result, 0)
        # main() resolves the tree root (macOS /var -> /private/var,
        # Windows short names), so compare resolved forms.
        self.assertEqual(constructed[0][1]["bundle"], tree.resolve())
        self.assertIn("release bundle", stderr)

    def test_no_manifest_no_bundle_default(self) -> None:
        result, constructed, _ = self.run_main(
            ["--serial", "192.0.2.1:5555", "--status"]
        )
        self.assertEqual(result, 0)
        self.assertIsNone(constructed[0][1]["bundle"])


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class PreflightSummaryTest(unittest.TestCase):
    def make_provisioner(self, temporary: str, **kwargs):
        return PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary), **kwargs
        )

    def run_summary(self, provisioner, tty=False, answer=None):
        output = io.StringIO()
        stdin = _Tty() if tty else io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "stdin", stdin))
            stack.enter_context(contextlib.redirect_stdout(output))
            if answer is not None:
                stack.enter_context(
                    mock.patch("builtins.input", return_value=answer)
                )
            try:
                provisioner.confirm_run_plan()
                error = None
            except ProvisionError as exc:
                error = exc
        return error, output.getvalue()

    def test_non_interactive_prints_and_proceeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(
                temporary, debloat=True, remove_meta_accounts=True
            )
            error, output = self.run_summary(provisioner)
        self.assertIsNone(error)
        self.assertIn("This run will:", output)
        # Debloat's contents, in plain words, including the folded
        # Private DNS and app verifier changes.
        self.assertIn("Private DNS off", output)
        self.assertIn("app verifier", output)
        # The one-way step is named as one-way.
        self.assertIn("One-way step", output)
        self.assertIn("cannot be undone", output)
        self.assertIn("Nothing has been changed yet", output)

    def test_autoroot_is_named_plainly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary, autoroot=True)
            error, output = self.run_summary(provisioner)
        self.assertIsNone(error)
        self.assertIn("Root this Portal", output)

    def test_interactive_no_cancels_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary, debloat=True)
            error, _ = self.run_summary(provisioner, tty=True, answer="n")
        self.assertIsNotNone(error)
        self.assertIn("no changes were made", str(error))

    def test_interactive_yes_proceeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.make_provisioner(temporary, debloat=True)
            error, _ = self.run_summary(provisioner, tty=True, answer="y")
        self.assertIsNone(error)


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class ConnectDiagnosticsTest(unittest.TestCase):
    def run_connect(self, connect_output: str, state_output: str):
        session = DeviceSession("192.0.2.1:5555")

        def run(arguments, timeout=None, check=False):
            del timeout, check
            if arguments[1] == "connect":
                return subprocess.CompletedProcess(
                    arguments, 0, connect_output
                )
            return subprocess.CompletedProcess(arguments, 0, "")

        def adb_run(arguments, timeout=None, check=False):
            del timeout, check
            return subprocess.CompletedProcess(arguments, 1, state_output)

        output = io.StringIO()
        with (
            mock.patch.object(session, "run", side_effect=run),
            mock.patch.object(session, "adb_run", side_effect=adb_run),
            mock.patch.object(device_session_module, "time", _FakeClock()),
            contextlib.redirect_stdout(output),
        ):
            try:
                session.connect(wait_seconds=10)
                error = None
            except ProvisionError as exc:
                error = exc
        return error, output.getvalue()

    def test_refused_connection_names_the_debug_menu_fix(self) -> None:
        error, output = self.run_connect(
            "cannot connect to 192.0.2.1:5555: Connection refused",
            "error: device '192.0.2.1:5555' not found",
        )
        self.assertIsNotNone(error)
        self.assertIn("could not connect to 192.0.2.1:5555", str(error))
        self.assertIn("refused the connection", output)
        self.assertIn("Debug menu", output)

    def test_unauthorized_names_the_allow_prompt(self) -> None:
        error, output = self.run_connect(
            "connected to 192.0.2.1:5555",
            "error: device unauthorized. Please check the "
            "confirmation dialog on your device.",
        )
        self.assertIsNotNone(error)
        self.assertIn("tap Allow", output)

    def test_silence_names_the_address_and_network_check(self) -> None:
        error, output = self.run_connect(
            "failed to connect to '192.0.2.1:5555': Connection timed out",
            "error: device '192.0.2.1:5555' not found",
        )
        self.assertIsNotNone(error)
        self.assertIn("same Wi-Fi network", output)


class GuidedConnectTest(unittest.TestCase):
    """Guided connect against scripted adb seams: the device-list
    sequence, the on-device Wi-Fi read (ip addr, route fallback),
    the tcpip switch and the wireless connect."""

    def run_guided(self, device_script, command_outputs):
        clock = _FakeClock()
        devices = list(device_script)
        calls = []

        def fake_devices():
            return devices.pop(0) if devices else []

        def fake_command(arguments, timeout=15):
            del timeout
            calls.append(list(arguments))
            key = " ".join(str(argument) for argument in arguments)
            for fragment, (returncode, stdout) in command_outputs.items():
                if fragment in key:
                    return subprocess.CompletedProcess(
                        arguments, returncode, stdout, ""
                    )
            return subprocess.CompletedProcess(arguments, 0, "", "")

        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(cli_module, "_adb_devices", fake_devices)
            )
            stack.enter_context(
                mock.patch.object(cli_module, "_adb_command", fake_command)
            )
            stack.enter_context(
                mock.patch.object(
                    cli_module,
                    "time",
                    types.SimpleNamespace(
                        monotonic=clock.monotonic, sleep=clock.sleep
                    ),
                )
            )
            stack.enter_context(contextlib.redirect_stdout(output))
            try:
                serial = cli_module.guided_connect(wait_seconds=30)
                error = None
            except ProvisionError as exc:
                serial, error = None, exc
        return serial, error, output.getvalue(), calls

    HAPPY_COMMANDS = {
        "ip addr show wlan0": (
            0,
            "    inet 192.0.2.5/24 brd 192.0.2.255 scope global wlan0",
        ),
        "tcpip": (0, "restarting in TCP mode port: 5555"),
        "connect": (0, "connected to 192.0.2.5:5555"),
        "get-state": (0, "device"),
    }

    def test_happy_path_waits_for_allow_then_connects(self) -> None:
        serial, error, output, calls = self.run_guided(
            [
                [],
                [("USB1", "unauthorized")],
                [("USB1", "device")],
            ],
            self.HAPPY_COMMANDS,
        )
        self.assertIsNone(error)
        self.assertEqual(serial, "192.0.2.5:5555")
        self.assertIn("tap Allow", output)
        self.assertIn("Connected: 192.0.2.5:5555", output)
        joined = [" ".join(call) for call in calls]
        self.assertTrue(any("tcpip 5555" in call for call in joined))

    def test_route_source_is_the_ip_fallback(self) -> None:
        commands = dict(self.HAPPY_COMMANDS)
        commands["ip addr show wlan0"] = (0, "wlan0: DOWN")
        commands["ip route"] = (
            0,
            "192.0.2.0/24 dev wlan0 proto kernel scope link "
            "src 192.0.2.5",
        )
        serial, error, _, _ = self.run_guided(
            [[("USB1", "device")]], commands
        )
        self.assertIsNone(error)
        self.assertEqual(serial, "192.0.2.5:5555")

    def test_no_usb_portal_is_a_plain_error(self) -> None:
        serial, error, _, _ = self.run_guided([], self.HAPPY_COMMANDS)
        self.assertIsNone(serial)
        self.assertIn("no USB Portal appeared", str(error))
        self.assertIn("Debug menu", str(error))

    def test_two_usb_devices_are_not_guessed(self) -> None:
        serial, error, _, _ = self.run_guided(
            [[("USB1", "device"), ("USB2", "device")]],
            self.HAPPY_COMMANDS,
        )
        self.assertIsNone(serial)
        self.assertIn("more than one USB device", str(error))

    def test_no_wifi_address_is_a_plain_error(self) -> None:
        commands = dict(self.HAPPY_COMMANDS)
        commands["ip addr show wlan0"] = (0, "wlan0: DOWN")
        commands["ip route"] = (0, "")
        serial, error, _, _ = self.run_guided(
            [[("USB1", "device")]], commands
        )
        self.assertIsNone(serial)
        self.assertIn("Wi-Fi address", str(error))


class MainConnectTest(unittest.TestCase):
    def run_main(self, argv):
        constructed = []

        class FakeProvisioner:
            def __init__(self, *args, **kwargs):
                constructed.append((args, kwargs))

            def provision(self):
                return None

        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(sys, "argv", ["provision_portal.py", *argv])
            )
            stack.enter_context(
                mock.patch.object(
                    cli_module.shutil, "which", return_value="/usr/bin/adb"
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cli_module,
                    "guided_connect",
                    return_value="192.0.2.5:5555",
                )
            )
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            result = cli_module.main(CONFIG, FakeProvisioner)
        return result, constructed, output.getvalue()

    def test_connect_alone_connects_and_prints_the_next_command(
        self,
    ) -> None:
        result, constructed, output = self.run_main(["--connect"])
        self.assertEqual(result, 0)
        self.assertEqual(constructed, [])
        self.assertIn("--serial 192.0.2.5:5555 --full", output)

    def test_connect_with_actions_continues_the_run(self) -> None:
        result, constructed, _ = self.run_main(["--connect", "--full"])
        self.assertEqual(result, 0)
        self.assertEqual(constructed[0][0][0], "192.0.2.5:5555")
        self.assertTrue(constructed[0][1]["autoroot"])


if __name__ == "__main__":
    unittest.main()
