# SPDX-License-Identifier: Apache-2.0
# Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
# See LICENSE and NOTICE.

from __future__ import annotations

import contextlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import cast
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import provision_portal as provision_portal_module  # noqa: E402

from provision_portal import (  # noqa: E402
    ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
    AUTOROOT_HELPER_PACKAGE,
    EXPLOIT_SENTINEL_PACKAGE,
    OTA_BACKEND_BACKUP_REMOTE,
    OTA_BACKEND_PROPERTY,
    OTA_JSON_URL,
    OTA_POLL_INTERVAL_MINUTES,
    PACKAGE_STATE_SETTLE_SECONDS,
    PRESENCE_HELPER_PACKAGE,
    ADB_ENABLED_SETTING,
    DEFAULT_CUSTOM_PAYLOAD_LOCAL,
    MHA_AUDIO_VERIFIED_LOG,
    META_AUTHENTICATOR_COMPONENTS,
    REMOTE_WIPE_COMPONENTS,
    SHIZUKU_HELPER_PACKAGE,
    SIGNATURE_MISMATCH_RETRY_PACKAGES,
    PortalProvisioner,
    ProvisionError,
    android_build_environment,
    build,
    parse_args,
    parse_ota_config,
    watch_step_action,
)
from meta_debloat_components import (  # noqa: E402
    DEBLOAT_COMPONENT_NAMES,
    PORTAL_PLUS_ALOHA_SAFE_COMPONENT_NAMES,
)
from portal_targets import TARGETS  # noqa: E402


class _FakeClock:
    """monotonic()/sleep() stand-in: sleep advances the clock instantly."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class AudioWatchdogVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.omni = next(target for target in TARGETS if target.device == "omni")
        self.terry = next(target for target in TARGETS if target.device == "terry")

    def test_omni_rejects_legacy_voice_parameter_success_log(self) -> None:
        legacy = "audio processing verified aec=0 ns=0 backend=java"
        self.assertFalse(
            PortalProvisioner.audio_processing_disabled_observed(
                legacy, self.omni
            )
        )

    def test_omni_accepts_only_the_mha_verification_log(self) -> None:
        self.assertTrue(
            PortalProvisioner.audio_processing_disabled_observed(
                MHA_AUDIO_VERIFIED_LOG, self.omni
            )
        )

    def test_non_omni_keeps_voice_parameter_verification(self) -> None:
        legacy = "audio processing verified aec=0 ns=0 backend=java"
        self.assertTrue(
            PortalProvisioner.audio_processing_disabled_observed(
                legacy, self.terry
            )
        )


class PersistentWirelessAdbCliTest(unittest.TestCase):
    def test_standalone_flag_does_not_enable_the_default_audio_action(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--persistent-wireless-adb"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.persistent_wireless_adb)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                persistent_wireless_adb=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {
                    "persistent_wireless_adb": True,
                    "disable_adb_auth_timeout": True,
                },
            )
            self.assertTrue(provisioner.privileged_requested())

    def test_cli_pairs_persistent_wireless_adb_with_non_expiring_auth(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--persistent-wireless-adb"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.disable_adb_auth_timeout)

    def test_persistent_wireless_adb_rejects_timeout_restore(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            [
                "provision_portal.py",
                "--persistent-wireless-adb",
                "--restore",
                "adb-auth-timeout",
            ],
        ):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_every_target_installs_adb_framework_boot_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for target in TARGETS:
                with self.subTest(target=target.key):
                    provisioner = PortalProvisioner(
                        "192.0.2.1:5555",
                        1,
                        pathlib.Path(temporary),
                        persistent_wireless_adb=True,
                    )
                    provisioner.target = target
                    self.assertTrue(
                        provisioner.adb_framework_boot_install_requested()
                    )
                    self.assertTrue(provisioner.needs_uid1000_payload())
                    provisioner.adb_framework_boot_configured = True
                    self.assertFalse(
                        provisioner.adb_framework_boot_install_requested()
                    )
                    self.assertFalse(provisioner.needs_uid1000_payload())

    def test_android9_internal_bootstrap_keeps_wireless_and_uid1000_phases_split(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wireless = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                wireless_adb_only=True,
            )
            framework = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                adb_framework_only=True,
            )
            self.assertFalse(
                wireless.adb_framework_boot_persistence_requested()
            )
            self.assertTrue(
                framework.adb_framework_boot_persistence_requested()
            )
            self.assertTrue(framework.privileged_requested())


class SystemThemeControlCliTest(unittest.TestCase):
    def test_flag_accepts_only_light_or_dark_without_default_audio(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--system-theme-control", "dark"],
        ):
            arguments = parse_args()

        self.assertEqual(arguments.system_theme_control, "dark")
        self.assertFalse(arguments.audio)

        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--system-theme-control", "automatic"],
        ):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_android_10_uses_uid1000_but_android_9_uses_shell(self) -> None:
        targets = {target.key: target for target in TARGETS}
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                system_theme_control="light",
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"system_theme_control": "light"},
            )

            provisioner.target = targets["portal-10-omni-3051355900018050"]
            self.assertTrue(provisioner.needs_uid1000_payload())
            self.assertTrue(provisioner.privileged_requested())

            provisioner.target = targets["portal-plus-aloha-1041515800015050"]
            self.assertFalse(provisioner.needs_uid1000_payload())
            self.assertFalse(provisioner.privileged_requested())

    def test_locked_build_sends_a_strict_property_request(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-10-omni-3051355900018050"
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                system_theme_control="dark",
            )
            provisioner.target = target
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ) as adb_run,
                mock.patch("provision_portal.time.sleep"),
            ):
                provisioner.apply_system_theme_request()

        self.assertEqual(
            adb_run.call_args_list,
            [
                mock.call(
                    [
                        "shell",
                        "logcat",
                        "-d",
                        "-s",
                        "PortalSystemTheme:*",
                    ],
                    timeout=10,
                ),
                mock.call(
                    [
                        "shell",
                        "setprop",
                        "debug.portal.system_theme",
                        "none",
                    ],
                    timeout=5,
                    check=True,
                ),
                mock.call(
                    [
                        "shell",
                        "setprop",
                        "debug.portal.system_theme",
                        "dark",
                    ],
                    timeout=5,
                    check=True,
                ),
            ],
        )

    def test_uid1000_payload_rejects_a_hook_for_another_runtime(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-go-terry-5051355900018050"
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            helper = directory / "helper"
            hook = directory / "hook"
            helper.write_bytes(b"helper")
            hook.write_bytes(
                b"/data/app/dev.portal.uid1000runtime-stale/lib/arm64/"
                b"libportal_uid1000_exec.so\0"
            )
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                directory,
                system_theme_control="dark",
            )
            provisioner.target = target
            with (
                mock.patch.object(
                    provisioner, "uid1000_helper_local", return_value=helper
                ),
                mock.patch.object(
                    provisioner, "uid1000_hook_local", return_value=hook
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "does not contain the target helper path"
                ):
                    provisioner.validate_uid1000_payload()

                hook.write_bytes(
                    b"prefix/data/portal-uid1000/portal-camera-led-watch\0suffix"
                )
                provisioner.validate_uid1000_payload()

    def test_uid1000_build_does_not_reuse_timestamp_fresh_artifacts(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-go-terry-5051355900018050"
        )
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
                target=target,
                build_audio=False,
                build_account=False,
                build_components=False,
                build_shizuku=False,
                build_autoroot=False,
                build_presence=False,
                build_uid1000=True,
                build_sentinel=False,
            )

        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(
            ["make", "-B", "-C", str(ROOT / "uid1000-helper"), "all"],
            commands,
        )



class CustomPayloadCliTest(unittest.TestCase):
    def parse(self, argv):
        with mock.patch.object(sys, "argv", ["provision_portal.py", *argv]):
            return parse_args()

    def parse_error(self, argv):
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["provision_portal.py", *argv]),
            contextlib.redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit):
                parse_args()
        return stderr.getvalue()

    def test_custom_payload_flag_is_a_clean_break(self) -> None:
        # The root-payload step is internal: it always uses the
        # in-repo root daemon and is armed only by --autoroot.
        # The old --custom-payload flag (bare or with a PATH) is
        # gone; forking the repo is the way to change the daemon.
        for argv in (
            ["--custom-payload"],
            ["--custom-payload", "/tmp/other-daemon"],
            ["--autoroot", "--custom-payload", "/tmp/other"],
        ):
            with self.subTest(argv=argv):
                self.assertIn(
                    "unrecognized arguments", self.parse_error(argv)
                )

    def test_no_flag_run_leaves_custom_payload_unset(self) -> None:
        arguments = self.parse([])

        self.assertIsNone(arguments.custom_payload)

    def test_serial_has_no_default(self) -> None:
        arguments = self.parse([])
        self.assertIsNone(arguments.serial)

    def test_main_rejects_missing_serial(self) -> None:
        with (
            mock.patch.object(sys, "argv", ["provision_portal.py"]),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            result = provision_portal_module.main()
        self.assertEqual(result, 2)
        self.assertIn("--serial is required", stderr.getvalue())

    def test_autoroot_implies_shizuku_and_bare_custom_payload(self) -> None:
        arguments = self.parse(["--autoroot"])

        self.assertTrue(arguments.autoroot)
        self.assertTrue(arguments.shizuku)
        self.assertEqual(arguments.custom_payload, DEFAULT_CUSTOM_PAYLOAD_LOCAL)
        self.assertFalse(arguments.audio)

    def test_autoroot_implies_shizuku_and_the_in_repo_daemon(self) -> None:
        arguments = self.parse(["--autoroot"])

        self.assertTrue(arguments.autoroot)
        self.assertTrue(arguments.shizuku)
        self.assertEqual(arguments.custom_payload, DEFAULT_CUSTOM_PAYLOAD_LOCAL)
        self.assertFalse(arguments.audio)

    def test_autoroot_implied_shizuku_satisfies_shizuku_apk(self) -> None:
        arguments = self.parse(["--autoroot", "--shizuku-apk", "/tmp/shizuku.apk"])

        self.assertTrue(arguments.shizuku)
        self.assertEqual(arguments.shizuku_apk, pathlib.Path("/tmp/shizuku.apk"))

    def test_autoroot_rejects_remove_shizuku(self) -> None:
        with mock.patch.object(
            sys, "argv", ["provision_portal.py", "--autoroot", "--remove-shizuku"]
        ):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_daemon_build_command_is_included_only_when_requested(self) -> None:
        target = TARGETS[0]
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
                target=target,
                build_audio=False,
                build_account=False,
                build_components=False,
                build_shizuku=False,
                build_autoroot=False,
                build_presence=False,
                build_uid1000=False,
                build_sentinel=False,
                build_daemon=True,
            )

        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(["make", "-C", str(ROOT / "root-daemon")], commands)


class AndroidBuildEnvironmentTest(unittest.TestCase):
    def setUp(self) -> None:
        # These tests pin the POSIX host's SDK/NDK resolution semantics
        # (the fake trees are laid out for it). The native-Windows gate
        # itself is pinned in test_cross_platform.
        patcher = mock.patch.object(sys, "platform", "linux")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_build_files_do_not_contain_an_author_home_path(self) -> None:
        build_files = [ROOT / "android-env.mk", *ROOT.glob("*/Makefile")]
        for path in build_files:
            self.assertNotIn("/home/jxlarrea", path.read_text(), str(path))

    def test_explicit_sdk_root_is_propagated_to_make(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = pathlib.Path(temporary) / "sdk"
            ndk = sdk / "ndk" / "28.2.13676358"
            toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
            build_tools = sdk / "build-tools" / "37.0.0"
            platform = sdk / "platforms" / "android-36"
            for path in (
                toolchain / "aarch64-linux-android29-clang",
                toolchain / "armv7a-linux-androideabi28-clang",
                toolchain / "armv7a-linux-androideabi29-clang",
                build_tools / "aapt",
                build_tools / "apksigner",
                build_tools / "zipalign",
                build_tools / "d8",
                platform / "android.jar",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
                mock.patch(
                    "provision_portal.keystore_certificate_sha256",
                    return_value=(
                        provision_portal_module.PROJECT_DEBUG_KEYSTORE_SHA256
                    ),
                ),
            ):
                environment = android_build_environment()

        self.assertEqual(environment["SDK"], str(sdk))
        self.assertEqual(environment["ANDROID_SDK_ROOT"], str(sdk))
        self.assertEqual(environment["NDK"], str(ndk))
        self.assertEqual(environment["BUILD_TOOLS"], str(build_tools))

    def test_simpleperf_required_for_autoroot_on_non_bundled_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = pathlib.Path(temporary) / "sdk"
            ndk = sdk / "ndk" / "28.2.13676358"
            toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
            build_tools = sdk / "build-tools" / "37.0.0"
            platform = sdk / "platforms" / "android-36"
            for path in (
                toolchain / "aarch64-linux-android29-clang",
                toolchain / "armv7a-linux-androideabi28-clang",
                toolchain / "armv7a-linux-androideabi29-clang",
                build_tools / "aapt",
                build_tools / "apksigner",
                build_tools / "zipalign",
                build_tools / "d8",
                platform / "android.jar",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

            target = next(
                entry
                for entry in TARGETS
                if entry.key == "portal-10-omni-3051355900018050"
            )
            self.assertFalse(target.bundled_simpleperf)
            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
                mock.patch(
                    "provision_portal.keystore_certificate_sha256",
                    return_value=(
                        provision_portal_module.PROJECT_DEBUG_KEYSTORE_SHA256
                    ),
                ),
            ):
                # Without autoroot the NDK simpleperf is not required
                # for a non-bundled target; with autoroot it is, so a
                # missing binary fails here instead of mid-staging.
                android_build_environment(target)
                with self.assertRaisesRegex(
                    ProvisionError, "Android NDK arm64 simpleperf"
                ):
                    android_build_environment(target, require_simpleperf=True)
                simpleperf = ndk / "simpleperf/bin/android/arm64/simpleperf"
                simpleperf.parent.mkdir(parents=True, exist_ok=True)
                simpleperf.touch()
                android_build_environment(target, require_simpleperf=True)

    def test_missing_sdk_fails_with_configuration_help(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = pathlib.Path(temporary) / "missing-sdk"
            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
            ):
                with self.assertRaisesRegex(
                    ProvisionError,
                    "no Portal changes were made.*ANDROID_SDK_ROOT",
                ):
                    android_build_environment()

    def _fake_sdk(self, temporary: str) -> pathlib.Path:
        sdk = pathlib.Path(temporary) / "sdk"
        ndk = sdk / "ndk" / "28.2.13676358"
        toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
        build_tools = sdk / "build-tools" / "37.0.0"
        platform = sdk / "platforms" / "android-36"
        for path in (
            toolchain / "aarch64-linux-android29-clang",
            toolchain / "armv7a-linux-androideabi28-clang",
            toolchain / "armv7a-linux-androideabi29-clang",
            build_tools / "aapt",
            build_tools / "apksigner",
            build_tools / "zipalign",
            build_tools / "d8",
            platform / "android.jar",
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        return sdk

    def test_repo_debug_keystore_is_preferred(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = self._fake_sdk(temporary)
            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
                mock.patch(
                    "provision_portal.keystore_certificate_sha256",
                    return_value=(
                        provision_portal_module.PROJECT_DEBUG_KEYSTORE_SHA256
                    ),
                ) as reader,
            ):
                environment = android_build_environment()

        self.assertEqual(environment["KEYSTORE"], str(ROOT / "debug.keystore"))
        reader.assert_called_once_with(ROOT / "debug.keystore")

    def test_explicit_keystore_overrides_repo_keystore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = self._fake_sdk(temporary)
            custom = pathlib.Path(temporary) / "custom.keystore"
            custom.touch()
            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk), "KEYSTORE": str(custom)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
                mock.patch(
                    "provision_portal.keystore_certificate_sha256",
                    return_value=(
                        provision_portal_module.PROJECT_DEBUG_KEYSTORE_SHA256
                    ),
                ),
            ):
                environment = android_build_environment()

        self.assertEqual(environment["KEYSTORE"], str(custom))

    def test_keystore_fingerprint_mismatch_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = self._fake_sdk(temporary)
            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
                mock.patch(
                    "provision_portal.keystore_certificate_sha256",
                    return_value=(
                        "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:"
                        "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "keystore fingerprint mismatch"
                ):
                    android_build_environment()

    def test_missing_keystore_fails_instead_of_regenerating(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = self._fake_sdk(temporary)
            absent = pathlib.Path(temporary) / "absent.keystore"
            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk), "KEYSTORE": str(absent)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
                mock.patch(
                    "provision_portal.keystore_certificate_sha256"
                ) as reader,
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "keystore not found"
                ):
                    android_build_environment()

            reader.assert_not_called()

    def test_keystore_certificate_sha256_parses_keytool_output(self) -> None:
        completed = subprocess.CompletedProcess(
            [],
            0,
            "Certificate fingerprints:\n"
            "\t SHA1: 5D:0B:1C:2D:3E:4F:50:61:72:83:94:A5:B6:C7:D8:E9:"
            "FA:0B:1C:2D\n"
            "\t SHA256: 7e:65:e6:8e:f9:4a:31:a5:27:7a:d5:b4:70:75:a0:32:"
            "9f:74:2e:f7:7c:6c:33:96:56:50:fe:44:25:85:8d:07\n",
        )
        with mock.patch("provision_portal.subprocess.run", return_value=completed):
            fingerprint = provision_portal_module.keystore_certificate_sha256(
                pathlib.Path("debug.keystore")
            )

        self.assertEqual(
            fingerprint, provision_portal_module.PROJECT_DEBUG_KEYSTORE_SHA256
        )

    def test_keystore_certificate_sha256_rejects_unreadable_keystore(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess([], 1, "")
        with mock.patch("provision_portal.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(ProvisionError, "unverified signing key"):
                provision_portal_module.keystore_certificate_sha256(
                    pathlib.Path("debug.keystore")
                )

class AdbAuthorizationTimeoutCliTest(unittest.TestCase):
    def test_standalone_flag_needs_no_root_action(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--disable-adb-auth-timeout"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.disable_adb_auth_timeout)
        self.assertFalse(arguments.audio)
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_adb_auth_timeout=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"disable_adb_auth_timeout": True},
            )
            self.assertFalse(provisioner.privileged_requested())
            provisioner.target = TARGETS[0]
            self.assertFalse(
                provisioner.adb_framework_boot_persistence_requested()
            )
            self.assertFalse(provisioner.needs_uid1000_payload())

    def test_disable_and_restore_preserve_an_absent_original_setting(self) -> None:
        current = {
            ADB_ENABLED_SETTING: "0",
            "adb_allowed_connection_time": "null",
        }
        saved: list[str] = []

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[:2] == ["shell", "cat"]:
                if not saved:
                    return subprocess.CompletedProcess(arguments, 1, "")
                return subprocess.CompletedProcess(arguments, 0, saved[0])
            if arguments[1:4] == ["settings", "get", "global"]:
                return subprocess.CompletedProcess(
                    arguments, 0, current[arguments[4]] + "\n"
                )
            if arguments[1:4] == ["settings", "put", "global"]:
                current[arguments[4]] = arguments[-1]
            elif arguments[1:4] == ["settings", "delete", "global"]:
                current[arguments[4]] = "null"
            return subprocess.CompletedProcess(arguments, 0, "")

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_adb_auth_timeout=True,
            )
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: (
                        self.assertEqual(remote, ADB_AUTH_TIMEOUT_BACKUP_REMOTE),
                        saved.append(contents),
                    ),
                ),
            ):
                provisioner.disable_adb_authorization_timeout()
                self.assertEqual(current[ADB_ENABLED_SETTING], "1")
                self.assertEqual(current["adb_allowed_connection_time"], "0")
                provisioner.disable_adb_auth_timeout = False
                provisioner.restore_adb_auth_timeout = True
                provisioner.restore_adb_authorization_timeout()

        self.assertEqual(current[ADB_ENABLED_SETTING], "1")
        self.assertEqual(current["adb_allowed_connection_time"], "null")

    def test_privileged_timeout_action_installs_boot_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for target in TARGETS:
                with self.subTest(target=target.key):
                    provisioner = PortalProvisioner(
                        "192.0.2.1:5555",
                        1,
                        pathlib.Path(temporary),
                        audio=True,
                        disable_adb_auth_timeout=True,
                    )
                    provisioner.target = target
                    self.assertTrue(
                        provisioner.adb_framework_boot_persistence_requested()
                    )
                    self.assertTrue(provisioner.needs_uid1000_payload())

    def test_wireless_adb_waits_for_framework_boot_recovery_on_all_targets(
        self,
    ) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-go-terry-5051355900018050"
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                persistent_wireless_adb=True,
            )
            provisioner.target = target
            provisioner.persist_wireless_adb = True
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, "5555\n"),
                ),
                mock.patch.object(provisioner, "verify_adb_auth_timeout"),
                mock.patch.object(
                    provisioner, "verify_adb_framework_enabled"
                ) as verify_framework,
            ):
                provisioner.verify_requested_state()

        verify_framework.assert_called_once_with(wait_seconds=45)

    def test_meta_account_preflight_enables_new_host_prompts_first(self) -> None:
        order: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                remove_meta_accounts=True,
            )
            with (
                mock.patch.object(
                    provisioner,
                    "ensure_adb_framework_enabled",
                    side_effect=lambda: order.append("adb-framework"),
                ) as ensure,
                mock.patch.object(
                    provisioner,
                    "meta_accounts",
                    side_effect=lambda: order.append("accounts") or [],
                ),
                mock.patch.object(
                    provisioner,
                    "disabled_meta_authenticators",
                    return_value=set(),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "# portal-meta-accounts-before-v1\n"
                    ),
                ),
            ):
                provisioner.meta_accounts_preflight()

        ensure.assert_called_once_with()
        self.assertEqual(order[:2], ["adb-framework", "accounts"])

    def test_meta_account_preflight_detects_disabled_package(self) -> None:
        # A package-disabled alohausers (user trial, another tool) is
        # not the designed end state (package enabled, authenticators
        # disabled): preflight must not call it clean even when no
        # accounts remain and the authenticators already read
        # disabled, or the run would skip the action and still fail
        # the strict final verification.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                remove_meta_accounts=True,
            )
            package_state = {"disabled": True}

            def adb_run(
                arguments: list[str],
                timeout: float | None = None,
                check: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                del timeout, check
                if arguments[1:4] == ["pm", "list", "packages"]:
                    output = (
                        "package:com.facebook.alohaservices.alohausers\n"
                        if package_state["disabled"]
                        else ""
                    )
                    return subprocess.CompletedProcess(arguments, 0, output)
                return subprocess.CompletedProcess(
                    arguments, 0, "# portal-meta-accounts-before-v1\n"
                )

            with (
                mock.patch.object(
                    provisioner, "ensure_adb_framework_enabled"
                ),
                mock.patch.object(
                    provisioner, "meta_accounts", return_value=[]
                ),
                mock.patch.object(
                    provisioner,
                    "disabled_meta_authenticators",
                    return_value=set(META_AUTHENTICATOR_COMPONENTS),
                ),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=adb_run
                ),
                mock.patch.object(
                    provisioner.settings_feature, "verify_retained_platform"
                ),
            ):
                self.assertFalse(provisioner.meta_accounts_preflight())
                self.assertTrue(provisioner.meta_accounts_package_disabled)
                # The unchanged strict verification still rejects the
                # package-disabled state...
                with self.assertRaisesRegex(
                    ProvisionError,
                    "alohausers package was disabled instead of its "
                    "authenticators",
                ):
                    provisioner.verify_meta_accounts_removed()
                # ...and passes once the action's device-side enable
                # has normalized the package state.
                package_state["disabled"] = False
                provisioner.verify_meta_accounts_removed()

    def test_meta_account_env_requests_package_enable_only_when_disabled(
        self,
    ) -> None:
        aloha = next(t for t in TARGETS if t.device == "aloha")
        for package_disabled in (True, False):
            with self.subTest(package_disabled=package_disabled):
                with tempfile.TemporaryDirectory() as temporary:
                    provisioner = PortalProvisioner(
                        "192.0.2.1:5555",
                        1,
                        pathlib.Path(temporary),
                        remove_meta_accounts=True,
                    )
                    provisioner.target = aloha
                    provisioner.meta_accounts_package_disabled = (
                        package_disabled
                    )
                    # Staged by the run before any attempt is built.
                    provisioner.uid1000_runtime_apk_remote = (
                        "/data/local/tmp/portal-uid1000-runtime.apk"
                    )
                    provisioner.uid1000_runtime_library_remote = (
                        "/data/local/tmp/libportal-uid1000.so"
                    )

                    def adb_run(
                        arguments: list[str],
                        timeout: float | None = None,
                        check: bool = False,
                    ) -> subprocess.CompletedProcess[str]:
                        del timeout, check
                        value = (
                            "1204"
                            if arguments[:2] == ["shell", "pidof"]
                            else "1000"
                        )
                        return subprocess.CompletedProcess(
                            arguments, 0, value + "\n"
                        )

                    with mock.patch.object(
                        provisioner, "adb_run", side_effect=adb_run
                    ):
                        environment = provisioner.build_exploit_environment(
                            0x1000, 0x2000, 1
                        )
                    self.assertEqual(
                        environment["GHOSTLOCK_REMOVE_META_ACCOUNTS"], "1"
                    )
                    if package_disabled:
                        self.assertEqual(
                            environment[
                                "GHOSTLOCK_META_ACCOUNTS_ENABLE_PACKAGE"
                            ],
                            "1",
                        )
                    else:
                        self.assertNotIn(
                            "GHOSTLOCK_META_ACCOUNTS_ENABLE_PACKAGE",
                            environment,
                        )

    def test_fops_meta_accounts_package_enable_precedes_authenticator_state(
        self,
    ) -> None:
        # The package enable runs in the action's own credential
        # context, before any authenticator state is applied, and a
        # failed enable fails the action there (no completion
        # marker) instead of surfacing later as the host
        # verification's abort.
        for relative in (
            "exploit/src/fops.c",
            "exploit/targets/portal-ripley-2041515800015050/fops.c",
        ):
            fops = (ROOT / relative).read_text()
            self.assertIn("GHOSTLOCK_META_ACCOUNTS_ENABLE_PACKAGE", fops)
            self.assertIn(
                "META_ACCOUNTS_PACKAGE_ENABLED prior=disabled", fops
            )
            self.assertIn(
                "META_ACCOUNTS_PACKAGE_ENABLE_FAILED prior=disabled", fops
            )
            function = fops[fops.index("static int remove_meta_accounts"):]
            enable_at = function.index(
                "GHOSTLOCK_META_ACCOUNTS_ENABLE_PACKAGE"
            )
            failed_at = function.index("META_ACCOUNTS_PACKAGE_ENABLE_FAILED")
            disable_at = function.index(
                "run_pm_disable_component(components[i])"
            )
            self.assertLess(enable_at, disable_at)
            self.assertIn("return 0;", function[failed_at:disable_at])

    def test_framework_enable_must_persist(self) -> None:
        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            output = "0\n" if arguments[1:4] == ["settings", "get", "global"] else ""
            return subprocess.CompletedProcess(arguments, 0, output)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provision_portal_module, "time", _FakeClock()
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "authorization prompts cannot appear"
                ):
                    provisioner.ensure_adb_framework_enabled()

    def test_framework_enable_survives_adbd_restart_window(self) -> None:
        # Run 34 (Portal Mini, Android 10): writing adb_enabled restarts
        # adbd; reads through the restart window first fail at the
        # transport level, then return '', then the written value.
        get_results: list[object] = [
            "\n",
            ProvisionError("error: device offline"),
            "\n",
            "1\n",
        ]

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[1:4] == ["settings", "get", "global"]:
                result = get_results.pop(0)
                if isinstance(result, Exception):
                    raise result
                return subprocess.CompletedProcess(arguments, 0, result)
            return subprocess.CompletedProcess(arguments, 0, "")

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            output = io.StringIO()
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provision_portal_module, "time", _FakeClock()
                ),
                contextlib.redirect_stdout(output),
            ):
                provisioner.ensure_adb_framework_enabled()

        lines = output.getvalue().splitlines()
        self.assertIn(
            "ADB_FRAMEWORK_RESTART_EXPECTED "
            f"reason={ADB_ENABLED_SETTING}-write "
            "detail=adbd-may-restart settle=45s",
            lines,
        )
        self.assertIn(
            f"ADB_FRAMEWORK_OK action=enabled {ADB_ENABLED_SETTING}=1 "
            "prompts=enabled",
            lines,
        )

    def test_framework_verify_zero_wait_keeps_transport_errors(self) -> None:
        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del arguments, timeout, check
            raise ProvisionError("error: device offline")

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                with self.assertRaisesRegex(ProvisionError, "device offline"):
                    provisioner.verify_adb_framework_enabled()


def flag_aware_adb_run(state: dict | None = None):
    """adb_run fake modelling the autoroot disable flag on a device
    whose /data/local/tmp is writable. provision() sets and restores
    that flag on every run (the re-run guard), so fakes that drive
    provision() must answer its commands; every other command fails
    with rc=1."""
    if state is None:
        state = {"present": False, "content": ""}

    def adb_run(arguments, timeout=None, check=False):
        del timeout, check
        arguments = [str(argument) for argument in arguments]
        joined = " ".join(arguments)
        if "portal-autoroot.disable" not in joined:
            return subprocess.CompletedProcess(arguments, 1, "")
        if "test" in arguments:
            return subprocess.CompletedProcess(
                arguments,
                0 if state["present"] else 1,
                provision_portal_module.AUTOROOT_FLAG_PRESENT_TOKEN
                if state["present"]
                else provision_portal_module.AUTOROOT_FLAG_ABSENT_TOKEN,
            )
        if "cat" in arguments:
            if not state["present"]:
                return subprocess.CompletedProcess(arguments, 1, "")
            return subprocess.CompletedProcess(
                arguments, 0, state["content"]
            )
        if "rm" in arguments:
            state["present"] = False
            state["content"] = ""
            return subprocess.CompletedProcess(arguments, 0, "")
        state["present"] = True
        parts = joined.split()
        if "echo" in parts:
            state["content"] = parts[parts.index("echo") + 1]
        return subprocess.CompletedProcess(arguments, 0, "")

    return adb_run


class ShizukuCliTest(unittest.TestCase):
    def test_download_failure_is_reported_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                shizuku=True,
            )
            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=flag_aware_adb_run()
                ),
                # Keep the suite hermetic: without this fake the boot
                # preflight shells out to a real adb binary, which errors
                # on hosts that do not have adb installed. A real adb
                # against an unconfigured device reports "not installed",
                # i.e. False.
                mock.patch.object(
                    provisioner,
                    "adb_framework_boot_preflight",
                    return_value=False,
                ),
                mock.patch(
                    "provision_portal.android_build_environment",
                    return_value={},
                ),
                mock.patch.object(provisioner, "verify_target"),
                mock.patch.object(
                    provisioner,
                    "resolve_shizuku_apk",
                    side_effect=ProvisionError(
                        "Shizuku APK download failed on the host computer"
                    ),
                ),
                mock.patch.object(provisioner, "reboot") as reboot,
            ):
                with self.assertRaisesRegex(ProvisionError, "host computer"):
                    provisioner.provision()

            reboot.assert_not_called()


class RemoteWipeCliTest(unittest.TestCase):
    def test_portal_plus_aloha_debloat_uses_only_validated_components(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-plus-aloha-1041515800015050"
        )
        states = {
            component: ("test", "default")
            for component in DEBLOAT_COMPONENT_NAMES
        }
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                debloat=True,
            )
            provisioner.target = target
            captured: list[str] = []
            with (
                mock.patch.object(
                    provisioner, "read_component_backup", return_value=states
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 1, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        action_lines = captured[0].splitlines()[1:]
        self.assertEqual(len(action_lines), 39)
        self.assertEqual(
            action_lines,
            [
                f"disable\t{component}"
                for component in PORTAL_PLUS_ALOHA_SAFE_COMPONENT_NAMES
            ],
        )

    def test_portal_plus_restore_still_undoes_every_saved_component(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-plus-aloha-1041515800015050"
        )
        states = {
            component: ("test", "default")
            for component in DEBLOAT_COMPONENT_NAMES
        }
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                restore_bloat=True,
            )
            provisioner.target = target
            captured: list[str] = []
            with (
                mock.patch.object(
                    provisioner, "read_component_backup", return_value=states
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        self.assertEqual(len(captured[0].splitlines()[1:]), len(DEBLOAT_COMPONENT_NAMES))

    def test_portal_plus_detects_cross_model_component_overrides(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-plus-aloha-1041515800015050"
        )
        outside_profile = next(
            component
            for component in DEBLOAT_COMPONENT_NAMES
            if component not in PORTAL_PLUS_ALOHA_SAFE_COMPONENT_NAMES
        )
        saved = {
            component: ("test", "default")
            for component in DEBLOAT_COMPONENT_NAMES
        }
        current = dict(saved)
        current[outside_profile] = ("test", "disabled")
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            provisioner.target = target

            self.assertEqual(
                provisioner.unexpected_disabled_debloat_components(saved, current),
                [outside_profile],
            )

    def test_combined_ota_waits_for_remote_wipe_component_actions(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-go-terry-5051355900018050"
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
                debloat=True,
                block_remote_wipe=True,
            )
            provisioner.target = target
            provisioner.ota_already_configured = False
            provisioner.debloat_already_configured = True
            provisioner.remote_wipe_already_configured = False
            real_popen = subprocess.Popen
            action_processes: list[subprocess.Popen[bytes]] = []

            def action_process(
                *args: object, **kwargs: object
            ) -> subprocess.Popen[bytes]:
                # sys.executable child, not /bin/sh, so the suite
                # runs on hosts without a POSIX shell (Windows).
                process = real_popen(
                    [
                        sys.executable,
                        "-c",
                        "import time; "
                        "print('OTA block file install ok=1', flush=True); "
                        "print('component ctl child=123 "
                        "status=00000000 ok=1 uid=0 euid=0', flush=True); "
                        "time.sleep(30)",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                )
                action_processes.append(process)
                return process

            output = io.StringIO()
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
                mock.patch(
                    "provision_portal.subprocess.Popen",
                    side_effect=action_process,
                ),
                mock.patch.object(sys, "stdout", output),
            ):
                self.assertTrue(provisioner.exploit(0x1000, 0x2000, 1))
            for process in action_processes:
                assert process.stdout is not None
                process.stdout.close()

        self.assertIn(
            "NATIVE_ACTIONS_OK actions=component_profile,ota_block",
            output.getvalue(),
        )

    def test_combined_component_actions_are_a_single_bootstrap_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                debloat=True,
                block_remote_wipe=True,
            )

            self.assertTrue(provisioner.only_component_actions_requested())

            provisioner.audio = True
            self.assertFalse(provisioner.only_component_actions_requested())

    def test_completed_component_profiles_are_not_reapplied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                debloat=True,
                block_remote_wipe=True,
            )
            provisioner.debloat_already_configured = True
            provisioner.remote_wipe_already_configured = True

            self.assertFalse(provisioner.needs_component_ctl())

            provisioner.remote_wipe_already_configured = False
            self.assertTrue(provisioner.needs_component_ctl())

            provisioner.remote_wipe_already_configured = True
            provisioner.debloat_already_configured = False
            self.assertTrue(provisioner.needs_component_ctl())

    def test_standalone_block_targets_only_the_two_receivers(self) -> None:
        # The block itself is reached through --debloat now (the
        # fold sets the internal attribute); the provisioner-level
        # action still targets only the two receivers.
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--debloat"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.block_remote_wipe)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                block_remote_wipe=True,
            )
            captured: list[str] = []
            states = {component: "default" for component in REMOTE_WIPE_COMPONENTS}
            with (
                mock.patch.object(
                    provisioner,
                    "ensure_remote_wipe_backup",
                    return_value=states,
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        self.assertEqual(
            provisioner.requested_actions(), {"block_remote_wipe": True}
        )
        self.assertTrue(provisioner.privileged_requested())
        self.assertEqual(len(captured), 1)
        action_lines = captured[0].splitlines()[1:]
        self.assertEqual(
            action_lines,
            [f"disable\t{component}" for component in REMOTE_WIPE_COMPONENTS],
        )

    def test_restore_preserves_each_saved_component_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                restore_remote_wipe=True,
            )
            states = {
                REMOTE_WIPE_COMPONENTS[0]: "default",
                REMOTE_WIPE_COMPONENTS[1]: "enabled",
            }
            captured: list[str] = []
            with (
                mock.patch.object(
                    provisioner,
                    "read_remote_wipe_backup",
                    return_value=states,
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        self.assertEqual(
            captured[0].splitlines()[1:],
            [
                f"default\t{REMOTE_WIPE_COMPONENTS[0]}",
                f"enable\t{REMOTE_WIPE_COMPONENTS[1]}",
            ],
        )



class ApkInstallVerifierBaselineTest(unittest.TestCase):
    def test_each_apk_install_records_its_own_verifier_baseline(self) -> None:
        verifier_states = iter(
            ("", "package:com.facebook.appverifier\n")
        )

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[:5] == ["shell", "pm", "list", "packages", "-d"]:
                return subprocess.CompletedProcess(
                    arguments, 0, next(verifier_states)
                )
            if arguments[0] == "push":
                return subprocess.CompletedProcess(arguments, 0, "1 file pushed\n")
            return subprocess.CompletedProcess(arguments, 0, "Success\n")

        with tempfile.TemporaryDirectory() as temporary:
            apk = pathlib.Path(temporary) / "payload.apk"
            apk.touch()
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                provisioner.install_apk_preserving_verifier(apk, "first")
                self.assertFalse(
                    provisioner.package_verifier_before_install_disabled
                )
                provisioner.install_apk_preserving_verifier(apk, "second")
                self.assertTrue(
                    provisioner.package_verifier_before_install_disabled
                )


class HelperSignatureMismatchInstallTest(unittest.TestCase):
    """INSTALL_FAILED_UPDATE_INCOMPATIBLE fallback, Shizuku helper."""

    INCOMPATIBLE = (
        "Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package "
        "dev.portal.shizukuhelper signatures do not match previously "
        "installed version]\n"
    )

    def _run_install(
        self,
        temporary: str,
        package: str,
        install_outputs: list[str],
    ) -> tuple[dict[str, object], str, ProvisionError | None]:
        calls: dict[str, object] = {"install": 0, "uninstall": [], "push": 0}
        outputs = iter(install_outputs)

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[0] == "push":
                calls["push"] = int(calls["push"]) + 1
                return subprocess.CompletedProcess(
                    arguments, 0, "1 file pushed\n"
                )
            if arguments[:3] == ["shell", "pm", "path"]:
                return subprocess.CompletedProcess(arguments, 1, "")
            if arguments[:5] == ["shell", "pm", "list", "packages", "-d"]:
                return subprocess.CompletedProcess(arguments, 0, "")
            if arguments[0] == "uninstall":
                cast(list[str], calls["uninstall"]).append(arguments[1])
                return subprocess.CompletedProcess(arguments, 0, "Success\n")
            if arguments[0] == "shell":
                calls["install"] = int(calls["install"]) + 1
                output = next(outputs)
                return subprocess.CompletedProcess(
                    arguments, 0 if "Success" in output else 1, output
                )
            raise AssertionError(f"unexpected adb arguments: {arguments}")

        apk = pathlib.Path(temporary) / "helper.apk"
        apk.touch()
        provisioner = PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary)
        )
        stdout = io.StringIO()
        error: ProvisionError | None = None
        with (
            mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
            contextlib.redirect_stdout(stdout),
        ):
            try:
                provisioner.install_apk_preserving_verifier(
                    apk, "shizuku-helper", package
                )
            except ProvisionError as exc:
                error = exc
        return calls, stdout.getvalue(), error

    def test_helper_signature_mismatch_uninstalls_and_reinstalls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, stdout, error = self._run_install(
                temporary,
                "dev.portal.shizukuhelper",
                [self.INCOMPATIBLE, "Success\n"],
            )
        self.assertIsNone(error)
        self.assertEqual(calls["install"], 2)
        self.assertEqual(calls["push"], 2)
        self.assertEqual(calls["uninstall"], ["dev.portal.shizukuhelper"])
        self.assertIn("APK_INSTALL_RETRY", stdout)
        self.assertIn("APK_INSTALL_OK", stdout)

    def test_helper_other_install_error_still_fails_hard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, _, error = self._run_install(
                temporary,
                "dev.portal.shizukuhelper",
                ["Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]\n"],
            )
        self.assertIsNotNone(error)
        self.assertEqual(calls["install"], 1)
        self.assertEqual(calls["uninstall"], [])

    def test_other_package_signature_mismatch_still_fails_hard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, _, error = self._run_install(
                temporary,
                "moe.shizuku.privileged.api",
                [self.INCOMPATIBLE],
            )
        self.assertIsNotNone(error)
        self.assertEqual(calls["install"], 1)
        self.assertEqual(calls["uninstall"], [])

    def test_helper_failed_reinstall_still_fails_hard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, _, error = self._run_install(
                temporary,
                "dev.portal.shizukuhelper",
                [self.INCOMPATIBLE, self.INCOMPATIBLE],
            )
        self.assertIsNotNone(error)
        self.assertEqual(calls["install"], 2)
        self.assertEqual(calls["uninstall"], ["dev.portal.shizukuhelper"])


class OwnPackageSignatureMismatchInstallTest(unittest.TestCase):
    """INSTALL_FAILED_UPDATE_INCOMPATIBLE fallback, own packages."""

    @staticmethod
    def _incompatible(package: str) -> str:
        return (
            "Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package "
            f"{package} signatures do not match previously "
            "installed version]\n"
        )

    def _run_install(
        self,
        temporary: str,
        package: str,
        tag: str,
        install_outputs: list[str],
        force: bool = False,
    ) -> tuple[dict[str, object], str, ProvisionError | None]:
        calls: dict[str, object] = {"install": 0, "uninstall": [], "push": 0}
        outputs = iter(install_outputs)

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[0] == "push":
                calls["push"] = int(calls["push"]) + 1
                return subprocess.CompletedProcess(
                    arguments, 0, "1 file pushed\n"
                )
            if arguments[:3] == ["shell", "pm", "path"]:
                return subprocess.CompletedProcess(arguments, 1, "")
            if arguments[:5] == ["shell", "pm", "list", "packages", "-d"]:
                return subprocess.CompletedProcess(arguments, 0, "")
            if arguments[0] == "uninstall":
                cast(list[str], calls["uninstall"]).append(arguments[1])
                return subprocess.CompletedProcess(arguments, 0, "Success\n")
            if arguments[0] == "shell":
                calls["install"] = int(calls["install"]) + 1
                output = next(outputs)
                return subprocess.CompletedProcess(
                    arguments, 0 if "Success" in output else 1, output
                )
            raise AssertionError(f"unexpected adb arguments: {arguments}")

        apk = pathlib.Path(temporary) / "payload.apk"
        apk.touch()
        provisioner = PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary), force=force
        )
        stdout = io.StringIO()
        error: ProvisionError | None = None
        with (
            mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
            contextlib.redirect_stdout(stdout),
        ):
            try:
                provisioner.install_apk_preserving_verifier(
                    apk, tag, package
                )
            except ProvisionError as exc:
                error = exc
        return calls, stdout.getvalue(), error

    def test_sentinel_signature_mismatch_uninstalls_and_reinstalls(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, stdout, error = self._run_install(
                temporary,
                EXPLOIT_SENTINEL_PACKAGE,
                "exploit-sentinel",
                [self._incompatible(EXPLOIT_SENTINEL_PACKAGE), "Success\n"],
            )
        self.assertIsNone(error)
        self.assertEqual(calls["install"], 2)
        self.assertEqual(calls["push"], 2)
        self.assertEqual(calls["uninstall"], [EXPLOIT_SENTINEL_PACKAGE])
        self.assertIn("APK_INSTALL_RETRY", stdout)
        self.assertIn("APK_INSTALL_OK", stdout)

    def test_sentinel_other_install_error_still_fails_hard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, _, error = self._run_install(
                temporary,
                EXPLOIT_SENTINEL_PACKAGE,
                "exploit-sentinel",
                ["Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]\n"],
            )
        self.assertIsNotNone(error)
        self.assertEqual(calls["install"], 1)
        self.assertEqual(calls["uninstall"], [])

    def test_autoroot_helper_signature_mismatch_uninstalls_and_reinstalls(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, stdout, error = self._run_install(
                temporary,
                AUTOROOT_HELPER_PACKAGE,
                "autoroot-helper",
                [self._incompatible(AUTOROOT_HELPER_PACKAGE), "Success\n"],
            )
        self.assertIsNone(error)
        self.assertEqual(calls["install"], 2)
        self.assertEqual(calls["push"], 2)
        self.assertEqual(calls["uninstall"], [AUTOROOT_HELPER_PACKAGE])
        self.assertIn("APK_INSTALL_RETRY", stdout)
        self.assertIn("APK_INSTALL_OK", stdout)

    def test_force_autoroot_helper_signature_mismatch_still_retries(
        self,
    ) -> None:
        # Regression (Nov 17, 2026): --force used to null the package
        # on its way to the feature, disarming the retry along with
        # the identical-skip. A force run's autoroot staging install
        # hard-failed on a helper signed by the lost pre-Nov-16
        # keystore even though the package is in the retry set.
        with tempfile.TemporaryDirectory() as temporary:
            calls, stdout, error = self._run_install(
                temporary,
                AUTOROOT_HELPER_PACKAGE,
                "autoroot-helper",
                [self._incompatible(AUTOROOT_HELPER_PACKAGE), "Success\n"],
                force=True,
            )
        self.assertIsNone(error)
        self.assertEqual(calls["install"], 2)
        self.assertEqual(calls["push"], 2)
        self.assertEqual(calls["uninstall"], [AUTOROOT_HELPER_PACKAGE])
        self.assertIn("APK_INSTALL_RETRY", stdout)
        self.assertIn("APK_INSTALL_OK", stdout)

    def test_force_other_package_signature_mismatch_still_fails_hard(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, _, error = self._run_install(
                temporary,
                "moe.shizuku.privileged.api",
                "shizuku",
                [self._incompatible("moe.shizuku.privileged.api")],
                force=True,
            )
        self.assertIsNotNone(error)
        self.assertEqual(calls["install"], 1)
        self.assertEqual(calls["uninstall"], [])

    def test_presence_helper_signature_mismatch_uninstalls_and_reinstalls(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            calls, stdout, error = self._run_install(
                temporary,
                PRESENCE_HELPER_PACKAGE,
                "presence-helper",
                [self._incompatible(PRESENCE_HELPER_PACKAGE), "Success\n"],
            )
        self.assertIsNone(error)
        self.assertEqual(calls["install"], 2)
        self.assertEqual(calls["push"], 2)
        self.assertEqual(calls["uninstall"], [PRESENCE_HELPER_PACKAGE])
        self.assertIn("APK_INSTALL_RETRY", stdout)
        self.assertIn("APK_INSTALL_OK", stdout)

    def test_retry_packages_are_exactly_the_own_persistent_packages(
        self,
    ) -> None:
        self.assertEqual(
            SIGNATURE_MISMATCH_RETRY_PACKAGES,
            {
                SHIZUKU_HELPER_PACKAGE,
                EXPLOIT_SENTINEL_PACKAGE,
                AUTOROOT_HELPER_PACKAGE,
                PRESENCE_HELPER_PACKAGE,
            },
        )


class StreamliningTest(unittest.TestCase):
    """Safe-bucket streamlining: skip work already done, cache per run."""

    def _provisioner(self, temporary: str) -> PortalProvisioner:
        return PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary)
        )

    def test_settle_skips_sleep_without_immediate_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            sleeps: list[float] = []
            with (
                mock.patch.object(
                    provision_portal_module, "time"
                ) as fake_time,
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                fake_time.sleep.side_effect = sleeps.append
                provisioner.settle_package_state()
                self.assertEqual(sleeps, [])
                provisioner.settle_package_state(before_reboot=True)
                self.assertEqual(sleeps, [PACKAGE_STATE_SETTLE_SECONDS])

    def test_tool_revision_is_cached(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            calls: list = []

            def fake_run(arguments, timeout=None):
                calls.append(arguments)
                output = "" if "status" in arguments else "abc123\n"
                return subprocess.CompletedProcess(arguments, 0, output)

            with mock.patch.object(provisioner, "run", side_effect=fake_run):
                self.assertEqual(provisioner.tool_revision(), "abc123")
                self.assertEqual(provisioner.tool_revision(), "abc123")
            self.assertEqual(len(calls), 2)

    def test_artifact_hashes_are_cached(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            real_read_bytes = pathlib.Path.read_bytes
            reads: list[pathlib.Path] = []

            def counting_read_bytes(self_path):
                reads.append(self_path)
                return real_read_bytes(self_path)

            with mock.patch.object(
                pathlib.Path, "read_bytes", counting_read_bytes
            ):
                first = provisioner.selected_artifact_hashes()
                count_after_first = len(reads)
                second = provisioner.selected_artifact_hashes()
            self.assertGreater(count_after_first, 0)
            self.assertEqual(len(reads), count_after_first)
            self.assertEqual(first, second)

    def test_simpleperf_push_needed(self) -> None:
        import hashlib as _hashlib

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            local = pathlib.Path(temporary) / "simpleperf"
            local.write_bytes(b"binary-bytes")
            digest = _hashlib.sha256(b"binary-bytes").hexdigest()

            def adb_with(stdout: str, returncode: int = 0):
                return mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], returncode, stdout
                    ),
                )

            with adb_with(f"{digest}  /data/local/tmp/portal-simpleperf\n"):
                self.assertFalse(
                    provisioner.simpleperf_push_needed(
                        local, "/data/local/tmp/portal-simpleperf"
                    )
                )
            with adb_with("0" * 64 + "  /data/local/tmp/portal-simpleperf\n"):
                self.assertTrue(
                    provisioner.simpleperf_push_needed(
                        local, "/data/local/tmp/portal-simpleperf"
                    )
                )
            with adb_with("", returncode=1):
                self.assertTrue(
                    provisioner.simpleperf_push_needed(
                        local, "/data/local/tmp/portal-simpleperf"
                    )
                )

    def test_apk_install_skipped_when_installed_copy_is_identical(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self._provisioner(temporary)
            apk = pathlib.Path(temporary) / "payload.apk"
            apk.write_bytes(b"apk-bytes")
            seen: list[list[str]] = []

            def adb_run(arguments, timeout=None, check=False):
                del timeout, check
                seen.append(list(arguments))
                if arguments[:4] == ["shell", "pm", "path", "com.example.x"]:
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        "package:/data/app/com.example.x/base.apk\n",
                    )
                if arguments[0] == "pull":
                    pathlib.Path(arguments[2]).write_bytes(b"apk-bytes")
                    return subprocess.CompletedProcess(arguments, 0, "")
                raise AssertionError(f"unexpected adb call: {arguments}")

            stdout = io.StringIO()
            with (
                mock.patch.object(
                    provisioner, "adb_run", side_effect=adb_run
                ),
                contextlib.redirect_stdout(stdout),
            ):
                provisioner.install_apk_preserving_verifier(
                    apk, "payload", "com.example.x"
                )
            self.assertIn("APK_INSTALL_SKIP", stdout.getvalue())
            self.assertFalse(any(call[0] == "push" for call in seen))


class DeKioskScrubTest(unittest.TestCase):
    """The de-Kiosk scrub: removed flags are rejected, generic set parses."""

    REMOVED = (
        ["--profile", "kiosk"],
        ["--install-kiosk-satellite"],
        ["--kiosk-permissions"],
        ["--kiosk-home"],
        ["--restore-kiosk-home"],
        ["--device-owner"],
    )

    def test_removed_flags_are_rejected(self) -> None:
        for argv_tail in self.REMOVED:
            with self.subTest(argv=argv_tail):
                with mock.patch.object(
                    sys, "argv", ["provision_portal.py", *argv_tail]
                ), mock.patch("sys.stderr", io.StringIO()):
                    with self.assertRaises(SystemExit):
                        parse_args()

    def test_removed_attributes_are_gone(self) -> None:
        with mock.patch.object(
            sys, "argv", ["provision_portal.py", "--audio"]
        ):
            arguments = parse_args()
        for name in (
            "profile",
            "install_kiosk_satellite",
            "kiosk_permissions",
            "device_owner",
            "kiosk_home",
            "restore_kiosk_home",
        ):
            self.assertFalse(hasattr(arguments, name), name)

    def test_bootstrap_generic_flag_set_parses(self) -> None:
        # The generic flag set bootstrap.sh passes for Portal
        # devices after the scrub (replacing --profile kiosk).
        # The update block and remote-wipe block ride along with
        # --debloat since the consolidation; bootstrap.sh's list
        # was updated to match.
        argv = [
            "provision_portal.py",
            "--serial", "192.0.2.1:5555",
            "--audio",
            "--debloat",
            "--remove-meta-accounts",
            "--optimize-presence",
            "--disable-adb-auth-timeout",
            "--verify-boots", "1",
            "--shizuku",
            "--autoroot",
        ]
        with mock.patch.object(sys, "argv", argv):
            arguments = parse_args()
        self.assertTrue(arguments.audio)
        self.assertTrue(arguments.disable_updates)
        self.assertTrue(arguments.block_remote_wipe)
        self.assertTrue(arguments.debloat)
        self.assertTrue(arguments.remove_meta_accounts)
        self.assertTrue(arguments.optimize_presence)
        self.assertTrue(arguments.allow_app_updates)
        self.assertTrue(arguments.disable_adb_auth_timeout)
        self.assertEqual(arguments.verify_boots, 1)
        self.assertTrue(arguments.shizuku)
        self.assertTrue(arguments.autoroot)
        self.assertEqual(arguments.custom_payload, DEFAULT_CUSTOM_PAYLOAD_LOCAL)


class OtaPlatformBackendTest(unittest.TestCase):
    """Aloha OTA backend selection (upstream issue #31) and the
    provenance-based OTA verification rules."""

    @staticmethod
    def aloha_target():
        return next(t for t in TARGETS if t.device == "aloha")

    @staticmethod
    def omni_target():
        return next(t for t in TARGETS if t.device == "omni")

    @staticmethod
    def ota_adb(
        *,
        disabled_packages: tuple[str, ...] = (),
        gate_false: bool = False,
        backend: str | None = None,
        provenance: bool = False,
        polling_off: bool = True,
    ):
        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[:4] == ["shell", "pm", "list", "packages"]:
                output = "".join(
                    f"package:{package}\n" for package in disabled_packages
                )
            elif arguments[:2] == ["shell", "getprop"]:
                output = (backend or "") + "\n"
            elif arguments[:3] == [
                "shell",
                "dumpsys",
                "facebook.aloha.otaservice",
            ]:
                output = (
                    "Dump OtaConfig\n"
                    "    getString(kOtaJsonUrl): "
                    + (
                        OTA_JSON_URL
                        if polling_off
                        else "https://graph.facebook.com/"
                        "mobile_release_updates"
                    )
                    + "\n"
                    "    getBool(kUpdateIntervalFromServer): false\n"
                    "    getInt64(kUpdateIntervalInitialMinutes): "
                    + (
                        str(OTA_POLL_INTERVAL_MINUTES)
                        if polling_off
                        else "6"
                    )
                    + "\n"
                    "    getBool(kFirmwareOtaUpdateEnable): "
                    + ("false" if gate_false else "true")
                    + "\n"
                )
            elif arguments[:2] == ["shell", "logcat"]:
                output = (
                    "getLatestBooleanWithOptions [18296358819858434], "
                    "latestBoolean: false, source: OVERRIDE\n"
                    if provenance
                    else ""
                )
            else:
                output = ""
            return subprocess.CompletedProcess(arguments, 0, output)

        return adb_run

    def test_backend_backup_preserves_first_value_on_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            with (
                mock.patch.object(
                    provisioner,
                    "read_ota_backend_backup",
                    return_value="false",
                ),
                mock.patch.object(provisioner, "adb_run") as adb,
                mock.patch.object(provisioner, "push_text_atomic") as push,
            ):
                provisioner.prepare_ota_backend_backup()
            adb.assert_not_called()
            push.assert_not_called()

    def test_backend_backup_records_current_value_when_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            with (
                mock.patch.object(
                    provisioner, "read_ota_backend_backup", return_value=None
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "false\n"
                    ),
                ),
                mock.patch.object(provisioner, "push_text_atomic") as push,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                provisioner.prepare_ota_backend_backup()
            contents, remote = push.call_args.args
            self.assertEqual(remote, OTA_BACKEND_BACKUP_REMOTE)
            saved = provision_portal_module.json.loads(contents)
            self.assertEqual(saved["property"], OTA_BACKEND_PROPERTY)
            self.assertEqual(saved["value"], "false")

    def test_backend_restore_phase_uses_saved_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                enable_updates=True,
            )
            provisioner.target = self.aloha_target()
            with (
                mock.patch.object(
                    provisioner,
                    "read_ota_backend_backup",
                    return_value="false",
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "true\n"
                    ),
                ),
                mock.patch(
                    "provision_portal.PortalProvisioner"
                ) as phase,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(provisioner.configure_ota_backend_phase())
            self.assertEqual(
                phase.call_args.kwargs["ota_backend_value"], "false"
            )
            self.assertTrue(phase.call_args.kwargs["enable_updates"])
            phase.return_value.provision.assert_called_once()

    def test_backend_phase_skips_when_property_already_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = self.aloha_target()
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "true\n"
                    ),
                ),
                mock.patch("provision_portal.PortalProvisioner") as phase,
            ):
                self.assertFalse(provisioner.configure_ota_backend_phase())
            phase.assert_not_called()

    def test_backend_phase_does_not_run_for_omni(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = self.omni_target()
            with mock.patch.object(provisioner, "adb_run") as adb:
                self.assertFalse(provisioner.configure_ota_backend_phase())
            adb.assert_not_called()

    def test_backend_property_action_uses_system_identity_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
                ota_backend_value="true",
            )
            provisioner.target = self.aloha_target()
            calls: list[list[str]] = []

            def adb_run(
                arguments: list[str],
                timeout: float | None = None,
                check: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                del timeout, check
                calls.append(arguments)
                value = (
                    "1204"
                    if arguments[:2] == ["shell", "pidof"]
                    else "1000"
                )
                return subprocess.CompletedProcess(
                    arguments, 0, value + "\n"
                )

            with mock.patch.object(
                provisioner, "adb_run", side_effect=adb_run
            ):
                environment = provisioner.build_exploit_environment(
                    0x1000, 0x2000, 1
                )
            self.assertIn(
                ["shell", "pidof", "system_server"],
                calls,
            )
            self.assertEqual(
                environment["GHOSTLOCK_OTA_BACKEND_VALUE"], "true"
            )
            self.assertNotIn("GHOSTLOCK_OTA_BLOCK", environment)
            self.assertNotIn("GHOSTLOCK_RESTORE_OTA_BLOCK", environment)

    def test_aloha_install_uses_installer_identity_and_pins_backend(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = self.aloha_target()
            calls: list[list[str]] = []

            def adb_run(
                arguments: list[str],
                timeout: float | None = None,
                check: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                del timeout, check
                calls.append(arguments)
                value = (
                    "1204"
                    if arguments[:2] == ["shell", "pidof"]
                    else "1000"
                )
                return subprocess.CompletedProcess(
                    arguments, 0, value + "\n"
                )

            with mock.patch.object(
                provisioner, "adb_run", side_effect=adb_run
            ):
                environment = provisioner.build_exploit_environment(
                    0x1000, 0x2000, 1
                )
            self.assertIn(["shell", "pidof", "installd"], calls)
            self.assertEqual(environment["GHOSTLOCK_OTA_BLOCK"], "1")
            self.assertEqual(
                environment["GHOSTLOCK_OTA_PLATFORM_BACKEND"], "1"
            )
            self.assertNotIn("GHOSTLOCK_OTA_BACKEND_VALUE", environment)

    def test_omni_install_has_no_platform_backend_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = self.omni_target()
            calls: list[list[str]] = []

            def adb_run(
                arguments: list[str],
                timeout: float | None = None,
                check: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                del timeout, check
                calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 0, "")

            with mock.patch.object(
                provisioner, "adb_run", side_effect=adb_run
            ):
                environment = provisioner.build_exploit_environment(
                    0x1000, 0x2000, 1
                )
            self.assertFalse(
                any(
                    call[:2] == ["shell", "pidof"] for call in calls
                ),
                "omni OTA install must not resolve a credential identity",
            )
            self.assertEqual(environment["GHOSTLOCK_OTA_BLOCK"], "1")
            self.assertNotIn("GHOSTLOCK_OTA_PLATFORM_BACKEND", environment)
            self.assertNotIn("GHOSTLOCK_OTA_BACKEND_VALUE", environment)

    def test_combined_aloha_env_omits_ota_block(self) -> None:
        # A multi-action run on an installer-credential target: the
        # dedicated OTA phase owns the OTA block action. The main
        # flow's attempts run under init's credential, where the
        # action fails with EACCES and discards won races, so the
        # combined environment must not carry the key even while the
        # OTA state is still unverified.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                audio=True,
                disable_updates=True,
            )
            provisioner.target = self.aloha_target()
            self.assertFalse(provisioner.ota_already_configured)
            calls: list[list[str]] = []

            def adb_run(
                arguments: list[str],
                timeout: float | None = None,
                check: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                del timeout, check
                calls.append(arguments)
                value = (
                    "1204"
                    if arguments[:2] == ["shell", "pidof"]
                    else "1000"
                )
                return subprocess.CompletedProcess(
                    arguments, 0, value + "\n"
                )

            with mock.patch.object(
                provisioner, "adb_run", side_effect=adb_run
            ):
                environment = provisioner.build_exploit_environment(
                    0x1000, 0x2000, 1
                )
            self.assertNotIn("GHOSTLOCK_OTA_BLOCK", environment)
            self.assertNotIn("GHOSTLOCK_OTA_PLATFORM_BACKEND", environment)
            self.assertNotIn(
                "GHOSTLOCK_ACTION_CREDENTIAL_PID", environment
            )
            self.assertFalse(
                any(
                    call[:2] == ["shell", "pidof"] for call in calls
                ),
                "combined attempts must not resolve a credential identity",
            )
            # Sanity: the combined environment really was built, with
            # the run's other actions present.
            self.assertEqual(environment["GHOSTLOCK_AUDIO_PERSIST"], "1")

    def test_combined_aloha_env_omits_presence_profile(self) -> None:
        # Same phase rule as the OTA block: the dedicated presence
        # phase owns the profile action on installer-credential
        # targets, so a combined run's environment must not carry it.
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
                optimize_presence=True,
            )
            provisioner.target = self.aloha_target()
            self.assertFalse(provisioner.presence_already_configured)
            with mock.patch.object(
                provisioner,
                "adb_run",
                return_value=subprocess.CompletedProcess([], 0, "1000\n"),
            ):
                environment = provisioner.build_exploit_environment(
                    0x1000, 0x2000, 1
                )
            self.assertNotIn("GHOSTLOCK_PRESENCE_PROFILE", environment)
            self.assertNotIn("GHOSTLOCK_OTA_BLOCK", environment)

    def test_dedicated_aloha_presence_env_has_presence_profile(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                optimize_presence=True,
            )
            provisioner.target = self.aloha_target()
            calls: list[list[str]] = []

            def adb_run(
                arguments: list[str],
                timeout: float | None = None,
                check: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                del timeout, check
                calls.append(arguments)
                value = (
                    "1204"
                    if arguments[:2] == ["shell", "pidof"]
                    else "1000"
                )
                return subprocess.CompletedProcess(
                    arguments, 0, value + "\n"
                )

            with mock.patch.object(
                provisioner, "adb_run", side_effect=adb_run
            ):
                environment = provisioner.build_exploit_environment(
                    0x1000, 0x2000, 1
                )
            self.assertIn(["shell", "pidof", "installd"], calls)
            self.assertEqual(environment["GHOSTLOCK_PRESENCE_PROFILE"], "1")
            self.assertEqual(
                environment["GHOSTLOCK_PRESENCE_PRIVATE_ONLY"], "1"
            )

    def test_watch_step_action_names_ladder_steps(self) -> None:
        self.assertEqual(watch_step_action(0), "none")
        self.assertEqual(watch_step_action(17), "OTA block")
        self.assertEqual(watch_step_action(19), "presence profile")
        self.assertEqual(watch_step_action(24), "MHA tuning")
        self.assertEqual(watch_step_action(30), "lock repair")
        self.assertEqual(watch_step_action(75), "custom payload")
        self.assertEqual(watch_step_action(151), "audio persistence")
        self.assertEqual(watch_step_action(251), "UID1000 helper")
        self.assertEqual(watch_step_action(999), "unknown")

    def test_preflight_aloha_requires_backend_property(self) -> None:
        aloha = self.aloha_target()
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = aloha
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    side_effect=self.ota_adb(
                        disabled_packages=aloha.ota_packages,
                        gate_false=True,
                        backend="false",
                    ),
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertFalse(provisioner.ota_preflight())
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    side_effect=self.ota_adb(
                        disabled_packages=aloha.ota_packages,
                        gate_false=True,
                        backend="true",
                    ),
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(provisioner.ota_preflight())

    def test_verify_block_aloha_rejects_unselected_backend(self) -> None:
        aloha = self.aloha_target()
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = aloha
            with mock.patch.object(
                provisioner,
                "adb_run",
                side_effect=self.ota_adb(
                    disabled_packages=aloha.ota_packages,
                    gate_false=True,
                    backend="false",
                    provenance=True,
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError,
                    "not using the platform MobileConfig backend",
                ):
                    provisioner.verify_ota_block()

    def test_verify_block_aloha_accepts_override_provenance(self) -> None:
        aloha = self.aloha_target()
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = aloha
            output = io.StringIO()
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    side_effect=self.ota_adb(
                        disabled_packages=aloha.ota_packages,
                        gate_false=True,
                        backend="true",
                        provenance=True,
                    ),
                ),
                contextlib.redirect_stdout(output),
            ):
                provisioner.verify_ota_block()
            self.assertIn("OTA_BLOCK_OK", output.getvalue())
            self.assertIn("source=OVERRIDE", output.getvalue())
            self.assertFalse(provisioner.ota_unverified)

    def test_verify_block_aloha_without_provenance_is_unverified(
        self,
    ) -> None:
        aloha = self.aloha_target()
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = aloha
            output = io.StringIO()
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    side_effect=self.ota_adb(
                        disabled_packages=aloha.ota_packages,
                        gate_false=True,
                        backend="true",
                        provenance=False,
                    ),
                ),
                mock.patch.object(
                    provision_portal_module, "time", _FakeClock()
                ),
                contextlib.redirect_stdout(output),
            ):
                provisioner.verify_ota_block(wait_seconds=4)
            self.assertIn("OTA_BLOCK_UNVERIFIED", output.getvalue())
            self.assertTrue(provisioner.ota_unverified)

    def test_verify_block_omni_keeps_effective_config_pass(self) -> None:
        omni = self.omni_target()
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.target = omni
            output = io.StringIO()
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    side_effect=self.ota_adb(
                        disabled_packages=omni.ota_packages,
                        gate_false=True,
                        provenance=False,
                    ),
                ),
                contextlib.redirect_stdout(output),
            ):
                provisioner.verify_ota_block()
            self.assertIn("source=effective-config", output.getvalue())
            self.assertFalse(provisioner.ota_unverified)

    def test_unverified_ota_action_is_recorded_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            provisioner.ota_unverified = True
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "Facebook/aloha_prod/aloha:9/x\n"
                    ),
                ),
                mock.patch.object(provisioner, "run_state") as run_state,
            ):
                provisioner.write_state("complete")
            actions = run_state.write_state.call_args.kwargs["actions"]
            self.assertEqual(actions["disable_updates"], "unverified")

    def test_verified_ota_action_is_recorded_as_applied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
            )
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "Facebook/aloha_prod/aloha:9/x\n"
                    ),
                ),
                mock.patch.object(provisioner, "run_state") as run_state,
            ):
                provisioner.write_state("complete")
            actions = run_state.write_state.call_args.kwargs["actions"]
            self.assertIs(actions["disable_updates"], True)

    def test_restore_rejects_unrestored_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                enable_updates=True,
            )
            provisioner.target = self.aloha_target()

            def adb_run(
                arguments: list[str],
                timeout: float | None = None,
                check: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                del timeout, check
                output = (
                    "true\n"
                    if arguments[:2] == ["shell", "getprop"]
                    else ""
                )
                return subprocess.CompletedProcess(arguments, 0, output)

            with (
                mock.patch.object(
                    provisioner,
                    "read_ota_backend_backup",
                    return_value="false",
                ),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=adb_run
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError,
                    "backend was not restored",
                ):
                    provisioner.verify_ota_restored()

    def test_restore_accepts_restored_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                enable_updates=True,
            )
            provisioner.target = self.aloha_target()

            def adb_run(
                arguments: list[str],
                timeout: float | None = None,
                check: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                del timeout, check
                output = (
                    "false\n"
                    if arguments[:2] == ["shell", "getprop"]
                    else ""
                )
                return subprocess.CompletedProcess(arguments, 0, output)

            output = io.StringIO()
            with (
                mock.patch.object(
                    provisioner,
                    "read_ota_backend_backup",
                    return_value="false",
                ),
                mock.patch.object(
                    provisioner, "adb_run", side_effect=adb_run
                ),
                contextlib.redirect_stdout(output),
            ):
                provisioner.verify_ota_restored()
            self.assertIn("OTA_RESTORE_OK", output.getvalue())

    def test_fops_recognizes_gate_only_body_as_upgrade_source(
        self,
    ) -> None:
        fops = (ROOT / "exploit/src/fops.c").read_text()
        self.assertIn(
            "21220: portal_framework_platform_mobileconfig", fops
        )
        self.assertIn(
            "1: enable_aosp_mobileconfig_util_over_platform_mobileconfig:",
            fops,
        )
        self.assertIn("GHOSTLOCK_OTA_PLATFORM_BACKEND", fops)
        self.assertIn(
            "file_has_exact_contents(path, contents, "
            "sizeof(contents) - 1)",
            fops,
        )
        # The pre-port gate-only body stays recognized as a legacy
        # upgrade source alongside the extended body.
        self.assertIn("legacy_contents", fops)
        self.assertIn(
            "file_has_exact_contents(path, legacy_contents,",
            fops,
        )

    def test_fops_still_refuses_foreign_override(self) -> None:
        fops = (ROOT / "exploit/src/fops.c").read_text()
        self.assertIn(
            "OTA block refused to replace unrelated existing override",
            fops,
        )
        self.assertIn("errno = EEXIST", fops)
        self.assertIn(
            "file_has_exact_contents(path, body, body_len)", fops
        )
        self.assertIn("GHOSTLOCK_OTA_BACKEND_VALUE", fops)
        self.assertIn("configure_ota_backend", fops)
        self.assertIn(
            "persist.sys.mobileconfigutil.usePlatformMobileConfig", fops
        )

    def test_fops_ota_block_early_returns_log(self) -> None:
        # The OTA block install path's early returns log the failing
        # operation and errno, so the captured per-attempt log names
        # the failure instead of recovering nothing on those paths.
        for relative in (
            "exploit/src/fops.c",
            "exploit/targets/portal-ripley-2041515800015050/fops.c",
        ):
            fops = (ROOT / relative).read_text()
            self.assertIn(
                "OTA block existing override is not a regular file",
                fops,
            )
            self.assertIn(
                "OTA block absence marker write failed", fops
            )
            self.assertIn("OTA block temp file open failed", fops)
        shared = (ROOT / "exploit/src/fops.c").read_text()
        self.assertIn("OTA backend property value rejected", shared)


OTA_DUMP_HEAD = (
    "----------\n"
    "Dump OtaService\n"
    "    lastKnownOtaStatus_: 0, (OtaStatusEnum: idle)\n"
)


def ota_config_dump(
    gate: str = "false",
    interval: str = "1000000",
    url: str = OTA_JSON_URL,
) -> str:
    return (
        OTA_DUMP_HEAD
        + "----------\n"
        "Dump OtaConfig\n"
        f"    getString(kOtaJsonUrl): {url}\n"
        "    getBool(kUpdateIntervalFromServer): false\n"
        f"    getInt64(kUpdateIntervalInitialMinutes): {interval}\n"
        f"    getBool(kFirmwareOtaUpdateEnable): {gate}\n"
        "----------\n"
    )


class PhaseC2RestoreFpsGatingTest(unittest.TestCase):
    """Phase C2 item 2: the restore keys and the presence FPS keys
    follow the same phase-ownership predicates as their apply
    counterparts (the PR #38 pattern). A key carried into a phase
    whose credential cannot perform it fails inside the app-private
    directory and discards won races (steps 17/19/21); a key gated
    out of the owning phase would silently never apply."""

    @staticmethod
    def aloha_target():
        return next(t for t in TARGETS if t.device == "aloha")

    @staticmethod
    def omni_target():
        return next(t for t in TARGETS if t.device == "omni")

    @staticmethod
    def fake_adb(
        arguments: list[str],
        timeout: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        del timeout, check
        return subprocess.CompletedProcess(arguments, 0, "1000\n")

    def environment(self, temporary: str, target, **kwargs):
        provisioner = PortalProvisioner(
            "192.0.2.1:5555", 1, pathlib.Path(temporary), **kwargs
        )
        provisioner.target = target
        # Normally prepared by the uid1000 staging step before any
        # environment is built on embedded-helper targets.
        provisioner.uid1000_runtime_apk_remote = "/data/local/tmp/rt.apk"
        provisioner.uid1000_runtime_library_remote = "/data/local/tmp/rt.so"
        with mock.patch.object(
            provisioner, "adb_run", side_effect=self.fake_adb
        ):
            return provisioner.build_exploit_environment(0x1000, 0x2000, 1)

    def test_dedicated_enable_updates_env_has_ota_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.environment(
                temporary, self.aloha_target(), enable_updates=True
            )
            self.assertEqual(environment["GHOSTLOCK_RESTORE_OTA_BLOCK"], "1")

    def test_combined_enable_updates_env_omits_ota_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.environment(
                temporary,
                self.aloha_target(),
                enable_updates=True,
                audio=True,
            )
            self.assertNotIn("GHOSTLOCK_RESTORE_OTA_BLOCK", environment)

    def test_omni_combined_env_keeps_ota_restore(self) -> None:
        # No dedicated OTA credential: the main flow owns the
        # restore and must keep the key even in a combined run.
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.environment(
                temporary,
                self.omni_target(),
                enable_updates=True,
                audio=True,
            )
            self.assertEqual(environment["GHOSTLOCK_RESTORE_OTA_BLOCK"], "1")

    def test_dedicated_profile_restore_env_has_restore_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.environment(
                temporary,
                self.aloha_target(),
                restore_presence_profile=True,
            )
            self.assertEqual(
                environment["GHOSTLOCK_RESTORE_PRESENCE_PROFILE"], "1"
            )
            self.assertEqual(environment["GHOSTLOCK_RESTORE_PRESENCE_FPS"], "1")
            self.assertEqual(environment["GHOSTLOCK_PRESENCE_REMOVE_KEY"], "1")

    def test_combined_profile_restore_env_omits_restore_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.environment(
                temporary,
                self.aloha_target(),
                restore_presence_profile=True,
                audio=True,
            )
            self.assertNotIn("GHOSTLOCK_RESTORE_PRESENCE_PROFILE", environment)
            self.assertNotIn("GHOSTLOCK_RESTORE_PRESENCE_FPS", environment)
            self.assertNotIn("GHOSTLOCK_PRESENCE_REMOVE_KEY", environment)

    def test_dedicated_fps_env_has_cap_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.environment(
                temporary,
                self.aloha_target(),
                optimize_presence=True,
                presence_fps_cap=5,
            )
            self.assertEqual(environment["GHOSTLOCK_PRESENCE_FPS_CAP"], "5")
            self.assertEqual(environment["GHOSTLOCK_UID1000_PRESENCE_FPS"], "5")
            self.assertEqual(environment["GHOSTLOCK_PRESENCE_REMOVE_KEY"], "1")

    def test_combined_fps_env_omits_cap_keeps_uid1000_fps(self) -> None:
        # The cap keys belong to the dedicated FPS phase on
        # installer-credential targets; GHOSTLOCK_UID1000_PRESENCE_
        # FPS stays in the main flow by design (uid1000 runtime
        # feature configuration + retained-FPS carriage).
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.environment(
                temporary,
                self.aloha_target(),
                audio=True,
                optimize_presence=True,
                presence_fps_cap=5,
            )
            self.assertNotIn("GHOSTLOCK_PRESENCE_FPS_CAP", environment)
            self.assertNotIn("GHOSTLOCK_PRESENCE_REMOVE_KEY", environment)
            self.assertEqual(environment["GHOSTLOCK_UID1000_PRESENCE_FPS"], "5")

    def test_omni_combined_fps_env_keeps_cap_keys(self) -> None:
        # No uid1000 installer credential: no dedicated FPS phase
        # exists, so the main flow keeps the cap keys.
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.environment(
                temporary,
                self.omni_target(),
                audio=True,
                presence_fps_cap=5,
            )
            self.assertEqual(environment["GHOSTLOCK_PRESENCE_FPS_CAP"], "5")
            self.assertEqual(
                environment["GHOSTLOCK_PRESENCE_PREF_ACTION"], "set:5"
            )


class OtaPollingOverrideTest(unittest.TestCase):
    """The OTA override also stops otad's update polling (port of
    upstream 5c2c531d): preflight and verification require the gate
    off AND polling off, and tolerate dumps cut off while otad is
    still starting."""

    def provisioner(self, temporary: str) -> PortalProvisioner:
        provisioner = PortalProvisioner(
            "192.0.2.1:5555",
            1,
            pathlib.Path(temporary),
            disable_updates=True,
        )
        provisioner.target = next(
            target for target in TARGETS if target.device == "omni"
        )
        return provisioner

    def adb(self, dumps: list[str]) -> mock.Mock:
        disabled = "".join(
            f"package:{package}\n"
            for package in next(
                target for target in TARGETS if target.device == "omni"
            ).ota_packages
        )
        remaining = list(dumps)

        def run(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if args[:2] == ["shell", "pm"]:
                return subprocess.CompletedProcess(args, 0, disabled)
            if args[:2] == ["shell", "dumpsys"]:
                text = remaining.pop(0) if len(remaining) > 1 else remaining[0]
                return subprocess.CompletedProcess(args, 0, text)
            return subprocess.CompletedProcess(args, 0, "")

        return mock.Mock(side_effect=run)

    def test_parse_rejects_dump_cut_before_config(self) -> None:
        self.assertIsNone(parse_ota_config(OTA_DUMP_HEAD))
        config = parse_ota_config(ota_config_dump())
        self.assertIsNotNone(config)
        assert config is not None
        self.assertEqual(config["kFirmwareOtaUpdateEnable"], "false")
        self.assertEqual(
            config["kUpdateIntervalInitialMinutes"],
            str(OTA_POLL_INTERVAL_MINUTES),
        )
        self.assertEqual(config["kOtaJsonUrl"], OTA_JSON_URL)

    def test_preflight_retries_while_otad_is_starting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb([OTA_DUMP_HEAD, OTA_DUMP_HEAD, ota_config_dump()])
            with mock.patch.object(provisioner, "adb_run", adb), mock.patch(
                "provision_portal.time.sleep"
            ), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertTrue(provisioner.ota_preflight())
            self.assertIn("dump=complete", output.getvalue())
            self.assertIn("action=skip", output.getvalue())

    def test_preflight_reinstalls_legacy_gate_only_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb(
                [
                    ota_config_dump(
                        interval="6",
                        url="https://graph.facebook.com/"
                        "mobile_release_updates",
                    )
                ]
            )
            with mock.patch.object(provisioner, "adb_run", adb), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertFalse(provisioner.ota_preflight())
            self.assertIn("firmware_gate_false=1", output.getvalue())
            self.assertIn("poll_interval_minutes=6", output.getvalue())
            self.assertIn("update_url_blocked=0", output.getvalue())
            self.assertIn("action=install", output.getvalue())

    def test_preflight_requires_blocked_update_url(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb(
                [
                    ota_config_dump(
                        url="https://graph.facebook.com/"
                        "mobile_release_updates"
                    )
                ]
            )
            with mock.patch.object(provisioner, "adb_run", adb), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertFalse(provisioner.ota_preflight())
            self.assertIn(
                "poll_interval_minutes=1000000", output.getvalue()
            )
            self.assertIn("update_url_blocked=0", output.getvalue())

    def test_preflight_survives_dumpsys_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb([ota_config_dump()])
            original = adb.side_effect
            calls = {"dumpsys": 0}

            def flaky(args: list[str], **kwargs: object):
                if args[:2] == ["shell", "dumpsys"]:
                    calls["dumpsys"] += 1
                    if calls["dumpsys"] == 1:
                        raise ProvisionError(
                            "command timed out: adb shell dumpsys"
                        )
                return original(args, **kwargs)

            adb.side_effect = flaky
            with mock.patch.object(provisioner, "adb_run", adb), mock.patch(
                "provision_portal.time.sleep"
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(provisioner.ota_preflight())
            self.assertEqual(calls["dumpsys"], 2)

    def test_verify_block_requires_polling_off(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb(
                [
                    ota_config_dump(
                        interval="6",
                        url="https://graph.facebook.com/"
                        "mobile_release_updates",
                    )
                ]
            )
            with mock.patch.object(provisioner, "adb_run", adb), \
                    mock.patch.object(
                        provision_portal_module, "time", _FakeClock()
                    ), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(
                    ProvisionError, "polling interval"
                ):
                    provisioner.verify_ota_block(wait_seconds=4)

    def test_fops_bodies_carry_polling_keys_and_legacy(self) -> None:
        for relative in (
            "exploit/src/fops.c",
            "exploit/targets/portal-ripley-2041515800015050/fops.c",
        ):
            fops = (ROOT / relative).read_text()
            for key in (
                "1: updateintervalfromserver: false",
                f"15: updateintervalinitial: {OTA_POLL_INTERVAL_MINUTES}",
                f"21: jsonqueryurl: {OTA_JSON_URL}",
                f"26: updateintervalnonetw: {OTA_POLL_INTERVAL_MINUTES}",
                "36: firmware_ota_update_enable: false",
            ):
                self.assertIn(key, fops, f"{key} missing from {relative}")
            # The gate-only body stays recognized as an upgrade source
            # and the installed-body check is exact-contents.
            self.assertIn("legacy_contents", fops)
            self.assertIn(
                "file_has_exact_contents(path, contents, "
                "sizeof(contents) - 1)",
                fops,
            )


class CollectStatusSupportFieldsTest(unittest.TestCase):
    """--status carries what a support request for another build
    needs: the retail model name when the build is supported, and
    the raw model, device, fingerprint and full kernel string
    either way."""

    ALOHA_FINGERPRINT = (
        "Facebook/aloha_prod/aloha:9/PKQ1.191202.001/"
        "1041515800015050:user/prod-keys"
    )
    KERNEL = (
        "Linux localhost 4.4.153+ #1 SMP PREEMPT armv7l"
    )

    def collect(self, fingerprint: str) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )

            def fake_adb_run(arguments, timeout=None, **_kwargs):
                command = list(arguments)
                if command[:1] == ["shell"]:
                    command = command[1:]
                output = ""
                returncode = 1
                if command[:1] == ["getprop"]:
                    returncode = 0
                    output = {
                        "ro.build.fingerprint": fingerprint,
                        "ro.product.device": "aloha",
                        "ro.product.model": "Portal+",
                    }.get(command[1], "")
                elif command[:2] == ["uname", "-a"]:
                    returncode = 0
                    output = self.KERNEL
                return subprocess.CompletedProcess(
                    arguments, returncode, output, ""
                )

            with mock.patch.object(
                provisioner, "adb_run", side_effect=fake_adb_run
            ):
                return provisioner.collect_status()

    def test_supported_build_reports_retail_model_and_kernel(self) -> None:
        status = self.collect(self.ALOHA_FINGERPRINT)
        target = status["target"]
        self.assertTrue(target["supported"])
        self.assertEqual(
            target["retail_model"], "Meta Portal+ (1st generation)"
        )
        self.assertEqual(target["kernel"], self.KERNEL)
        self.assertEqual(target["fingerprint"], self.ALOHA_FINGERPRINT)

    def test_unsupported_build_still_reports_identifiers(self) -> None:
        status = self.collect(
            "Facebook/aloha_prod/aloha:9/PKQ1.191202.001/"
            "9999999999999999:user/prod-keys"
        )
        target = status["target"]
        self.assertFalse(target["supported"])
        self.assertIsNone(target["retail_model"])
        self.assertEqual(target["model"], "Portal+")
        self.assertEqual(target["device"], "aloha")
        self.assertEqual(target["kernel"], self.KERNEL)


if __name__ == "__main__":
    unittest.main()
