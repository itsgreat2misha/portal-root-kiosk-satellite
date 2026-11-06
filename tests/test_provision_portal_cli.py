from __future__ import annotations

import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from provision_portal import (  # noqa: E402
    ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
    ADB_ENABLED_SETTING,
    DEFAULT_CUSTOM_PAYLOAD_LOCAL,
    MHA_AUDIO_VERIFIED_LOG,
    REMOTE_WIPE_COMPONENTS,
    PortalProvisioner,
    ProvisionError,
    android_build_environment,
    build,
    parse_args,
)
from meta_debloat_components import (  # noqa: E402
    DEBLOAT_COMPONENT_NAMES,
    PORTAL_PLUS_ALOHA_SAFE_COMPONENT_NAMES,
)
from portal_targets import TARGETS  # noqa: E402


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
                "--restore-adb-auth-timeout",
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

    def test_bare_custom_payload_uses_the_in_repo_daemon_build(self) -> None:
        arguments = self.parse(["--custom-payload"])

        self.assertEqual(arguments.custom_payload, DEFAULT_CUSTOM_PAYLOAD_LOCAL)
        self.assertEqual(
            arguments.custom_payload, ROOT / "root-daemon" / "portal-root-daemon"
        )
        self.assertFalse(arguments.shizuku)
        self.assertFalse(arguments.autoroot)

    def test_bare_custom_payload_does_not_enable_default_audio(self) -> None:
        arguments = self.parse(["--custom-payload"])

        self.assertFalse(arguments.audio)

    def test_explicit_custom_payload_path_is_an_override(self) -> None:
        arguments = self.parse(["--custom-payload", "/tmp/other-daemon"])

        self.assertEqual(arguments.custom_payload, pathlib.Path("/tmp/other-daemon"))

    def test_autoroot_implies_shizuku_and_bare_custom_payload(self) -> None:
        arguments = self.parse(["--autoroot"])

        self.assertTrue(arguments.autoroot)
        self.assertTrue(arguments.shizuku)
        self.assertEqual(arguments.custom_payload, DEFAULT_CUSTOM_PAYLOAD_LOCAL)
        self.assertFalse(arguments.audio)

    def test_autoroot_keeps_an_explicit_custom_payload_override(self) -> None:
        arguments = self.parse(["--autoroot", "--custom-payload", "/tmp/other"])

        self.assertTrue(arguments.shizuku)
        self.assertEqual(arguments.custom_payload, pathlib.Path("/tmp/other"))

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
            ):
                environment = android_build_environment()

        self.assertEqual(environment["SDK"], str(sdk))
        self.assertEqual(environment["ANDROID_SDK_ROOT"], str(sdk))
        self.assertEqual(environment["NDK"], str(ndk))
        self.assertEqual(environment["BUILD_TOOLS"], str(build_tools))

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
            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                with self.assertRaisesRegex(
                    ProvisionError, "authorization prompts cannot appear"
                ):
                    provisioner.ensure_adb_framework_enabled()


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
                process = real_popen(
                    [
                        "/bin/sh",
                        "-c",
                        "printf 'OTA block file install ok=1\\n"
                        "component ctl child=123 status=00000000 ok=1 "
                        "uid=0 euid=0\\n'; sleep 30",
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
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--block-remote-wipe"],
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
        # The exact generic flag set bootstrap.sh passes for Portal
        # devices after the scrub (replacing --profile kiosk).
        argv = [
            "provision_portal.py",
            "--serial", "192.0.2.1:5555",
            "--audio",
            "--disable-updates",
            "--block-remote-wipe",
            "--debloat",
            "--remove-meta-accounts",
            "--optimize-presence",
            "--allow-app-updates",
            "--disable-adb-auth-timeout",
            "--verify-boots", "1",
            "--shizuku",
            "--custom-payload",
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


if __name__ == "__main__":
    unittest.main()
