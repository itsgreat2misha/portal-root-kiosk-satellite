#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
# See LICENSE and NOTICE.

"""Inspect, provision, recover, and verify supported Meta Portal devices."""

from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import queue
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from typing import Callable

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
from portal_targets import PortalTarget, find_sibling_target, find_target
import prebuilt_bundle
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
    MHA_TUNING_PATCHED_REMOTE,
    MHA_TUNING_STOCK_REMOTE,
    VOICE_AUDIO_VERIFIED_LOG,
    AudioFeature,
    audio_processing_disabled_observed,
)
from features.shizuku import (
    SIGNATURE_MISMATCH_RETRY_PACKAGES,
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
    OTA_NODEMON_PROPERTY,
    UID1000_RUNTIME_APK_LOCAL,
    UID1000_RUNTIME_PACKAGE,
    PayloadConfig,
    PayloadFeature,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
# Single source of truth for the provisioner version. Release tags must
# read "v" + this string (the release workflow enforces the match).
# The "-dev" suffix marks an untagged development state; it is dropped
# in the commit that cuts a release. This fork ships preview releases
# on the 0.9.x line until the 1.0.0 relaunch.
PROVISIONER_VERSION = "0.9.0"
PROJECT_URL = "https://github.com/itsgreat2misha/portal-root-kiosk-satellite"
ANDROID_NDK_VERSION = "28.2.13676358"
ANDROID_BUILD_TOOLS_VERSION = "37.0.0"
ANDROID_PLATFORM_VERSION = "android-36"
# The project debug signing key, committed at the repository root so
# every build signs the helper APKs with the same key. A device refuses
# a signature-mismatched update, so building with any other key (for
# example a locally regenerated ~/.android/debug.keystore) would strand
# every already-provisioned device; the build-environment check enforces
# this fingerprint and never lets a replacement key be generated.
PROJECT_DEBUG_KEYSTORE = ROOT / "debug.keystore"
PROJECT_DEBUG_KEYSTORE_SHA256 = (
    "7E:65:E6:8E:F9:4A:31:A5:27:7A:D5:B4:70:75:A0:32:"
    "9F:74:2E:F7:7C:6C:33:96:56:50:FE:44:25:85:8D:07"
)
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
DIAGNOSTICS_PRELOAD_REMOTE = "/data/local/tmp/portal-diagnostics-preload.so"
DEFAULT_CUSTOM_PAYLOAD_LOCAL = ROOT / "root-daemon" / "portal-root-daemon"
CUSTOM_PAYLOAD_REMOTE = "/data/local/tmp/portal-root-daemon"
HELPER_REMOTE = "/data/local/tmp/libportal_audio_persist.so"
AUDIO_CTL_LOCAL = ROOT / "exploit/build/portal-audio-ctl.jar"
AUDIO_CTL_REMOTE = "/data/local/tmp/portal-audio-ctl.jar"
ACCOUNT_CTL_LOCAL = ROOT / "exploit/build/portal-account-ctl.jar"
ACCOUNT_CTL_REMOTE = "/data/local/tmp/portal-account-ctl.jar"
COMPONENT_CTL_LOCAL = ROOT / "exploit/build/portal-component-ctl.jar"
COMPONENT_CTL_REMOTE = "/data/local/tmp/portal-component-ctl.jar"
#: Where the channel component executor captures the jar's own
#: output and exit code (see _run_component_ctl_via_rish). The
#: capture lives in a host-created subdirectory of /data/local/tmp
#: because that directory itself is drwxrwx--x on the fleet
#: firmware: the server-side shell runs as uid 0, which is neither
#: the directory's owner nor in its group, so it can traverse the
#: directory and read files by path but cannot create files
#: directly in it. A host-created 0777 subdirectory is creatable
#: and writable from both sides.
COMPONENT_CTL_CAPTURE_DIR = "/data/local/tmp/portal-component-ctl"
COMPONENT_CTL_CAPTURE_REMOTE = COMPONENT_CTL_CAPTURE_DIR + "/last-run.out"
COMPONENT_CTL_RC_MARKER = "PORTAL_COMPONENT_CTL_RC="
RISH_SCRIPT_REMOTE = "/data/local/tmp/rish"
RISH_DEX_REMOTE = "/data/local/tmp/rish_shizuku.dex"
#: The Shizuku manager activity the rish transport prep starts to
#: wake the manager process (see _prepare_rish_transport). The
#: component name is part of the pinned, hash-verified Shizuku
#: APK (SHIZUKU_VERSION), as stable as the rish asset paths above.
SHIZUKU_MANAGER_ACTIVITY = (
    "moe.shizuku.privileged.api/moe.shizuku.manager.MainActivity"
)
#: How many rish probes the transport prep runs before giving up.
RISH_PROBE_ATTEMPTS = 3
#: Shizuku's server config: the shell app's own data file, which
#: the server loads at start and which adb shell can read and
#: write directly (the shell user owns it). The rish client
#: attaches as uid 2000 / com.android.shell; without an allowed
#: entry for that uid the root-mode server demands an on-screen
#: permission confirmation nobody can answer on a kiosk (see
#: _prepare_rish_transport). FLAG_ALLOWED is ConfigManager's
#: 1 << 1 in the pinned Shizuku API; FLAG_DENIED is 1 << 2.
SHIZUKU_CONFIG_REMOTE = "/data/user_de/0/com.android.shell/shizuku.json"
SHIZUKU_RISH_UID = 2000
SHIZUKU_FLAG_ALLOWED = 2
SHIZUKU_FLAG_DENIED = 4
APP_VERIFIER_BACKUP_REMOTE = "/data/local/tmp/portal-package-verifier-before-v1"
APP_VERIFIER_PACKAGE = "com.facebook.appverifier"
ADB_ENABLED_SETTING = "adb_enabled"
#: The TCP port wireless ADB persistence installs and the
#: wireless-ADB restore removes; the verify paths compare the
#: persisted property against this value throughout.
WIRELESS_ADB_PORT = "5555"
#: The manifest action keys that record a Private DNS end state.
#: A completed record must carry at most one of them: the readers
#: resolve the family in this order (dhcp first), so a record
#: holding two — a pre-#64 pair the manifest merges preserved —
#: shadows the intent the later one established (Defect D).
DNS_ACTION_KEYS = ("dhcp_dns", "privacy_dns", "restore_privacy_dns")
#: The manifest action keys that record an operation — a
#: --restore <name> action, plus the Shizuku removal — rather
#: than a persistent end state (Defect E). A recorded operation
#: says it ran once, not that the live state still matches what
#: it produced, so the no-op gate must never satisfy one from
#: the record: a requested operation always executes and
#: verifies its live end state.
OPERATION_ACTION_KEYS = (
    "restore_adb_auth_timeout",
    "restore_audio",
    "enable_updates",
    "restore_bloat",
    "restore_remote_wipe",
    "restore_presence_profile",
    "restore_presence_fps",
    "restore_privacy_dns",
    "restore_app_verifier",
    "restore_camera_light",
    "restore_autoroot",
    "restore_wireless_adb",
    "restore_theme",
    "restore_meta_authenticators",
    "remove_shizuku",
)
#: Apply/restore action pairs for one feature (Defect E record
#: hygiene, mirroring the DNS family drop): a completed record
#: must not carry both sides — the pair is contradictory, and
#: the stale side misstates the device's state to every reader.
#: The DNS pair is the family's own mechanism (DNS_ACTION_KEYS)
#: and is not repeated here. Autoroot has no apply action key —
#: its apply side is the staging request itself, handled in
#: write_state from the autoroot flag.
APPLY_RESTORE_PAIRS = (
    ("audio", "restore_audio"),
    ("disable_updates", "enable_updates"),
    ("debloat", "restore_bloat"),
    ("block_remote_wipe", "restore_remote_wipe"),
    ("remove_meta_accounts", "restore_meta_authenticators"),
    ("optimize_presence", "restore_presence_profile"),
    ("presence_fps_cap", "restore_presence_fps"),
    ("allow_app_updates", "restore_app_verifier"),
    ("disable_adb_auth_timeout", "restore_adb_auth_timeout"),
    ("disable_camera_light", "restore_camera_light"),
    ("persistent_wireless_adb", "restore_wireless_adb"),
    ("system_theme_control", "restore_theme"),
    ("shizuku", "remove_shizuku"),
)
ADB_AUTH_TIMEOUT_SETTING = "adb_allowed_connection_time"
ADB_AUTH_TIMEOUT_BACKUP_REMOTE = (
    "/data/local/tmp/portal-adb-auth-timeout-before-v1.json"
)
PACKAGE_STATE_SETTLE_SECONDS = 15
# Flush-and-age guard for race boots (2026-11-19): a race attempt may
# not start until its boot is at least this old, and the runner syncs
# before the attempt and before every reboot it issues. Every boot
# auto-connects WiFi within seconds; the connection makes
# system_server update the saved-network record and schedule an
# asynchronous WifiConfigStore write, and race boots die young and
# uncleanly (attempt panics, watchdog cuts, runner reboots) inside
# that write's flush window — repeated episodes lost a unit's saved
# network outright. See PortalProvisioner.wait_for_race_boot_window.
# The floor started at 120 s and is 60 s since the 2026-11-19 timing
# measurement (wifi-guard-timing-measurement-2026-11-19): the store's
# deferred flush is a fixed 10.0 s alarm in the device framework
# (BUFFERED_WRITE_ALARM_INTERVAL_MS = 10,000 ms), live
# change-to-write-complete measured 10.1-11.5 s, and the modeled
# heavy-load worst case lands the flush by ~52 s.
RACE_BOOT_MIN_AGE_SECONDS = 60
RACE_BOOT_GUARD_POLL_SECONDS = 5
OTA_UI_PACKAGE = "com.facebook.aloha.otaui"
OTA_SETUP_PACKAGE = "com.facebook.aloha.alohaotasetup"
OTA_BACKEND_PROPERTY = "persist.sys.mobileconfigutil.usePlatformMobileConfig"
OTA_BACKEND_BACKUP_REMOTE = "/data/local/tmp/portal-ota-backend-before-v1.json"
# Minutes otad sleeps between update checks once the OTA override is
# installed, and the closed local URL it uses for any check it still makes.
# Both must match the native override in exploit/src/fops.c.
OTA_POLL_INTERVAL_MINUTES = 1_000_000
OTA_JSON_URL = "https://127.0.0.1:9/"
# The MobileConfig override the native OTA action installs; the path
# must match exploit/src/fops.c. It lives in alohausers' app-private
# directory, so the shell cannot stat it — see _ota_override_present.
OTA_OVERRIDE_REMOTE = (
    "/data/user/0/com.facebook.alohaservices.alohausers/files/"
    "mobileconfig/mc_overrides.json"
)


def parse_ota_config(dump: str) -> dict[str, str] | None:
    """Return otad's effective config values, or None for an incomplete dump.

    otad answers dumpsys while it is still starting and the output can stop
    before its config section, so a missing value is not a stock value.
    """
    if (
        "Dump OtaConfig" not in dump
        or "getBool(kFirmwareOtaUpdateEnable):" not in dump
    ):
        return None
    return {
        match.group(1): match.group(2).strip()
        for match in re.finditer(
            r"get(?:Bool|Int64|String)\((k\w+)\): ([^\r\n]*)", dump
        )
    }
DEFAULT_UID1000_HOST_PACKAGE = "com.facebook.alohasdk.platformbatterystate"
WIRELESS_ADB_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-wireless-adb-installed-v1"
)
OTA_PACKAGES_BACKUP_REMOTE = (
    "/data/local/tmp/portal-ota-packages-before-v1.json"
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
# The flag probe answers with one of these tokens instead of relying
# on the test command's exit code alone (see _autoroot_flag_present).
AUTOROOT_FLAG_PRESENT_TOKEN = "portal-flag-present"
AUTOROOT_FLAG_ABSENT_TOKEN = "portal-flag-absent"
# Delays (seconds) between the guard restore's apply+verify rounds.
# An adbd disruption at restore time (Run 34) clears in seconds, so
# the restore rides it out briefly instead of reporting against a
# transport that was never actually read.
AUTOROOT_GUARD_RESTORE_DELAYS = (0.0, 2.0, 5.0, 10.0)
# Nesting depth of the autoroot guard across PortalProvisioner instances
# in this process: bootstrap phases run nested provision() calls against
# the same device, and only the outermost run owns the flag lifecycle.
_autoroot_guard_depth = 0


def print_banner() -> None:
    print(PROVISIONER_BANNER, file=sys.stderr, flush=True)


# The watch verdict's STEP is cfi_last_step from the native payload:
# the CFI-stage steps below plus the post-root action ladder in
# run_postroot_actions() (exploit/src/fops.c), where the step names
# the first failed action. Steps 70-79 are the custom payload's
# failure phase, 150-199 the audio-persistence sub-steps, and
# 250-269 the UID1000 helper's sub-steps.
WATCH_STEP_ACTIONS: dict[int, str] = {
    0: "none",
    1: "CFI write",
    2: "CFI llseek repair",
    3: "CFI readback",
    4: "FOPS check",
    5: "FOPS restore",
    6: "FOPS verify",
    7: "post-root cleanup",
    8: "credential install",
    9: "KASLR base",
    10: "boot-id restore",
    11: "ashmem open",
    12: "runtime memstart",
    13: "audio control",
    14: "wireless ADB",
    16: "device owner",
    17: "OTA block",
    18: "Meta accounts",
    19: "presence profile",
    20: "Shizuku key",
    21: "presence FPS",
    22: "component profile",
    23: "presence key",
    24: "MHA tuning",
    25: "UID1000 camera light",
    26: "action child spawn",
    27: "owner clear",
    28: "binary scratch verify",
    30: "lock repair",
}


def watch_step_action(step: int) -> str:
    """Name the native ladder step a watch verdict reports."""
    if step in WATCH_STEP_ACTIONS:
        return WATCH_STEP_ACTIONS[step]
    if 70 <= step < 80:
        return "custom payload"
    if 150 <= step < 200:
        return "audio persistence"
    if 250 <= step < 270:
        return "UID1000 helper"
    return "unknown"


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
        collect_diagnostics: bool = False,
        backup_path: pathlib.Path | None = None,
        recover: bool = False,
        skip_build: bool = False,
        bundle: pathlib.Path | None = None,
        force: bool = False,
        persistent_wireless_adb: bool = False,
        disable_adb_auth_timeout: bool = False,
        restore_adb_auth_timeout: bool = False,
        restore_autoroot: bool = False,
        restore_wireless_adb: bool = False,
        restore_theme: bool = False,
        restore_meta_authenticators: bool = False,
        wireless_adb_only: bool = False,
        adb_framework_only: bool = False,
        meta_accounts_local_only: bool = False,
        meta_accounts_auth_only: bool = False,
        meta_accounts_finalize_only: bool = False,
        ota_backend_value: str | None = None,
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
        self.ota_backend_value = ota_backend_value
        self.ota_unverified = False
        # Set when a presence runtime verification deferred because
        # the camera lens cover is closed: the durable presence
        # state was verified, but the pipeline was never observed
        # streaming. write_state records the presence actions as
        # "deferred" (the ota_unverified pattern above) so no later
        # run treats the streaming verification as done, and
        # report_deferred_failures() surfaces it in the final
        # report without failing the run.
        self.presence_deferred = False
        # Set when the fast path skipped the root-channel apply up
        # front because the unified audio verdict read repair: the
        # repair is performable only by the dedicated installer-
        # credential bootstrap on the race path, so the channel
        # never engages for it (Defect H). report_deferred_failures()
        # names the outcome at the end, judged against the device's
        # end state (the C3-B verification-at-the-end shape).
        self.audio_repair_channel_skipped = False
        # Set when any win in this run (a nested bootstrap run's win
        # included, propagated by the phase that ran it) set
        # otad.nodemon and read it back true. The posture judgment
        # uses it because the property itself is per-boot and no
        # mechanism sets it on the payload boot a combined run ends
        # on (PR #45 validation, 2026-11-17).
        self.ota_nodemon_set_this_run = False
        # Set when this run's dedicated OTA bootstrap returned
        # normally, which means its install action completed — and
        # that action verifies the override file's exact contents
        # as its last step. The posture judgment's override-presence
        # evidence when no root channel can stat the file.
        self._ota_install_verified_this_run = False
        # While true, report_deferred_failures() re-judges but does
        # not raise: a custom payload phase is still to run in this
        # invocation, and the judgment that ends the run happens in
        # the final report after it.
        self._payload_phase_pending = False
        # The alohausers package state observed at this run's start
        # (before any phase of the run could change it), and whether
        # the end-of-run posture apply already ran. Together with
        # the start manifest they decide the recorded desired state
        # (C3-A): a run that STARTS with the package disabled while
        # removing Meta accounts records the disabled posture as the
        # desired end state instead of treating it as drift.
        self._alohausers_disabled_at_start: bool | None = None
        self._posture_apply_attempted = False
        # Set when this run has verified it ENDS in the disabled
        # posture: the end-of-run posture step's own verification,
        # or the completion-write end-state observation in
        # write_state. _desired_state() then records the posture
        # from the run's own end state, regardless of the start
        # state or the flags requested (Defect J): the start-state
        # rule alone made the posture unreachable from a drifted
        # device, because the only run that recorded it had to
        # start already disabled.
        self._alohausers_posture_established = False
        # The live Private DNS values behind the most recent
        # _dns_drift verdict, for the fast-path drift log line.
        self._dns_drift_live: tuple[str, str] | None = None
        # Process whose credential the most recently built exploit
        # environment's action child clones, if any; reported by
        # exploit() alongside the environment's action keys.
        self._action_credential_source: str | None = None
        self.enable_updates = enable_updates
        self.debloat = debloat
        self.debloat_already_configured = False
        self.restore_bloat = restore_bloat
        self.block_remote_wipe = block_remote_wipe
        self.remote_wipe_already_configured = False
        self.restore_remote_wipe = restore_remote_wipe
        self.remove_meta_accounts = remove_meta_accounts
        self.meta_accounts_absent = False
        self.meta_accounts_package_disabled = False
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
        # Phase C2 Private DNS state: the manifest this run started
        # from (captured before any write of ours replaces it), the
        # stages path's deferred DNS apply, and a recorded-state
        # repair routed through the channel path.
        self._start_state: dict[str, object] | None = None
        self._start_state_captured = False
        # The verification boots THIS run established, recorded by
        # verify_across_two_reboots. A merged completion write
        # takes them over the start manifest's verification block:
        # in a combined run the standard install phase verifies
        # the boots and writes them, and the payload phase's
        # terminal merged write then merged against the START
        # snapshot, carrying its (null) verification forward over
        # the boots the run itself had just recorded (Defect K).
        self._verified_boots: tuple[str | None, str | None] | None = None
        self._dns_apply_deferred = False
        self._dns_repair_expectation: tuple[str, str] | None = None
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
                disable_updates=self.disable_updates,
                enable_updates=self.enable_updates,
                disable_camera_light=self.disable_camera_light,
                restore_camera_light=self.restore_camera_light,
                restore_presence_fps=self.restore_presence_fps,
                restore_presence_profile=self.restore_presence_profile,
                presence_fps_cap=self.presence_fps_cap,
                privacy_dns=self.privacy_dns,
                dhcp_dns=self.dhcp_dns,
                restore_privacy_dns=self.restore_privacy_dns,
                custom_payload=self.custom_payload is not None,
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
            stage_simpleperf=(
                lambda *a, **k: self.stage_simpleperf(*a, **k)
            ),
            presence_fps_action_requested=(
                lambda: self.presence_fps_action_requested()
            ),
            stop_root_daemon=lambda *a, **k: self.stop_root_daemon(*a, **k),
            authorized_shizuku_key=lambda: self.authorized_shizuku_key,
            read_saved_shizuku_key_marker=(
                lambda: self.read_saved_shizuku_key_marker()
            ),
            read_private_dns_backup=lambda *a, **k: (
                self.read_private_dns_backup(*a, **k)
            ),
            desired_state=lambda: self._desired_state(),
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
            authorized_shizuku_key=lambda: self.authorized_shizuku_key,
            authorized_shizuku_key_already=(
                lambda: self.authorized_shizuku_key_already
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
                restore_meta_authenticators=self.restore_meta_authenticators,
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
            alohausers_desired_disabled=lambda: (
                self._desired_state().get("alohausers_package") == "disabled"
            ),
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
        self.shizuku_key_source: str | None = None
        # The public key a race win in THIS run authorized (the staged
        # host copy at that win), and whether that authorize found it
        # already in adb_keys. Autoroot staging judges the pair it
        # copies against this record; the on-device saved marker is
        # only the fallback for runs that authorized nothing, because
        # its writer (the native save from the staged scratch file)
        # can lag the helper's live pair in the reuse path.
        self.authorized_shizuku_key: str | None = None
        self.authorized_shizuku_key_already: bool = False
        self.staged_autoroot_key_sha256: str | None = None
        self.presence_public_key: pathlib.Path | None = None
        self.uid1000_runtime_apk_remote: str | None = None
        self.uid1000_runtime_library_remote: str | None = None
        self.uid1000_runtime_package_installed = False
        self.package_verifier_before_install_disabled: bool | None = None
        self.status_only = status_only
        self.dry_run = dry_run
        self.collect_diagnostics = collect_diagnostics
        self.backup_path = backup_path
        self.recover = recover
        self.skip_build = skip_build
        self.bundle = bundle
        self.bundle_root: pathlib.Path | None = None
        self.force = force
        self.persistent_wireless_adb = persistent_wireless_adb
        self.disable_adb_auth_timeout = (
            disable_adb_auth_timeout or persistent_wireless_adb
        )
        self.restore_adb_auth_timeout = restore_adb_auth_timeout
        self.restore_autoroot = restore_autoroot
        self.restore_wireless_adb = restore_wireless_adb
        self.restore_theme = restore_theme
        self.restore_meta_authenticators = restore_meta_authenticators
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
            wait_notice=lambda: self._adb_wait_notice(),
        )
        self.adb = self.session.adb
        self.target: PortalTarget | None = None
        self.persist_wireless_adb = False
        self._wireless_adb_verified = False
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

    def restore_theme_uid1000_action_requested(self) -> bool:
        """The theme restore needs the install loop only where the
        theme control lives behind the UID-1000 marker (its deletion
        and the helper teardown are native work); elsewhere the
        recorded value replays from the shell."""
        return bool(
            self.restore_theme
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
            or self.restore_meta_authenticators
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
            "restore_meta_authenticators",
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

    def _adb_wait_notice(self) -> str | None:
        # While a reboot wait runs on a Portal whose wireless ADB is not
        # persistent yet, the device only comes back when the user
        # re-enables ADB by hand; DeviceSession prints this during long
        # unanswered waits. Once persistence is installed (or verified)
        # the device returns on its own and no prompt may appear.
        if not self.persist_wireless_adb or self._wireless_adb_verified:
            return None
        return (
            "WAITING_FOR_ADB the Portal has not reconnected since the "
            "reboot. If WIRELESS_ADB_OK has not appeared yet, enable ADB "
            "in the Portal's Debug menu and run `adb -d tcpip 5555` from "
            "another terminal; the provisioner keeps waiting."
        )

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

    def _activate_prebuilt_bundle(self) -> None:
        """Verify the --bundle release bundle against the selected
        target and install its artifacts in place of a local build.

        Runs after verify_target() and before every fast path, build
        and artifact read: the manifest's target entry must match
        the device-selected target (key, fingerprint, preload),
        every listed file must hash to its recorded value, and a
        release signature, when present, must verify against the
        pinned release certificate. Any failure raises before the
        run changes anything on the device. On success the run
        proceeds with skip_build set: the bundle's artifacts are
        byte-identical to what the local build would produce, and
        every later artifact-hash gate reads them as usual.
        """
        if self.target is None:
            raise ProvisionError("target must be selected before bundle use")
        bundle = prebuilt_bundle.load_bundle(self.bundle)
        signed = prebuilt_bundle.verify_signature(bundle, ROOT)
        entry = prebuilt_bundle.select_target_entry(bundle, self.target)
        prebuilt_bundle.verify_files(bundle)
        installed = prebuilt_bundle.install_artifacts(bundle, ROOT)
        self.bundle_root = bundle.root
        self.skip_build = True
        if self.shizuku and self.shizuku_apk is None:
            apk = prebuilt_bundle.bundled_shizuku_apk(bundle, SHIZUKU_APK_NAME)
            if apk is not None:
                self.shizuku_apk = apk
                self.shizuku_feature.shizuku_apk = apk
        print(
            f"PREBUILT_BUNDLE_OK target={entry['key']} "
            f"version={bundle.manifest.get('provisioner_version')} "
            f"files={len(installed)} signed={int(signed)} "
            f"root={bundle.root}",
            flush=True,
        )

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
        # The probe answers with an explicit token, never a bare
        # exit code: during an adbd disruption (Run 34: the run's
        # own adb_enabled write restarting adbd) a bare `test -f`
        # returned a plain non-zero with no error text while the
        # command never executed, and the guard release read that
        # as "absent" - it printed AUTOROOT_GUARD_RESTORED over a
        # flag that was still on disk. Only an answer carrying a
        # token is believed; anything else is a transport failure
        # the caller surfaces, never a state.
        result = self.adb_run(
            [
                "shell",
                "test",
                "-f",
                AUTOROOT_DISABLE_FLAG_REMOTE,
                "&&",
                "echo",
                AUTOROOT_FLAG_PRESENT_TOKEN,
                "||",
                "echo",
                AUTOROOT_FLAG_ABSENT_TOKEN,
            ],
            timeout=15,
        )
        answers = result.stdout.split()
        if AUTOROOT_FLAG_PRESENT_TOKEN in answers:
            return True
        if AUTOROOT_FLAG_ABSENT_TOKEN in answers:
            return False
        raise ProvisionError(
            "could not determine the autoroot disable flag state: "
            f"adb answered {result.stdout.strip()!r} "
            f"(rc={result.returncode})"
        )

    def _apply_autoroot_flag_state(self, present: bool) -> None:
        if present:
            self.adb_run(
                ["shell", "touch", AUTOROOT_DISABLE_FLAG_REMOTE],
                timeout=15,
            )
        else:
            self.adb_run(
                ["shell", "rm", "-f", AUTOROOT_DISABLE_FLAG_REMOTE],
                timeout=15,
            )

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
        self._report_autoroot_stood_down()

    def _report_autoroot_stood_down(self) -> None:
        """Surface a failure-budget stand-down found on the device.

        After 10 consecutive verdict-less (crashed or frozen)
        attempts the on-device helper stops racing and records the
        stand-down in its state file; a provision run is the next
        host connection, so report it here, where the run already
        inspects the autoroot guard state. Best-effort: a device
        without the state file, or without the stand-down key, has
        nothing to report, and a failed read never fails the run.
        The stand-down itself is untouched - a re-stage clears it,
        and so does the user on the device.
        """
        try:
            result = self.adb_run(
                ["shell", "cat", f"{AUTOROOT_REMOTE_DIR}/state"],
                timeout=15,
            )
        except (ProvisionError, OSError):
            return
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key.strip()] = value.strip()
        if values.get("budget_stood_down") == "1":
            print(
                "AUTOROOT_STOOD_DOWN streak="
                + values.get("budget_streak", "?"),
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
        # Apply, then verify against the flag's actual state, in a
        # bounded retry loop: the Run 34 restore issued its rm into
        # an adbd disruption, the rm never landed, and the old
        # exit-code check read the broken transport as success.
        # Each round re-applies (the apply is idempotent) and only
        # a verified read of the wanted state ends the loop; the
        # delays ride out a disruption that clears in seconds. A
        # restore that never verifies reports RESTORE_FAILED with
        # the last observed problem - the log line and the device
        # end state cannot silently disagree again.
        want_present = prior == "present"
        problem: str | None = None
        for delay in AUTOROOT_GUARD_RESTORE_DELAYS:
            if delay:
                time.sleep(delay)
            problem = (
                "the pre-existing disable flag could not be restored"
                if want_present
                else "the disable flag is still present"
            )
            try:
                self._apply_autoroot_flag_state(want_present)
                if self._autoroot_flag_present() == want_present:
                    problem = None
                    break
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

    # ---- re-run fast paths: no-op and root-channel apply -----------
    #
    # On an already-provisioned device, a re-run whose recorded state
    # still matches this build, the requested actions, and the live
    # root setup has nothing to do (no-op, below). A re-run whose
    # state drifted only in shell-applicable ways applies just the
    # delta under the device's verified existing root setup (the
    # channel path) instead of re-racing both races. Anything else —
    # and any channel failure — falls back to the normal guarded race
    # run. --force skips both fast paths. Neither path ever runs for
    # nested bootstrap provision() calls (guard depth > 1): a
    # bootstrap's single action must always really apply.

    def _noop_blocker(self, state: dict[str, object]) -> str | None:
        """Manifest-side no-op conditions; None when they all hold."""
        if state.get("status") != "complete":
            return f"status-{state.get('status')}"
        if state.get("tool_revision") != self.tool_revision():
            return "tool-revision"
        if self.target is None or state.get("target") != self.target.key:
            return "target"
        if state.get("fingerprint") != self.target.fingerprint:
            return "fingerprint"
        recorded_actions = state.get("actions")
        if not isinstance(recorded_actions, dict):
            return "actions-unrecorded"
        for name, value in self.requested_actions().items():
            if name in OPERATION_ACTION_KEYS:
                # Operations are not states (Defect E): the
                # record satisfied a repeated --restore theme
                # against a live ui_night_mode a later apply had
                # changed, and the run no-oped without executing
                # (closure session 6, Nov 19, 2026). A requested
                # operation blocks the no-op unconditionally so
                # it executes and verifies its live end state.
                return f"actions-{name}"
            if recorded_actions.get(name) == value:
                continue
            if (
                name == "disable_updates"
                and self._recorded_posture_ota_gating_trusted(state)
            ):
                # Gating only: on a boot where autoroot has not
                # won, no live OTA proof can pass in the recorded
                # posture (otad.nodemon is per-boot and win-set;
                # the override is inert behind the disabled
                # package), so a completion recorded "unverified"
                # by a win-less run's posture judgment would refuse
                # the no-op forever. The posture criteria that CAN
                # be read stand in at the gate; nothing here records
                # the action verified, and a run that applies OTA
                # still ends in the unchanged end-of-run judgment.
                continue
            return f"actions-{name}"
        recorded_hashes = state.get("artifact_sha256")
        if not isinstance(recorded_hashes, dict):
            return "artifacts-unrecorded"
        current_hashes = self.selected_artifact_hashes()
        for name, digest in recorded_hashes.items():
            # Only artifacts this run also selects can be compared: a
            # subset run does not select (and must not be blocked by)
            # artifacts belonging to actions it did not request.
            current = current_hashes.get(name)
            if current is not None and current != digest:
                return f"artifact-{name}"
        return None

    def _shizuku_root_ok(self) -> bool:
        pid = self.adb_run(
            ["shell", "pidof", "shizuku_server"], timeout=5
        ).stdout.strip()
        if not pid:
            return False
        status = self.adb_run(
            ["shell", "cat", f"/proc/{pid.split()[0]}/status"], timeout=5
        ).stdout
        match = re.search(r"^Uid:\s+(\d+)", status, re.MULTILINE)
        return match is not None and match.group(1) == "0"

    def _root_setup_blocker(self) -> str | None:
        """Live proof that the device's existing root setup is intact:
        root-mode Shizuku answering on this boot (which only the
        autoroot handoff or a provision run can have produced), plus
        the sentinel and autoroot helper packages present."""
        if not self._shizuku_root_ok():
            return "shizuku-root"
        if self.uses_exploit_sentinel():
            path = self.adb_run(
                ["shell", "pm", "path", EXPLOIT_SENTINEL_PACKAGE],
                timeout=10,
            ).stdout
            if not path.startswith("package:"):
                return "sentinel-missing"
        if self.autoroot:
            path = self.adb_run(
                ["shell", "pm", "path", AUTOROOT_HELPER_PACKAGE],
                timeout=10,
            ).stdout
            if not path.startswith("package:"):
                return "autoroot-helper-missing"
        return None

    def autoroot_staged(self) -> bool:
        """Whether autoroot staging is in place on the device, staged
        by this run or an earlier one. Staged autoroot replays the
        exploit on every boot and needs the exploit sentinel package
        installed, so a run that finds staging in place must leave
        the sentinel installed on every exit path."""
        if self.autoroot:
            return True
        return (
            self.adb_run(
                ["shell", "test", "-f", f"{AUTOROOT_REMOTE_DIR}/run.sh"],
                timeout=5,
            ).returncode
            == 0
        )

    def _ensure_sentinel_for_staged_autoroot(self) -> None:
        """Run-exit guarantee for the exploit sentinel.

        Phases remove the sentinel at their ends, and the failure
        paths patched earlier only cover aborts raised inside those
        phases: an abort landing after a phase-end removal (run37b:
        a verification failure after the install loop's removal, with
        no later phase to re-stage it) still left staged autoroot
        with no sentinel to replay and no way to ever win.
        provision() calls this on every exit of the outermost run:
        when autoroot is staged, leave the sentinel installed —
        reinstall it when a removal was the last word, otherwise
        record the retention. A failed reinstall raises, so a run
        never reports success while stranding staged autoroot."""
        if self._autoroot_guard_nested:
            # A bootstrap phase's nested provision(): the outermost
            # run owns the sentinel's end state, as it owns the
            # autoroot guard's flag lifecycle.
            return
        if not self.uses_exploit_sentinel():
            return
        if not self.autoroot_staged():
            return
        path = self.adb_run(
            ["shell", "pm", "path", EXPLOIT_SENTINEL_PACKAGE],
            timeout=10,
        ).stdout
        if path.startswith("package:"):
            print(
                "EXPLOIT_SENTINEL_RETAINED reason=autoroot",
                flush=True,
            )
            return
        self.prepare_exploit_sentinel()
        print("EXPLOIT_SENTINEL_RESTAGED reason=autoroot", flush=True)

    def _channel_blocker(self, state: dict[str, object]) -> str | None:
        """Eligibility for the root-channel apply path; None when the
        delta can be applied without racing. Any requested action
        whose apply mechanism is a credential bootstrap, the install
        loop, or an adb_keys write disqualifies the channel — the
        race run owns those."""
        if state.get("status") != "complete":
            return f"status-{state.get('status')}"
        blocker = self._root_setup_blocker()
        if blocker is not None:
            return blocker
        if self.disable_camera_light:
            return "retired-camera-light"
        property_name = (
            self.target.wireless_adb_file_property
            if self.target and self.target.wireless_adb_file_property
            else "persist.adb.tcp.port"
        )
        if self.target and self.target.wireless_adb_file_property:
            persistent_port = (
                "5555"
                if self.adb_run(
                    ["shell", "test", "-f", WIRELESS_ADB_INSTALLED_REMOTE],
                    timeout=5,
                ).returncode
                == 0
                else ""
            )
        else:
            persistent_port = self.adb_run(
                ["shell", "getprop", property_name], timeout=5
            ).stdout.strip()
        if self.privileged_requested() and persistent_port != "5555":
            return "wireless-adb-bootstrap"
        if (
            self.adb_framework_boot_install_requested()
            and not self.adb_framework_boot_configured
        ):
            return "adb-framework-bootstrap"
        if self.audio:
            # The routing decision is made HERE, before the channel
            # can engage, from the one audio verdict both preflights
            # print (Defect H). A repair verdict is its own blocker:
            # the repair is a private install performed by the
            # dedicated bootstrap with the installer credential a
            # race win obtains, and no channel mechanism performs it
            # (re-pushing the staged artifact would not make the
            # running watchdog load it, and nothing on the channel
            # path restarts aiservice), so the race path owns it
            # from the start rather than after an engaged channel
            # run falls back into it.
            audio_action = self.audio_health().action
            if audio_action == "repair":
                return "audio-repair-bootstrap"
            if audio_action != "skip":
                return "audio-not-configured"
        if (
            self.disable_updates
            and not self.ota_preflight()
            and not self._recorded_posture_ota_trusted(state)
            and not self._recorded_posture_ota_gating_trusted(state)
        ):
            # In the recorded alohausers-disabled posture the live
            # dump reads unconfigured by design; the manifest's
            # posture-judged completion is the trust record (C3-A).
            # The verify step re-checks the posture criteria
            # directly, so a device that left the posture still
            # fails there rather than passing on the record alone.
            # The gating trust covers the record a win-less run's
            # posture judgment left "unverified": it re-checks the
            # posture criteria that can be read on any boot (the
            # staged conf, the package state) and stands in only
            # for the ones that cannot (the per-boot property, the
            # app-private override file).
            return "ota-not-configured"
        if self.remove_meta_accounts and not self.meta_accounts_preflight():
            # In the recorded alohausers-disabled posture the
            # preflight's already_clean is unreachable by design:
            # it requires the package NOT disabled, while the
            # posture disables it. The recorded posture satisfies
            # that one clause when the preflight's live reads
            # (accounts absent, authenticators disabled) still
            # hold; the stages path's enable-then-remove flow
            # keeps using the preflight unchanged.
            if not self._recorded_posture_meta_trusted(state):
                return "meta-accounts-not-clean"
        if self.optimize_presence and not self.presence_preflight():
            return "presence-not-configured"
        if (
            self.presence_fps_cap is not None
            and not self.presence_fps_preflight()
        ):
            return "presence-fps-not-configured"
        if (
            self.debloat
            and self.target
            and self.target.shell_root_package_actions
            and not self.debloat_preflight()
        ):
            return "debloat-bootstrap"
        if (
            self.block_remote_wipe
            and self.target
            and self.target.shell_root_package_actions
            and not self.remote_wipe_preflight()
        ):
            return "remote-wipe-bootstrap"
        if (
            self.system_theme_control is not None
            and not self.system_theme_control_preflight()
        ):
            return "system-theme-not-configured"
        if self.restore_audio:
            return "restore-audio"
        if self.remove_shizuku:
            return "remove-shizuku"
        if self.enable_updates:
            return "enable-updates"
        if self.restore_camera_light:
            return "restore-camera-light"
        # A missing staged simpleperf is not a blocker: autoroot
        # staging pushes it on demand.
        return None

    def _apply_shell_level_state(
        self,
        *,
        debloat_configured: bool,
        remote_wipe_configured: bool,
        defer_dns: bool,
    ) -> None:
        """The one host shell-level apply sequence, shared by the
        race (stages) path and the root-channel path so the two can
        never drift apart: every shell-applicable action applies
        here, in this order, on both paths.

        The two callers differ only in where the debloat /
        remote-wipe skip answers come from, and both are honest:
        the stages path passes the run's cached preflight results
        (a dedicated bootstrap phase may have just changed them,
        and the cache is what the rest of the run consults), the
        channel path passes fresh live preflights (no bootstrap ran
        on that path). The stages path also defers the Private DNS
        applies to final verification (defer_dns): the write used
        to sit pre-race, where the race's crash-reboots could
        discard the SettingsProvider async flush before it
        persisted (Nov 15 robustness decision). The channel path
        has no races, so it applies DNS inline like everything
        else."""
        if self.debloat and not debloat_configured:
            self.apply_debloat()
        if self.restore_bloat:
            self.restore_debloat()
        if self.block_remote_wipe and not remote_wipe_configured:
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
        if defer_dns:
            if (
                self.privacy_dns
                or self.dhcp_dns
                or self.restore_privacy_dns
            ):
                self._dns_apply_deferred = True
        else:
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
        if self.restore_theme:
            self.restore_system_theme()
        if self.needs_component_ctl():
            self.prepare_component_actions()

    def _component_ctl_presence_action(self) -> str:
        """The PortalComponentCtl presence argument for a channel
        execution, mirroring the payload env rule: native-pref
        targets never carry it in the jar, and targets with a
        dedicated presence/FPS phase keep it with that phase; where
        the jar is the only carrier it takes the run's request."""
        if self.target is None or self.uses_native_presence_prefs():
            return "none"
        if (
            self.target.uid1000_installer_credentials
            or self.target.presence_installer_credentials
        ):
            return "none"
        if self.presence_fps_action_requested():
            return f"set:{self.presence_fps_cap}"
        if self.restore_presence_fps or self.restore_presence_profile:
            return "restore"
        return "none"

    def execute_component_actions(self) -> None:
        """Execute the staged PortalComponentCtl actions on the
        channel path.

        _apply_shell_level_state stages the actions file
        (prepare_component_actions) on both paths, but the jar's
        only other executor is the payload's post-win sequence
        (fops.c run_portal_component_ctl): a channel run that must
        actually change component state therefore verified against
        state nothing had applied and fell back to the race path
        (Defect G, closure session 8 leg 2b). Here the same jar
        runs with the same arguments through Shizuku's own shell
        client (rish, extracted from the pinned Shizuku APK): the
        server-side shell the binder spawns runs it as uid 0, the
        identity class the jar already runs under post-win.
        Loopback-ADB shell cannot substitute — PackageManager's
        binder caller check excludes uid 2000.

        rish itself does not talk to the server directly (the
        assumption recorded with PR #73, that the root-mode
        server simply accepts a rish client from an adb shell,
        proved wrong live in closure sessions 9.5 and 14): its
        loader gets the server binder from the Shizuku manager
        app, but the Shell then attaches as a client under
        com.android.shell, which the root-mode server only
        serves with a Shizuku permission grant — ungranted,
        the attach blocks behind the manager's on-screen
        confirmation until the loader's 5 s watchdog reports
        a misleading timeout. _prepare_rish_transport
        establishes the grant before the jar runs; see its
        docstring for the full mechanism.

        Without Shizuku root (the --skip-shizuku-root opt-out, or
        the server not answering as uid 0) the step does not run
        and claims nothing: verification decides, and a state that
        still needs changing falls back to the race path exactly
        as before."""
        if self.skip_shizuku_root:
            print(
                "COMPONENT_CTL_EXECUTE_SKIPPED reason=skip-shizuku-root",
                flush=True,
            )
            return
        if not self._shizuku_root_ok():
            print(
                "COMPONENT_CTL_EXECUTE_SKIPPED "
                "reason=shizuku-root-unavailable",
                flush=True,
            )
            return
        if COMPONENT_CTL_LOCAL.is_file():
            self.adb_run(
                ["push", str(COMPONENT_CTL_LOCAL), COMPONENT_CTL_REMOTE],
                timeout=30,
                check=True,
            )
            self.adb_run(
                ["shell", "chmod", "0755", COMPONENT_CTL_REMOTE],
                timeout=5,
                check=True,
            )
        elif (
            self.adb_run(
                ["shell", "test", "-f", COMPONENT_CTL_REMOTE], timeout=5
            ).returncode
            != 0
        ):
            raise ProvisionError(
                "component ctl jar is neither built nor staged"
            )
        self._stage_rish_client()
        self._prepare_rish_transport()
        presence_action = self._component_ctl_presence_action()
        result = self._run_component_ctl_via_rish(
            "/system/bin/app_process64", presence_action
        )
        if result.returncode == 127:
            # fops.c's fallback: app_process64 may be absent, in
            # which case the payload retries with app_process.
            result = self._run_component_ctl_via_rish(
                "/system/bin/app_process", presence_action
            )
        ok_line = next(
            (
                line.strip()
                for line in result.stdout.splitlines()
                if "PORTAL_COMPONENT_CTL_OK" in line
            ),
            "",
        )
        if result.returncode != 0 or not ok_line:
            raise ProvisionError(
                "component ctl execution failed on the channel path: "
                f"exit={result.returncode} "
                f"output={result.stdout.strip()[-300:]!r}"
            )
        print(
            f"COMPONENT_CTL_EXECUTED transport=shizuku-root {ok_line}",
            flush=True,
        )
        # The payload settles after a successful jar run before its
        # state is read back (fops.c settle_package_manager_state:
        # PackageManager's restrictions write is asynchronous);
        # the channel path's verification is that read-back.
        self.settle_package_state(before_reboot=True)

    def _run_component_ctl_via_rish(
        self, app_process: str, presence_action: str
    ) -> subprocess.CompletedProcess[str]:
        # Mirror fops.c's invocation: CLASSPATH points at the jar,
        # app_process loads PortalComponentCtl with the staged
        # actions file and the presence action as arguments.
        #
        # The result, though, cannot come back over the rish
        # transport itself: measured live (closure session 15
        # follow-up, Nov 19, 2026), the transport returns only the
        # remote command's stdout and reports exit 0 regardless of
        # the command's real exit code (`false` and `exit 3` both
        # return 0), and stderr never arrives. The jar prints its
        # success line to stdout but every failure goes to stderr
        # with exit 1, so a failed jar run presented as exit=0 with
        # empty output and the real error was invisible. The jar's
        # output and exit code are therefore captured to a file on
        # the device (COMPONENT_CTL_CAPTURE_REMOTE) and read back;
        # the returned process carries the jar's own stdout/stderr
        # and exit code. When no capture lands (the transport died
        # before the command ran), the transport's own result
        # stands, exactly as before.
        self.adb_run(
            ["shell", "mkdir", "-p", COMPONENT_CTL_CAPTURE_DIR],
            timeout=10,
        )
        self.adb_run(
            ["shell", "rm", "-f", COMPONENT_CTL_CAPTURE_REMOTE],
            timeout=10,
        )
        inner = (
            f"CLASSPATH={COMPONENT_CTL_REMOTE} "
            f"{app_process} /system/bin PortalComponentCtl "
            f"{DEBLOAT_COMPONENT_ACTIONS_REMOTE} {presence_action} "
            f"> {COMPONENT_CTL_CAPTURE_REMOTE} 2>&1; "
            f"echo {COMPONENT_CTL_RC_MARKER}$? "
            f">> {COMPONENT_CTL_CAPTURE_REMOTE}"
        )
        transport = self.adb_run(
            ["shell", f"sh {RISH_SCRIPT_REMOTE} -c {shlex.quote(inner)}"],
            timeout=120,
        )
        captured = self.adb_run(
            ["shell", "cat", COMPONENT_CTL_CAPTURE_REMOTE],
            timeout=10,
        )
        if captured.returncode == 0:
            jar_output_lines = []
            jar_returncode = None
            for line in captured.stdout.splitlines():
                if line.startswith(COMPONENT_CTL_RC_MARKER):
                    try:
                        jar_returncode = int(
                            line[len(COMPONENT_CTL_RC_MARKER):].strip()
                        )
                    except ValueError:
                        jar_returncode = None
                else:
                    jar_output_lines.append(line)
            if jar_returncode is not None:
                return subprocess.CompletedProcess(
                    args=transport.args,
                    returncode=jar_returncode,
                    stdout="\n".join(jar_output_lines),
                )
        return transport

    def _prepare_rish_transport(self) -> None:
        """Make the rish transport answer before the jar runs.

        rish does not talk to the server directly. Its loader
        (rikka.shizuku.shell.ShizukuShellLoader) broadcasts a
        binder request to the Shizuku manager app, receives the
        server binder, and runs moe.shizuku.manager.shell.Shell
        as a server client under the calling package
        com.android.shell (uid 2000, the only package for the
        shell uid). Against the root-mode server that client
        needs a Shizuku permission grant: with no allowed entry
        for uid 2000 in the server config, the server starts the
        manager's RequestPermissionActivity ("Allow Shell to
        access Shizuku?") and blocks the attach pending an
        answer; the loader's fixed 5 s watchdog then kills it
        and prints the misleading "Request timeout ... disable
        all battery optimization features" message. That is the
        failure closure sessions 9.5 and 14 hit (diagnosed live
        Nov 19, 2026: the broadcast history shows the binder
        delivered in milliseconds and a permission-activity
        START from uid 0 half a second into every blocked
        probe, with the probe exiting at exactly +5 s; granting
        "Allow all the time" made the next probe answer uid=0
        immediately, and the exact jar invocation then printed
        PORTAL_COMPONENT_CTL_OK). A shell-mode server exempts
        its own uid, which is why the same invocation worked in
        manual shell-mode tests. The secondary shape is a cold
        manager process: the broadcast cold-starts it and its
        receiver can answer before the server's BinderSender
        delivers the binder, yielding a null-binder reply
        ("Server is not running"); foregrounding the manager is
        the delivery trigger that resolves it.

        The prep therefore, in order: (a) adds the manager and
        the shell to the deviceidle whitelist — the timeout
        message's own remedy, so doze cannot defer the binder
        broadcast on other builds; (b) ensures the persisted
        grant in the server config file (shell-owned, so adb
        shell writes it directly), which every later server
        start loads — a server already running does not re-read
        it, so (c) probes the transport with a trivial rish
        command and repairs the running server by shape: a
        timeout-shaped failure taps "Allow all the time" on
        the permission dialog (bounds read live from a
        uiautomator dump of the pinned manager), which records
        the grant in the running server; any other failure
        starts the manager activity. If no probe answers as
        uid 0, the step raises and claims nothing, so
        verification and the race fallback behave exactly as
        for a failed execution.
        """
        for package in (SHIZUKU_PACKAGE, "com.android.shell"):
            self.adb_run(
                [
                    "shell",
                    "dumpsys",
                    "deviceidle",
                    "whitelist",
                    f"+{package}",
                ],
                timeout=10,
            )
        self._ensure_shizuku_rish_grant()
        last = ""
        for attempt in range(1, RISH_PROBE_ATTEMPTS + 1):
            result = self.adb_run(
                ["shell", f"sh {RISH_SCRIPT_REMOTE} -c id"],
                timeout=30,
            )
            last = result.stdout.strip()
            if result.returncode == 0 and "uid=0" in result.stdout:
                print(
                    "COMPONENT_CTL_RISH_READY "
                    f"attempt={attempt} output={last[:80]!r}",
                    flush=True,
                )
                return
            print(
                "COMPONENT_CTL_RISH_NOT_READY "
                f"attempt={attempt} exit={result.returncode} "
                f"output={last[-160:]!r}",
                flush=True,
            )
            if attempt < RISH_PROBE_ATTEMPTS:
                tapped = "Request timeout" in last and (
                    self._tap_shizuku_permission_allow()
                )
                if not tapped:
                    self.adb_run(
                        [
                            "shell",
                            "am",
                            "start",
                            "-n",
                            SHIZUKU_MANAGER_ACTIVITY,
                        ],
                        timeout=10,
                    )
                time.sleep(2)
        raise ProvisionError(
            "component ctl rish transport did not become ready: "
            f"last probe output={last[-200:]!r}"
        )

    def _ensure_shizuku_rish_grant(self) -> None:
        """Persist the Shizuku grant for the rish client uid.

        The server config (/data/user_de/0/com.android.shell/
        shizuku.json) is owned by the shell user, so the host
        shell channel can merge the grant in directly: an entry
        for uid 2000 with FLAG_ALLOWED and the com.android.shell
        package, other entries preserved. A server already
        running loaded its config at start and will not re-read
        the file (the probe loop repairs that case separately);
        every later start — each boot's autoroot handoff, each
        provision run's root start — loads the grant from here.
        An unreadable file is treated as an empty config; an
        unparseable one is left untouched (it may carry other
        apps' grants) and logged.
        """
        result = self.adb_run(
            ["shell", "cat", SHIZUKU_CONFIG_REMOTE], timeout=10
        )
        raw = result.stdout.strip() if result.returncode == 0 else ""
        if raw:
            try:
                config = json.loads(raw)
                entries = config["packages"]
                if not isinstance(entries, list):
                    raise ValueError("packages is not a list")
            except (ValueError, KeyError, TypeError):
                print(
                    "COMPONENT_CTL_RISH_GRANT_SKIPPED "
                    "reason=config-unparseable",
                    flush=True,
                )
                return
        else:
            config = {"version": 2, "packages": []}
            entries = config["packages"]
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("uid") != (
                SHIZUKU_RISH_UID
            ):
                continue
            flags = entry.get("flags", 0)
            packages = entry.get("packages", [])
            if (flags & SHIZUKU_FLAG_ALLOWED) and (
                "com.android.shell" in packages
            ):
                print(
                    "COMPONENT_CTL_RISH_GRANT_PRESENT "
                    f"uid={SHIZUKU_RISH_UID}",
                    flush=True,
                )
                return
            entry["flags"] = (
                flags & ~SHIZUKU_FLAG_DENIED
            ) | SHIZUKU_FLAG_ALLOWED
            if "com.android.shell" not in packages:
                packages.append("com.android.shell")
                entry["packages"] = packages
            break
        else:
            entries.append(
                {
                    "uid": SHIZUKU_RISH_UID,
                    "flags": SHIZUKU_FLAG_ALLOWED,
                    "packages": ["com.android.shell"],
                }
            )
        payload = json.dumps(config)
        with tempfile.TemporaryDirectory(
            prefix="portal-shizuku-config-"
        ) as tmp:
            local = pathlib.Path(tmp) / "shizuku.json"
            local.write_text(payload)
            self.adb_run(
                ["push", str(local), "/data/local/tmp/shizuku.json.tmp"],
                timeout=15,
                check=True,
            )
        self.adb_run(
            [
                "shell",
                "cp /data/local/tmp/shizuku.json.tmp "
                f"{SHIZUKU_CONFIG_REMOTE} && "
                "rm /data/local/tmp/shizuku.json.tmp",
            ],
            timeout=10,
            check=True,
        )
        print(
            "COMPONENT_CTL_RISH_GRANT_WRITTEN "
            f"uid={SHIZUKU_RISH_UID} flags={SHIZUKU_FLAG_ALLOWED}",
            flush=True,
        )

    def _tap_shizuku_permission_allow(self) -> bool:
        """Tap "Allow all the time" on Shizuku's permission dialog.

        The dialog is the pinned manager's own grant UI for the
        rish client (com.android.shell); its button bounds are
        read live from a uiautomator dump, never assumed. The
        grant is recorded by the server for the uid, so the tap
        unblocks later probes even though the probe that raised
        the dialog has already hit its 5 s watchdog. Returns
        False when no such dialog is on screen.
        """
        dump_remote = "/data/local/tmp/portal-window-dump.xml"
        dumped = self.adb_run(
            ["shell", "uiautomator", "dump", dump_remote], timeout=15
        )
        if dumped.returncode != 0:
            return False
        try:
            xml = self.adb_run(
                ["shell", "cat", dump_remote], timeout=10
            ).stdout
            for node in re.findall(r"<node[^>]*>", xml):
                if 'text="Allow all the time"' not in node:
                    continue
                if f'package="{SHIZUKU_PACKAGE}"' not in node:
                    continue
                bounds = re.search(
                    r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node
                )
                if bounds is None:
                    continue
                x = (int(bounds.group(1)) + int(bounds.group(3))) // 2
                y = (int(bounds.group(2)) + int(bounds.group(4))) // 2
                self.adb_run(
                    ["shell", "input", "tap", str(x), str(y)],
                    timeout=10,
                )
                print(
                    f"COMPONENT_CTL_RISH_GRANT_TAPPED x={x} y={y}",
                    flush=True,
                )
                return True
            return False
        finally:
            self.adb_run(["shell", "rm", "-f", dump_remote], timeout=5)

    def _stage_rish_client(self) -> None:
        """Push Shizuku's rish shell client (script + dex) from the
        pinned Shizuku APK: the pair is versioned with the server
        it talks to, so it comes from the same hash-verified
        artifact the install path uses."""
        apk = self.resolve_shizuku_apk()
        assets = {
            "assets/rish": (RISH_SCRIPT_REMOTE, "0755"),
            "assets/rish_shizuku.dex": (RISH_DEX_REMOTE, "0644"),
        }
        try:
            with zipfile.ZipFile(apk) as archive:
                payloads = {asset: archive.read(asset) for asset in assets}
        except (OSError, KeyError, zipfile.BadZipFile) as exc:
            raise ProvisionError(
                f"could not extract the rish client from {apk}: {exc}"
            ) from exc
        with tempfile.TemporaryDirectory(prefix="portal-rish-") as tmp:
            for asset, (remote, mode) in assets.items():
                local = pathlib.Path(tmp) / pathlib.Path(asset).name
                local.write_bytes(payloads[asset])
                self.adb_run(
                    ["push", str(local), remote], timeout=30, check=True
                )
                self.adb_run(
                    ["shell", "chmod", mode, remote],
                    timeout=5,
                    check=True,
                )

    def _apply_via_channel(self, reason: str) -> bool:
        """Apply the drifted delta through the device's existing root
        setup: the same shell-level applies, package installs, and
        autoroot staging the race run performs, minus the races
        themselves (their persistent products — root-mode Shizuku,
        the lock repair — are already in place). The helper key is
        NOT assumed authorized: this path cannot write adb_keys, so
        install must produce the already-authorized pair (the
        helper's own, or seeded from the autoroot helper's copy);
        a freshly generated pair, or one that is not the recorded
        authorized key, aborts to the race run below, and staging
        independently compares the pair it copies against the
        recorded authorized key. No reboots. Any failure logs
        the fallback and returns False so the caller continues into
        the normal race run; every apply here is idempotent, so
        re-applying there is safe. The completion write merges
        into the recorded manifest (write_state's merge_prior):
        this path applies a delta, and the record must keep the
        actions and hashes earlier runs established."""
        print(f"PROVISION_CHANNEL_ENGAGED reason={reason}", flush=True)
        try:
            if self.privileged_requested() and not self.skip_build:
                android_build_environment(
                    self.target, require_simpleperf=self.autoroot
                )
            if self.shizuku:
                self.resolve_shizuku_apk()
            self.write_state("pending")
            self._apply_shell_level_state(
                debloat_configured=(
                    self.debloat_preflight() if self.debloat else False
                ),
                remote_wipe_configured=(
                    self.remote_wipe_preflight()
                    if self.block_remote_wipe
                    else False
                ),
                defer_dns=False,
            )
            if not self.skip_build:
                build(
                    target=self.target,
                    build_audio=False,
                    build_account=self.remove_meta_accounts,
                    build_components=self.needs_component_ctl(),
                    build_shizuku=self.shizuku,
                    build_autoroot=self.autoroot,
                    build_presence=False,
                    build_uid1000=self.needs_uid1000_payload(),
                    build_sentinel=self.uses_exploit_sentinel(),
                    build_daemon=(
                        self.custom_payload is not None
                        and self.custom_payload
                        == DEFAULT_CUSTOM_PAYLOAD_LOCAL
                    ),
                )
            if self.needs_uid1000_payload():
                self.validate_uid1000_payload()
            if self.shizuku:
                self.install_shizuku_payload()
            if self.autoroot and self.shizuku_key_source == "keygen":
                # A freshly generated pair has no surviving copy and
                # no authorization; only a race win can authorize it,
                # and staging it here would strand autoroot recovery
                # on a key adb_keys does not hold. Fall back to the
                # race run instead of staging it.
                raise ProvisionError(
                    "channel apply generated a new helper keypair "
                    "that only a race win can authorize"
                )
            if self.autoroot and self.shizuku_public_key is not None:
                # The same refusal one generation later: a reused
                # pair that is not the recorded authorized key (this
                # run's authorize record, or the on-device saved
                # marker for a run that authorized nothing) has no
                # proven authorization either. When no record can be
                # read there is nothing to contradict the pair, and
                # staging's own comparison stays the backstop.
                reference = (
                    self.authorized_shizuku_key
                    or self.read_saved_shizuku_key_marker()
                )
                prepared = None
                try:
                    prepared = self.shizuku_public_key.read_text(
                        encoding="ascii"
                    ).strip()
                except OSError:
                    pass
                if (
                    reference is not None
                    and prepared is not None
                    and reference != prepared
                ):
                    raise ProvisionError(
                        "channel apply prepared a helper keypair "
                        "that is not the recorded authorized key; "
                        "only a race win can authorize it"
                    )
            if (
                self.needs_uid1000_payload()
                and self.target
                and self.target.uid1000_embedded_helper
            ):
                self.install_uid1000_runtime_payload()
            if self.restore_presence_fps or self.restore_presence_profile:
                self.uninstall_presence_helper()
            if self.uses_exploit_sentinel():
                self.prepare_exploit_sentinel()
            if self.autoroot:
                self.stage_autoroot_payload()
            if self.needs_component_ctl():
                self.execute_component_actions()
            self.verify_requested_state(via_channel=True)
            if not self._shizuku_root_ok():
                raise ProvisionError(
                    "root-mode Shizuku did not survive the channel apply"
                )
        except (ProvisionError, OSError) as exc:
            print(
                f"PROVISION_CHANNEL_FALLBACK reason={exc}", flush=True
            )
            return False
        # The channel completion is this run's end state: record
        # the disabled posture from it when it holds (Defect J).
        # write_state's own observation is gated on no payload
        # phase pending, which a channel-handled full request
        # still shows, so the observation is made here instead.
        self._observe_posture_end_state()
        self.write_state("complete", merge_prior=True)
        print(
            "PROVISION_CHANNEL_OK reboots=0 "
            f"logs={self.log_dir}",
            flush=True,
        )
        print(f"PROVISION_OK reboots=0 logs={self.log_dir}", flush=True)
        return True

    def _run_fast_path(self) -> bool:
        """No-op / channel decision for the outermost run. Returns
        True when the run is fully handled (no-op exit or a completed
        channel apply) and the stages must not continue."""
        try:
            state = self.read_state()
        except ProvisionError:
            return False
        if state is None:
            return False
        blocker = self._noop_blocker(state)
        if blocker is None:
            root_blocker = self._root_setup_blocker()
            if root_blocker is None:
                # The no-op decision may not pass over Private DNS
                # drift: the manifest records the desired end
                # state, so live drift routes to the channel path,
                # whose final verification performs the repair.
                # When this run carries a DNS intent of its own,
                # the verdict judges live state against the
                # REQUESTED intent, not the record: a recorded
                # pre-#64 pair resolves dhcp-first, so a bare
                # --dns HOSTNAME run over a live-off device whose
                # record held that hostname matched "off" and
                # no-oped with its request unapplied (Defect D,
                # closure session 3). Runs carrying no intent keep
                # the recorded expectation exactly as before.
                requested_dns = self._requested_dns_expectation()
                drift = self._dns_drift(state, requested_dns)
                if drift is not None:
                    live = self._dns_drift_live
                    source = (
                        "requested" if requested_dns is not None else "recorded"
                    )
                    print(
                        "PRIVACY_DNS_DRIFT "
                        f"{source}_mode={drift[0]} "
                        f"{source}_hostname={drift[1]} "
                        f"live_mode={live[0] if live else 'unreadable'} "
                        f"live_hostname={live[1] if live else 'unreadable'}",
                        flush=True,
                    )
                    self._dns_repair_expectation = drift
                    blocker = "dns-drift"
                else:
                    # The recorded alohausers posture is part of
                    # the no-op decision too (C3-A): the package
                    # re-enabled outside a run is drift the
                    # channel path's verification repairs, not a
                    # state a no-op may pass over.
                    posture = self._posture_drift(state)
                    if posture is None:
                        print(
                            "PROVISION_NOOP reason=already-provisioned "
                            f"tool_revision={state.get('tool_revision')} "
                            f"logs={self.log_dir}",
                            flush=True,
                        )
                        return True
                    blocker = posture
            else:
                blocker = root_blocker
        print(f"PROVISION_NOOP_SKIP reason={blocker}", flush=True)
        channel_blocker = self._channel_blocker(state)
        if channel_blocker is not None:
            print(
                f"PROVISION_CHANNEL_SKIP reason={channel_blocker}",
                flush=True,
            )
            if channel_blocker == "audio-repair-bootstrap":
                self.audio_repair_channel_skipped = True
            return False
        return self._apply_via_channel(blocker)

    # ---- Private DNS end-state invariant (Phase C2) ---------------
    #
    # A run's own DNS request is verified against the request, but
    # nothing used to compare the live state to the state the
    # previous completed run recorded: the no-op path never read
    # live DNS at all, and a run that requested no DNS change never
    # looked at it either, so user-side drift and flush-loss drift
    # were both invisible. The invariant closes that: the recorded
    # state is the desired end state on every later run.

    def _capture_start_state(self) -> None:
        """Snapshot the manifest this run started from, before any
        write of ours replaces it. The invariant judges the
        finished device against the previously recorded state, not
        against this run's request, so the snapshot has to predate
        this run's first write_state."""
        if self._start_state_captured:
            return
        self._start_state_captured = True
        try:
            self._start_state = self.read_state()
        except ProvisionError:
            self._start_state = None

    def _observe_start_package_state(self) -> None:
        """Record the alohausers package state as this run found
        it. Called once the target is known and before any phase
        of the run can change the package; one desired-state
        recording rule keys off this observation (a run that
        removes Meta accounts ends with the package enabled by
        construction, which would erase the very posture it
        started from). The end-state rule in _desired_state is
        separate: it keys off the posture the run verifies at
        its own end (Defect J)."""
        if self._alohausers_disabled_at_start is not None:
            return
        if self.target is None or self.target.device != "aloha":
            return
        try:
            self._alohausers_disabled_at_start = (
                self.alohausers_package_disabled()
            )
        except ProvisionError:
            self._alohausers_disabled_at_start = None

    def _desired_state(self) -> dict[str, str]:
        """The desired state this run's manifest writes record
        (C3-A): end state future boots should keep, currently the
        alohausers-disabled posture on aloha.

        Recording rules, applied in order: a run that does not
        request removal preserves a desire recorded by an earlier
        run, so an unrelated re-provision never erases the
        posture record; a run that requests Meta-account removal
        and STARTS with the package disabled records the desire,
        while one that starts enabled drops it (absence = no
        posture desire, and the removal flow ends with the
        package enabled by construction); and a run that verifies
        it ENDS in the posture — the end-of-run posture step
        disabled the package, or found it disabled, with the
        posture conf staged — records the desire from its own
        end state regardless of start state or flags requested
        (Defect J: the start-state rules alone made the posture
        unreachable from a drifted device, because the only run
        that recorded it had to start already disabled)."""
        desired: dict[str, str] = {}
        start = self._start_state
        if isinstance(start, dict):
            recorded = start.get("desired_state")
            if isinstance(recorded, dict):
                value = recorded.get("alohausers_package")
                if value in ("disabled", "enabled"):
                    desired["alohausers_package"] = value
        if (
            self.target is not None
            and self.target.device == "aloha"
            and self.remove_meta_accounts
            and self._alohausers_disabled_at_start is not None
        ):
            if self._alohausers_disabled_at_start:
                desired["alohausers_package"] = "disabled"
            else:
                desired.pop("alohausers_package", None)
        if (
            self.target is not None
            and self.target.device == "aloha"
            and self._alohausers_posture_established
        ):
            desired["alohausers_package"] = "disabled"
        return desired

    def _observe_posture_end_state(self) -> None:
        """Record the disabled posture from this run's own end
        state (Defect J): when the run ends with the alohausers
        package disabled and the posture conf (OTA_NODEMON)
        staged, the manifest records the desire, whatever the
        start state or the flags requested. This is the general
        form of the rule the end-of-run posture step applies on
        the payload path, for completing paths that never run
        that step; write_state calls it at completion writes
        once no payload phase is still pending, and the channel
        path calls it before its completion write. Fail-closed:
        an unreadable package state or conf records nothing, a
        run ending enabled records nothing, and a run that
        already records the desire reads nothing."""
        if self._alohausers_posture_established:
            return
        if self.target is None or self.target.device != "aloha":
            return
        if self._desired_state().get("alohausers_package") == "disabled":
            return
        try:
            if not self.alohausers_package_disabled():
                return
            if not self._ota_nodemon_conf_staged():
                return
        except (ProvisionError, OSError):
            return
        self._alohausers_posture_established = True
        print(
            "ALOHAUSERS_POSTURE_RECORDED source=end-state",
            flush=True,
        )

    @staticmethod
    def _recorded_posture_ota_trusted(
        state: dict[str, object] | None,
    ) -> bool:
        """Whether a manifest's disable_updates completion may be
        trusted as OTA-blocked without re-deriving the block from
        the live config dump: it was recorded under the C3-B
        posture judgment (the manifest carries the alohausers-
        disabled desire, which only a posture-judged run records).
        In the posture the dump reads unconfigured BY DESIGN -
        otad's own settings and the MobileConfig override are inert
        behind the disabled package - so re-deriving OTA from the
        dump refuses every posture device forever (the C3-B run-8
        no-op refusal)."""
        if not isinstance(state, dict):
            return False
        actions = state.get("actions")
        if not isinstance(actions, dict):
            return False
        if actions.get("disable_updates") is not True:
            return False
        desired = state.get("desired_state")
        return (
            isinstance(desired, dict)
            and desired.get("alohausers_package") == "disabled"
        )

    def _recorded_posture_ota_gating_trusted(
        self, state: dict[str, object] | None
    ) -> bool:
        """Whether the fast-path gates (the no-op decision and the
        channel OTA clause) may treat the OTA action as satisfied
        on a device in the recorded alohausers-disabled posture
        whose recorded completion is not a plain done — the shape a
        win-less run leaves behind: its end-of-run posture judgment
        cannot pass without a win this boot or this run (the
        property is per-boot and only a payload win sets it; the
        override file sits behind the disabled package's private
        directory), so it records the action "unverified", and
        re-deriving the block at the gate from the live dump or
        the property refuses the finished device into a race on
        every later win-less boot.

        The trust mirrors the posture criteria, split by what a
        win-less boot can read: the manifest records the posture,
        the staged autoroot conf carries OTA_NODEMON (so the next
        win re-asserts the property), and the alohausers package
        is actually disabled live. The two criteria no win-less
        boot can read — the property itself and the override
        file — are exactly what the trust stands in for, and only
        at the gates: a run that applies or re-applies OTA still
        ends in the unchanged end-of-run verification and posture
        judgment, and nothing on this path records the action
        verified. Any precondition failing returns the gate to
        the live checks exactly."""
        if not isinstance(state, dict):
            return False
        desired = state.get("desired_state")
        if not (
            isinstance(desired, dict)
            and desired.get("alohausers_package") == "disabled"
        ):
            return False
        if self.target is None or self.target.device != "aloha":
            return False
        if not self._ota_nodemon_conf_staged():
            return False
        try:
            return self.alohausers_package_disabled()
        except (ProvisionError, OSError):
            return False

    def _recorded_posture_meta_trusted(
        self, state: dict[str, object] | None
    ) -> bool:
        """Whether the channel gate may treat the meta-accounts
        removal as already applied on a device in the recorded
        alohausers-disabled posture. The preflight's already_clean
        requires the package NOT disabled, so it is unreachable
        in the posture even though the removal's substantive end
        state holds. The record overrides only that one clause:
        the package must actually be disabled (the posture), and
        the preflight's live reads from the call just made -
        accounts absent, authenticators disabled - must still
        hold. Scoped to the channel gate; the stages path keeps
        judging by the preflight alone."""
        if not isinstance(state, dict):
            return False
        desired = state.get("desired_state")
        if not (
            isinstance(desired, dict)
            and desired.get("alohausers_package") == "disabled"
        ):
            return False
        if not self.meta_accounts_package_disabled:
            return False
        if not self.meta_accounts_absent:
            return False
        disabled = self.disabled_meta_authenticators()
        hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
        return (
            set(META_AUTHENTICATOR_COMPONENTS) <= disabled
            and hardware_class not in disabled
        )

    def _posture_drift(
        self, state: dict[str, object] | None
    ) -> str | None:
        """The recorded alohausers posture when the live package
        state has drifted from it; None when it holds, nothing is
        recorded, or the live state cannot be read (an unreadable
        package state is surfaced by the spot-checks that gate the
        no-op, not guessed at here)."""
        if not isinstance(state, dict):
            return None
        desired = state.get("desired_state")
        if not isinstance(desired, dict):
            return None
        if desired.get("alohausers_package") != "disabled":
            return None
        if self.target is None or self.target.device != "aloha":
            return None
        try:
            disabled = self.alohausers_package_disabled()
        except ProvisionError:
            return None
        return None if disabled else "alohausers-enabled"

    def _posture_conf_backed(self, recorded: bool) -> bool:
        """Whether a disabled posture this run ends in is backed
        by the staged autoroot conf the per-boot drift pass
        enforces from: an earlier run staged it (the recorded
        case), this run's autoroot staging renders OTA_NODEMON
        from its own --disable-updates request, or the staged
        conf already carries OTA_NODEMON."""
        return bool(
            recorded or self.autoroot or self._ota_nodemon_conf_staged()
        )

    def _apply_recorded_posture(self) -> None:
        """End-of-run posture apply (C3-A, extended by Defect J):
        put the alohausers package into the disabled posture
        through the payload daemon after the final verification
        and with no reboot after it, so the write gets its settle
        by construction (a package write followed within about a
        minute by crash-reboots was silently lost in C3-B
        validation).

        The step engages when the run's manifest records the
        desire (the C3-A case: the accounts flow re-enabled the
        package mid-run and the recorded end state is restored),
        or when the run itself stages the OTA posture — it
        requested --disable-updates without --enable-updates, so
        its staged autoroot conf carries OTA_NODEMON: the
        disabled posture is the decided end state on aloha, so
        such a run establishes it instead of only ever
        preserving it (before Defect J a drifted device could
        never re-enter the posture through the tool). A verified
        disabled end state backed by the posture conf is marked
        on the run (_alohausers_posture_established), so the
        manifest records the desire from the run's own end state
        and the staging that follows renders the conf's
        ALOHAUSERS_DISABLED key from it. When the posture cannot
        be established here (no payload daemon channel), the run
        ends in the enabled posture instead: that outcome stays
        visible — the DEFERRED line below, OTA judged by the
        override path, and no desired_state recorded — never a
        silent posture claim. A daemon disable that does not
        verify is deferred, never silent: the run must not
        report complete while the device sits outside the end
        state this step set out to establish."""
        if self._posture_apply_attempted:
            return
        self._posture_apply_attempted = True
        if self.target is None or self.target.device != "aloha":
            return
        recorded = (
            self._desired_state().get("alohausers_package") == "disabled"
        )
        ota_posture_run = self.disable_updates and not self.enable_updates
        if not (recorded or ota_posture_run):
            return
        if self.custom_payload != DEFAULT_CUSTOM_PAYLOAD_LOCAL:
            print(
                "ALOHAUSERS_POSTURE_DEFERRED reason=no-daemon-channel",
                flush=True,
            )
            return
        if self.alohausers_package_disabled():
            print("ALOHAUSERS_POSTURE_OK state=already-disabled", flush=True)
            if self._posture_conf_backed(recorded):
                self._alohausers_posture_established = True
            return
        try:
            code, _output = self.daemon_exec(
                "pm disable --user 0 "
                "com.facebook.alohaservices.alohausers"
            )
        except (OSError, ProvisionError) as exc:
            code = -1
            _output = str(exc)
        if code == 0 and self.alohausers_package_disabled():
            print(
                "ALOHAUSERS_POSTURE_APPLIED "
                "package=com.facebook.alohaservices.alohausers "
                "state=disabled",
                flush=True,
            )
            if self._posture_conf_backed(recorded):
                self._alohausers_posture_established = True
            return
        self.deferred_phase_failures.append(
            "alohausers_posture: end-of-run posture apply did not "
            f"verify (daemon exit={code})"
        )
        print(
            "ALOHAUSERS_POSTURE_APPLY_FAILED "
            f"daemon_exit={code}",
            flush=True,
        )

    def _requested_dns_expectation(self) -> tuple[str, str] | None:
        """The Private DNS end state THIS run requests, resolved
        from its own requested actions with the same rules the
        recorded expectation uses; None when the run carries no
        DNS intent, or the intent's end state cannot be determined
        (a restore whose on-device backup is unreadable), in which
        case the caller falls back to the recorded expectation."""
        actions = self.requested_actions()
        if not any(actions.get(name) for name in DNS_ACTION_KEYS):
            return None
        return self._recorded_dns_expectation({"actions": actions})

    def _recorded_dns_expectation(
        self, state: dict[str, object] | None
    ) -> tuple[str, str] | None:
        """The Private DNS end state a manifest records, as
        (mode, specifier) with "null" for an absent specifier;
        None when the manifest records no DNS action (nothing to
        enforce) or the recorded state cannot be determined (a
        recorded restore whose on-device backup is unreadable)."""
        if not state:
            return None
        actions = state.get("actions")
        if not isinstance(actions, dict):
            return None
        if actions.get("dhcp_dns"):
            return ("off", "null")
        privacy_dns = actions.get("privacy_dns")
        if isinstance(privacy_dns, str) and privacy_dns.strip():
            return ("hostname", privacy_dns.strip().lower())
        if actions.get("restore_privacy_dns"):
            backup = self.read_private_dns_backup()
            if backup is None:
                return None
            mode = backup.get("mode")
            hostname = backup.get("hostname")
            if not isinstance(mode, str) or not isinstance(hostname, str):
                return None
            return (
                mode if mode not in ("", "null") else "null",
                hostname if hostname not in ("", "null") else "null",
            )
        return None

    def _dns_drift(
        self,
        state: dict[str, object] | None,
        expectation: tuple[str, str] | None = None,
    ) -> tuple[str, str] | None:
        """The DNS expectation when the live state has drifted
        from it; None when it matches or nothing is expected. The
        expectation defaults to the manifest-recorded one; the
        fast path passes this run's requested intent instead when
        the run carries one (Defect D: a recorded pair resolves
        dhcp-first, which can contradict the very intent the run
        was asked to establish). A single mismatching sample is confirmed with
        one re-read after a short delay before it counts as drift:
        the C3-B run-8 no-op refusal (2026-11-18) was a lone
        disagreeing read on a device whose DNS had been verified
        minutes earlier and that no writer had touched since -
        most likely a transient empty or garbled settings read,
        and a gate that treats one sample as truth refuses a
        healthy device. A state that is unreadable on BOTH reads
        still counts as drift: the no-op decision must never pass
        over state it could not check, and the repair path
        surfaces a real I/O failure if there is one. The live
        values behind the verdict are kept on
        self._dns_drift_live for the caller's log line."""
        if expectation is None:
            expectation = self._recorded_dns_expectation(state)
        if expectation is None:
            return None
        self._dns_drift_live = None
        try:
            live = self.read_private_dns_state()
        except ProvisionError:
            live = None
        if live == expectation:
            return None
        time.sleep(2)
        try:
            live = self.read_private_dns_state()
        except ProvisionError:
            live = None
        self._dns_drift_live = live
        if live == expectation:
            return None
        return expectation

    def _enforce_recorded_dns(
        self, state: dict[str, object] | None
    ) -> None:
        """Enforce the invariant against a starting manifest: on
        drift, re-write the recorded state, log the repair, and
        re-read before the run may call itself complete. The
        drift verdict goes through _dns_drift's confirmed read,
        so a lone transient sample never triggers a repair write
        either."""
        expectation = self._recorded_dns_expectation(state)
        if expectation is None:
            return
        if self._dns_drift(state) is None:
            live = self._dns_drift_live or self.read_private_dns_state()
            print(
                "PRIVACY_DNS_RECORDED_OK "
                f"mode={live[0]} hostname={live[1]}",
                flush=True,
            )
            return
        live = self._dns_drift_live
        if live is None:
            live = ("unreadable", "unreadable")
        print(
            "PRIVACY_DNS_DRIFT "
            f"recorded_mode={expectation[0]} "
            f"recorded_hostname={expectation[1]} "
            f"live_mode={live[0]} live_hostname={live[1]}",
            flush=True,
        )
        self.write_private_dns_state(*expectation)
        live = self.read_private_dns_state()
        if live != expectation:
            raise ProvisionError(
                "Private DNS drift repair did not persist: "
                f"mode={live[0]!r}/{expectation[0]!r} "
                f"hostname={live[1]!r}/{expectation[1]!r}"
            )
        print(
            "PRIVACY_DNS_REPAIRED "
            f"mode={expectation[0]} hostname={expectation[1]}",
            flush=True,
        )

    def _finalize_dns_state(self) -> None:
        """End-of-run Private DNS position for the outermost run:
        first apply any stages-path DNS write deferred to this
        point (post-race, so a crash-reboot can no longer discard
        its SettingsProvider flush), then — when this run
        requested no DNS change of its own — enforce the
        manifest-recorded end state."""
        if self._autoroot_guard_nested:
            return
        if self._dns_apply_deferred:
            self._dns_apply_deferred = False
            if self.privacy_dns:
                self.apply_privacy_dns()
            if self.dhcp_dns:
                self.apply_dhcp_dns()
            if self.restore_privacy_dns:
                self.restore_private_dns()
            return
        if self.privacy_dns or self.dhcp_dns or self.restore_privacy_dns:
            return
        self._enforce_recorded_dns(self._start_state)

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
        self._rejudge_deferred_failures(
            final=not self._payload_phase_pending
        )
        if self._payload_phase_pending:
            # A custom payload phase is still to run in this
            # invocation. The re-judgment above may already have
            # cleared a failure against the current state, but the
            # judgment that ends the run (and may raise) happens in
            # the final report after that phase.
            return
        if self.presence_deferred:
            # Not a failure: the run's presence verification
            # deferred (lens cover closed) and the manifest records
            # it as "deferred". Surface it in the final report so a
            # completed run never reads as fully verified.
            print(
                "PRESENCE_VERIFY_DEFERRED reason=shutter_closed "
                "report=final",
                flush=True,
            )
        if self.audio_repair_channel_skipped:
            # The channel was skipped up front because the unified
            # audio verdict read repair (Defect H): the repair is
            # race-only, so this run's stages path owned it. Judge
            # the outcome against the device's current state, the
            # same verification-at-the-end shape as the OTA re-judge
            # above: performed when the verdict now reads skip,
            # deferred otherwise — and a deferred repair joins the
            # failure entries (unless the audio bootstrap's own
            # deferred entry already names it), so the run cannot
            # report complete over an unrepaired install.
            performed = self.audio_health().action == "skip"
            print(
                "AUDIO_REPAIR_OUTCOME route=bootstrap "
                f"result={'performed' if performed else 'deferred'}",
                flush=True,
            )
            if not performed and not any(
                entry.startswith("audio")
                for entry in self.deferred_phase_failures
            ):
                self.deferred_phase_failures.append(
                    "audio: repair deferred (channel skipped up "
                    "front, reason=audio-repair-bootstrap; the "
                    "end-state verdict still reads repair)"
                )
        if self.deferred_phase_failures:
            raise ProvisionError(
                "bootstrap phases failed: "
                + "; ".join(self.deferred_phase_failures)
            )

    def _rejudge_deferred_failures(self, *, final: bool) -> None:
        """Re-judge a deferred OTA bootstrap verification failure
        against the device's current state.

        The dedicated OTA bootstrap verifies while the run is still
        in its bootstrap ordering: on a device in the
        alohausers-disabled posture its in-phase verification
        cannot observe the override being served, because the
        accounts phase that re-enables the package has not run yet
        (Run 37C). The failure is therefore re-judged at report
        time — ota_preflight() against the current state, or, when
        the end state is the disabled posture itself, the posture
        criteria (_judge_ota_posture). A judgment that confirms the
        failure marks the action unverified and corrects a manifest
        that already claimed it done; a provisional judgment (a
        payload phase still pending) may clear a failure but never
        confirms one. Only the bootstrap's verification failure is
        re-judgeable: an entry recording a different failure (the
        nested run died, the transport dropped) stays as recorded.
        """
        entries = [
            entry
            for entry in self.deferred_phase_failures
            if entry.startswith("disable_updates:")
            and "did not verify" in entry
        ]
        if not entries:
            return
        if self._ota_end_state_verified():
            for entry in entries:
                self.deferred_phase_failures.remove(entry)
            print(
                "OTA_DEFERRED_FAILURE_CLEARED "
                "reason=end-state-verified",
                flush=True,
            )
            if self.ota_unverified:
                # The run's own mid-run verification marked the
                # action unverified (in the disabled posture its
                # provenance check cannot pass) before the end-state
                # judgment judged it done. Clear the mark so the
                # run's remaining manifest writes record the judged
                # result, and at the final report repair a manifest
                # that already recorded "unverified".
                self.ota_unverified = False
                if final:
                    self._correct_manifest_for_verified_ota()
            return
        if not final:
            return
        self.ota_unverified = True
        self._correct_manifest_for_unverified_ota()

    def _ota_end_state_verified(self) -> bool:
        if self.ota_preflight():
            return True
        return self._judge_ota_posture()

    def _judge_ota_posture(self) -> bool:
        """Judge the OTA action by the disabled posture's own pass
        conditions (owner decision, Nov 18, 2026).

        Applies only when the run ends in the alohausers-disabled
        posture: the MobileConfig service is then absent by design,
        so the provenance verification ota_preflight() performs can
        never pass, and the block rests on the posture's own
        mechanism instead — otad.nodemon re-asserted after every
        boot by the staged autoroot payload, the config provider
        package disabled, and the override file present as the
        inert backstop (the posture itself was proven over a full
        241-minute cycle with zero check-ins, Nov 17, 2026). Every
        criterion is read back live; any one false leaves the
        action unverified. When alohausers is enabled at the end
        this judgment does not apply at all, and a failed
        provenance verification stands exactly as before.
        """
        if not self.target or self.target.device != "aloha":
            return False
        if not self.alohausers_package_disabled():
            return False
        conf_staged = self._ota_nodemon_conf_staged()
        nodemon_now = (
            self.adb_run(
                ["shell", "getprop", OTA_NODEMON_PROPERTY], timeout=5
            ).stdout.strip()
            == "true"
        )
        nodemon = nodemon_now or self.ota_nodemon_set_this_run
        override_present = self._ota_override_present()
        judged_done = bool(conf_staged and nodemon and override_present)
        print(
            "OTA_POSTURE_JUDGED "
            f"result={'done' if judged_done else 'unverified'} "
            f"conf_staged={int(conf_staged)} "
            f"nodemon={int(nodemon)} "
            "nodemon_source="
            + (
                "current-boot"
                if nodemon_now
                else "set-this-run"
                if self.ota_nodemon_set_this_run
                else "none"
            )
            + " alohausers_disabled=1 "
            f"override_present={int(override_present)}",
            flush=True,
        )
        return judged_done

    def alohausers_package_disabled(self) -> bool:
        return self.settings_feature.alohausers_package_disabled()

    def _ota_nodemon_conf_staged(self) -> bool:
        result = self.adb_run(
            ["shell", "cat", AUTOROOT_CONF_REMOTE], timeout=5
        )
        if result.returncode != 0:
            return False
        return any(
            line.strip() == "OTA_NODEMON=1"
            for line in result.stdout.splitlines()
        )

    def _ota_override_present(self) -> bool:
        """Whether the MobileConfig override file is in place.

        The file lives in alohausers' app-private directory, which
        the shell cannot stat. When the custom payload's root
        daemon is serving it answers directly (a nonzero answer is
        not authoritative — the daemon's shell domain may be
        refused the stat — so it only ever proves presence).
        Otherwise the evidence is this run's own install action:
        the deferred verification failure being judged exists only
        because that action completed, and it verifies the file's
        exact contents as its last step (a failed install discards
        the attempt instead of reaching verification).
        """
        try:
            code, _output = self.daemon_exec(
                f"test -f {OTA_OVERRIDE_REMOTE}"
            )
            if code == 0:
                return True
        except Exception:
            pass
        return self._ota_install_verified_this_run

    def _manifest_boots(
        self, state: dict[str, object]
    ) -> tuple[str | None, str | None]:
        """The verification boots a manifest re-write preserves:
        the record's own block first, then the boots this run
        itself established where the record's block is missing
        them (Defect K: a correction re-write must not carry a
        stale null block over the run's verified boots)."""
        first_boot = second_boot = None
        verification = state.get("verification")
        if isinstance(verification, dict):
            if isinstance(verification.get("first_boot"), str):
                first_boot = verification["first_boot"]
            if isinstance(verification.get("second_boot"), str):
                second_boot = verification["second_boot"]
        if self._verified_boots is not None:
            own_first, own_second = self._verified_boots
            if first_boot is None:
                first_boot = own_first
            if second_boot is None:
                second_boot = own_second
        return first_boot, second_boot

    def _correct_manifest_for_unverified_ota(self) -> None:
        """Re-write a completed manifest that claimed the OTA
        action done now that the final judgment marks it
        unverified, preserving the recorded verification boots, so
        the on-disk record never claims an unverified action as
        done (write_state maps the action to "unverified" while
        ota_unverified is set)."""
        try:
            state = self.read_state()
        except ProvisionError:
            state = None
        if not state or state.get("status") != "complete":
            return
        actions = state.get("actions")
        if not isinstance(actions, dict):
            return
        if actions.get("disable_updates") is not True:
            return
        first_boot, second_boot = self._manifest_boots(state)
        self.write_state("complete", first_boot, second_boot)
        print(
            "OTA_MANIFEST_CORRECTED action=disable_updates "
            "recorded=unverified",
            flush=True,
        )

    def _correct_manifest_for_verified_ota(self) -> None:
        """Re-write a completed manifest that recorded the OTA
        action "unverified" now that the final judgment judges it
        done (the mid-run provenance verification marks it
        unverified in the disabled posture, before the end-state
        judgment runs), preserving the recorded verification
        boots, so the device can qualify for the no-op path on
        later runs (write_state records the action done while
        ota_unverified is clear)."""
        try:
            state = self.read_state()
        except ProvisionError:
            state = None
        if not state or state.get("status") != "complete":
            return
        actions = state.get("actions")
        if not isinstance(actions, dict):
            return
        if actions.get("disable_updates") != "unverified":
            return
        first_boot, second_boot = self._manifest_boots(state)
        self.write_state("complete", first_boot, second_boot)
        print(
            "OTA_MANIFEST_CORRECTED action=disable_updates "
            "recorded=done",
            flush=True,
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
            "restore_autoroot",
            "restore_wireless_adb",
            "restore_theme",
            "restore_meta_authenticators",
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
        *,
        merge_prior: bool = False,
    ) -> None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        actions = self.requested_actions()
        if self.ota_unverified and "disable_updates" in actions:
            # The OTA block was applied but its effectiveness could
            # not be positively established; record it as unverified
            # so a later run never treats it as a completed no-op.
            actions["disable_updates"] = "unverified"
        if self.presence_deferred:
            # The presence runtime verification deferred (camera
            # lens cover closed): the durable state was verified
            # but the pipeline was never observed streaming. Record
            # the presence actions as "deferred" so the no-op
            # gate's exact-match comparison refuses a later no-op
            # claim and a later run re-attempts the streaming
            # verification (the "unverified" pattern above).
            if "optimize_presence" in actions:
                actions["optimize_presence"] = "deferred"
            if "presence_fps_cap" in actions:
                actions["presence_fps_cap"] = "deferred"
        artifact_sha256 = self.selected_artifact_hashes()
        autoroot_key_sha256 = self.staged_autoroot_key_sha256
        # The DNS intent THIS run's own action set establishes
        # (Defect D record hygiene, applied after the merge
        # below): a run that completes a DNS apply must record
        # only that intent, so a prior record's sibling key has
        # to be actively dropped — the merge preserves prior
        # actions per key, and the expectation readers resolve
        # the DNS family dhcp-first, so a surviving sibling
        # shadows the intent the run just established.
        own_dns_keys = [
            name for name in DNS_ACTION_KEYS if actions.get(name)
        ]
        # The pair sides THIS run's own action set drops from the
        # merged record (Defect E record hygiene, applied after
        # the merge below, with the DNS drop): a run that
        # completes one side of an apply/restore pair must drop
        # the recorded other side — the merge preserves prior
        # actions per key, so without an active drop the record
        # carries the contradictory pair forever (a channel theme
        # apply left system_theme_control beside the restore_theme
        # an earlier restore had recorded). Autoroot's apply side
        # is the staging request itself, not an action key.
        own_pair_drops = [
            other
            for apply_key, restore_key in APPLY_RESTORE_PAIRS
            for own, other in (
                (apply_key, restore_key),
                (restore_key, apply_key),
            )
            if actions.get(own)
        ]
        if self.autoroot:
            own_pair_drops.append("restore_autoroot")
        if self._verified_boots is not None:
            # The boots THIS run established fill any the caller
            # did not supply, on every write (Defect M): the fill
            # used to live inside the merge below, gated on the
            # start record being complete, so a combined run that
            # started from a pending record (a recovered run) let
            # its payload phase's terminal write replace the
            # verification write's good record with null boots.
            # Explicit caller boots still win, and the merge below
            # still carries the start record's block over where
            # this run verified none.
            own_first, own_second = self._verified_boots
            if first_boot is None:
                first_boot = own_first
            if second_boot is None:
                second_boot = own_second
        if merge_prior:
            # Merge into the manifest this run started from instead
            # of replacing it: the recorded manifest is the device's
            # accumulated state, and a delta run (the channel path)
            # does not un-apply the actions it did not request, so
            # dropping them would falsify the record the fast-path
            # gates, the OTA posture trust and --status all read.
            # This run's applied actions and artifact hashes win
            # per key, with one exception: verification-grade
            # values merge monotonically (below). The recorded
            # autoroot key hash survives unless this run restaged
            # autoroot (then the staged hash above is the new
            # one); the start record's verification block carries
            # over where this write supplies no boots (this run's
            # own verified boots were filled in above, before the
            # merge; the manifest-correction re-writes preserve
            # them the same way). Tool revision and desired state
            # follow the completing run, as in every other write.
            prior = self._start_state
            if isinstance(prior, dict) and prior.get("status") == "complete":
                prior_actions = prior.get("actions")
                if isinstance(prior_actions, dict):
                    actions = {**prior_actions, **actions}
                    if (
                        actions.get("disable_updates") == "unverified"
                        and prior_actions.get("disable_updates") is True
                    ):
                        # Defect M: this run's "unverified" records
                        # that it could not positively judge the
                        # OTA block (a win-less boot cannot read
                        # the posture's per-boot property or stat
                        # the override file), not that the block
                        # is absent, so it does not downgrade a
                        # value an earlier run positively
                        # verified. Only a run that itself
                        # verifies (records the action done) or
                        # positively refutes it (the
                        # enable-updates restore, whose pair
                        # hygiene drops the key below) changes
                        # the recorded value. Nothing here
                        # creates a verified value: with no
                        # verified prior, "unverified" records
                        # exactly as before.
                        actions["disable_updates"] = True
                prior_hashes = prior.get("artifact_sha256")
                if isinstance(prior_hashes, dict):
                    artifact_sha256 = {**prior_hashes, **artifact_sha256}
                if autoroot_key_sha256 is None:
                    recorded_key = prior.get("autoroot_key_sha256")
                    if isinstance(recorded_key, str):
                        autoroot_key_sha256 = recorded_key
                verification = prior.get("verification")
                if isinstance(verification, dict):
                    if first_boot is None and isinstance(
                        verification.get("first_boot"), str
                    ):
                        first_boot = verification["first_boot"]
                    if second_boot is None and isinstance(
                        verification.get("second_boot"), str
                    ):
                        second_boot = verification["second_boot"]
                if len(own_dns_keys) == 1:
                    # Defect D hygiene, before the count below is
                    # logged: the merged record carries only the
                    # DNS intent this run established. (On a
                    # replace write this could never fire — the
                    # run's own set holds no sibling — so the drop
                    # lives here with the merge it corrects. A run
                    # carrying no DNS intent leaves the recorded
                    # DNS actions untouched; a run carrying two, a
                    # composed config the CLI no longer produces,
                    # keeps today's record.)
                    for name in DNS_ACTION_KEYS:
                        if name != own_dns_keys[0]:
                            actions.pop(name, None)
                for name in own_pair_drops:
                    # Defect E hygiene, with the DNS drop above and
                    # before the count below is logged: the merged
                    # record carries only the pair side this run
                    # established. (On a replace write this could
                    # never fire — the CLI keeps a run's own set
                    # pair-clean — so the drop lives here with the
                    # merge it corrects. A run establishing neither
                    # side leaves the recorded pair untouched.)
                    actions.pop(name, None)
                print(
                    "STATE_MANIFEST_MERGED "
                    f"actions={len(actions)} "
                    f"artifacts={len(artifact_sha256)}",
                    flush=True,
                )
        if state_status == "complete" and not self._payload_phase_pending:
            # A completion write with no payload phase still to
            # run records the run's end state: let it pick up the
            # disabled posture from that end state (Defect J). A
            # combined run's mid-run completion write (the
            # standard install phase's) skips this — the payload
            # phase can still change the package state after it,
            # and the end-of-run posture step owns the observation
            # at the payload terminal instead.
            self._observe_posture_end_state()
        self.run_state.write_state(
            state_status,
            fingerprint=fingerprint,
            target_key=self.target.key if self.target else None,
            tool_revision=self.tool_revision(),
            artifact_sha256=artifact_sha256,
            actions=actions,
            first_boot=first_boot,
            second_boot=second_boot,
            autoroot_key_sha256=autoroot_key_sha256,
            desired_state=self._desired_state() or None,
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
        ota_nodemon = shell("getprop", OTA_NODEMON_PROPERTY, timeout=5)
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
                "poll_interval_minutes": (
                    (parse_ota_config(ota_dump) or {}).get(
                        "kUpdateIntervalInitialMinutes"
                    )
                ),
                "update_url": (
                    (parse_ota_config(ota_dump) or {}).get("kOtaJsonUrl")
                ),
                "nodemon": ota_nodemon or None,
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
                "staged_autoroot_key_sha256": (
                    manifest.get("autoroot_key_sha256")
                    if isinstance(manifest, dict)
                    else None
                ),
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
        (self.log_dir / "status.json").write_text(rendered + "\n", newline="")
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
                self.restore_autoroot,
                self.restore_wireless_adb,
                self.restore_meta_authenticators,
                self.restore_theme_uid1000_action_requested(),
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
                **{
                    name: shutil.which(name) is not None
                    for name in ("adb", "git", "make")
                },
                # The interpreter running this process, not a PATH
                # probe: stock Windows provides python.exe/py.exe but
                # no python3 (the Microsoft Store python3.exe is a
                # stub), so a PATH probe misreports both ways.
                "python3": bool(sys.executable),
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
                json.dumps(status, indent=2, sort_keys=True) + "\n",
                newline="",
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
                (root / filename).write_text(
                    result.stdout, errors="replace", newline=""
                )
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
                OTA_BACKEND_BACKUP_REMOTE,
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
                    hashes[path.relative_to(root).as_posix()] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
            (root / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                newline="",
            )
            with tarfile.open(destination, "w:gz") as archive:
                archive.add(root, arcname="portal-backup")
        destination.chmod(0o600)
        print(f"BACKUP_OK path={destination}")
        return destination

    def collect_diagnostics_bundle(self) -> pathlib.Path:
        """Collect a read-only diagnostics bundle for any build.

        Lets a firmware build the target table does not support yet
        be evaluated without the device: identity props, the
        bugreport archive, the nearest sibling target's write-free
        page-prep diagnostic, and best-effort kernel config/kallsyms.
        Nothing is staged, installed, or rebooted; the one device-side
        file (the diagnostic preload in /data/local/tmp) is removed
        again before returning.
        """
        items: dict[str, dict[str, str]] = {}

        def record(name: str, status: str, detail: str = "") -> None:
            items[name] = {"status": status, "detail": detail}

        def prop(name: str) -> str:
            return self.adb_run(
                ["shell", "getprop", name], timeout=10, check=True
            ).stdout.strip()

        fingerprint = prop("ro.build.fingerprint")
        device = prop("ro.product.device")
        product_model = prop("ro.product.model")
        sibling = self.target or find_sibling_target(device)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        bundle_path = self.log_dir / f"portal-diagnostics-{stamp}.zip"
        with tempfile.TemporaryDirectory(
            prefix="portal-diagnostics-"
        ) as temporary:
            root = pathlib.Path(temporary) / "portal-diagnostics"
            root.mkdir()

            def capture(
                name: str,
                filename: str,
                arguments: list[str],
                timeout: int = 30,
            ) -> None:
                try:
                    result = self.adb_run(
                        arguments, timeout=timeout, check=True
                    )
                except (ProvisionError, OSError) as exc:
                    record(name, "failed", str(exc)[:200])
                    return
                (root / filename).write_text(
                    result.stdout, errors="replace", newline=""
                )
                record(name, "collected")

            capture("getprop", "getprop.txt", ["shell", "getprop"])
            capture("uname", "uname.txt", ["shell", "uname", "-a"])
            capture(
                "proc_version",
                "proc-version.txt",
                ["shell", "cat", "/proc/version"],
            )
            capture("nproc", "nproc.txt", ["shell", "nproc"])
            capture(
                "cpuinfo",
                "cpuinfo.txt",
                ["shell", "head", "-n", "100", "/proc/cpuinfo"],
            )
            # MobileConfig backend selection is per-family (the
            # aloha OTA override defect was a legacy backend being
            # selected); recording the selector property and the
            # MobileConfig package/service inventory lets families
            # we do not own be classified from a tester's bundle.
            try:
                backend = prop(
                    "persist.sys.mobileconfigutil.usePlatformMobileConfig"
                )
            except (ProvisionError, OSError) as exc:
                record("mobileconfig_backend", "failed", str(exc)[:200])
            else:
                (root / "mobileconfig-backend.txt").write_text(
                    backend + "\n", newline=""
                )
                record(
                    "mobileconfig_backend",
                    "collected",
                    "usePlatformMobileConfig="
                    + (backend or "(unset)"),
                )
            for name, filename, arguments in (
                (
                    "mobileconfig_packages",
                    "mobileconfig-packages.txt",
                    ["shell", "pm", "list", "packages"],
                ),
                (
                    "mobileconfig_services",
                    "mobileconfig-services.txt",
                    ["shell", "dumpsys", "activity", "services"],
                ),
            ):
                try:
                    result = self.adb_run(
                        arguments, timeout=30, check=True
                    )
                except (ProvisionError, OSError) as exc:
                    record(name, "failed", str(exc)[:200])
                    continue
                lines = [
                    line
                    for line in result.stdout.splitlines()
                    if "mobileconfig" in line.lower()
                ]
                (root / filename).write_text(
                    "\n".join(lines) + ("\n" if lines else ""),
                    errors="replace",
                    newline="",
                )
                record(name, "collected", f"{len(lines)} matching lines")
            try:
                self.bugreport_text(
                    "diagnostics", archive_sink=root / "bugreport.zip"
                )
                record("bugreport", "collected")
            except (ProvisionError, OSError, zipfile.BadZipFile) as exc:
                record("bugreport", "failed", str(exc)[:200])
            self._diagnostics_page_prep(root, sibling, record)
            self._diagnostics_kernel_files(root, record)
            manifest = {
                "schema": 1,
                "kind": "portal-diagnostics",
                "tool_version": PROVISIONER_VERSION,
                "tool_revision": self.tool_revision(),
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "serial": self.serial,
                "model": product_model,
                "device": device,
                "fingerprint": fingerprint,
                "supported_target": (
                    self.target.key if self.target else None
                ),
                "sibling_target": sibling.key if sibling else None,
                "items": items,
            }
            (root / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                newline="",
            )
            self.log_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(
                bundle_path, "w", zipfile.ZIP_DEFLATED
            ) as archive:
                for path in sorted(root.rglob("*")):
                    if path.is_file():
                        archive.write(
                            path, arcname=path.relative_to(root).as_posix()
                        )
        bundle_path.chmod(0o600)
        print(f"DIAGNOSTICS_OK bundle={bundle_path}", flush=True)
        print(
            "DIAGNOSTICS_SUMMARY "
            f"model={product_model} device={device} "
            f"fingerprint={fingerprint} "
            f"supported={'yes' if self.target else 'no'}",
            flush=True,
        )
        for name in sorted(items):
            detail = items[name]["detail"]
            suffix = f" ({detail})" if detail else ""
            print(
                f"DIAGNOSTICS_ITEM {name}={items[name]['status']}{suffix}",
                flush=True,
            )
        print(
            "Attach this bundle to a firmware-support issue for this "
            "build so support can be evaluated without the device.",
            flush=True,
        )
        print(
            "Privacy note: the bundled bugreport can contain the "
            "device serial and usage metadata; review it or share it "
            "privately before posting it publicly.",
            flush=True,
        )
        return bundle_path

    def _diagnostics_page_prep(
        self,
        root: pathlib.Path,
        sibling: PortalTarget | None,
        record: Callable[[str, str, str], None],
    ) -> None:
        """Run the sibling preload's page-prep diagnostic, write-free.

        This is the same GHOSTLOCK_DIAG_PAGE_PREP_ONLY run memstart()
        uses on allocator-strategy targets; its KernelSnitch
        mm_struct leak result is the most decision-relevant signal
        for an unsupported build. The pushed preload is removed from
        /data/local/tmp again before returning.
        """
        if sibling is None:
            record(
                "page_prep_diag",
                "skipped",
                "no target for this device codename",
            )
            return
        preload = sibling.preload_path(ROOT)
        if not preload.is_file():
            record(
                "page_prep_diag",
                "skipped",
                f"sibling preload {preload.name} is not built "
                "on this host",
            )
            return
        command = (
            "env GHOSTLOCK_VOLATILE_LOG=1 "
            "GHOSTLOCK_DIAG_PAGE_PREP_ONLY=1 "
            "GHOSTLOCK_PAGE_COLLISIONS=5 "
            "GHOSTLOCK_LOG_P0_CANDIDATES=1 "
            f"LD_PRELOAD={shlex.quote(DIAGNOSTICS_PRELOAD_REMOTE)} "
            "/system/bin/true"
        )
        try:
            self.adb_run(
                ["push", str(preload), DIAGNOSTICS_PRELOAD_REMOTE],
                timeout=60,
                check=True,
            )
            result = self.adb_run(["shell", command], timeout=120)
        except (ProvisionError, OSError) as exc:
            record("page_prep_diag", "failed", str(exc)[:200])
            return
        finally:
            try:
                self.adb_run(
                    ["shell", "rm", "-f", DIAGNOSTICS_PRELOAD_REMOTE],
                    timeout=20,
                )
            except (ProvisionError, OSError):
                pass
        output = result.stdout + result.stderr
        (root / "page-prep-diag.txt").write_text(
            output, errors="replace", newline=""
        )
        if "KernelSnitch mm_struct leak failed" in output:
            detail = "KernelSnitch mm_struct leak FAILED"
        else:
            leak_line = next(
                (
                    line.strip()
                    for line in output.splitlines()
                    if "mm_struct" in line
                ),
                "",
            )
            detail = leak_line[:200] or "no mm_struct line in output"
        record("page_prep_diag", "collected", detail)

    def _diagnostics_kernel_files(
        self,
        root: pathlib.Path,
        record: Callable[[str, str, str], None],
    ) -> None:
        """Best-effort /proc/config.gz and /proc/kallsyms capture.

        Both are expected to fail or come back zeroed at shell
        privilege on production builds; the attempt and its outcome
        are recorded either way and never fail the bundle.
        """
        try:
            result = self.adb_run(
                ["shell", "base64", "/proc/config.gz"], timeout=30
            )
            encoded = "".join(result.stdout.split())
            data = (
                base64.b64decode(encoded, validate=True) if encoded else b""
            )
        except (ProvisionError, OSError, ValueError) as exc:
            record(
                "proc_config_gz",
                "attempted",
                f"unavailable: {str(exc)[:160]}",
            )
        else:
            if result.returncode == 0 and data:
                (root / "proc-config.gz").write_bytes(data)
                record(
                    "proc_config_gz", "collected", f"{len(data)} bytes"
                )
            else:
                record(
                    "proc_config_gz",
                    "attempted",
                    "not readable at shell privilege",
                )
        try:
            result = self.adb_run(
                ["shell", "head", "-c", "65536", "/proc/kallsyms"],
                timeout=30,
            )
        except (ProvisionError, OSError) as exc:
            record(
                "proc_kallsyms",
                "attempted",
                f"unavailable: {str(exc)[:160]}",
            )
        else:
            text = result.stdout
            if text.strip():
                (root / "proc-kallsyms.txt").write_text(
                    text, errors="replace", newline=""
                )
                zeroed = all(
                    line.startswith("0000000000000000") or not line.strip()
                    for line in text.splitlines()
                )
                record(
                    "proc_kallsyms",
                    "collected",
                    "addresses zeroed (kptr_restrict)"
                    if zeroed
                    else f"{len(text)} bytes",
                )
            else:
                record(
                    "proc_kallsyms",
                    "attempted",
                    "empty at shell privilege",
                )

    def backup_private_dns(self) -> None:
        return self.settings_feature.backup_private_dns()

    def verify_adb_framework_enabled(
        self, action: str = "verified", wait_seconds: int = 0
    ) -> None:
        deadline = time.monotonic() + wait_seconds
        actual = ""
        while True:
            try:
                actual = self.adb_run(
                    ["shell", "settings", "get", "global", ADB_ENABLED_SETTING],
                    timeout=5,
                    check=True,
                ).stdout.strip()
            except ProvisionError:
                if not wait_seconds:
                    raise
                # Writing adb_enabled restarts adbd on some builds; while
                # it is down the read fails at the transport level instead
                # of returning a value. That is the expected restart
                # window, not a verdict: keep polling until the deadline.
                actual = ""
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
            print(
                "ADB_FRAMEWORK_RESTART_EXPECTED "
                f"reason={ADB_ENABLED_SETTING}-write "
                "detail=adbd-may-restart settle=45s",
                flush=True,
            )
        self.verify_adb_framework_enabled(
            action="already-enabled" if before == "1" else "enabled",
            wait_seconds=0 if before == "1" else 45,
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

    def read_private_dns_state(self) -> tuple[str, str]:
        return self.settings_feature.read_private_dns_state()

    def write_private_dns_state(self, mode: str, hostname: str) -> None:
        return self.settings_feature.write_private_dns_state(mode, hostname)

    def read_private_dns_backup(self) -> dict[str, object] | None:
        return self.settings_feature.read_private_dns_backup()

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
            local.write_text(json.dumps(backup, indent=2) + "\n", newline="")
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
        self.shizuku_key_source = self.shizuku_feature.shizuku_key_source

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
            apk,
            tag,
            package,
            # --force bypasses only the byte-identical install skip,
            # so every install of the provisioner's own packages is
            # genuine. The package still goes through: it also gates
            # the signature-mismatch retry, and nulling it here used
            # to disarm that retry for every install in a force run —
            # the autoroot staging install hard-failed on a stale
            # old-keystore helper that way (Nov 17, 2026).
            skip_if_identical=not self.force,
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

    def refresh_shizuku_key_marker(self) -> None:
        return self.shizuku_feature.refresh_shizuku_key_marker()

    def read_saved_shizuku_key_marker(self) -> str | None:
        """The on-device saved marker's public key, or None when no
        channel can read it.

        The native authorize saves the marker root-owned 0600 on
        non-buffered targets, where a plain shell cat silently
        returns nothing unless adbd happens to be in root mode; read
        it through the payload root daemon while a win has it up,
        and fall back to the shell cat (the marker is host-pushed and
        shell-readable on buffered targets, and after a host-side
        refresh). An unreadable marker is not an error: it means
        there is no recorded authorization to judge against.
        """
        try:
            code, output = self.daemon_exec(
                f"cat {SHIZUKU_SAVED_KEY_REMOTE}", timeout=10
            )
            if code == 0 and output.strip():
                return output.strip()
        except (OSError, ProvisionError):
            pass
        marker = self.adb_run(
            ["shell", "cat", SHIZUKU_SAVED_KEY_REMOTE], timeout=10
        ).stdout.strip()
        return marker or None

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

    def verify_shizuku_channel(self) -> None:
        """Channel-path Shizuku verification: the end-state check
        (package installed, server live as uid 0, package-verifier
        state restored) plus the channel eligibility gate's own
        identity conditions re-asserted — root setup intact means
        the sentinel and autoroot helper packages are present."""
        self.shizuku_feature.verify_shizuku_channel()
        blocker = self._root_setup_blocker()
        if blocker is not None:
            raise ProvisionError(
                "root setup did not survive the channel apply: "
                f"{blocker}"
            )

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
            "restore_autoroot",
            "restore_wireless_adb",
            "restore_theme",
            "restore_meta_authenticators",
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
        self.meta_accounts_package_disabled = (
            self.settings_feature.meta_accounts_package_disabled
        )
        return result

    def audio_preflight(self) -> bool:
        return self.audio_feature.audio_preflight()

    def audio_health(self):
        return self.audio_feature.audio_health()

    def audio_channel_preflight(self) -> bool:
        return self.audio_feature.audio_channel_preflight()

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
        config, _ = self.read_ota_config(wait_seconds=30)
        gate_false, polling_off = self.ota_override_applied(config)
        interval = (
            config.get("kUpdateIntervalInitialMinutes", "missing")
            if config is not None
            else "unknown"
        )
        url_blocked = (
            config is not None and config.get("kOtaJsonUrl") == OTA_JSON_URL
        )
        backend_selected = True
        if self.target and self.target.device == "aloha":
            # On Aloha the native OTA client only reads the override
            # through the platform MobileConfig backend; without the
            # selector property set, a false gate in this dump does not
            # establish that the block is in effect.
            backend_selected = (
                self.adb_run(
                    ["shell", "getprop", OTA_BACKEND_PROPERTY], timeout=5
                ).stdout.strip()
                == "true"
            )
        healthy = (
            packages_disabled and gate_false and polling_off
            and backend_selected
        )
        print(
            "OTA_PREFLIGHT "
            f"packages_disabled={int(packages_disabled)} "
            f"firmware_gate_false={int(gate_false)} "
            f"poll_interval_minutes={interval} "
            f"update_url_blocked={int(url_blocked)} "
            f"backend_platform={int(backend_selected)} "
            f"dump={'complete' if config is not None else 'incomplete'} "
            f"action={'skip' if healthy else 'install'}"
        )
        return healthy

    def read_ota_config(
        self, wait_seconds: int
    ) -> tuple[dict[str, str] | None, str]:
        """Read otad's config, retrying while otad is starting or slow."""
        deadline = time.monotonic() + wait_seconds
        dump = ""
        while True:
            try:
                dump = self.adb_run(
                    ["shell", "dumpsys", "facebook.aloha.otaservice"],
                    timeout=15,
                ).stdout
            except ProvisionError:
                dump = ""
            config = parse_ota_config(dump)
            if config is not None or time.monotonic() >= deadline:
                return config, dump
            time.sleep(2)

    @staticmethod
    def ota_override_applied(
        config: dict[str, str] | None,
    ) -> tuple[bool, bool]:
        """Return whether the OTA gate is off and update polling is off.

        Polling counts as off only when otad both sleeps for the override
        interval and sends any remaining check to the closed local URL.
        """
        if config is None:
            return False, False
        return (
            config.get("kFirmwareOtaUpdateEnable") == "false",
            config.get("kUpdateIntervalInitialMinutes")
            == str(OTA_POLL_INTERVAL_MINUTES)
            and config.get("kOtaJsonUrl") == OTA_JSON_URL,
        )

    def read_ota_backend_backup(self) -> str | None:
        result = self.adb_run(
            ["shell", "cat", OTA_BACKEND_BACKUP_REMOTE], timeout=5
        )
        if result.returncode != 0:
            return None
        try:
            saved = json.loads(result.stdout)
            if saved["property"] != OTA_BACKEND_PROPERTY:
                raise ValueError("unexpected property")
            value = saved["value"]
            if value not in ("", "true", "false", "1", "0"):
                raise ValueError("unexpected backend value")
            return value
        except (ValueError, KeyError, TypeError) as exc:
            raise ProvisionError("invalid OTA backend backup") from exc

    def prepare_ota_backend_backup(self) -> None:
        if self.read_ota_backend_backup() is not None:
            return
        value = self.adb_run(
            ["shell", "getprop", OTA_BACKEND_PROPERTY], timeout=5, check=True
        ).stdout.strip()
        if value not in ("", "true", "false", "1", "0"):
            raise ProvisionError(f"unexpected OTA backend value: {value!r}")
        self.push_text_atomic(
            json.dumps({"property": OTA_BACKEND_PROPERTY, "value": value})
            + "\n",
            OTA_BACKEND_BACKUP_REMOTE,
        )
        print(
            f"OTA_BACKEND_BACKUP value={value!r} "
            f"path={OTA_BACKEND_BACKUP_REMOTE}"
        )

    def configure_ota_backend_phase(self) -> bool:
        """Use the system identity only for the backend property update."""
        if self.ota_backend_value is not None or not self.target:
            return False
        if self.target.device != "aloha":
            return False
        value = (
            "true" if self.disable_updates else self.read_ota_backend_backup()
        )
        if value is None:
            return False
        current = self.adb_run(
            ["shell", "getprop", OTA_BACKEND_PROPERTY], timeout=5, check=True
        ).stdout.strip()
        if current == value:
            return False
        phase_logs = self.log_dir / "ota-backend"
        phase_logs.mkdir(parents=True, exist_ok=True)
        print(f"OTA_BACKEND_PHASE value={value!r}", flush=True)
        PortalProvisioner(
            self.serial,
            self.attempts,
            phase_logs,
            disable_updates=self.disable_updates,
            enable_updates=self.enable_updates,
            skip_build=self.skip_build,
            bundle=self.bundle,
            ota_backend_value=value,
        ).provision()
        return True

    def _read_staged_autoroot_conf(self) -> str | None:
        """The staged autoroot.conf content, or None when there is
        no readable staged config to sync.

        A failed cat is not an empty config: the command runner
        merges stderr into stdout, so a config removed with the
        staging directory (--restore autoroot removes the whole
        directory) surfaces as cat's error text, which the conf
        syncs once treated as config lines and rewrote (Defect I,
        2026-11-19)."""
        result = self.adb_run(["shell", "cat", AUTOROOT_CONF_REMOTE], timeout=5)
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return result.stdout

    def _write_staged_autoroot_conf(self, contents: str) -> None:
        """Rewrite the staged autoroot.conf in place, creating the
        staging directory first.

        The directory is created by autoroot staging and removed
        by --restore autoroot, so a write into it cannot assume it
        exists: adb push cannot create it (its secure_mkdirs is
        refused on these devices), which killed the first
        re-provision after an autoroot restore (Defect I,
        2026-11-19)."""
        self.adb_run(
            ["shell", "mkdir", "-p", AUTOROOT_REMOTE_DIR],
            timeout=5,
            check=True,
        )
        self.push_text_atomic(contents, AUTOROOT_CONF_REMOTE)
        self.adb_run(
            ["shell", "chmod", "0644", AUTOROOT_CONF_REMOTE],
            timeout=5,
            check=True,
        )

    def sync_ota_nodemon_autoroot_conf(self) -> None:
        """Keep the staged autoroot config's OTA_NODEMON key in step
        with this run's updates request.

        The staged autoroot payload re-asserts otad.nodemon after
        every boot only while the staged config carries
        OTA_NODEMON=1 (see PayloadFeature._ota_nodemon_desired for
        the staging-time decision). A later run that changes the
        updates state without re-staging autoroot — a bare
        --enable-updates is the common case — would otherwise leave
        the payload asserting a property the user just turned off.
        Runs that request no updates change leave the config
        untouched.
        """
        if not (self.disable_updates or self.enable_updates):
            return
        if not self.target or self.target.device != "aloha":
            return
        if not self.autoroot_staged():
            return
        existing = self._read_staged_autoroot_conf()
        if existing is None:
            return
        lines = [
            line
            for line in existing.splitlines()
            if not line.startswith("OTA_NODEMON=")
        ]
        if self.disable_updates:
            lines.append("OTA_NODEMON=1")
        updated = "".join(f"{line}\n" for line in lines)
        if updated == existing:
            return
        self._write_staged_autoroot_conf(updated)
        print(
            "OTA_NODEMON_CONF_SYNC "
            f"value={'1' if self.disable_updates else '0'}",
            flush=True,
        )

    def sync_drift_conf_keys(self) -> None:
        """Keep the staged autoroot config's drift-pass keys in
        step with this run's requests (C3-A), the same discipline
        as sync_ota_nodemon_autoroot_conf: staging derives
        DNS_MODE / DNS_SPECIFIER / ALOHAUSERS_DISABLED from the
        run, but a later run that changes the DNS request or the
        recorded posture without re-staging autoroot would
        otherwise leave the helper enforcing the old recorded
        state on every boot. Runs that mention neither item leave
        the config untouched, as does a device with nothing
        staged."""
        dns_requested = bool(
            self.dhcp_dns or self.privacy_dns or self.restore_privacy_dns
        )
        posture_requested = bool(
            self.remove_meta_accounts
            and self.target is not None
            and self.target.device == "aloha"
        )
        if not (dns_requested or posture_requested):
            return
        if not self.autoroot_staged():
            return
        existing = self._read_staged_autoroot_conf()
        if existing is None:
            return
        lines = existing.splitlines()
        if dns_requested:
            resolved = self._requested_dns_expectation()
            if resolved is not None:
                lines = [
                    line
                    for line in lines
                    if not line.startswith("DNS_MODE=")
                    and not line.startswith("DNS_SPECIFIER=")
                ]
                lines.append(f"DNS_MODE={resolved[0]}")
                lines.append(f"DNS_SPECIFIER={resolved[1]}")
                print(
                    "DRIFT_CONF_SYNC item=private_dns "
                    f"mode={resolved[0]} specifier={resolved[1]}",
                    flush=True,
                )
        if posture_requested:
            desired = self._desired_state()
            lines = [
                line
                for line in lines
                if not line.startswith("ALOHAUSERS_DISABLED=")
            ]
            if desired.get("alohausers_package") == "disabled":
                lines.append("ALOHAUSERS_DISABLED=1")
            print(
                "DRIFT_CONF_SYNC item=alohausers value="
                f"{'1' if desired.get('alohausers_package') == 'disabled' else '0'}",
                flush=True,
            )
        updated = "".join(f"{line}\n" for line in lines)
        if updated == existing:
            return
        self._write_staged_autoroot_conf(updated)

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
        configured = self.presence_feature.presence_preflight()
        if configured and self.presence_feature.presence_verify_deferred:
            self.presence_deferred = True
        return configured

    def presence_fps_preflight(self) -> bool:
        configured = self.presence_feature.presence_fps_preflight()
        if configured and self.presence_feature.presence_verify_deferred:
            self.presence_deferred = True
        return configured

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

    def resolve_ndk_simpleperf(self) -> pathlib.Path:
        """Locate the NDK's arm64 simpleperf on the host.

        The candidate search KASLR discovery has always used: NDK
        roots from the environment first, then NDKs installed under
        the SDK roots and the default SDK locations. In bundle mode
        the bundle's own copy (the same NDK binary, hash-verified
        with the rest of the bundle) wins: a bundle host has no NDK.
        """
        if self.bundle_root is not None:
            bundled = self.bundle_root / prebuilt_bundle.SIMPLEPERF_BUNDLE_PATH
            if bundled.is_file():
                return bundled
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
            candidate / "ndk" for candidate in default_sdk_candidates()
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
        return local_simpleperf

    def stage_simpleperf(self) -> None:
        """Push the NDK arm64 simpleperf to its staging path unless
        the on-device copy already hashes identically."""
        local_simpleperf = self.resolve_ndk_simpleperf()
        remote = "/data/local/tmp/portal-simpleperf"
        if self.simpleperf_push_needed(local_simpleperf, remote):
            self.adb_run(
                ["push", str(local_simpleperf), remote],
                timeout=120,
                check=True,
            )
            self.adb_run(
                ["shell", "chmod", "0755", remote], timeout=20, check=True
            )
        else:
            print(
                "SIMPLEPERF_PUSH_SKIP reason=on-device-hash-matches",
                flush=True,
            )

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
            self.stage_simpleperf()
            simpleperf = "/data/local/tmp/portal-simpleperf"
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

    def bugreport_text(
        self, tag: str, archive_sink: pathlib.Path | None = None
    ) -> str:
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
            if archive_sink is not None:
                # Diagnostics bundles ship the archive itself, not
                # only the parsed text; copy it out before the
                # temporary directory is discarded.
                shutil.copyfile(local, archive_sink)
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
        if self.restore_wireless_adb:
            environment["GHOSTLOCK_RESTORE_WIRELESS_ADB"] = "1"
            if self.target.wireless_adb_file_property:
                environment["GHOSTLOCK_WIRELESS_ADB_FILE_PROPERTY"] = (
                    self.target.wireless_adb_file_property
                )
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
                        "GHOSTLOCK_MHA_TUNING_PATH": (
                            self.audio_feature.mha_tuning_device_path()
                        ),
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
                        "GHOSTLOCK_MHA_TUNING_PATH": (
                            self.audio_feature.mha_tuning_device_path()
                        ),
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
        self._action_credential_source = None
        if credential_action:
            if private_meta_action and (
                self.meta_accounts_local_only or self.meta_accounts_finalize_only
            ):
                source_process = "com.facebook.alohaservices.alohausers"
            elif private_ota_action and self.ota_backend_value is not None:
                source_process = "system_server"
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
            self._action_credential_source = source_process
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
        # The OTA block action belongs to the dedicated OTA phase,
        # whose action child clones the OTA installer credential. On
        # targets with such a credential, the main flow's own attempts
        # run under init's credential instead: install_ota_block()
        # writes inside the alohausers app-private directory, fails
        # there with EACCES (step 17), and every race the phase won is
        # discarded (Run 37A, 2026-11-16: the dedicated phases had run,
        # verification stayed unverified, and the key leaked into the
        # standard-install attempts). Targets without a dedicated OTA
        # credential have no separate phase, so their standard context
        # keeps the action exactly as before.
        ota_phase_owns_block = private_ota_action or not (
            self.target.ota_installer_credentials
            or self.target.ota_system_credentials
            or self.target.ota_credential_process is not None
        )
        if self.ota_backend_value is not None:
            environment["GHOSTLOCK_OTA_BACKEND_VALUE"] = self.ota_backend_value
        elif self.disable_updates and not self.ota_already_configured:
            if ota_phase_owns_block:
                environment["GHOSTLOCK_OTA_BLOCK"] = "1"
                if self.target.device == "aloha":
                    environment["GHOSTLOCK_OTA_PLATFORM_BACKEND"] = "1"
        if (
            self.enable_updates
            and self.ota_backend_value is None
            and ota_phase_owns_block
        ):
            # Same phase rule as the block install above: the
            # restore removes the override inside the same
            # alohausers app-private directory (step 17), so on
            # targets with a dedicated OTA credential only the
            # dedicated OTA phase's environment carries it.
            environment["GHOSTLOCK_RESTORE_OTA_BLOCK"] = "1"
        # The nodemon action belongs to the standard-install
        # attempts: their action child clones init's credential (no
        # per-phase credential source, no preserved shell domain),
        # which is the only context the property service accepts
        # otad.nodemon writes from (probe, 2026-11-17: an init-cloned
        # child set the property in two runs; the shell domain was
        # refused everywhere, so the root-daemon set shipped earlier
        # could never land). The dedicated OTA phase's child clones
        # the OTA installer credential and the payload phase's child
        # preserves the shell domain, so the key stays out of both;
        # in the payload phase and in on-device autoroot the native
        # payload runs the same action in a dedicated init-cloned
        # child instead, keyed there by the staged runner from
        # autoroot.conf, not by this environment.
        if (
            self.disable_updates
            and self.target.device == "aloha"
            and not credential_action
            and not preserve_shell_domain
            and not self._in_custom_payload_phase
        ):
            environment["GHOSTLOCK_OTA_NODEMON"] = "1"
        presence_phase_owns_profile = private_presence_action or not (
            self.target.presence_installer_credentials
        )
        if self.optimize_presence and not self.presence_already_configured:
            # Same phase rule as the OTA block: on targets with a
            # dedicated presence installer credential the profile
            # action belongs to the dedicated presence phase. Carried
            # into the main flow's attempts it writes inside the
            # aiservice app-private directory under init's credential,
            # fails with EACCES (step 19), and discards won races.
            if presence_phase_owns_profile:
                environment["GHOSTLOCK_PRESENCE_PROFILE"] = "1"
        if self.restore_presence_profile and presence_phase_owns_profile:
            # The restore writes the same app-private directory as
            # the install (step 19), so it follows the install's
            # phase rule exactly.
            environment["GHOSTLOCK_RESTORE_PRESENCE_PROFILE"] = "1"
        # Presence FPS phase ruling (Phase C2, from the code):
        # the FPS cap install/restore write inside the aiservice
        # app-private directory (install_presence_fps_cap /
        # restore_presence_fps_cap, step 21) — the same wall as
        # the profile — so on targets with a dedicated FPS phase
        # (uid1000 installer credential) the cap keys belong to
        # that phase, exactly like the profile. The restore keys
        # are additionally owned by the presence phase, because a
        # profile restore is what sets them when no FPS action is
        # requested. Targets with neither credential have no
        # dedicated phase: the main flow is the only carrier and
        # keeps the keys. GHOSTLOCK_UID1000_PRESENCE_FPS is
        # deliberately NOT gated: its consumers are the uid1000
        # runtime feature configuration, not the app-private
        # write, and the retained-FPS block below re-sets it from
        # the on-device backup in the main flow by design.
        fps_phase_owns_cap = private_uid1000_action or not (
            self.target.uid1000_installer_credentials
        )
        fps_phase_owns_restore = (
            private_uid1000_action
            or private_presence_action
            or not (
                self.target.uid1000_installer_credentials
                or self.target.presence_installer_credentials
            )
        )
        if self.presence_fps_action_requested():
            if fps_phase_owns_cap:
                environment["GHOSTLOCK_PRESENCE_FPS_CAP"] = str(
                    self.presence_fps_cap
                )
                environment["GHOSTLOCK_PRESENCE_REMOVE_KEY"] = "1"
            environment["GHOSTLOCK_UID1000_PRESENCE_FPS"] = str(
                self.presence_fps_cap
            )
        if self.restore_presence_fps or self.restore_presence_profile:
            if fps_phase_owns_restore:
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
        if (
            self.presence_fps_action_requested()
            and not native_presence_prefs
            and fps_phase_owns_cap
        ):
            environment["GHOSTLOCK_PRESENCE_PREF_ACTION"] = (
                f"set:{self.presence_fps_cap}"
            )
        if (
            (self.restore_presence_fps or self.restore_presence_profile)
            and not native_presence_prefs
            and fps_phase_owns_restore
        ):
            environment["GHOSTLOCK_PRESENCE_PREF_ACTION"] = "restore"
        if self.remove_meta_accounts and not self.meta_accounts_already_clean:
            environment.update(
                {
                    "GHOSTLOCK_REMOVE_META_ACCOUNTS": "1",
                    "GHOSTLOCK_META_ACCOUNT_CTL_JAR": ACCOUNT_CTL_REMOTE,
                }
            )
            if self.meta_accounts_package_disabled:
                # The alohausers package itself is disabled (a
                # legitimate prior state: a user trial, another
                # tool). The action normalizes it device-side before
                # applying the authenticator state; shell pm enable
                # is denied for uid 2000 on this build, so the host
                # cannot do it from here.
                environment["GHOSTLOCK_META_ACCOUNTS_ENABLE_PACKAGE"] = "1"
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
        if self.remove_shizuku or self.restore_autoroot:
            # Autoroot staging merged the Shizuku helper's keypair
            # into the autoroot helper, so unstaging autoroot removes
            # the same authorized line through the same action.
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
        if self.restore_theme_uid1000_action_requested():
            environment["GHOSTLOCK_RESTORE_SYSTEM_THEME"] = "1"
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

    def _log_watch_result_evidence(self, attempt: int) -> None:
        """Best-effort capture of the on-device watch result after a
        failed attempt, read before the runner reboots the device.

        The watch thread writes
        /data/local/tmp/ghostlock-watch-result.txt after every stage
        return, win or fail. When a won attempt's stream dies before
        the stage returns (the discarded-win shape diagnosed on
        Nov 18, 2026), this file plus the current boot id are the
        evidence that separates a kernel panic (the boot id has
        already changed) from a whole-process death (same boot id),
        and the unconditional reboot after a failed attempt erases
        the boot-id half of it. The reads are short and bounded; any
        failure is logged as unknown and never affects the run.
        """
        present = 0
        step = "none"
        boot_id = "unknown"
        try:
            watch_result = self.adb_run(
                [
                    "shell",
                    "cat",
                    "/data/local/tmp/ghostlock-watch-result.txt",
                ],
                timeout=5,
            ).stdout.strip()
            if watch_result:
                present = 1
                match = re.search(r"\bSTEP=(\d+)", watch_result)
                if match:
                    step = match.group(1)
        except Exception:
            pass
        try:
            current_boot = self.adb_run(
                ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
                timeout=5,
            ).stdout.strip()
            if current_boot:
                boot_id = current_boot
        except Exception:
            pass
        print(
            f"WATCH_RESULT_EVIDENCE attempt={attempt} "
            f"present={present} step={step} boot_id={boot_id}",
            flush=True,
        )

    def _boot_uptime_seconds(self) -> float | None:
        """Seconds since the current boot started, or None when the
        device does not answer the read."""
        try:
            result = self.adb_run(
                ["shell", "cat", "/proc/uptime"], timeout=5
            )
            if result.returncode != 0:
                return None
            fields = result.stdout.split()
            return float(fields[0]) if fields else None
        except Exception:
            return None

    def _current_boot_id(self) -> str | None:
        try:
            result = self.adb_run(
                ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
                timeout=5,
            )
            if result.returncode != 0:
                return None
            boot_id = result.stdout.strip()
            return boot_id or None
        except Exception:
            return None

    def wait_for_race_boot_window(self, attempt: int) -> None:
        """Flush-and-age guard: no race attempt starts on a young boot.

        Every boot auto-connects WiFi within seconds, and the
        connection makes system_server update the saved-network
        record and schedule an asynchronous WifiConfigStore write.
        Race boots then die young and uncleanly (attempt panics,
        watchdog cuts, the runner's own reboot), inside that write's
        flush window; repeated episodes lost the library unit's
        saved network outright (investigation 2026-11-19). So before
        an attempt starts, its boot must be at least
        RACE_BOOT_MIN_AGE_SECONDS old — by then the connect-time
        write has long been scheduled — and a sync pushes it to
        durable storage, so the boot may die without taking the
        store with it. When the uptime read does not answer, the
        guard fails toward waiting, never toward skipping: it counts
        its own observation time on the same boot id as a lower bound
        on the boot's age and waits the full window out.
        """
        observed_since = time.monotonic()
        observed_boot = self._current_boot_id()
        announced = False
        final_age = "unknown"
        while True:
            age = self._boot_uptime_seconds()
            if age is not None:
                if age >= RACE_BOOT_MIN_AGE_SECONDS:
                    final_age = f"{age:.0f}"
                    break
                remaining = RACE_BOOT_MIN_AGE_SECONDS - age
                shown_age = f"{age:.0f}"
            else:
                current_boot = self._current_boot_id()
                if (
                    observed_boot is not None
                    and current_boot is not None
                    and current_boot != observed_boot
                ):
                    observed_boot = current_boot
                    observed_since = time.monotonic()
                observed = time.monotonic() - observed_since
                if observed >= RACE_BOOT_MIN_AGE_SECONDS:
                    break
                remaining = RACE_BOOT_MIN_AGE_SECONDS - observed
                shown_age = "unknown"
            if not announced:
                print(
                    "WIFI_FLUSH_GUARD_WAIT "
                    f"attempt={attempt} boot_age_seconds={shown_age} "
                    f"required={RACE_BOOT_MIN_AGE_SECONDS}",
                    flush=True,
                )
                announced = True
            time.sleep(min(remaining, RACE_BOOT_GUARD_POLL_SECONDS))
        self.adb_run(["shell", "sync"], timeout=60, check=True)
        print(
            "WIFI_FLUSH_GUARD "
            f"attempt={attempt} boot_age_seconds={final_age} synced=1",
            flush=True,
        )

    def exploit(
        self, base: int, memstart: int, attempt: int, *,
        skip_final_reboot: bool = False,
    ) -> bool:
        if self.target is None:
            raise ProvisionError("target must be selected before exploitation")
        environment = self.build_exploit_environment(base, memstart, attempt)
        credential_action = "GHOSTLOCK_ACTION_CREDENTIAL_PID" in environment
        # One line per attempt naming the phase's credential context
        # and every GHOSTLOCK_* key its action child will run, so an
        # action key leaking into a phase whose context cannot
        # perform it is visible in the host log at a glance.
        print(
            "EXPLOIT_ATTEMPT_ENV "
            f"attempt={attempt} "
            f"credential_source={self._action_credential_source or 'none'} "
            "credential_pid="
            f"{environment.get('GHOSTLOCK_ACTION_CREDENTIAL_PID', 'none')} "
            "ghostlock_keys="
            + ",".join(
                sorted(
                    name
                    for name in environment
                    if name.startswith("GHOSTLOCK_")
                )
            ),
            flush=True,
        )
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
            "KernelSnitch mm_struct leak failed",
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
        if "GHOSTLOCK_RESTORE_WIRELESS_ADB" in environment:
            expected_markers["wireless_adb_restore"] = (
                "wireless ADB persistence restore",
                True,
            )
            expected_markers["wireless_adb_uid1000_restore"] = (
                "UID1000 wireless ADB helper restore",
                False,
            )
        if "GHOSTLOCK_RESTORE_SYSTEM_THEME" in environment:
            expected_markers["system_theme_uid1000_restore"] = (
                "UID1000 system theme helper restore",
                False,
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
        if self.ota_backend_value is not None:
            expected_markers["ota_backend"] = ("OTA backend property", True)
        elif "GHOSTLOCK_OTA_BLOCK" in environment:
            expected_markers["ota_block"] = ("OTA block file install", True)
        if "GHOSTLOCK_RESTORE_OTA_BLOCK" in environment:
            expected_markers["ota_restore"] = ("OTA block restore", True)
        if (
            self.optimize_presence
            and not self.presence_already_configured
            and "GHOSTLOCK_PRESENCE_PROFILE" in environment
        ):
            expected_markers["presence_profile"] = (
                "presence profile install",
                True,
            )
        if (
            self.restore_presence_profile
            and "GHOSTLOCK_RESTORE_PRESENCE_PROFILE" in environment
        ):
            expected_markers["presence_restore"] = (
                "presence profile restore",
                True,
            )
        if self.presence_fps_action_requested():
            # The FPS cap marker is required only in the phase
            # whose environment carries the cap action (Phase C2
            # gating); the uid1000 markers stay config-based
            # because GHOSTLOCK_UID1000_PRESENCE_FPS is carried in
            # every phase by design.
            if (
                "GHOSTLOCK_PRESENCE_FPS_CAP" in environment
                or "GHOSTLOCK_PRESENCE_PREF_ACTION" in environment
            ):
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
        if (
            self.restore_presence_fps or self.restore_presence_profile
        ) and (
            "GHOSTLOCK_RESTORE_PRESENCE_FPS" in environment
            or "GHOSTLOCK_PRESENCE_PREF_ACTION" in environment
        ):
            expected_markers["presence_fps_restore"] = (
                (
                    "PORTAL_PRESENCE_FPS_NATIVE action=restore"
                    if self.uses_native_presence_prefs()
                    else "PORTAL_PRESENCE_FPS action=restore"
                ),
                True,
            )
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
            # How the read loop ended, for INSTALL_ATTEMPT_EXIT: an
            # attempt that dies silently is only diagnosable if the
            # log says whether output ended by EOF, by the process
            # exiting, by a marker, or by the deadline expiring.
            attempt_end = "deadline"
            # Stream the attempt output through a reader thread and a
            # queue: select() on a pipe is POSIX-only (Windows accepts
            # sockets only), while a blocking read in a thread is
            # portable. The reader drains the pipe to EOF in order, so
            # the line processing below sees exactly what the select
            # loop saw.
            output_queue: queue.Queue[bytes | None] = queue.Queue()

            def _pump_attempt_output() -> None:
                try:
                    while True:
                        chunk = os.read(process.stdout.fileno(), 4096)
                        if not chunk:
                            break
                        output_queue.put(chunk)
                except OSError:
                    pass
                output_queue.put(None)

            threading.Thread(target=_pump_attempt_output, daemon=True).start()
            while time.monotonic() < deadline:
                try:
                    chunk = output_queue.get(timeout=1)
                except queue.Empty:
                    if process.poll() is not None:
                        attempt_end = "process-exit"
                        break
                    continue
                if chunk is None:
                    attempt_end = "eof"
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
                    watch_match = re.search(
                        r"WATCH_CFI_OK=\d+ STEP=(\d+) ERRNO=\d+", line
                    )
                    if watch_match:
                        step = int(watch_match.group(1))
                        annotation = (
                            f"WATCH_STEP step={step} "
                            f"action={watch_step_action(step)}\n"
                        )
                        sys.stdout.write(annotation)
                        sys.stdout.flush()
                        output.write(annotation)
                        output.flush()
                    if (
                        "OTA_NODEMON_SET property=" in line
                        and "value=true" in line
                    ):
                        # The win's dedicated child set the per-boot
                        # property and read it back true (the native
                        # line is emitted from that read-back). The
                        # posture judgment uses this record because
                        # the property does not survive the reboots
                        # between this phase and the run's end.
                        self.ota_nodemon_set_this_run = True
                    authorize_match = re.search(
                        r"Shizuku ADB key authorize already=(\d+) ok=(\d+)",
                        line,
                    )
                    if authorize_match and authorize_match.group(2) == "1":
                        # This win authorized the key stage() staged
                        # for the attempt: the host log-dir copy
                        # install prepared from the helper. Record it
                        # (and whether adb_keys already held it) —
                        # autoroot staging judges the pair it copies
                        # against this record, not against the
                        # on-device saved marker, whose native writer
                        # saves the staged scratch file and can lag
                        # the helper's live pair in the reuse path.
                        if self.shizuku_public_key is not None:
                            try:
                                self.authorized_shizuku_key = (
                                    self.shizuku_public_key.read_text(
                                        encoding="ascii"
                                    ).strip()
                                )
                                self.authorized_shizuku_key_already = (
                                    authorize_match.group(1) == "1"
                                )
                            except OSError:
                                pass
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
                    attempt_end = (
                        "success-marker" if success else "failure-marker"
                    )
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
            if not success:
                self._log_watch_result_evidence(attempt)
            if not skip_final_reboot or not success:
                # Flush before the reboot this runner issues (F1,
                # 2026-11-19): the boot's asynchronous writes — the
                # WiFi config store's connect-time write above all —
                # must be durable before the boot ends. Best-effort,
                # exactly like the reboot itself: a device the attempt
                # panicked cannot answer either call.
                try:
                    self.adb_run(["shell", "sync"], timeout=60)
                except ProvisionError:
                    pass
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
            exit_line = (
                f"INSTALL_ATTEMPT_EXIT attempt={attempt} "
                f"returncode={process.returncode} end={attempt_end}"
            )
            print(exit_line, flush=True)
            output.write(exit_line + "\n")
            output.flush()
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
                self.wait_for_race_boot_window(attempt)
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
                # Terminal step for a run whose manifest records
                # the alohausers-disabled posture (C3-A): restore
                # the recorded end state through the daemon now,
                # after the final verification and with no reboot
                # after it, so the package write settles.
                self._apply_recorded_posture()
                self.apply_post_payload_root_steps()
                # Terminal write of a payload-only invocation:
                # merge into the start manifest like the other
                # subset completions, so the payload phase does
                # not shrink the recorded state it did not touch.
                self.write_state("complete", merge_prior=True)
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
        # Staging renders the frozen on-device exploit environments
        # through build_exploit_environment(), whose custom-payload
        # block is gated on the payload phase. Race-path staging
        # already runs inside that phase; channel-path staging
        # (_apply_via_channel) does not, and its env files silently
        # lacked the block, so on-device wins skipped the custom
        # payload and the lock repair. Render in the payload-phase
        # context regardless of the caller's phase.
        previous_phase = self._in_custom_payload_phase
        self._in_custom_payload_phase = True
        try:
            result = self.payload_feature.stage_autoroot_payload()
        finally:
            self._in_custom_payload_phase = previous_phase
        self.staged_autoroot_key_sha256 = (
            self.payload_feature.staged_autoroot_key_sha256
        )
        return result

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

    def _ota_package_list(self) -> tuple[str, ...]:
        return (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )

    def read_ota_package_record(self) -> dict[str, str] | None:
        """The first-run record of the OTA packages' states, or
        None when no --disable-updates run with recording has
        happened on this device yet."""
        result = self.adb_run(
            ["shell", "cat", OTA_PACKAGES_BACKUP_REMOTE], timeout=5
        )
        if result.returncode != 0:
            return None
        try:
            parsed = json.loads(result.stdout)
            states = parsed["packages"]
            if not isinstance(states, dict):
                return None
            return {
                str(package): str(state)
                for package, state in states.items()
            }
        except (ValueError, KeyError, TypeError):
            return None

    def record_ota_package_states(self) -> None:
        """First-run record of the OTA packages' pre-disable states
        (restore-completeness: the updates restore used to enable
        unconditionally). First record wins."""
        if self.read_ota_package_record() is not None:
            print("OTA_PACKAGES_BACKUP_OK existing=1")
            return
        installed, disabled = self.package_sets()
        states = {
            package: (
                "absent"
                if package not in installed
                else "disabled"
                if package in disabled
                else "enabled"
            )
            for package in self._ota_package_list()
        }
        self.push_text_atomic(
            json.dumps({"packages": states}) + "\n",
            OTA_PACKAGES_BACKUP_REMOTE,
        )
        print(
            "OTA_PACKAGES_BACKUP_OK existing=0 states="
            + ",".join(
                f"{package}={states[package]}" for package in sorted(states)
            )
        )

    def disable_ota_packages(self, record_original: bool = True) -> None:
        if record_original:
            self.record_ota_package_states()
        packages = self._ota_package_list()
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
        packages = self._ota_package_list()
        recorded = self.read_ota_package_record()
        for package in packages:
            # Two-tier restore semantics: replay the recorded
            # original state when a record exists; the factory
            # default (all enabled) applies otherwise.
            state = recorded.get(package, "enabled") if recorded else "enabled"
            if state == "absent":
                continue
            if state == "disabled":
                result = self.adb_run(
                    ["shell", "pm", "disable-user", "--user", "0", package],
                    timeout=10,
                )
                if result.returncode != 0:
                    raise ProvisionError(
                        f"failed to re-disable OTA package {package}: "
                        f"{result.stdout}"
                    )
                continue
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
        if self.target and self.target.device == "aloha":
            original = self.read_ota_backend_backup()
            if original is not None:
                current = self.adb_run(
                    ["shell", "getprop", OTA_BACKEND_PROPERTY],
                    timeout=5,
                    check=True,
                ).stdout.strip()
                if current != original:
                    raise ProvisionError(
                        "OTA native configuration backend was not restored"
                    )
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=10,
            check=True,
        ).stdout
        packages = self._ota_package_list()
        recorded = self.read_ota_package_record()
        if recorded is not None:
            # With a first-run record, "restored" means each package
            # is back in its recorded state (a package that was
            # disabled before provisioning stays disabled).
            installed, _ = self.package_sets()
            mismatched = []
            for package in packages:
                state = recorded.get(package, "enabled")
                if state == "absent":
                    if package in installed:
                        mismatched.append(package)
                elif (f"package:{package}" in disabled) != (
                    state == "disabled"
                ):
                    mismatched.append(package)
            if mismatched:
                raise ProvisionError(
                    "OTA packages do not match their recorded states: "
                    + ", ".join(mismatched)
                )
            print("OTA_RESTORE_OK packages=recorded override=restored")
            return
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

    def verify_ota_block(
        self, wait_seconds: int = 30, via_channel: bool = False
    ) -> None:
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

        aloha = bool(self.target and self.target.device == "aloha")
        if aloha and via_channel and self._recorded_posture_ota_trusted(
            self._start_state
        ):
            # Channel-path verification on a posture device (C3-A):
            # the config dump reads unconfigured BY DESIGN in the
            # posture (otad's settings and the override sit inert
            # behind the disabled alohausers package), so the dump
            # loop below can never pass and must not be re-derived
            # here. Verify the posture criteria directly instead -
            # the same four checks the C3-B posture judgment uses.
            # A device that left the posture fails these and falls
            # back to the full dump verification.
            posture_ok = self._judge_ota_posture()
            if posture_ok:
                print(
                    "OTA_POSTURE_OK packages=disabled "
                    "alohausers=disabled nodemon=true override=present",
                    flush=True,
                )
                return
            print(
                "OTA_POSTURE_CHECK_FAILED; falling back to the "
                "config-dump verification",
                flush=True,
            )
        if aloha:
            # A false gate in the service dump alone does not establish
            # that the block is in effect on Aloha: the native OTA
            # client reads the override only through the platform
            # MobileConfig backend, and that path is selected by this
            # property. If it is not set, the native client is known
            # not to be reading the override.
            backend = self.adb_run(
                ["shell", "getprop", OTA_BACKEND_PROPERTY], timeout=5
            ).stdout.strip()
            if backend != "true":
                raise ProvisionError(
                    f"OTA backend property {OTA_BACKEND_PROPERTY} is "
                    f"{backend!r}, not 'true': the native OTA client is "
                    "not using the platform MobileConfig backend, so "
                    "the local override is not in effect for it"
                )

        deadline = time.monotonic() + wait_seconds
        last_dump = ""
        last_log = ""
        gate_false = False
        while time.monotonic() < deadline:
            config, last_dump = self.read_ota_config(wait_seconds=0)
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
            gate_now, polling_off = self.ota_override_applied(config)
            if gate_now:
                gate_false = True
                if polling_off and (override_loaded or not aloha):
                    print(
                        "OTA_BLOCK_OK packages=disabled "
                        "firmware_ota_update_enable=false "
                        f"poll_interval_minutes={OTA_POLL_INTERVAL_MINUTES} "
                        f"update_url={OTA_JSON_URL} source="
                        + ("OVERRIDE" if override_loaded else "effective-config")
                    )
                    return
            time.sleep(2)
        if aloha and gate_false:
            # The gate reads false and the platform backend is
            # selected, but no client was observed reading the gate
            # from the override, so effectiveness is not positively
            # established. Report the action as unverified rather
            # than claiming the block is in place.
            self.ota_unverified = True
            print(
                "OTA_BLOCK_UNVERIFIED packages=disabled "
                "firmware_ota_update_enable=false backend=platform "
                "provenance=absent: the override was not observed "
                "being read as an override, so the OTA block is "
                "recorded as unverified, not applied"
            )
            return
        raise ProvisionError(
            "OTA daemon did not report its firmware-update gate and polling "
            "interval from the local override; recent dump/log follow:\n"
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
            # newline="": the file is parsed on the device, and a
            # Windows host's default text mode would write CRLF.
            local.write_text(contents, encoding="utf-8", newline="")
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
        # whose next step actually is a reboot, or whose verification
        # must observe the settled state: the channel component
        # execution settles there because the payload settles after
        # the same jar run before its state is read back.
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
    ) -> str:
        outcome = self.presence_feature.verify_presence_runtime(
            require_profile, expected_analysis_fps, wait_seconds
        )
        if outcome == "deferred":
            self.presence_deferred = True
        return outcome

    def verify_presence_runtime_channel(
        self,
        expected_analysis_fps: int | None = None,
        require_marker: bool = True,
        wait_seconds: int = 90,
    ) -> str:
        outcome = self.presence_feature.verify_presence_runtime_channel(
            expected_analysis_fps, require_marker, wait_seconds
        )
        if outcome == "deferred":
            self.presence_deferred = True
        return outcome

    def verify_meta_accounts_removed(self) -> None:
        return self.settings_feature.verify_meta_accounts_removed()

    def verify_requested_state(self, via_channel: bool = False) -> None:
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
            self._wireless_adb_verified = True
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
            if via_channel:
                # The channel apply verifies on the device's current
                # boot, however old: verify_watchdog()'s logcat probe
                # rotates away on long uptimes, so the channel verifies
                # audio with the one durable + live verdict the
                # eligibility gate used (audio_health).
                if not self.audio_channel_preflight():
                    raise ProvisionError(
                        "audio did not verify after the channel apply"
                    )
            else:
                self.verify_watchdog()
        if self.restore_audio:
            self.verify_audio_restored()
        if self.disable_updates:
            self.disable_ota_packages(record_original=False)
            self.verify_ota_block(via_channel=via_channel)
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
            if via_channel:
                # The channel verifies on the finished autoroot
                # state, where the install-phase startup check
                # (standalone helper present, server as shell) is
                # unsatisfiable by design; use the end-state check.
                self.verify_shizuku_channel()
            else:
                self.verify_shizuku()
        if self.remove_shizuku:
            self.verify_shizuku_removed()
        if (
            self.optimize_presence
            or self.presence_fps_cap is not None
            or self.restore_presence_fps
        ):
            if via_channel:
                # The race verify proves the profile from logcat
                # lines emitted at config-load/activation time,
                # which rotate away on the current boot; the
                # channel verifies durable markers + the live
                # pipeline subset instead.
                self.verify_presence_runtime_channel(
                    expected_analysis_fps=self.presence_fps_cap,
                    require_marker=bool(
                        self.optimize_presence
                        or self.presence_fps_cap is not None
                    ),
                )
            else:
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
        self._finalize_dns_state()
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
        if self.restore_wireless_adb:
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
            if persistent_port == "5555":
                raise ProvisionError(
                    "wireless ADB persistence is still set: "
                    f"{property_name}=5555"
                )
            for path in (
                WIRELESS_ADB_INSTALLED_REMOTE,
                self.uid1000_path("wireless-adb-enabled"),
                self.uid1000_path("adb-framework-enabled"),
            ):
                if self.adb_run(
                    ["shell", "test", "-e", path], timeout=5
                ).returncode == 0:
                    raise ProvisionError(
                        f"wireless ADB restore left {path} in place"
                    )
            print(
                "WIRELESS_ADB_RESTORE_OK "
                f"property={property_name} value=unset"
            )
        if self.restore_theme:
            self.verify_system_theme_restored()
            if self.adb_run(
                [
                    "shell", "test", "-e",
                    self.uid1000_path("system-theme-control-enabled"),
                ],
                timeout=5,
            ).returncode == 0:
                raise ProvisionError(
                    "UID-1000 system theme control marker remains"
                )
            print("SYSTEM_THEME_RESTORE_VERIFIED")
        if self.restore_meta_authenticators:
            disabled = self.disabled_meta_authenticators()
            still_disabled = set(META_AUTHENTICATOR_COMPONENTS) & disabled
            if still_disabled:
                raise ProvisionError(
                    "Meta authenticators remain disabled: "
                    + ", ".join(sorted(still_disabled))
                )
            print("META_AUTHENTICATORS_RESTORE_OK authenticators=restored")
        if self.restore_autoroot:
            installed, _ = self.package_sets()
            if AUTOROOT_HELPER_PACKAGE in installed:
                raise ProvisionError("autoroot helper is still installed")
            if self.adb_run(
                ["shell", "test", "-f", f"{AUTOROOT_REMOTE_DIR}/run.sh"],
                timeout=5,
            ).returncode == 0:
                raise ProvisionError("autoroot staging is still in place")
            print("AUTOROOT_RESTORE_VERIFIED helper=absent staging=absent")

    def verify_camera_light_disabled(self, wait_seconds: int = 35) -> None:
        return self.presence_feature.verify_camera_light_disabled(wait_seconds)

    def verify_camera_light_restored(self) -> None:
        return self.presence_feature.verify_camera_light_restored()

    def record_system_theme_original(self) -> None:
        return self.presence_feature.record_system_theme_original()

    def restore_system_theme(self) -> None:
        return self.presence_feature.restore_system_theme()

    def verify_system_theme_restored(self) -> None:
        return self.presence_feature.verify_system_theme_restored()

    def unstage_autoroot(self) -> None:
        return self.payload_feature.unstage_autoroot()

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
        # The boots this run itself established: later writes of
        # this run (a combined run's payload terminal write, the
        # OTA manifest corrections) record these, never a stale
        # snapshot's verification block (Defect K).
        self._verified_boots = (first_boot, second_boot)
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
                self.wait_for_race_boot_window(attempt)
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
                    self.refresh_shizuku_key_marker()
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
                if self.configure_ota_backend_phase():
                    if self.requested_actions() in (
                        {"disable_updates": True},
                        {"enable_updates": True},
                    ):
                        # The backend phase verified the same
                        # requested state on its own boots and wrote
                        # the final manifest.
                        self.report_deferred_failures()
                        return
                    post_attempt_boot = self.adb_run(
                        [
                            "shell",
                            "cat",
                            "/proc/sys/kernel/random/boot_id",
                        ],
                        timeout=5,
                        check=True,
                    ).stdout.strip()
                if self.remove_shizuku:
                    self.uninstall_shizuku_payload()
                if self.restore_autoroot:
                    self.unstage_autoroot()
                if self.presence_fps_action_requested():
                    self.uninstall_presence_helper()
                if (
                    self.restore_camera_light
                    or self.restore_presence_fps
                    or self.restore_presence_profile
                    or self.restore_theme
                    or self.restore_wireless_adb
                ):
                    self.restore_uid1000_package_state_if_unused()
                self.verify_across_two_reboots(first_boot=post_attempt_boot)
                self.report_deferred_failures()
                return
        finally:
            if self.exploit_users_created:
                self.cleanup_exploit_users(best_effort=True)
            if use_exploit_sentinel and not sentinel_removed:
                if self.autoroot_staged():
                    print(
                        "EXPLOIT_SENTINEL_RETAINED reason=autoroot",
                        flush=True,
                    )
                else:
                    self.uninstall_exploit_sentinel(best_effort=True)
            if self.uid1000_runtime_package_installed:
                self.uninstall_uid1000_runtime_payload(best_effort=True)
        raise ProvisionError(f"provisioning failed after {self.attempts} attempts")

    def _connected_via_wireless_adb(self) -> bool:
        """Whether this run's adb connection is the device's
        wireless ADB endpoint: a host:port serial on the persisted
        wireless port. A USB serial never carries a port, so it
        never matches — over USB the host survives the restore's
        reboot because USB ADB does not depend on the persisted
        wireless port."""
        host, sep, port = self.serial.rpartition(":")
        return bool(sep and host) and port == WIRELESS_ADB_PORT

    def _refuse_wireless_adb_restore_on_wireless(self) -> None:
        """Defect L: the wireless-ADB restore removes the very
        transport a wireless run is connected through. Closure
        session 16, Nov 19, 2026: the restore executed fully
        on-device, the post-attempt reboot brought the unit up
        with wireless ADB gone, and the host-side verify could
        never run — the run failed waiting for ADB and left the
        autoroot guard flag set. Host verification and run
        completion both require the transport the restore
        removes, so the combination is refused before any state
        change. Callers: provision() before the guard engages
        (covers every CLI-requested run — the no-op gate, the
        channel gate, the subset exits and the stages all sit
        downstream in _provision_stages) and _provision_stages
        itself after --recover adopts the restore from a pending
        manifest's recorded actions."""
        if not self.restore_wireless_adb:
            return
        if not self._connected_via_wireless_adb():
            return
        print(
            "PROVISION_REFUSED "
            "reason=wireless-adb-restore-over-wireless "
            f"serial={self.serial}",
            flush=True,
        )
        raise ProvisionError(
            "refusing to restore wireless ADB over the wireless "
            "ADB connection itself: the restore clears the "
            "persisted wireless ADB port, so the reboot that "
            "follows strands this run mid-flight (the restore "
            "would complete on-device but could not be verified "
            "or recorded). Connect the Portal by USB and re-run "
            "the same command."
        )

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
        if self.collect_diagnostics:
            # Read-only path that works on any build, supported or
            # not: verify_target only reports here, nothing is staged
            # or rebooted, so the autoroot guard does not engage.
            self.verify_target(require_supported=False)
            self.collect_diagnostics_bundle()
            return
        # Before the guard engages and before _provision_stages
        # can stage, race, or route anywhere: a run that would
        # remove its own transport is refused outright (Defect L).
        self._refuse_wireless_adb_restore_on_wireless()
        self._engage_autoroot_guard()
        try:
            self._provision_stages()
        except BaseException:
            # The run is already failing; still enforce the sentinel
            # exit guarantee, but never let its own failure mask the
            # original error — report it in the log instead.
            try:
                self._ensure_sentinel_for_staged_autoroot()
            except Exception as exc:
                print(
                    "EXPLOIT_SENTINEL_RESTAGE_FAILED "
                    f"error={exc}; staged autoroot cannot win "
                    "until the sentinel is reinstalled",
                    flush=True,
                )
            self._release_autoroot_guard(succeeded=False)
            raise
        try:
            self._ensure_sentinel_for_staged_autoroot()
        except BaseException:
            self._release_autoroot_guard(succeeded=False)
            raise
        self._release_autoroot_guard(succeeded=True)

    def _provision_stages(self) -> None:
        # While a custom payload phase is part of this invocation,
        # deferred-failure reports re-judge but do not raise; the
        # payload branch clears this and makes the final report.
        self._payload_phase_pending = self.custom_payload is not None
        self._capture_start_state()
        resumed_pending = False
        if self.recover:
            self.verify_target(require_supported=False)
            if not self.recover_actions():
                return
            self.recover = False
            resumed_pending = True
        # --recover may have adopted the wireless-ADB restore
        # from the pending manifest's recorded actions, after
        # provision()'s up-front refusal already passed; the
        # same refusal applies here, before any phase can stage
        # or execute it (Defect L). On this path the guard is
        # engaged, and raising returns through provision()'s
        # guard release while the device is still reachable, so
        # no flag is left behind either.
        self._refuse_wireless_adb_restore_on_wireless()
        if self.dry_run:
            self.verify_target(require_supported=False)
            status = self.print_status()
            self.dry_run_report(status)
            if self.backup_path:
                self.create_backup_bundle(self.backup_path)
            return
        self.verify_target()
        if self.bundle is not None:
            # Verify and install the prebuilt bundle before any fast
            # path, build-environment check or artifact read: in
            # bundle mode there is no Android toolchain on the host,
            # and a bundle that does not match this device must
            # refuse the run before anything changes.
            self._activate_prebuilt_bundle()
        # Observe the alohausers package state before any phase of
        # this run can change it: the desired-state recording rule
        # (C3-A) keys off the state the run STARTED from.
        self._observe_start_package_state()
        self.adb_framework_boot_configured = (
            self.adb_framework_boot_preflight()
        )
        if (
            not self.force
            and not resumed_pending
            and _autoroot_guard_depth == 1
            and self._run_fast_path()
        ):
            return
        if self.system_theme_control is not None:
            # Record the pre-change value before any apply can
            # overwrite it (restore-completeness gap 5); first
            # record wins, so this is a no-op on later runs.
            self.record_system_theme_original()
            self.system_theme_control_already_configured = (
                self.system_theme_control_preflight()
            )
            if (
                self.system_theme_control_already_configured
                and self.requested_actions()
                == {"system_theme_control": self.system_theme_control}
            ):
                # Subset completion writes in this method merge
                # into the start manifest (write_state's
                # merge_prior, as the channel path's does): the
                # run applied only its own action and must not
                # shrink the record earlier runs established.
                self.write_state("complete", merge_prior=True)
                print(
                    "PROVISION_OK reboots=0 "
                    f"system_theme={self.system_theme_control} logs={self.log_dir}"
                )
                return
        if self.privileged_requested() and not self.skip_build:
            android_build_environment(
                self.target, require_simpleperf=self.autoroot
            )
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
                self.write_state("complete", merge_prior=True)
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
            and not self.restore_wireless_adb
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
                bundle=self.bundle,
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
                bundle=self.bundle,
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
                    bundle=self.bundle,
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
                self.write_state("complete", merge_prior=True)
            print(f"PROVISION_ALREADY_COMPLETE actions=audio logs={self.log_dir}")
            self.report_deferred_failures()
            return
        self.write_state("pending")
        if (
            self.disable_updates
            and self.ota_backend_value is None
            and self.target
            and self.target.device == "aloha"
        ):
            self.prepare_ota_backend_backup()
        self.ota_already_configured = (
            self.ota_preflight() if self.disable_updates else False
        )
        self.sync_ota_nodemon_autoroot_conf()
        self.sync_drift_conf_keys()
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
                bootstrap = PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    disable_updates=True,
                    skip_build=self.skip_build,
                    bundle=self.bundle,
                )
                bootstrap.provision()
                if bootstrap.ota_nodemon_set_this_run:
                    self.ota_nodemon_set_this_run = True
                self.connect(wait_seconds=30)
                self.verify_target()
                self.ota_already_configured = self.ota_preflight()
                if not self.ota_already_configured:
                    # The nested run returned normally, so its
                    # install action completed — and that action
                    # verifies the override file's exact contents
                    # as its last step. The posture judgment uses
                    # this as its override-presence evidence when
                    # no root channel can stat the app-private
                    # file (see _ota_override_present).
                    self._ota_install_verified_this_run = True
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
                self.write_state("complete", merge_prior=True)
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
                        bundle=self.bundle,
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
                        bundle=self.bundle,
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
                    bundle=self.bundle,
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
                    bundle=self.bundle,
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
                self.write_state("complete", merge_prior=True)
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
                    bundle=self.bundle,
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
                self.write_state("complete", merge_prior=True)
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
                    bundle=self.bundle,
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
                self.write_state("complete", merge_prior=True)
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
                    bundle=self.bundle,
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
            self.write_state("complete", merge_prior=True)
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
                    bundle=self.bundle,
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
        self._apply_shell_level_state(
            debloat_configured=self.debloat_already_configured,
            remote_wipe_configured=self.remote_wipe_already_configured,
            defer_dns=True,
        )

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
            or self.restore_autoroot
            or self.restore_wireless_adb
            or self.restore_meta_authenticators
            or self.restore_theme_uid1000_action_requested()
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
                "restore_theme",
            }:
                self.verify_requested_state()
                self.write_state("complete", merge_prior=True)
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
                # The payload path ends without verify_requested_
                # state(), so the deferred DNS apply and the
                # recorded-state invariant take their post-race
                # position here instead.
                self._finalize_dns_state()
            finally:
                if use_exploit_sentinel and not self.autoroot_staged():
                    self.uninstall_exploit_sentinel(best_effort=True)
                    sentinel_removed = True
                elif use_exploit_sentinel:
                    print(
                        "EXPLOIT_SENTINEL_RETAINED reason=autoroot",
                        flush=True,
                    )
            # The payload-only path used to return here without
            # ever reporting deferred bootstrap failures, silently
            # dropping them; the combined path's mid-run report
            # could only defer its raise to this point. Either way
            # this is the judgment that ends the run.
            self._payload_phase_pending = False
            self.report_deferred_failures()
            return
        self.run_standard_install(use_exploit_sentinel)


def keystore_certificate_sha256(keystore: pathlib.Path) -> str:
    """Return the SHA-256 fingerprint of a keystore's signing certificate."""
    result = subprocess.run(
        [
            "keytool",
            "-list",
            "-v",
            "-keystore",
            str(keystore),
            "-storepass",
            "android",
            "-alias",
            "androiddebugkey",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"SHA256:\s*([0-9A-Fa-f:]+)", result.stdout)
    if result.returncode != 0 or match is None:
        raise ProvisionError(
            f"could not read the signing certificate of {keystore} with "
            "keytool; refusing to build with an unverified signing key"
        )
    return match.group(1).upper()


def ndk_host_tag(platform: str | None = None) -> str:
    """The NDK prebuilt toolchain directory tag for a host platform.

    The NDK ships linux-x86_64, darwin-x86_64 and windows-x86_64
    prebuilts; the tag is part of every toolchain path, so a hardcoded
    linux tag made the build report its compilers missing on macOS
    and Windows hosts."""
    platform = sys.platform if platform is None else platform
    if platform == "darwin":
        return "darwin-x86_64"
    if platform.startswith("win") or platform in ("msys", "cygwin"):
        return "windows-x86_64"
    return "linux-x86_64"


def build_tools_filename(name: str, platform: str | None = None) -> str:
    """An Android SDK build-tools program name for a host platform.

    Windows ships the native tools as .exe and the Java-based tools
    (apksigner, d8) as .bat shims; POSIX hosts use the bare names."""
    platform = sys.platform if platform is None else platform
    if platform.startswith("win"):
        return name + (".bat" if name in ("apksigner", "d8") else ".exe")
    return name


def default_sdk_candidates() -> tuple[pathlib.Path, ...]:
    """Per-user Android SDK locations probed when no env var names one.

    Includes the standard Android Studio locations for each host
    platform (~/Library/Android/sdk on macOS, %LOCALAPPDATA% on
    Windows), not only the Linux ones."""
    home = pathlib.Path.home()
    candidates = [
        home / "Android/Sdk",
        home / "Android/sdk",
        home / "android-sdk",
    ]
    if sys.platform == "darwin":
        candidates.append(home / "Library/Android/sdk")
    elif sys.platform.startswith("win"):
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(pathlib.Path(local_app_data) / "Android/Sdk")
    return tuple(candidates)


def android_build_environment(
    target: PortalTarget | None = None,
    *,
    require_simpleperf: bool = False,
) -> dict[str, str]:
    """Resolve and validate the per-user Android toolchain."""
    if sys.platform == "win32":
        # The build drives GNU make and POSIX shell recipes, which a
        # native Windows Python cannot run. Gate honestly instead of
        # failing at the first make invocation: the prebuilt bundle
        # needs only Python + adb, and WSL2 provides a Linux
        # environment where the source build works unchanged.
        raise ProvisionError(
            "source builds are not supported under native Windows "
            "Python: the build requires GNU make and a POSIX shell. "
            "Use a prebuilt release bundle (Python + adb only), or run "
            "the source build inside WSL2."
        )
    environment = dict(os.environ)

    sdk_value = environment.get("ANDROID_SDK_ROOT") or environment.get(
        "ANDROID_HOME"
    )
    if sdk_value:
        sdk = pathlib.Path(sdk_value).expanduser()
    else:
        sdk_candidates = default_sdk_candidates()
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
    d8 = pathlib.Path(
        environment.get("D8", str(build_tools / build_tools_filename("d8")))
    ).expanduser()
    toolchain_bin = ndk / "toolchains/llvm/prebuilt" / ndk_host_tag() / "bin"

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
        "Android Build Tools aapt": build_tools / build_tools_filename("aapt"),
        "Android Build Tools apksigner": build_tools
        / build_tools_filename("apksigner"),
        "Android Build Tools zipalign": build_tools
        / build_tools_filename("zipalign"),
        "Android Build Tools d8": d8,
    }
    if target and (target.bundled_simpleperf or require_simpleperf):
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

    keystore_value = environment.get("KEYSTORE")
    if keystore_value:
        keystore = pathlib.Path(keystore_value).expanduser()
    elif PROJECT_DEBUG_KEYSTORE.is_file():
        keystore = PROJECT_DEBUG_KEYSTORE
    else:
        keystore = pathlib.Path.home() / ".android" / "debug.keystore"
    if not keystore.is_file():
        raise ProvisionError(
            f"Android debug keystore not found: {keystore}. The build "
            "signs every helper APK with the project debug key and never "
            "generates a replacement: a fresh key would be refused as an "
            "update by every already-provisioned device. Restore the "
            "committed debug.keystore or point KEYSTORE at it."
        )
    keystore_fingerprint = keystore_certificate_sha256(keystore)
    if keystore_fingerprint != PROJECT_DEBUG_KEYSTORE_SHA256:
        raise ProvisionError(
            f"Android debug keystore fingerprint mismatch: {keystore} "
            f"has SHA-256 {keystore_fingerprint}, but this build must "
            f"sign with the project debug key "
            f"{PROJECT_DEBUG_KEYSTORE_SHA256}. Refusing to build: APKs "
            "signed with a different key are rejected as updates by "
            "already-provisioned devices."
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
            "KEYSTORE": str(keystore),
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
    environment = android_build_environment(
        target, require_simpleperf=build_autoroot
    )
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
