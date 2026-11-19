# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mikhail
"""Presence / system-theme / camera-light feature cluster.

Extracted from provision_portal.py in the M3.3 monolith-split phase.
Mechanical move only: markers, formats, flags, and device-operation
sequences are frozen. Cross-cluster seams (adb transport, package
verifier, uid1000 paths, logcat helpers) are late-bound callables
supplied by PortalProvisioner so test patching of the provisioner's
own attributes keeps intercepting exactly as before.
PresenceFeature owns the theme-control bookkeeping state
(system_theme_control_log_count_before /
system_theme_control_runtime_verified) and presence_public_key,
which only this cluster reads or writes.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import re
import subprocess
import tempfile
import time
from typing import Callable

from device_session import ProvisionError
from portal_targets import PortalTarget

ROOT = pathlib.Path(__file__).resolve().parents[2]

PRESENCE_HELPER_PACKAGE = "dev.portal.presencehelper"
PRESENCE_HELPER_LOCAL = ROOT / "presence-helper/build/portal-presence-helper.apk"
PRESENCE_KEY_REMOTE = "/data/local/tmp/portal-presence-adbkey.pub"
PRESENCE_SAVED_KEY_REMOTE = "/data/local/tmp/portal-presence-adbkey-v1.pub"
PRESENCE_PROFILE_SETTINGS = {
    "enable_cv_background_detector_v2": False,
    "enable_hardware_cropping": False,
    "enable_liveness_metric": False,
    "enable_color_based_reid": False,
    "enable_face_rec_based_reid_v3": False,
}
PRESENCE_PROFILE_KEYS = tuple(PRESENCE_PROFILE_SETTINGS)
PRESENCE_LOG_MARKER = "Notify people presence"
PRESENCE_ANALYSIS_FRAME_MARKER = "Frame available for analysis stream"
PRESENCE_ROI_FRAME_MARKER = "Frame available for roi stream"
PRESENCE_WIDE_FRAME_MARKER = "Disabled hardware cropping"
PRESENCE_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-presence-backup/installed-v1"
)
PRESENCE_LOGCAT_REGEX = (
    "settings_config.xml\\|"
    "Frame.available.for.analysis.stream\\|"
    "Frame.available.for.roi.stream\\|"
    "Disabled.hardware.cropping\\|"
    "Notify.people.presence\\|"
    "Setting.AI.Processing.FPS\\|presence.FPS.activation\\|"
    "CAMERA_SERVICE.not.running\\|privacy.mode"
)
CAMERA_SERVICE_COMPONENT = (
    "com.facebook.portal.aiservice/"
    "com.facebook.alohaapp.app.services.CameraService"
)
CAMERA_LIGHT_HELPER_REMOTE = "/data/local/tmp/portal-camera-led-watch"
CAMERA_LIGHT_HOOK_REMOTE = "/data/local/tmp/portal-uid1000-hook.bin"
CAMERA_LIGHT_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-camera-light-backup/installed-v1"
)
CAMERA_LIGHT_RESTORED_REMOTE = (
    "/data/local/tmp/portal-camera-light-backup/restored-v1"
)
SYSTEM_THEME_PROPERTY = "debug.portal.system_theme"
SYSTEM_THEME_SETTING = "ui_night_mode"
SYSTEM_THEME_CONTROL_MARKER = "system-theme-control-enabled"
SYSTEM_THEME_BACKUP_REMOTE = "/data/local/tmp/portal-system-theme-before-v1.json"
# ui_night_mode value -> `cmd uimode night` argument / manager state.
UIMODE_NIGHT_BY_SETTING_VALUE = {"0": "auto", "1": "no", "2": "yes"}
# The manager state an ABSENT ui_night_mode key represents: at
# boot, with no key, UiModeManager falls back to night off.
UIMODE_ABSENT_KEY_MANAGER_STATE = "no"


@dataclasses.dataclass(frozen=True)
class PresenceConfig:
    """Provisioner flags this cluster slices (built fresh per access)."""

    system_theme_control: str | None
    presence_fps_cap: int | None


def loaded_profile_keys(logs: str) -> set[str]:
    """Presence profile keys whose settings_config.xml load lines
    (carrying the expected values) appear in a logcat dump."""
    return {
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
    }


def presence_full_scene_active(
    logs: str, camera: str, target: PortalTarget | None
) -> bool:
    active_request = camera.split("Tag monitoring disabled", 1)[0]
    full_sensor_frame = (
        "com.facebook.alohasdk.dewarp_crop_rect.width"
        not in active_request
    )
    if target and target.presence_full_sensor_width:
        crop_values: dict[str, float] = {}
        for coordinate in ("x_start", "y_start", "width"):
            match = re.search(
                rf"dewarp_crop_rect\.{coordinate}[^\n]*\n\s*"
                r"\[([0-9.]+)",
                active_request,
            )
            if match:
                crop_values[coordinate] = float(match.group(1))
        full_sensor_frame = (
            crop_values.get("x_start") == 0.0
            and crop_values.get("y_start") == 0.0
            and crop_values.get("width", 0.0)
            >= target.presence_full_sensor_width
        )
    return PRESENCE_WIDE_FRAME_MARKER in logs and full_sensor_frame


class PresenceFeature:
    """Presence helper, system-theme control, and camera-light ops."""

    def __init__(
        self,
        *,
        config: Callable[[], PresenceConfig],
        adb_run: Callable[..., "subprocess.CompletedProcess[str]"],
        run: Callable[..., "subprocess.CompletedProcess[str]"],
        target: Callable[[], "PortalTarget | None"],
        log_dir: Callable[[], pathlib.Path],
        uid1000_path: Callable[[str], str],
        install_apk_preserving_verifier: Callable[..., None],
        verify_package_verifier_state: Callable[..., None],
        settle_package_state: Callable[..., None],
        push_text_atomic: Callable[[str, str], None],
        package_sets: Callable[[], "tuple[set[str], set[str]]"],
        logcat_watermark: Callable[..., object],
        logcat_poll: Callable[..., str],
        adb_framework_boot_installed_remote: str,
    ):
        self._config_factory = config
        self._adb_run = adb_run
        self._run = run
        self._target = target
        self._log_dir = log_dir
        self._uid1000_path = uid1000_path
        self._install_apk_preserving_verifier = install_apk_preserving_verifier
        self._verify_package_verifier_state = verify_package_verifier_state
        self._settle_package_state = settle_package_state
        self._push_text_atomic = push_text_atomic
        self._package_sets = package_sets
        self._logcat_watermark = logcat_watermark
        self._logcat_poll = logcat_poll
        self._adb_framework_boot_installed_remote = (
            adb_framework_boot_installed_remote
        )
        self.system_theme_control_runtime_verified = False
        self.system_theme_control_log_count_before = 0
        self.presence_public_key: pathlib.Path | None = None
        # Outcome of the most recent presence runtime verification:
        # True only when it deferred (lens cover closed, durable
        # state verified, streaming unverified). Reset by every
        # verify call; read by the preflights and, through them,
        # the provisioner's own presence_deferred flag.
        self.presence_verify_deferred = False

    @property
    def _config(self) -> PresenceConfig:
        # Late-bound: built fresh from the provisioner's current flag
        # attributes on every access (see features/settings.py).
        return self._config_factory()


    def _shell_uimode_transport(self) -> bool:
        """True where the theme end state is driven through
        `cmd uimode` — every target except the UID-1000 ones,
        matching the transport choice in apply_system_theme_request."""
        target = self._target()
        return not (target and target.system_theme_uid1000_required)

    def _read_uimode_night_state(self) -> str | None:
        """The manager-side night state from `cmd uimode night`:
        "yes" / "no" / "auto", or None when unreadable."""
        result = self._adb_run(
            ["shell", "cmd", "uimode", "night"], timeout=5
        )
        match = re.search(
            r"Night mode:\s*(yes|no|auto)", result.stdout or ""
        )
        return match.group(1) if match else None

    def _set_uimode_night(self, night_arg: str, expected_key: str) -> None:
        """Drive UiModeManager to night_arg through `cmd uimode`
        so the manager state and the ui_night_mode key land
        together (the transport writes the key itself). A
        same-state `cmd uimode night` call is a no-op that never
        rewrites the key, so when the manager already reports
        the target state but the key disagrees, transition
        through the opposite state first to force a real one."""
        if (
            self._read_uimode_night_state() == night_arg
            and self._read_system_theme_setting() != expected_key
        ):
            intermediate = "yes" if night_arg == "no" else "no"
            self._adb_run(
                ["shell", "cmd", "uimode", "night", intermediate],
                timeout=10,
                check=True,
            )
        self._adb_run(
            ["shell", "cmd", "uimode", "night", night_arg],
            timeout=10,
            check=True,
        )

    def apply_system_theme_request(self) -> None:
        if self._config.system_theme_control not in {"light", "dark"}:
            raise ProvisionError("system theme must be light or dark")
        if self._target() and self._target().system_theme_uid1000_required:
            expected_log = (
                "system theme request "
                f"mode={self._config.system_theme_control} uid=1000 status=0"
            )
            prior_logs = self._adb_run(
                ["shell", "logcat", "-d", "-s", "PortalSystemTheme:*"],
                timeout=10,
            ).stdout
            self.system_theme_control_log_count_before = prior_logs.count(
                expected_log
            )
            self._adb_run(
                ["shell", "setprop", SYSTEM_THEME_PROPERTY, "none"],
                timeout=5,
                check=True,
            )
            # Ensure the 250 ms worker observes an ignored edge even when the
            # requested value is the same as its preceding request.
            time.sleep(1)
            self._adb_run(
                [
                    "shell",
                    "setprop",
                    SYSTEM_THEME_PROPERTY,
                    self._config.system_theme_control,
                ],
                timeout=5,
                check=True,
            )
            transport = "uid1000-property"
        else:
            night_mode = "yes" if self._config.system_theme_control == "dark" else "no"
            expected_key = "2" if self._config.system_theme_control == "dark" else "1"
            self._set_uimode_night(night_mode, expected_key)
            transport = "shell-uimode"
        print(
            "SYSTEM_THEME_REQUEST "
            f"mode={self._config.system_theme_control} transport={transport}",
            flush=True,
        )

    def verify_system_theme_control(self, wait_seconds: int = 20) -> None:
        if self._config.system_theme_control not in {"light", "dark"}:
            raise ProvisionError("system theme must be light or dark")
        uid1000_required = bool(
            self._target() and self._target().system_theme_uid1000_required
        )
        if uid1000_required and self._adb_run(
            [
                "shell",
                "test",
                "-f",
                self._uid1000_path(SYSTEM_THEME_CONTROL_MARKER),
            ],
            timeout=5,
        ).returncode != 0:
            raise ProvisionError("UID-1000 system theme control is not installed")

        expected = "2" if self._config.system_theme_control == "dark" else "1"
        expected_manager = (
            "yes" if self._config.system_theme_control == "dark" else "no"
        )
        deadline = time.monotonic() + wait_seconds
        observed = ""
        manager = ""
        process = ""
        helper_log = ""
        while time.monotonic() < deadline:
            observed = self._adb_run(
                ["shell", "settings", "get", "secure", SYSTEM_THEME_SETTING],
                timeout=5,
            ).stdout.strip()
            if not uid1000_required:
                # The key alone is not proof on shell-uimode
                # targets: the manager state must agree, or the
                # pair is diverged and a later same-state apply
                # would no-op against it.
                manager = self._read_uimode_night_state() or ""
            if uid1000_required:
                processes = self._adb_run(
                    ["shell", "ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS"],
                    timeout=10,
                    check=True,
                ).stdout
                process = next(
                    (
                        line
                        for line in processes.splitlines()
                        if "portal-camera-led-watch" in line
                        or "portal-led-watc" in line
                    ),
                    "",
                )
                helper_log = self._adb_run(
                    ["shell", "logcat", "-d", "-s", "PortalSystemTheme:*"],
                    timeout=10,
                ).stdout
                expected_log = (
                    "system theme request "
                    f"mode={self._config.system_theme_control} uid=1000 status=0"
                )
                if helper_log.count(expected_log) > (
                    self.system_theme_control_log_count_before
                ):
                    self.system_theme_control_runtime_verified = True
            runtime_verified = (
                self.system_theme_control_runtime_verified
                or not uid1000_required
            )
            if (
                observed == expected
                and (manager == expected_manager or uid1000_required)
                and (process or not uid1000_required)
                and runtime_verified
            ):
                print(
                    "SYSTEM_THEME_CONTROL_OK "
                    f"mode={self._config.system_theme_control} "
                    f"transport={'uid1000' if uid1000_required else 'shell'}"
                )
                return
            time.sleep(1)
        detail = (
            f"expected={expected} observed={observed!r} process={process!r} "
            f"helper_log={helper_log[-1000:]!r}"
        )
        if not uid1000_required:
            detail += (
                f" manager={manager!r} "
                f"expected_manager={expected_manager!r}"
            )
            implied_manager = UIMODE_NIGHT_BY_SETTING_VALUE.get(
                observed, UIMODE_ABSENT_KEY_MANAGER_STATE
            )
            if implied_manager != manager:
                detail += (
                    " (ui_night_mode key and UiModeManager state "
                    "diverged)"
                )
        raise ProvisionError(
            f"system theme request did not apply: {detail}"
        )

    def system_theme_control_preflight(self) -> bool:
        if self._config.system_theme_control is None:
            return False
        uid1000_required = bool(
            self._target() and self._target().system_theme_uid1000_required
        )
        if uid1000_required and self._adb_run(
            [
                "shell",
                "test",
                "-f",
                self._uid1000_path(SYSTEM_THEME_CONTROL_MARKER),
            ],
            timeout=5,
        ).returncode != 0:
            print("SYSTEM_THEME_PREFLIGHT action=install control=absent")
            return False
        # This preflight APPLIES the theme as its probe, and the
        # channel gate calls it before the stages path reaches
        # its own record step — so the original must be recorded
        # here, at the apply point, or a channel-route first
        # apply overwrites it before anyone records it and the
        # recorded-original restore tier can never engage
        # (Defect E). First record wins, so on the stages path,
        # whose record step already ran, this is a no-op.
        self.record_system_theme_original()
        self.apply_system_theme_request()
        try:
            self.verify_system_theme_control(wait_seconds=10)
        except ProvisionError as exc:
            print(f"SYSTEM_THEME_PREFLIGHT action=install reason={exc}")
            return False
        print(
            "SYSTEM_THEME_PREFLIGHT action=skip "
            f"mode={self._config.system_theme_control} capability=ready"
        )
        return True

    def _read_system_theme_setting(self) -> str | None:
        value = self._adb_run(
            ["shell", "settings", "get", "secure", SYSTEM_THEME_SETTING],
            timeout=5,
        ).stdout.strip()
        return None if value in ("", "null") else value

    def record_system_theme_original(self) -> None:
        """First-run backup of ui_night_mode before the theme
        control overwrites it (restore-completeness gap 5). First
        record wins, like the DNS and ADB-timeout backups: a later
        apply must not overwrite the pre-provision value."""
        if self._adb_run(
            ["shell", "test", "-f", SYSTEM_THEME_BACKUP_REMOTE], timeout=5
        ).returncode == 0:
            print("SYSTEM_THEME_BACKUP_OK existing=1")
            return
        current = self._read_system_theme_setting()
        self._push_text_atomic(
            json.dumps({"ui_night_mode": current}) + "\n",
            SYSTEM_THEME_BACKUP_REMOTE,
        )
        print(
            "SYSTEM_THEME_BACKUP_OK existing=0 "
            f"value={current if current is not None else 'absent'}"
        )

    def _recorded_system_theme(self) -> tuple[bool, str | None]:
        """(record_exists, recorded value or None for absent)."""
        result = self._adb_run(
            ["shell", "cat", SYSTEM_THEME_BACKUP_REMOTE], timeout=5
        )
        if result.returncode != 0:
            return (False, None)
        try:
            parsed = json.loads(result.stdout)
            value = parsed["ui_night_mode"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ProvisionError(
                f"unrecognized system theme backup: {exc}"
            ) from exc
        return (True, value if isinstance(value, str) else None)

    def restore_system_theme(self) -> None:
        """Two-tier restore: replay the recorded ui_night_mode; with
        no record, return to the factory default — the key ABSENT
        (verified fleet-wide on stock devices), so delete it. On
        shell-uimode targets both tiers drive the end state
        through the uimode transport: writing or deleting the key
        alone never transitions UiModeManager, so the manager
        would stay wherever the last apply left it and the pair
        would verify on the key while diverged — and a later
        same-state apply then no-ops against that manager."""
        recorded, value = self._recorded_system_theme()
        if (
            value is not None
            and self._shell_uimode_transport()
            and value in UIMODE_NIGHT_BY_SETTING_VALUE
        ):
            # The transport writes the key itself as it drives
            # the manager to the recorded mode.
            self._set_uimode_night(
                UIMODE_NIGHT_BY_SETTING_VALUE[value], value
            )
            source = "recorded"
        elif value is not None:
            self._adb_run(
                [
                    "shell", "settings", "put", "secure",
                    SYSTEM_THEME_SETTING, value,
                ],
                timeout=5,
                check=True,
            )
            source = "recorded"
        else:
            if self._shell_uimode_transport() and (
                self._read_uimode_night_state()
                != UIMODE_ABSENT_KEY_MANAGER_STATE
            ):
                # Transition the manager to the state an absent
                # key represents (its boot-time default) BEFORE
                # deleting the key: the transport writes the key
                # as it transitions, and the delete then leaves
                # the pair in the stock shape — key absent,
                # manager at the default.
                self._adb_run(
                    [
                        "shell", "cmd", "uimode", "night",
                        UIMODE_ABSENT_KEY_MANAGER_STATE,
                    ],
                    timeout=10,
                    check=True,
                )
            self._adb_run(
                ["shell", "settings", "delete", "secure", SYSTEM_THEME_SETTING],
                timeout=5,
                check=True,
            )
            source = "recorded" if recorded else "factory-default"
        print(
            f"SYSTEM_THEME_RESTORE_OK source={source} "
            f"value={value if value is not None else 'absent'}"
        )

    def verify_system_theme_restored(self) -> None:
        _, value = self._recorded_system_theme()
        observed = self._read_system_theme_setting()
        if observed != value:
            raise ProvisionError(
                "system theme was not restored: "
                f"expected={value!r} observed={observed!r}"
            )
        if self._shell_uimode_transport():
            expected_manager = (
                UIMODE_ABSENT_KEY_MANAGER_STATE
                if value is None
                else UIMODE_NIGHT_BY_SETTING_VALUE.get(value)
            )
            if expected_manager is not None:
                manager = self._read_uimode_night_state()
                if manager != expected_manager:
                    raise ProvisionError(
                        "system theme restore left the "
                        "ui_night_mode key and UiModeManager state "
                        f"diverged: key={observed!r} "
                        f"manager={manager!r} "
                        f"expected_manager={expected_manager!r}"
                    )

    def presence_preflight(self) -> bool:
        marker_present = self._adb_run(
            ["shell", "test", "-f", PRESENCE_INSTALLED_REMOTE], timeout=5
        ).returncode == 0
        try:
            self.verify_presence_runtime(
                require_profile=not marker_present, wait_seconds=90
            )
        except ProvisionError as exc:
            print(f"PRESENCE_PREFLIGHT action=install reason={exc}")
            return False
        if self.presence_verify_deferred:
            print(
                "PRESENCE_PREFLIGHT action=skip profile=durable "
                "deferred=shutter_closed "
                f"verified_marker={int(marker_present)}"
            )
            return True
        print(
            "PRESENCE_PREFLIGHT action=skip profile=active "
            f"verified_marker={int(marker_present)}"
        )
        return True

    def presence_fps_preflight(self) -> bool:
        if self._config.presence_fps_cap is None:
            return False
        marker = self._adb_run(
            [
                "shell", "cat",
                "/data/local/tmp/portal-presence-backup/fps-cap-v1",
            ],
            timeout=5,
        )
        if (
            marker.returncode != 0
            or marker.stdout.strip() != str(self._config.presence_fps_cap)
        ):
            print(
                "PRESENCE_FPS_PREFLIGHT action=install "
                f"expected={self._config.presence_fps_cap} marker=absent-or-mismatched"
            )
            return False
        try:
            self.verify_presence_runtime(
                require_profile=True,
                expected_analysis_fps=self._config.presence_fps_cap,
                wait_seconds=90,
            )
        except ProvisionError as exc:
            print(f"PRESENCE_FPS_PREFLIGHT action=install reason={exc}")
            return False
        if self.presence_verify_deferred:
            print(
                "PRESENCE_FPS_PREFLIGHT action=skip "
                f"fps={self._config.presence_fps_cap} "
                "deferred=shutter_closed"
            )
            return True
        print(
            "PRESENCE_FPS_PREFLIGHT action=skip "
            f"fps={self._config.presence_fps_cap} activation=uid1000"
        )
        return True

    def prepare_presence_helper(self) -> None:
        self._install_apk_preserving_verifier(
            PRESENCE_HELPER_LOCAL, "presence-helper", PRESENCE_HELPER_PACKAGE
        )
        self._settle_package_state()
        self._verify_package_verifier_state()
        private_key = self._adb_run(
            ["exec-out", "run-as", PRESENCE_HELPER_PACKAGE, "cat", "files/adbkey"],
            timeout=10,
        ).stdout
        existing_public = self._adb_run(
            [
                "exec-out",
                "run-as",
                PRESENCE_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
        ).stdout.strip()
        key_exists = (
            "-----BEGIN PRIVATE KEY-----" in private_key
            and "-----END PRIVATE KEY-----" in private_key
            and re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", existing_public)
            is not None
        )
        if not key_exists:
            with tempfile.TemporaryDirectory(prefix="portal-presence-key-") as temp:
                key = pathlib.Path(temp) / "adbkey"
                self._run(["adb", "keygen", str(key)], timeout=30, check=True)
                for source, remote, destination in (
                    (key, "/data/local/tmp/portal-presence-key.tmp", "files/adbkey"),
                    (
                        pathlib.Path(str(key) + ".pub"),
                        "/data/local/tmp/portal-presence-key.pub.tmp",
                        "files/adbkey.pub",
                    ),
                ):
                    self._adb_run(["push", str(source), remote], timeout=15, check=True)
                    self._adb_run(["shell", "chmod", "0644", remote], timeout=5, check=True)
                    self._adb_run(
                        ["shell", "run-as", PRESENCE_HELPER_PACKAGE, "mkdir", "-p", "files"],
                        timeout=10,
                        check=True,
                    )
                    self._adb_run(
                        ["shell", "run-as", PRESENCE_HELPER_PACKAGE, "cp", remote, destination],
                        timeout=10,
                        check=True,
                    )
                    self._adb_run(
                        ["shell", "run-as", PRESENCE_HELPER_PACKAGE, "chmod", "0600", destination],
                        timeout=10,
                        check=True,
                    )
                    self._adb_run(["shell", "rm", "-f", remote], timeout=5)
        public = self._adb_run(
            [
                "exec-out",
                "run-as",
                PRESENCE_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
            check=True,
        ).stdout.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", public):
            raise ProvisionError("Portal presence helper returned an invalid ADB public key")
        self._log_dir().mkdir(parents=True, exist_ok=True)
        self.presence_public_key = self._log_dir() / "portal-presence-adbkey.pub"
        self.presence_public_key.write_text(public + "\n", encoding="ascii")
        self.presence_public_key.chmod(0o600)
        print(
            f"PRESENCE_HELPER_PAYLOAD_OK package={PRESENCE_HELPER_PACKAGE} "
            f"key_reused={int(key_exists)}"
        )

    def activate_presence_helper(self) -> None:
        if self._config.presence_fps_cap is None:
            raise ProvisionError("presence helper requires an FPS cap")
        result = self._adb_run(
            [
                "shell",
                "am",
                "broadcast",
                "--include-stopped-packages",
                "-a",
                "dev.portal.presencehelper.CONFIG",
                "-n",
                f"{PRESENCE_HELPER_PACKAGE}/.BootReceiver",
                "--ei",
                "fps",
                str(self._config.presence_fps_cap),
            ],
            timeout=20,
            check=True,
        )
        if "result=0" not in result.stdout:
            raise ProvisionError(
                "presence helper configuration broadcast failed: "
                + result.stdout.strip()
            )
        self._adb_run(
            [
                "shell",
                "am",
                "broadcast",
                "--include-stopped-packages",
                "-a",
                "dev.portal.presencehelper.START",
                "-n",
                f"{PRESENCE_HELPER_PACKAGE}/.BootReceiver",
            ],
            timeout=20,
            check=True,
        )
        print(
            f"PRESENCE_HELPER_OK package={PRESENCE_HELPER_PACKAGE} "
            f"fps={self._config.presence_fps_cap}"
        )

    def uninstall_presence_helper(self) -> None:
        installed, _ = self._package_sets()
        if PRESENCE_HELPER_PACKAGE not in installed:
            print("PRESENCE_HELPER_REMOVE already_absent=1")
            return
        result = self._adb_run(
            ["uninstall", PRESENCE_HELPER_PACKAGE], timeout=30
        )
        if result.returncode != 0 or "Success" not in result.stdout:
            raise ProvisionError(
                "failed to remove presence helper: " + result.stdout.strip()
            )
        print(f"PRESENCE_HELPER_REMOVE package={PRESENCE_HELPER_PACKAGE}")

    def compile_camera_light_host_speed(self) -> None:
        if self._target() is None:
            raise ProvisionError("target must be selected before preparing UID 1000")
        host_package = self._target().uid1000_host_package
        self._adb_run(
            ["shell", "am", "force-stop", "--user", "0", host_package],
            timeout=10,
        )
        result = self._adb_run(
            [
                "shell",
                "cmd",
                "package",
                "compile",
                "-f",
                "-m",
                "speed",
                host_package,
            ],
            timeout=120,
        )
        if result.returncode != 0 or "Success" not in result.stdout:
            raise ProvisionError(
                "could not generate the guarded UID-1000 host ART cache: "
                + result.stdout
            )
        print(
            f"CAMERA_LIGHT_ART_CACHE_OK host={self._target().uid1000_host_label} "
            "compiler_filter=speed"
        )

    def uid1000_boot_hook_active(self) -> bool:
        result = self._adb_run(
            ["shell", "ps", "-A", "-o", "USER,PID,ARGS"],
            timeout=10,
            check=True,
        )
        for line in result.stdout.splitlines():
            fields = line.split(maxsplit=2)
            if (
                fields
                and fields[0] == "system"
                and "portal-camera-led-watch" in line
            ):
                return True
        return False

    def prepare_camera_light_install(self) -> None:
        if self._target() is None:
            raise ProvisionError("target must be selected before preparing UID 1000")
        installed, _ = self._package_sets()
        host_package = self._target().uid1000_host_package
        if host_package not in installed:
            raise ProvisionError(
                f"required persistent system package is absent: {host_package}"
            )
        if (
            self.uid1000_boot_hook_active()
            and not self._target().uid1000_embedded_helper
        ):
            print(
                "UID1000_BOOT_HOOK_RETAINED source=running-system-helper",
                flush=True,
            )
            return
        self.compile_camera_light_host_speed()

    def _presence_fps_configured_path(self) -> str:
        return (
            "/data/local/tmp/portal-presence-backup/fps-cap-v1"
            if self._target() and self._target().uid1000_embedded_helper
            else self._uid1000_path("presence-fps")
        )

    def _presence_shutter_closed(self) -> bool:
        """The camera lens cover state, from the platform state
        service: shutter_state=1 is the covered state (the device's
        own analytics name it CAMERA_LENS_COVERED). The privacy-mode
        signals the live check samples do NOT track the cover. An
        unreadable or absent value reads as open, so the live check
        decides exactly as it did before this gate existed (the
        aloha target exposes no shutter state at all)."""
        result = self._adb_run(
            ["shell", "dumpsys", "platform_state_service"], timeout=10
        )
        match = re.search(r"shutter_state=(\d+)", result.stdout or "")
        return match is not None and match.group(1) == "1"

    def _presence_service_problems(self) -> list[str]:
        """Durable service-level presence state, readable with the
        lens cover shut: the aiservice process is running and its
        CAMERA appop is allowed."""
        problems: list[str] = []
        pid = self._adb_run(
            ["shell", "pidof", "com.facebook.portal.aiservice"],
            timeout=5,
        ).stdout.strip()
        if not pid:
            problems.append("aiservice-not-running")
        appops = self._adb_run(
            [
                "shell",
                "cmd",
                "appops",
                "get",
                "com.facebook.portal.aiservice",
                "CAMERA",
            ],
            timeout=10,
        ).stdout
        if "CAMERA: allow" not in appops:
            problems.append("camera-appop-not-allow")
        return problems

    def _presence_profile_evidenced(
        self, required_profile_keys: set[str]
    ) -> bool:
        """Durable profile evidence usable with the cover shut: the
        installed marker (written only after a full streaming
        verification has passed once) or this boot's config-load
        lines still in logcat — aiservice loads settings_config.xml
        when it starts, and a run that applied the profile leaves
        them fresh in the buffer."""
        if self._adb_run(
            ["shell", "test", "-f", PRESENCE_INSTALLED_REMOTE],
            timeout=5,
        ).returncode == 0:
            return True
        logs = self._adb_run(
            [
                "shell",
                "logcat",
                "-d",
                "-v",
                "brief",
                "-e",
                PRESENCE_LOGCAT_REGEX,
            ],
            timeout=20,
        ).stdout
        return required_profile_keys.issubset(loaded_profile_keys(logs))

    def _verify_presence_durable(
        self,
        require_profile: bool,
        expected_analysis_fps: int | None,
        required_profile_keys: set[str],
    ) -> None:
        """Everything about the presence end state that can be
        verified with the lens cover shut. Raises ProvisionError
        listing every problem found; returns when the durable
        state holds. The FPS cap is evidenced by its marker file,
        whose content the live check already trusts the same way."""
        problems = self._presence_service_problems()
        if require_profile and not self._presence_profile_evidenced(
            required_profile_keys
        ):
            problems.append("profile-not-evidenced")
        if expected_analysis_fps is not None:
            configured = self._adb_run(
                ["shell", "cat", self._presence_fps_configured_path()],
                timeout=5,
            )
            if (
                configured.returncode != 0
                or configured.stdout.strip() != str(expected_analysis_fps)
            ):
                problems.append("fps-cap-marker-mismatch")
        if problems:
            raise ProvisionError(
                "presence durable state did not verify with the "
                "camera cover closed: " + ", ".join(problems)
            )

    def verify_presence_runtime(
        self,
        require_profile: bool,
        expected_analysis_fps: int | None = None,
        wait_seconds: int = 90,
    ) -> str:
        """Live presence verification. Returns "verified" when the
        pipeline was observed streaming, or "deferred" when the
        camera lens cover is closed: the cover gates the pipeline
        by design (it configures, starts, and pauses without ever
        opening the camera), so the streaming evidence can never
        appear while it is shut no matter how healthy the
        provisioned state is. In that case the durable end state
        is verified instead and the streaming verification is
        deferred to a later run with the cover open. A durable
        failure raises ProvisionError, as a live failure does."""
        self.presence_verify_deferred = False
        deadline = time.monotonic() + wait_seconds
        pid = ""
        camera_active = False
        camera_allowed = False
        camera_appop = ""
        presence_no_users = False
        privacy_blocked = False
        presence_event = False
        analysis_frames = False
        roi_frames = False
        pose_metrics = False
        frame_processor_loaded = False
        wide_frame = False
        loaded_keys: set[str] = set()
        analysis_fps_applied = False
        helper_activation = False
        uid1000_configured = expected_analysis_fps is None
        required_profile_keys = set(
            self._target().presence_runtime_keys
            if self._target() and self._target().presence_runtime_keys
            else PRESENCE_PROFILE_KEYS
        )
        if expected_analysis_fps is not None:
            configured = self._adb_run(
                ["shell", "cat", self._presence_fps_configured_path()],
                timeout=5,
            )
            uid1000_configured = (
                configured.returncode == 0
                and configured.stdout.strip() == str(expected_analysis_fps)
            )
        if self._presence_shutter_closed():
            self._verify_presence_durable(
                require_profile,
                expected_analysis_fps,
                required_profile_keys,
            )
            self.presence_verify_deferred = True
            print(
                "PRESENCE_VERIFY_DEFERRED reason=shutter_closed "
                f"require_profile={int(require_profile)} "
                f"analysis_fps={expected_analysis_fps or 'unlimited'} "
                "durable=ok",
                flush=True,
            )
            return "deferred"
        threads = ""
        while time.monotonic() < deadline:
            pid = self._adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"], timeout=5
            ).stdout.strip()
            camera = self._adb_run(
                ["shell", "dumpsys", "media.camera"], timeout=15
            ).stdout
            camera_active = (
                "Active Camera Clients:" in camera
                and "Client Package Name: com.facebook.portal.aiservice" in camera
            )
            appops = self._adb_run(
                [
                    "shell",
                    "cmd",
                    "appops",
                    "get",
                    "com.facebook.portal.aiservice",
                    "CAMERA",
                ],
                timeout=10,
            ).stdout
            camera_appop = " ".join(appops.split()) or "no-operation-recorded"
            camera_allowed = "CAMERA: allow" in appops
            logs = self._adb_run(
                [
                    "shell",
                    "logcat",
                    "-d",
                    "-v",
                    "brief",
                    "-e",
                    PRESENCE_LOGCAT_REGEX,
                ],
                timeout=20,
            ).stdout
            presence_event = presence_event or PRESENCE_LOG_MARKER in logs
            presence_no_users = presence_no_users or (
                "CAMERA_SERVICE not running, but no users found yet" in logs
            )
            privacy_blocked = privacy_blocked or any(
                marker in logs.lower()
                for marker in (
                    "cannot start privacy mode on",
                    "privacy mode is on",
                )
            )
            analysis_frames = (
                analysis_frames or PRESENCE_ANALYSIS_FRAME_MARKER in logs
            )
            roi_frames = roi_frames or PRESENCE_ROI_FRAME_MARKER in logs
            wide_frame = wide_frame or presence_full_scene_active(
                logs, camera, self._target()
            )
            loaded_keys.update(loaded_profile_keys(logs))
            analysis_fps_applied = analysis_fps_applied or (
                expected_analysis_fps is not None
                and any(
                    "Setting AI Processing FPS" in line
                    and re.search(
                        rf"\b{expected_analysis_fps}(?:\.0+)?\b", line
                    )
                    for line in logs.splitlines()
                )
            )
            helper_activation = helper_activation or (
                expected_analysis_fps is not None
                and any(
                    "PortalPresence" in line
                    and f"presence FPS activation complete fps={expected_analysis_fps}"
                    in line
                    and "uid=1000" in line
                    for line in logs.splitlines()
                )
            )
            config_ready = not require_profile or required_profile_keys.issubset(
                loaded_keys
            )
            fps_ready = expected_analysis_fps is None or (
                analysis_fps_applied
                and helper_activation
                and uid1000_configured
            )
            metrics = self._adb_run(
                [
                    "shell",
                    "dumpsys",
                    "activity",
                    "service",
                    CAMERA_SERVICE_COMPONENT,
                ],
                timeout=20,
            ).stdout
            pose_section = ""
            frame_section = ""
            if "[ PoseEstimatorManagerMetrics ]" in metrics:
                pose_section = metrics.split(
                    "[ PoseEstimatorManagerMetrics ]", 1
                )[1].split("[ AlohaFrameProcessor ]", 1)[0]
            if "[ AlohaFrameProcessor ]" in metrics:
                frame_section = metrics.split(
                    "[ AlohaFrameProcessor ]", 1
                )[1].split("[ AiCameramanController ]", 1)[0]
                frame_processor_loaded = bool(frame_section)
            latency_bucket = re.compile(r"\b\d+ ms - \d+ ms:\s+\d+\b")
            pose_metrics = bool(latency_bucket.search(pose_section))
            if (
                pid
                and camera_active
                and camera_allowed
                and analysis_frames
                and roi_frames
                and pose_metrics
                and frame_processor_loaded
                and (not require_profile or wide_frame)
                and config_ready
                and fps_ready
            ):
                threads = self._adb_run(
                    ["shell", "ps", "-T", "-p", pid.split()[0]], timeout=10
                ).stdout
                disabled_workers = [
                    name
                    for name in ("BackgroundDetec", "alohaLivenessMa")
                    if name not in threads
                ]
                if require_profile:
                    self._adb_run(
                        [
                            "shell",
                            "mkdir",
                            "-p",
                            "/data/local/tmp/portal-presence-backup",
                        ],
                        timeout=5,
                        check=True,
                    )
                    self._push_text_atomic(
                        "Portal presence profile verified\n",
                        PRESENCE_INSTALLED_REMOTE,
                    )
                    self._adb_run(
                        [
                            "shell",
                            "rm",
                            "-f",
                            "/data/local/tmp/portal-presence-backup/restored-v1",
                        ],
                        timeout=5,
                    )
                print(
                    "PRESENCE_RUNTIME_OK "
                    f"pid={pid.split()[0]} camera=active appop=allow "
                    "pipeline=active analysis_frames=observed "
                    "roi_frames=observed pose_metrics=populated "
                    "frame_processor=loaded "
                    f"field_of_view={'full' if wide_frame else 'firmware_default'} "
                    f"presence_event={'observed' if presence_event else 'not_observed'} "
                    f"profile_keys={len(loaded_keys)} "
                    f"analysis_fps={expected_analysis_fps or 'unlimited'} "
                    f"activation_host={'uid1000' if expected_analysis_fps else 'none'} "
                    f"workers_absent={','.join(disabled_workers) or 'none'}"
                )
                return "verified"
            time.sleep(2)
        camera_hint = (
            " Check that the Portal's physical camera cover is open and its "
            "camera/microphone privacy control is off."
            if not camera_active
            else ""
        )
        raise ProvisionError(
            "presence pipeline did not pass its live compatibility check: "
            f"pid={pid!r} camera_active={int(camera_active)} "
            f"camera_allowed={int(camera_allowed)} "
            f"camera_appop={camera_appop!r} "
            f"analysis_frames={int(analysis_frames)} "
            f"roi_frames={int(roi_frames)} "
            f"pose_metrics={int(pose_metrics)} "
            f"frame_processor_loaded={int(frame_processor_loaded)} "
            f"wide_frame={int(wide_frame)} "
            f"presence_event={int(presence_event)} "
            f"analysis_fps_applied={int(analysis_fps_applied)} "
            f"helper_activation={int(helper_activation)} "
            f"uid1000_configured={int(uid1000_configured)} "
            f"presence_no_users={int(presence_no_users)} "
            f"privacy_blocked={int(privacy_blocked)} "
            f"profile_keys={','.join(sorted(loaded_keys)) or 'none'}."
            f"{camera_hint}"
        )

    def verify_presence_runtime_channel(
        self,
        expected_analysis_fps: int | None = None,
        require_marker: bool = True,
        wait_seconds: int = 90,
    ) -> str:
        """End-state presence verification for the root-channel path.

        verify_presence_runtime() proves the profile from logcat
        evidence — settings_config.xml profile-key lines, the
        full-scene marker, the "Setting AI Processing FPS" line, the
        helper's activation line — that the aiservice emits when it
        loads its config or applies the cap. On the device's current
        boot, however old, those lines have rotated out of logcat,
        so the race-path verification can never pass there (the same
        defect class as the audio logcat probes). The live half of
        that verification is boot-age independent — the pipeline
        emits analysis/ROI frame markers continuously while it runs,
        and the pose/frame-processor metrics live in dumpsys — so
        this variant keeps exactly that live subset and replaces
        the rotated evidence with durable state: the installed
        marker, which verify_presence_runtime() writes only after
        a full profile verification has passed, and the fps-cap
        marker file whose content the race verify already reads.
        Guarantee preserved: the presence profile is the applied
        one (durable markers) and the presence pipeline is live
        with it now (live subset).

        Returns "verified" or "deferred", like
        verify_presence_runtime(): with the camera lens cover
        closed the live subset can never pass (the pipeline never
        opens the camera), so once the durable checks above hold
        and the service-level state verifies, the streaming
        verification defers instead of failing the run."""
        self.presence_verify_deferred = False
        if require_marker and self._adb_run(
            ["shell", "test", "-f", PRESENCE_INSTALLED_REMOTE],
            timeout=5,
        ).returncode != 0:
            raise ProvisionError(
                "presence profile marker is absent on the channel "
                "path; the profile has never completed a full "
                "verification on this device"
            )
        if expected_analysis_fps is not None:
            configured = self._adb_run(
                ["shell", "cat", self._presence_fps_configured_path()],
                timeout=5,
            )
            if (
                configured.returncode != 0
                or configured.stdout.strip() != str(expected_analysis_fps)
            ):
                raise ProvisionError(
                    "presence FPS cap marker does not match on the "
                    f"channel path: expected={expected_analysis_fps} "
                    f"marker={configured.stdout.strip()!r}"
                )
        if self._presence_shutter_closed():
            problems = self._presence_service_problems()
            if problems:
                raise ProvisionError(
                    "presence durable state did not verify with the "
                    "camera cover closed: " + ", ".join(problems)
                )
            self.presence_verify_deferred = True
            print(
                "PRESENCE_VERIFY_DEFERRED reason=shutter_closed "
                "path=channel durable=ok",
                flush=True,
            )
            return "deferred"
        deadline = time.monotonic() + wait_seconds
        pid = ""
        camera_active = False
        camera_allowed = False
        camera_appop = ""
        analysis_frames = False
        roi_frames = False
        pose_metrics = False
        frame_processor_loaded = False
        while time.monotonic() < deadline:
            pid = self._adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"],
                timeout=5,
            ).stdout.strip()
            camera = self._adb_run(
                ["shell", "dumpsys", "media.camera"], timeout=15
            ).stdout
            camera_active = (
                "Active Camera Clients:" in camera
                and "Client Package Name: com.facebook.portal.aiservice"
                in camera
            )
            appops = self._adb_run(
                [
                    "shell",
                    "cmd",
                    "appops",
                    "get",
                    "com.facebook.portal.aiservice",
                    "CAMERA",
                ],
                timeout=10,
            ).stdout
            camera_appop = " ".join(appops.split()) or "no-operation-recorded"
            camera_allowed = "CAMERA: allow" in appops
            logs = self._adb_run(
                [
                    "shell",
                    "logcat",
                    "-d",
                    "-v",
                    "brief",
                    "-e",
                    PRESENCE_LOGCAT_REGEX,
                ],
                timeout=20,
            ).stdout
            analysis_frames = (
                analysis_frames or PRESENCE_ANALYSIS_FRAME_MARKER in logs
            )
            roi_frames = roi_frames or PRESENCE_ROI_FRAME_MARKER in logs
            metrics = self._adb_run(
                [
                    "shell",
                    "dumpsys",
                    "activity",
                    "service",
                    CAMERA_SERVICE_COMPONENT,
                ],
                timeout=20,
            ).stdout
            pose_section = ""
            frame_section = ""
            if "[ PoseEstimatorManagerMetrics ]" in metrics:
                pose_section = metrics.split(
                    "[ PoseEstimatorManagerMetrics ]", 1
                )[1].split("[ AlohaFrameProcessor ]", 1)[0]
            if "[ AlohaFrameProcessor ]" in metrics:
                frame_section = metrics.split(
                    "[ AlohaFrameProcessor ]", 1
                )[1].split("[ AiCameramanController ]", 1)[0]
                frame_processor_loaded = bool(frame_section)
            latency_bucket = re.compile(r"\b\d+ ms - \d+ ms:\s+\d+\b")
            pose_metrics = bool(latency_bucket.search(pose_section))
            if (
                pid
                and camera_active
                and camera_allowed
                and analysis_frames
                and roi_frames
                and pose_metrics
                and frame_processor_loaded
            ):
                print(
                    "PRESENCE_RUNTIME_OK "
                    f"pid={pid.split()[0]} camera=active appop=allow "
                    "pipeline=active analysis_frames=observed "
                    "roi_frames=observed pose_metrics=populated "
                    "frame_processor=loaded profile=durable-marker "
                    f"analysis_fps={expected_analysis_fps or 'unlimited'}"
                )
                return "verified"
            time.sleep(2)
        camera_hint = (
            " Check that the Portal's physical camera cover is open "
            "and its camera/microphone privacy control is off."
            if not camera_active
            else ""
        )
        raise ProvisionError(
            "presence pipeline did not pass its channel live check: "
            f"pid={pid!r} camera_active={int(camera_active)} "
            f"camera_allowed={int(camera_allowed)} "
            f"camera_appop={camera_appop!r} "
            f"analysis_frames={int(analysis_frames)} "
            f"roi_frames={int(roi_frames)} "
            f"pose_metrics={int(pose_metrics)} "
            f"frame_processor_loaded={int(frame_processor_loaded)}."
            f"{camera_hint}"
        )

    def verify_camera_light_disabled(self, wait_seconds: int = 35) -> None:
        if self._adb_run(
            ["shell", "test", "-f", CAMERA_LIGHT_INSTALLED_REMOTE], timeout=5
        ).returncode != 0:
            raise ProvisionError("camera-light install marker is absent")
        private_runtime = bool(
            self._target() and self._target().uid1000_embedded_helper
        )
        if not private_runtime:
            if self._adb_run(
                [
                    "shell", "test", "-f",
                    self._uid1000_path("camera-led-enabled"),
                ],
                timeout=5,
            ).returncode != 0:
                raise ProvisionError(
                    "camera-light UID-1000 configuration is absent"
                )
            if self._adb_run(
                [
                    "shell", "test", "-x",
                    self._uid1000_path("portal-camera-led-watch"),
                ],
                timeout=5,
            ).returncode != 0:
                raise ProvisionError("camera-light watchdog executable is absent")
        deadline = time.monotonic() + wait_seconds
        since = self._logcat_watermark()
        last_process = ""
        last_logs = ""
        while time.monotonic() < deadline:
            processes = self._adb_run(
                ["shell", "ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS"],
                timeout=10,
                check=True,
            ).stdout
            last_process = next(
                (
                    line
                    for line in processes.splitlines()
                    if "portal-camera-led-watch" in line
                    or "portal-led-watc" in line
                ),
                "",
            )
            last_logs = self._logcat_poll("PortalCameraLed", since)
            if last_process and "watchdog connected uid=1000" in last_logs:
                selinux = self._adb_run(
                    ["shell", "getenforce"], timeout=5, check=True
                ).stdout.strip()
                if selinux != "Enforcing":
                    raise ProvisionError(f"SELinux is not enforcing: {selinux!r}")
                print(
                    "CAMERA_LIGHT_OK watchdog_uid=1000 "
                    f"host={self._target().uid1000_host_label if self._target() else 'unknown'} "
                    "trigger=persistent_app "
                    "selinux=Enforcing"
                )
                return
            time.sleep(2)
        raise ProvisionError(
            "camera-light UID-1000 watchdog did not start and connect; "
            f"process={last_process!r} logs={last_logs[-2000:]!r}"
        )

    def verify_camera_light_restored(self) -> None:
        if self._adb_run(
            ["shell", "test", "-f", CAMERA_LIGHT_RESTORED_REMOTE], timeout=5
        ).returncode != 0:
            raise ProvisionError("camera-light restore marker is absent")
        if (
            not (self._target() and self._target().uid1000_embedded_helper)
            and self._adb_run(
                ["shell", "test", "-e", self._uid1000_path("camera-led-enabled")],
                timeout=5,
            ).returncode == 0
        ):
            raise ProvisionError("camera-light UID-1000 configuration remains")
        if self._target() and self._target().uid1000_embedded_helper:
            retained = any(
                self._adb_run(
                    ["shell", "test", "-f", path], timeout=5
                ).returncode == 0
                for path in (
                    "/data/local/tmp/portal-presence-backup/fps-cap-v1",
                    self._adb_framework_boot_installed_remote,
                )
            )
            helper_present = retained
        else:
            retained = any(
                self._adb_run(["shell", "test", "-e", path], timeout=5).returncode
                == 0
                for path in (
                    self._uid1000_path("presence-fps"),
                    self._uid1000_path("wireless-adb-enabled"),
                    self._uid1000_path("adb-framework-enabled"),
                    self._uid1000_path(SYSTEM_THEME_CONTROL_MARKER),
                )
            )
            helper_present = self._adb_run(
                [
                    "shell", "test", "-e",
                    self._uid1000_path("portal-camera-led-watch"),
                ],
                timeout=5,
            ).returncode == 0
        if retained != helper_present:
            raise ProvisionError(
                "UID-1000 helper retention does not match remaining features: "
                f"retained_features={int(retained)} helper={int(helper_present)}"
            )
        processes = self._adb_run(
            ["shell", "ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS"],
            timeout=10,
            check=True,
        ).stdout
        camera_logs = self._adb_run(
            ["shell", "logcat", "-d", "-s", "PortalCameraLed:*"], timeout=10
        ).stdout
        if "watchdog connected uid=1000" in camera_logs:
            raise ProvisionError("camera-light watchdog remains active")
        print(
            "CAMERA_LIGHT_RESTORE_OK camera_watchdog=disabled "
            f"uid1000_helper={'retained' if retained else 'absent'}"
        )
