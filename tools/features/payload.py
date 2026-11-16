# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mikhail
"""Autoroot + custom-payload feature cluster: staging, daemon
lifecycle, payload verification, and the buffered uid1000-marker
finalize.

Extracted from provision_portal.py in the M3.5 monolith-split phase
(the final, most coupled cluster). Mechanical move only: the payload
race loop itself (apply_custom_payload / exploit) stays in the
orchestrator per the plan; what moves here is everything the loop
invokes after a win — payload verification, daemon EXEC/STOP,
post-payload root steps, autoroot staging, sentinel staging, the
uid1000 runtime payload installers, and the buffered uid1000-marker
finalize. Ordering is preserved call-for-call. Test-patched seams
(stage_autoroot_payload, start_shizuku_as_root) and cross-cluster
seams route through late-bound provisioner callables. The uid1000
runtime remote-path state is owned here and synced by the
provisioner wrappers after install/uninstall (the exploit
environment builder reads it on the provisioner).
"""
from __future__ import annotations

import dataclasses
import pathlib
import re
import shlex
import socket
import subprocess
import tempfile
import time
from typing import Callable

from device_session import ProvisionError
from features.shizuku import SHIZUKU_HELPER_PACKAGE
from portal_targets import PortalTarget

ROOT = pathlib.Path(__file__).resolve().parents[2]

AUTOROOT_REMOTE_DIR = "/data/local/tmp/portal-autoroot"
AUTOROOT_CONF_REMOTE = f"{AUTOROOT_REMOTE_DIR}/autoroot.conf"
AUTOROOT_HELPER_LOCAL = ROOT / "autoroot-helper/build/portal-autoroot-helper.apk"
AUTOROOT_HELPER_PACKAGE = "dev.portal.autoroothelper"
AUTOROOT_MAX_ATTEMPTS = 8
AUTOROOT_RUNNER_LOCAL = ROOT / "autoroot-helper/run.sh"
AUTOROOT_SESSION_WINDOW_SEC = 3600
EXPLOIT_SENTINEL_LOCAL = (
    ROOT / "exploit-sentinel/build/portal-exploit-sentinel.apk"
)
EXPLOIT_SENTINEL_PACKAGE = "dev.portal.exploitsentinel"
CUSTOM_PAYLOAD_DST_REMOTE = "/data/local/tmp/portal-root-daemon"
CUSTOM_PAYLOAD_PORT = 37373
UID1000_RUNTIME_PACKAGE = "dev.portal.uid1000runtime"
UID1000_RUNTIME_APK_LOCAL = (
    ROOT / "uid1000-helper/build/portal-uid1000-runtime.apk"
)


@dataclasses.dataclass(frozen=True)
class PayloadConfig:
    """Provisioner flags this cluster slices (built fresh per access)."""

    shizuku: bool
    skip_shizuku_root: bool
    autoroot: bool
    disable_camera_light: bool
    restore_camera_light: bool
    restore_presence_fps: bool
    restore_presence_profile: bool
    presence_fps_cap: int | None


class PayloadFeature:
    """Custom-payload verification/daemon + autoroot staging."""

    def __init__(
        self,
        *,
        config: Callable[[], PayloadConfig],
        adb_run: Callable[..., "subprocess.CompletedProcess[str]"],
        target: Callable[[], "PortalTarget | None"],
        install_apk_preserving_verifier: Callable[..., None],
        verify_package_verifier_state: Callable[..., None],
        settle_package_state: Callable[..., None],
        package_sets: Callable[..., "tuple[set[str], set[str]]"],
        push_text_atomic: Callable[..., None],
        build_exploit_environment: Callable[..., object],
        uid1000_path: Callable[[str], str],
        compile_camera_light_host_speed: Callable[..., None],
        start_shizuku_as_root: Callable[..., None],
        stage_autoroot_payload: Callable[..., None],
        stage_simpleperf: Callable[..., None],
        presence_fps_action_requested: Callable[[], bool],
        stop_root_daemon: Callable[..., None],
        autoroot_helper_local: Callable[[], pathlib.Path],
        autoroot_runner_local: Callable[[], pathlib.Path],
        adb_framework_boot_installed_remote: str,
    ):
        self._config_factory = config
        self._adb_run = adb_run
        self._target = target
        self._install_apk_preserving_verifier = install_apk_preserving_verifier
        self._verify_package_verifier_state = verify_package_verifier_state
        self._settle_package_state = settle_package_state
        self._package_sets = package_sets
        self._push_text_atomic = push_text_atomic
        self._build_exploit_environment = build_exploit_environment
        self._uid1000_path = uid1000_path
        self._compile_camera_light_host_speed = compile_camera_light_host_speed
        self._start_shizuku_as_root = start_shizuku_as_root
        self._stage_autoroot_payload = stage_autoroot_payload
        self._stage_simpleperf = stage_simpleperf
        self._presence_fps_action_requested = presence_fps_action_requested
        self._stop_root_daemon = stop_root_daemon
        self._autoroot_helper_local = autoroot_helper_local
        self._autoroot_runner_local = autoroot_runner_local
        self._adb_framework_boot_installed_remote = (
            adb_framework_boot_installed_remote
        )
        self.uid1000_runtime_apk_remote: str | None = None
        self.uid1000_runtime_library_remote: str | None = None
        self.uid1000_runtime_package_installed = False

    @property
    def _config(self) -> PayloadConfig:
        # Late-bound: built fresh from the provisioner's current flag
        # attributes on every access (see features/settings.py).
        return self._config_factory()


    def finalize_buffered_uid1000_markers(self) -> None:
        if not self._target() or not self._target().buffer_root_staged_sources:
            return
        if self._config.disable_camera_light:
            self._adb_run(
                [
                    "shell", "mkdir", "-p",
                    "/data/local/tmp/portal-camera-light-backup",
                ],
                timeout=5,
                check=True,
            )
            self._push_text_atomic(
                "Portal camera light watchdog installed\n",
                CAMERA_LIGHT_INSTALLED_REMOTE,
            )
            self._adb_run(
                ["shell", "rm", "-f", CAMERA_LIGHT_RESTORED_REMOTE],
                timeout=5,
                check=True,
            )
            print("CAMERA_LIGHT_MARKER_OK source=post-reboot")
        if self._config.restore_camera_light:
            self._adb_run(
                [
                    "shell",
                    "mkdir",
                    "-p",
                    "/data/local/tmp/portal-camera-light-backup",
                ],
                timeout=5,
                check=True,
            )
            self._adb_run(
                ["shell", "rm", "-f", CAMERA_LIGHT_INSTALLED_REMOTE],
                timeout=5,
                check=True,
            )
            self._push_text_atomic(
                "Portal camera light watchdog restored\n",
                CAMERA_LIGHT_RESTORED_REMOTE,
            )
            print("CAMERA_LIGHT_RESTORE_MARKER_OK source=post-reboot")
        if self._presence_fps_action_requested():
            self._adb_run(
                [
                    "shell", "mkdir", "-p",
                    "/data/local/tmp/portal-presence-backup",
                ],
                timeout=5,
                check=True,
            )
            self._push_text_atomic(
                f"{self._config.presence_fps_cap}\n",
                "/data/local/tmp/portal-presence-backup/fps-cap-v1",
            )
            self._adb_run(
                [
                    "shell", "rm", "-f",
                    "/data/local/tmp/portal-presence-backup/fps-restored-v1",
                ],
                timeout=5,
                check=True,
            )
            print("PRESENCE_FPS_MARKER_OK source=post-reboot")
        if self._config.restore_presence_fps or self._config.restore_presence_profile:
            self._adb_run(
                [
                    "shell", "mkdir", "-p",
                    "/data/local/tmp/portal-presence-backup",
                ],
                timeout=5,
                check=True,
            )
            self._adb_run(
                [
                    "shell", "rm", "-f",
                    "/data/local/tmp/portal-presence-backup/fps-cap-v1",
                ],
                timeout=5,
                check=True,
            )
            self._push_text_atomic(
                "Portal presence FPS cap restored\n",
                "/data/local/tmp/portal-presence-backup/fps-restored-v1",
            )
            print("PRESENCE_FPS_RESTORE_MARKER_OK source=post-reboot")

    def install_uid1000_runtime_payload(self) -> None:
        self._install_apk_preserving_verifier(
            UID1000_RUNTIME_APK_LOCAL, "uid1000-runtime", UID1000_RUNTIME_PACKAGE
        )
        package_path = self._adb_run(
            ["shell", "pm", "path", UID1000_RUNTIME_PACKAGE],
            timeout=10,
            check=True,
        ).stdout.strip()
        match = re.search(r"^package:(.+/base\.apk)$", package_path, re.MULTILINE)
        if not match:
            raise ProvisionError(
                "could not resolve the installed UID-1000 runtime paths"
            )
        package_directory = match.group(1).rsplit("/", 1)[0]
        library_path = (
            package_directory
            + "/lib/arm64/libportal_uid1000_watch.so"
        )
        if self._adb_run(
            ["shell", "test", "-f", library_path], timeout=5
        ).returncode != 0:
            raise ProvisionError(
                "installed UID-1000 runtime native library is absent: "
                + library_path
            )
        self.uid1000_runtime_apk_remote = match.group(1)
        self.uid1000_runtime_library_remote = library_path
        self.uid1000_runtime_package_installed = True
        print("UID1000_RUNTIME_APK_OK package=installed native=extracted")

    def uninstall_uid1000_runtime_payload(self, best_effort: bool = False) -> None:
        if not self.uid1000_runtime_package_installed:
            return
        result = self._adb_run(
            ["uninstall", UID1000_RUNTIME_PACKAGE], timeout=30
        )
        if not best_effort and result.returncode != 0:
            raise ProvisionError(
                "could not remove the temporary UID-1000 runtime package: "
                + result.stdout
            )
        self.uid1000_runtime_package_installed = False
        print("UID1000_RUNTIME_APK_REMOVE package=removed")

    def prepare_exploit_sentinel(self) -> None:
        if not EXPLOIT_SENTINEL_LOCAL.is_file():
            raise ProvisionError(
                f"missing exploit sentinel build output: {EXPLOIT_SENTINEL_LOCAL}"
            )
        try:
            self._install_apk_preserving_verifier(
                EXPLOIT_SENTINEL_LOCAL,
                "exploit-sentinel",
                EXPLOIT_SENTINEL_PACKAGE,
            )
            self._settle_package_state()
            result = self._adb_run(
                [
                    "shell",
                    "run-as",
                    EXPLOIT_SENTINEL_PACKAGE,
                    "/system/bin/true",
                ],
                timeout=15,
            )
            if result.returncode != 0:
                raise ProvisionError(
                    "exploit sentinel run-as preflight failed: "
                    + result.stdout.strip()
                )
            self._verify_package_verifier_state()
        except ProvisionError:
            self.uninstall_exploit_sentinel(best_effort=True)
            raise
        print(
            f"EXPLOIT_SENTINEL_OK package={EXPLOIT_SENTINEL_PACKAGE} "
            "run_as=verified"
        )

    def uninstall_exploit_sentinel(self, best_effort: bool = False) -> None:
        try:
            path = self._adb_run(
                ["shell", "pm", "path", EXPLOIT_SENTINEL_PACKAGE], timeout=15
            )
            if path.returncode != 0 or not path.stdout.startswith("package:"):
                print(
                    f"EXPLOIT_SENTINEL_REMOVE package={EXPLOIT_SENTINEL_PACKAGE} "
                    "already_absent=1"
                )
                return
            result = self._adb_run(
                ["uninstall", EXPLOIT_SENTINEL_PACKAGE], timeout=30
            )
            if result.returncode != 0 or "Success" not in result.stdout:
                raise ProvisionError(
                    "failed to remove exploit sentinel: "
                    + result.stdout.strip()
                )
            print(
                f"EXPLOIT_SENTINEL_REMOVE package={EXPLOIT_SENTINEL_PACKAGE} "
                "already_absent=0"
            )
        except ProvisionError as exc:
            if not best_effort:
                raise
            print(f"EXPLOIT_SENTINEL_REMOVE_DEFERRED error={exc}")

    def verify_custom_payload(self, wait_seconds: int = 30) -> None:
        """Require the started payload to answer ID as uid 0 on loopback."""
        self._adb_run(
            [
                "forward",
                f"tcp:{CUSTOM_PAYLOAD_PORT}",
                f"tcp:{CUSTOM_PAYLOAD_PORT}",
            ],
            timeout=10,
            check=True,
        )
        deadline = time.monotonic() + wait_seconds
        last = ""
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(
                    ("127.0.0.1", CUSTOM_PAYLOAD_PORT), timeout=5
                ) as sock:
                    sock.sendall(b"ID\n")
                    response = sock.recv(4096).decode(errors="replace")
                last = response.strip()
                if last.startswith("ID uid=0"):
                    print(f"CUSTOM_PAYLOAD_ID {last}", flush=True)
                    return
            except OSError as exc:
                last = str(exc)
            time.sleep(2)
        raise ProvisionError(f"custom payload did not answer as uid 0: {last}")

    def daemon_exec(self, command: str, timeout: int = 40) -> tuple[int, str]:
        """Run one command through the custom payload's loopback EXEC.

        The payload protocol answers every request with the command's
        stdout+stderr, an ``EXIT <code>`` line and a terminating ``END``
        line. Uses the adb forward set up by verify_custom_payload().
        """
        with socket.create_connection(
            ("127.0.0.1", CUSTOM_PAYLOAD_PORT), timeout=10
        ) as sock:
            sock.settimeout(timeout)
            sock.sendall(f"EXEC {command}\n".encode())
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
                lines = data.decode(errors="replace").splitlines()
                if "END" in lines:
                    break
        lines = data.decode(errors="replace").splitlines()
        exit_code = 1
        output_lines: list[str] = []
        for line in lines:
            if line.startswith("EXIT "):
                try:
                    exit_code = int(line.split()[1])
                except (IndexError, ValueError):
                    exit_code = 1
                break
            if line == "END":
                break
            output_lines.append(line)
        return exit_code, "\n".join(output_lines)

    def stop_root_daemon(self) -> None:
        """Ask the custom payload daemon to exit (the STOP verb).

        The daemon answers "BYE" and closes as it exits; there is no
        END line for this verb. Anything else means the listener on
        CUSTOM_PAYLOAD_PORT is not our daemon.
        """
        with socket.create_connection(
            ("127.0.0.1", CUSTOM_PAYLOAD_PORT), timeout=10
        ) as sock:
            sock.settimeout(10)
            sock.sendall(b"STOP\n")
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except (ConnectionResetError, socket.timeout):
                pass
        if b"BYE" not in data:
            raise ProvisionError(
                "root daemon did not acknowledge STOP: "
                f"{data.decode(errors='replace')!r}"
            )

    def apply_post_payload_root_steps(self) -> None:
        """Extra root-backed steps that need the payload serving first."""
        shizuku_root_ok = False
        if self._config.shizuku and not self._config.skip_shizuku_root:
            self._start_shizuku_as_root()
            shizuku_root_ok = True
        if self._config.autoroot:
            self._stage_autoroot_payload()
        if shizuku_root_ok:
            # The daemon was the bridge to root-mode Shizuku. With the
            # server verified as uid 0 it has no further job this boot,
            # and an unauthenticated root EXEC listener should not
            # outlive the handoff. Autoroot boots re-create the daemon
            # for their own handoff and stop it the same way. When
            # root-mode Shizuku is not in play (--skip-shizuku-root or
            # no --shizuku) the daemon is the run's root channel and
            # stays up.
            try:
                self._stop_root_daemon()
                print(
                    "PAYLOAD_DAEMON_STOPPED reason=shizuku-root-ok",
                    flush=True,
                )
            except (OSError, ProvisionError) as exc:
                print(
                    f"PAYLOAD_DAEMON_STOP_FAILED error={exc}",
                    flush=True,
                )

    def stage_autoroot_payload(self) -> None:
        """Stage the on-device autoroot runner and its boot helper.

        After this, a reboot needs no host: the boot helper notices the
        root payload is down, redoes the per-boot address discovery
        on-device (bugreport + the staged simpleperf), and runs the
        staged runner script, which replays the exploit environment
        this provisioner generated for attempts 1 and 2 (parity picks
        the geometry, exactly like host retries). The helper reuses the
        Shizuku helper's already-authorized ADB key, and the exploit
        sentinel app stays installed because every on-device attempt
        needs it.
        """
        if self._target() is None:
            raise ProvisionError("target must be selected before autoroot")
        if not self._config.shizuku:
            raise ProvisionError(
                "--autoroot requires --shizuku: the boot helper reuses "
                "the Shizuku helper's authorized ADB key"
            )
        if not self._autoroot_helper_local().is_file():
            raise ProvisionError(
                f"missing autoroot helper build output: {self._autoroot_helper_local()}"
            )
        if not self._autoroot_runner_local().is_file():
            raise ProvisionError(
                f"missing autoroot runner script: {self._autoroot_runner_local()}"
            )
        sentinel_path = self._adb_run(
            ["shell", "pm", "path", EXPLOIT_SENTINEL_PACKAGE], timeout=15
        ).stdout
        if not sentinel_path.startswith("package:"):
            raise ProvisionError(
                "exploit sentinel is not installed; autoroot attempts "
                "need it on every boot"
            )
        simpleperf_remote = "/data/local/tmp/portal-simpleperf"
        if self._adb_run(
            ["shell", "test", "-f", simpleperf_remote], timeout=5
        ).returncode != 0:
            # Discovery stages this binary only for bundled targets;
            # every other target arrives here with the file absent.
            # Push it on demand — the same resolve + hash check
            # discovery uses — rather than refusing to stage, then
            # re-test so a push that produced nothing still fails
            # with the absence error instead of proceeding.
            self._stage_simpleperf()
            if self._adb_run(
                ["shell", "test", "-f", simpleperf_remote], timeout=5
            ).returncode != 0:
                raise ProvisionError(
                    "staged simpleperf is absent; KASLR discovery for this "
                    "target pushes it during the custom-payload attempts"
                )
        self._install_apk_preserving_verifier(
            self._autoroot_helper_local(), "autoroot-helper", AUTOROOT_HELPER_PACKAGE
        )
        self._settle_package_state()
        self._verify_package_verifier_state()
        # Give the boot helper the Shizuku helper's ADB keypair: that
        # public key is already authorized on the device, so the helper
        # can drive loopback ADB without another privileged grant.
        for name in ("adbkey", "adbkey.pub"):
            staged = f"/data/local/tmp/portal-autoroot-{name}.tmp"
            self._adb_run(
                [
                    "shell",
                    f"run-as {SHIZUKU_HELPER_PACKAGE} cat files/{name}"
                    f" > {staged} && chmod 0644 {staged}",
                ],
                timeout=10,
                check=True,
            )
            self._adb_run(
                [
                    "shell",
                    "run-as",
                    AUTOROOT_HELPER_PACKAGE,
                    "mkdir",
                    "-p",
                    "files",
                ],
                timeout=10,
                check=True,
            )
            self._adb_run(
                [
                    "shell",
                    "run-as",
                    AUTOROOT_HELPER_PACKAGE,
                    "cp",
                    staged,
                    f"files/{name}",
                ],
                timeout=10,
                check=True,
            )
            self._adb_run(
                [
                    "shell",
                    "run-as",
                    AUTOROOT_HELPER_PACKAGE,
                    "chmod",
                    "0600",
                    f"files/{name}",
                ],
                timeout=10,
                check=True,
            )
            self._adb_run(["shell", "rm", "-f", staged], timeout=5)
        self._adb_run(
            ["shell", "mkdir", "-p", AUTOROOT_REMOTE_DIR],
            timeout=5,
            check=True,
        )
        self._adb_run(
            ["push", str(self._autoroot_runner_local()), f"{AUTOROOT_REMOTE_DIR}/run.sh"],
            timeout=15,
            check=True,
        )
        self._adb_run(
            ["shell", "chmod", "0755", f"{AUTOROOT_REMOTE_DIR}/run.sh"],
            timeout=5,
            check=True,
        )
        # Render the exploit environment for both attempt parities from
        # the same builder exploit() uses, minus the per-boot addresses
        # (the helper discovers those and passes them to run.sh).
        with tempfile.TemporaryDirectory(prefix="portal-autoroot-env-") as temp:
            for attempt, name in ((1, "env-odd.sh"), (2, "env-even.sh")):
                environment = self._build_exploit_environment(0, 0, attempt)
                environment.pop("GHOSTLOCK_KASLR_BASE", None)
                environment.pop("GHOSTLOCK_P0_MEMSTART", None)
                if "GHOSTLOCK_ACTION_CREDENTIAL_PID" in environment:
                    raise ProvisionError(
                        "autoroot cannot stage this run: its exploit "
                        "environment carries a per-boot credential "
                        "identity (pid/uid resolved live), which cannot "
                        "be frozen into the on-device runner"
                    )
                rendered = "".join(
                    f"export {key}={shlex.quote(value)}\n"
                    for key, value in sorted(environment.items())
                )
                local = pathlib.Path(temp) / name
                local.write_text(rendered, encoding="utf-8")
                remote = f"{AUTOROOT_REMOTE_DIR}/{name}"
                self._adb_run(["push", str(local), remote], timeout=15, check=True)
                self._adb_run(
                    ["shell", "chmod", "0644", remote], timeout=5, check=True
                )
            offsets = ",".join(
                hex(offset) for offset in self._target().kaslr_pc_offsets
            )
            conf = (
                f"MAX_ATTEMPTS={AUTOROOT_MAX_ATTEMPTS}\n"
                f"SESSION_WINDOW_SEC={AUTOROOT_SESSION_WINDOW_SEC}\n"
                f"SIMPLEPERF={simpleperf_remote}\n"
                f"KASLR_OFFSETS={offsets}\n"
            )
            local_conf = pathlib.Path(temp) / "autoroot.conf"
            local_conf.write_text(conf, encoding="utf-8")
            self._adb_run(
                ["push", str(local_conf), AUTOROOT_CONF_REMOTE],
                timeout=15,
                check=True,
            )
            self._adb_run(
                ["shell", "chmod", "0644", AUTOROOT_CONF_REMOTE],
                timeout=5,
                check=True,
            )
        # A fresh provision starts a fresh autoroot session: drop any state
        # an earlier staging left behind, so an exhausted attempt budget or
        # a stale session window cannot block recovery after this run.
        self._adb_run(
            ["shell", "rm", "-f", f"{AUTOROOT_REMOTE_DIR}/state"],
            timeout=5,
            check=False,
        )
        # Android keeps freshly installed packages in the stopped state,
        # which suppresses BOOT_COMPLETED delivery; launch the helper once
        # now (mirrors the shizuku helper activation in verify_shizuku) so
        # its boot receiver can fire on later reboots. The daemon is up at
        # this point, so the service's first run just records this boot as
        # done and exits.
        try:
            self._adb_run(
                [
                    "shell",
                    "am",
                    "broadcast",
                    "-f",
                    "0x20",
                    "-a",
                    "dev.portal.autoroothelper.START",
                    "-p",
                    AUTOROOT_HELPER_PACKAGE,
                ],
                timeout=15,
                check=True,
            )
        except ProvisionError:
            print("AUTOROOT_HELPER_ACTIVATION_PENDING early_boot=1")
        print("AUTOROOT_HELPER_ACTIVATED first_install=1")
        # The autoroot helper now holds its own copy of the loopback
        # keypair (copied above) and runs its own ADB client, so the
        # shizuku helper app has no remaining role in the autoroot
        # flow: remove it so the deployed system is just the sentinel,
        # Shizuku, and the autoroot helper. The authorized public key
        # in adb_keys is a plain line in a file and is unaffected by
        # removing the other app that happened to hold a copy.
        installed, _ = self._package_sets()
        if SHIZUKU_HELPER_PACKAGE in installed:
            result = self._adb_run(
                ["uninstall", SHIZUKU_HELPER_PACKAGE], timeout=60
            )
            if result.returncode != 0 or "Success" not in result.stdout:
                raise ProvisionError(
                    "failed to remove the shizuku helper after "
                    f"autoroot staging: {result.stdout.strip()}"
                )
            print("SHIZUKU_HELPER_REMOVED reason=autoroot-keypair-merged")
        print(
            f"AUTOROOT_STAGED_OK dir={AUTOROOT_REMOTE_DIR} "
            f"helper={AUTOROOT_HELPER_PACKAGE} "
            f"max_attempts={AUTOROOT_MAX_ATTEMPTS}",
            flush=True,
        )

    def restore_uid1000_package_state_if_unused(self) -> None:
        if self._target() and self._target().uid1000_embedded_helper:
            retained = []
            for path, label in (
                (CAMERA_LIGHT_INSTALLED_REMOTE, "camera-light"),
                (
                    "/data/local/tmp/portal-presence-backup/fps-cap-v1",
                    "presence-fps",
                ),
                (
                    self._adb_framework_boot_installed_remote,
                    "adb-framework",
                ),
            ):
                if self._adb_run(
                    ["shell", "test", "-f", path], timeout=5
                ).returncode == 0:
                    retained.append(label)
            if retained:
                if self.uid1000_runtime_package_installed:
                    self.uid1000_runtime_package_installed = False
                    print("UID1000_RUNTIME_APK_RETAIN package=installed")
                print("UID1000_BOOT_HOOK_RETAINED features=" + ",".join(retained))
                return
            self._compile_camera_light_host_speed()
            if self.uid1000_runtime_package_installed:
                self.uninstall_uid1000_runtime_payload()
            print(
                f"UID1000_BOOT_HOOK_RESTORED host={self._target().uid1000_host_label}"
            )
            return
        retained = [
            path
            for path in (
                self._uid1000_path("camera-led-enabled"),
                self._uid1000_path("presence-fps"),
                self._uid1000_path("wireless-adb-enabled"),
                self._uid1000_path("adb-framework-enabled"),
                self._uid1000_path(SYSTEM_THEME_CONTROL_MARKER),
            )
            if self._adb_run(
                ["shell", "test", "-e", path], timeout=5
            ).returncode == 0
        ]
        if retained:
            print(
                "UID1000_BOOT_HOOK_RETAINED features="
                + ",".join(path.rsplit("/", 1)[-1] for path in retained)
            )
            return
        self._compile_camera_light_host_speed()
        host_label = (
            self._target().uid1000_host_label
            if self._target()
            else DEFAULT_UID1000_HOST_PACKAGE.rsplit(".", 1)[-1]
        )
        print(f"UID1000_BOOT_HOOK_RESTORED host={host_label}")
