#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
# See LICENSE and NOTICE.

"""Audio feature cluster for the host provisioner.

Owns the audio-persistence feature: MHA tuning payload preparation
(Omni), the audio install preflight, the post-boot watchdog
verification, and the audio-restore verification. Extracted from
PortalProvisioner in Phase M3.1 of the monolith split; the
provisioner holds an AudioFeature and delegates through thin
wrappers so existing call sites are unchanged. Device-operation
order, console markers, and log strings are frozen.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import time
from collections.abc import Callable
from typing import NamedTuple

from device_session import ProvisionError
from mha_tuning import OMNI_STOCK_SHA256, patch_omni_tuning, sha256
from portal_targets import PortalTarget

MHA_AUDIO_VERIFIED_LOG = "mha audio processing verified aec=0 ns=0"
VOICE_AUDIO_VERIFIED_LOG = "audio processing verified aec=0 ns=0"
AUDIO_INSTALLED_MARKER = "/data/local/tmp/portal-audio-backup/installed-v1"
AUDIO_PERSIST_NATIVE_REMOTE = "/data/local/tmp/libportal_audio_persist.so"
AUDIO_PERSIST_JAVA_REMOTE = "/data/local/tmp/portal-audio-ctl.jar"
AISERVICE_PACKAGE = "com.facebook.portal.aiservice"
MHA_TUNING_PATH_TEMPLATE = "/vendor/etc/audio/{board}/mha_tuning_blobs.tub"
MHA_TUNING_STOCK_REMOTE = "/data/local/tmp/portal-mha-tuning-stock.tub"
MHA_TUNING_PATCHED_REMOTE = "/data/local/tmp/portal-mha-tuning-disabled.tub"
MHA_TUNING_BACKUP_REMOTE = (
    "/data/local/tmp/portal-audio-backup/mha_tuning_blobs.stock-v1.tub"
)

AdbRun = Callable[..., "subprocess.CompletedProcess[str]"]
PullFile = Callable[[str, pathlib.Path], bytes]
LogcatPoll = Callable[..., str]


def mha_tuning_path_for_board(board: str) -> str:
    """On-device MHA tuning blob path for a board (ro.boot.hardware).

    The audio stack keeps one tuning blob per board under
    /vendor/etc/audio/<board>/ and loads only that board's copy, so
    the provisioner must act on the file the device's own board
    reads. The board name becomes a single path component; anything
    that is not a plain component is refused rather than forming a
    path outside the per-board directory.
    """
    if (
        not board
        or board != board.strip()
        or "/" in board
        or board in (".", "..")
    ):
        raise ProvisionError(
            f"unexpected ro.boot.hardware value {board!r}; "
            "refusing to form an MHA tuning path"
        )
    return MHA_TUNING_PATH_TEMPLATE.format(board=board)


def audio_processing_disabled_observed(
    logs: str, target: PortalTarget | None
) -> bool:
    if target is not None and target.device == "omni":
        # Omni's MHA backend rejects VoiceParam 3001/4001.  In
        # particular, never let an old Java watchdog's synthetic 0.0
        # readbacks satisfy the health check on this target.
        return MHA_AUDIO_VERIFIED_LOG in logs
    if VOICE_AUDIO_VERIFIED_LOG in logs:
        return True
    aec = re.search(r"param=3001 .*after=0 .*ok=1", logs)
    ns = re.search(r"param=4001 .*after=0 .*ok=1", logs)
    return bool(aec and ns)


class AudioHealth(NamedTuple):
    """The one audio health verdict (Defect H).

    installed: the durable install marker is present (or was just
        written by the private-install probe below).
    private: no marker, but an installer-credential target's
        watchdog verified on this boot — a private install made
        outside this provisioner (upstream's shape).
    staged: the persist artifact the watchdog loads from is staged.
    aiservice: the watchdog's host process is alive right now.
    healthy / action: "skip" when the audio feature is in its
        configured end state, "install" when nothing is installed,
        "repair" when an install is present but a live signal
        disagrees."""

    installed: bool
    private: bool
    staged: bool
    aiservice: bool
    healthy: bool
    action: str


class AudioFeature:
    """Audio persistence apply/verify/restore host logic."""

    def __init__(
        self,
        *,
        adb_run: AdbRun,
        pull_file: PullFile,
        logcat_watermark: Callable[[], "str | None"],
        logcat_poll: LogcatPoll,
        log_dir: pathlib.Path,
        target: Callable[[], "PortalTarget | None"],
        restore_audio: Callable[[], bool],
    ):
        self._adb_run = adb_run
        self._pull_file = pull_file
        self._logcat_watermark = logcat_watermark
        self._logcat_poll = logcat_poll
        self._log_dir = log_dir
        self._target = target
        self._restore_audio = restore_audio
        self._mha_tuning_device_path: str | None = None

    @staticmethod
    def audio_processing_disabled_observed(
        logs: str, target: PortalTarget | None
    ) -> bool:
        return audio_processing_disabled_observed(logs, target)

    def mha_tuning_device_path(self) -> str:
        """This device's board-resolved MHA tuning blob path.

        Resolved once from ro.boot.hardware and cached. The payload
        receives the same path through GHOSTLOCK_MHA_TUNING_PATH, so
        the host pull/prepare/hash-gate and the on-device replace
        always act on the same file.
        """
        if self._mha_tuning_device_path is None:
            board = self._adb_run(
                ["shell", "getprop", "ro.boot.hardware"],
                timeout=5,
                check=True,
            ).stdout.strip()
            self._mha_tuning_device_path = mha_tuning_path_for_board(board)
        return self._mha_tuning_device_path

    def prepare_mha_tuning_payloads(
        self,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        current_path = self._log_dir / "mha_tuning_blobs.device.tub"
        stock_path = self._log_dir / "mha_tuning_blobs.stock.tub"
        patched_path = self._log_dir / "mha_tuning_blobs.disabled.tub"
        device_path = self.mha_tuning_device_path()
        current = self._pull_file(device_path, current_path)
        current_hash = sha256(current)

        if current_hash == OMNI_STOCK_SHA256:
            stock = current
        else:
            backup_path = self._log_dir / "mha_tuning_blobs.backup.tub"
            stock = self._pull_file(MHA_TUNING_BACKUP_REMOTE, backup_path)
            if sha256(stock) != OMNI_STOCK_SHA256:
                raise ProvisionError(
                    "Omni MHA stock backup has an unexpected SHA-256; "
                    "refusing to write /vendor"
                )
        patched, changes = patch_omni_tuning(stock)
        patched_hash = sha256(patched)
        if current_hash not in (OMNI_STOCK_SHA256, patched_hash):
            raise ProvisionError(
                "Omni MHA tuning blob has an unknown SHA-256; refusing to "
                f"write /vendor: {current_hash}"
            )
        stock_path.write_bytes(stock)
        patched_path.write_bytes(patched)
        print(
            "MHA_TUNING_PREPARED "
            f"path={device_path} "
            f"current={current_hash} stock={OMNI_STOCK_SHA256} "
            f"patched={patched_hash} parameters={len(changes)} "
            f"action={'restore' if self._restore_audio() else 'disable'}",
            flush=True,
        )
        return stock_path, patched_path

    def audio_health(self) -> AudioHealth:
        """The ONE audio health evaluation; both preflights print
        from it, so the channel eligibility gate and the apply path
        cannot disagree about the same boot state (Defect H,
        closure session 9.5: the gate read the durable signals
        healthy while the apply path's logcat probe read repair on
        the same long-uptime boot, and the run entered a race for a
        repair nothing needed).

        The criteria are the durable + live signals: the installed
        marker (written by verify_watchdog only after a fully
        verified boot), the staged persist artifact the watchdog
        loads from, and the aiservice process — the watchdog's
        host — alive right now. No logcat history is consulted for
        an installed device, so the answer does not depend on boot
        age: verify_watchdog()'s probe reads this boot's
        PortalAudioPersist lines, which rotate out of logcat as
        uptime grows and reported a healthy install as needing
        repair on any long-uptime device (Run 33 step 1). The
        logcat probe keeps two roles where boot age is not a
        factor: verifying a boot this run just caused
        (verify_watchdog after a race/reboot), and the
        marker-absent probe below — an installer-credential
        target whose watchdog verifies on this boot carries a
        private install this provisioner did not make; the probe
        also writes the marker, converting the device to the
        durable shape for every later read."""
        installed = self._adb_run(
            ["shell", "test", "-f", AUDIO_INSTALLED_MARKER], timeout=5
        ).returncode == 0
        if not installed:
            target = self._target()
            if target is not None and target.audio_installer_credentials:
                try:
                    self.verify_watchdog(wait_seconds=5)
                except ProvisionError:
                    return AudioHealth(
                        installed=False,
                        private=False,
                        staged=False,
                        aiservice=False,
                        healthy=False,
                        action="install",
                    )
                return AudioHealth(
                    installed=False,
                    private=True,
                    staged=False,
                    aiservice=True,
                    healthy=True,
                    action="skip",
                )
            return AudioHealth(
                installed=False,
                private=False,
                staged=False,
                aiservice=False,
                healthy=False,
                action="install",
            )
        target = self._target()
        artifact = (
            AUDIO_PERSIST_JAVA_REMOTE
            if target is not None and target.audio_java_fallback
            else AUDIO_PERSIST_NATIVE_REMOTE
        )
        staged = self._adb_run(
            ["shell", "test", "-f", artifact], timeout=5
        ).returncode == 0
        pid = self._adb_run(
            ["shell", "pidof", AISERVICE_PACKAGE], timeout=5
        ).stdout.strip()
        live = bool(staged and pid)
        return AudioHealth(
            installed=True,
            private=False,
            staged=staged,
            aiservice=bool(pid),
            healthy=live,
            action="skip" if live else "repair",
        )

    def audio_preflight(self) -> bool:
        health = self.audio_health()
        installed = "private" if health.private else int(health.installed)
        print(
            f"AUDIO_PREFLIGHT installed={installed} "
            f"healthy={int(health.healthy)} action={health.action}"
        )
        return health.action == "skip"

    def audio_channel_preflight(self) -> bool:
        """Channel eligibility view of the one verdict: prints the
        raw durable + live signals behind audio_health() and
        declines on anything but a skip verdict."""
        health = self.audio_health()
        installed = "private" if health.private else int(health.installed)
        print(
            f"AUDIO_CHANNEL_PREFLIGHT installed={installed} "
            f"staged={int(health.staged)} "
            f"aiservice={int(health.aiservice)} "
            f"action={'skip' if health.action == 'skip' else 'decline'}"
        )
        return health.action == "skip"

    def verify_watchdog(self, wait_seconds: int = 25) -> str:
        deadline = time.monotonic() + wait_seconds
        since = self._logcat_watermark()
        last_log = ""
        while time.monotonic() < deadline:
            last_log = self._logcat_poll("PortalAudioPersist", since)
            started = "persistent audio watchdog started" in last_log
            disabled = self.audio_processing_disabled_observed(
                last_log, self._target()
            )
            if started and disabled:
                pid = self._adb_run(
                    ["shell", "pidof", "com.facebook.portal.aiservice"],
                    timeout=5,
                    check=True,
                ).stdout.strip()
                boot_id = self._adb_run(
                    ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
                    timeout=5,
                    check=True,
                ).stdout.strip()
                print(f"WATCHDOG_OK boot_id={boot_id} aiservice_pid={pid}")
                # Persist a durable install marker: the logcat-based
                # check above rotates away on long uptimes, which made
                # preflight/--status flap between installed and unknown.
                self._adb_run(
                    ["shell", "mkdir", "-p", "/data/local/tmp/portal-audio-backup"],
                    timeout=5,
                )
                self._adb_run(
                    ["shell", "touch", "/data/local/tmp/portal-audio-backup/installed-v1"],
                    timeout=5,
                )
                print(last_log.rstrip())
                return boot_id
            time.sleep(2)
        raise ProvisionError(
            "watchdog did not verify after boot; recent log follows:\n"
            + last_log[-4000:]
        )

    def verify_audio_restored(self, wait_seconds: int = 20) -> None:
        marker = "/data/local/tmp/portal-audio-backup/restored-v1"
        marker_required = not (
            self._target() and self._target().audio_installer_credentials
        )
        if marker_required and self._adb_run(
            ["shell", "test", "-f", marker], timeout=5
        ).returncode != 0:
            raise ProvisionError("audio restore marker is absent")
        deadline = time.monotonic() + wait_seconds
        since = self._logcat_watermark()
        logs = ""
        pid = ""
        while time.monotonic() < deadline:
            pid = self._adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"], timeout=5
            ).stdout.strip()
            logs = self._logcat_poll("PortalAudioPersist", since)
            if pid:
                time.sleep(3)
                break
            time.sleep(2)
        logs = self._logcat_poll("PortalAudioPersist", since)
        if not pid or "persistent audio watchdog started" in logs:
            raise ProvisionError(
                "audio persistence restore did not verify: "
                f"aiservice_pid={pid!r} watchdog_started="
                f"{int('persistent audio watchdog started' in logs)}"
            )
        print(f"AUDIO_RESTORE_OK aiservice_pid={pid} watchdog=absent")
