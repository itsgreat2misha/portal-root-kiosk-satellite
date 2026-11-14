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

from device_session import ProvisionError
from mha_tuning import OMNI_STOCK_SHA256, patch_omni_tuning, sha256
from portal_targets import PortalTarget

MHA_AUDIO_VERIFIED_LOG = "mha audio processing verified aec=0 ns=0"
VOICE_AUDIO_VERIFIED_LOG = "audio processing verified aec=0 ns=0"
MHA_TUNING_DEVICE = "/vendor/etc/audio/omni/mha_tuning_blobs.tub"
MHA_TUNING_STOCK_REMOTE = "/data/local/tmp/portal-mha-tuning-stock.tub"
MHA_TUNING_PATCHED_REMOTE = "/data/local/tmp/portal-mha-tuning-disabled.tub"
MHA_TUNING_BACKUP_REMOTE = (
    "/data/local/tmp/portal-audio-backup/mha_tuning_blobs.stock-v1.tub"
)

AdbRun = Callable[..., "subprocess.CompletedProcess[str]"]
PullFile = Callable[[str, pathlib.Path], bytes]
LogcatPoll = Callable[..., str]


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

    @staticmethod
    def audio_processing_disabled_observed(
        logs: str, target: PortalTarget | None
    ) -> bool:
        return audio_processing_disabled_observed(logs, target)

    def prepare_mha_tuning_payloads(
        self,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        current_path = self._log_dir / "mha_tuning_blobs.device.tub"
        stock_path = self._log_dir / "mha_tuning_blobs.stock.tub"
        patched_path = self._log_dir / "mha_tuning_blobs.disabled.tub"
        current = self._pull_file(MHA_TUNING_DEVICE, current_path)
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
            f"current={current_hash} stock={OMNI_STOCK_SHA256} "
            f"patched={patched_hash} parameters={len(changes)} "
            f"action={'restore' if self._restore_audio() else 'disable'}",
            flush=True,
        )
        return stock_path, patched_path

    def audio_preflight(self) -> bool:
        marker = "/data/local/tmp/portal-audio-backup/installed-v1"
        installed = self._adb_run(
            ["shell", "test", "-f", marker], timeout=5
        ).returncode == 0
        if not installed and self._target() and self._target().audio_installer_credentials:
            try:
                self.verify_watchdog(wait_seconds=5)
            except ProvisionError:
                print("AUDIO_PREFLIGHT installed=0 healthy=0 action=install")
                return False
            print(
                "AUDIO_PREFLIGHT installed=private healthy=1 action=skip"
            )
            return True
        if not installed:
            print("AUDIO_PREFLIGHT installed=0 healthy=0 action=install")
            return False
        try:
            self.verify_watchdog(wait_seconds=5)
        except ProvisionError:
            print("AUDIO_PREFLIGHT installed=1 healthy=0 action=repair")
            return False
        print("AUDIO_PREFLIGHT installed=1 healthy=1 action=skip")
        return True

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
