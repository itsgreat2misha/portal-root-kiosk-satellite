#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Device transport core for the host provisioner.

Owns the adb connection to one Portal: the serial, the adb argv
prefix, generic command execution, connect/reconnect, and
reboot-and-boot polling. Extracted from PortalProvisioner in Phase
M1 of the monolith split; the provisioner holds a DeviceSession and
delegates through thin wrappers so existing call sites are unchanged.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import time
from collections.abc import Callable


class ProvisionError(RuntimeError):
    pass


def run_command(
    args: list[str], timeout: float | None = None, check: bool = False
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProvisionError(f"command timed out: {shlex.join(args)}") from exc
    if check and result.returncode != 0:
        raise ProvisionError(
            f"command failed ({result.returncode}): {shlex.join(args)}\n"
            f"{result.stdout[-2000:]}"
        )
    return result


class DeviceSession:
    """adb transport for a single device serial."""

    def __init__(
        self,
        serial: str,
        post_boot_settle_seconds: Callable[[], int] | None = None,
        wait_notice: Callable[[], str | None] | None = None,
    ):
        self.serial = serial
        self.adb = ["adb", "-s", serial]
        self._post_boot_settle_seconds = post_boot_settle_seconds or (lambda: 0)
        self._wait_notice = wait_notice or (lambda: None)

    def run(
        self, args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        return run_command(args, timeout=timeout, check=check)

    def adb_run(
        self, args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        return self.run(self.adb + args, timeout=timeout, check=check)

    def connect(self, wait_seconds: int = 150) -> None:
        try:
            self.run(["adb", "disconnect", self.serial], timeout=5)
        except ProvisionError:
            pass
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            try:
                self.run(["adb", "connect", self.serial], timeout=5)
                state = self.adb_run(["get-state"], timeout=5)
                completed = self.adb_run(
                    ["shell", "getprop", "sys.boot_completed"], timeout=5
                )
                if state.returncode == 0 and completed.stdout.strip() == "1":
                    return
            except ProvisionError:
                pass
            time.sleep(3)
        raise ProvisionError(f"{self.serial} did not reconnect after {wait_seconds}s")

    def reboot(self) -> tuple[str, str]:
        before = self.adb_run(
            ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
            timeout=5,
            check=True,
        ).stdout.strip()
        # Flush before rebooting (F1, 2026-11-19): a reboot ends the
        # boot, and any asynchronous write still in flight on it —
        # the WiFi config store's connect-time write is the one that
        # has bitten — must be durable first. Best-effort: a device
        # that cannot answer sync is rebooted anyway, as before.
        try:
            self.adb_run(["shell", "sync"], timeout=60)
        except ProvisionError:
            pass
        try:
            self.adb_run(["reboot"], timeout=8)
        except ProvisionError:
            # adbd can disappear before acknowledging a successful reboot.
            pass
        after = self.connect_after_reboot(before)
        return before, after

    def connect_after_reboot(self, before: str, wait_seconds: int = 600) -> str:
        try:
            self.run(["adb", "disconnect", self.serial], timeout=5)
        except ProvisionError:
            pass
        deadline = time.monotonic() + wait_seconds
        last_boot_id = ""
        answered = False
        next_notice = time.monotonic() + 15
        while time.monotonic() < deadline:
            if not answered and time.monotonic() >= next_notice:
                # The device has not answered at all since the reboot:
                # on a not-yet-persistent Portal it will not come back
                # until the user re-enables ADB by hand, so say so while
                # there is still time to act (the notice callback stays
                # silent for devices whose ADB persists on its own).
                notice = self._wait_notice()
                if notice:
                    print(notice, flush=True)
                next_notice = time.monotonic() + 60
            try:
                # One adb invocation per poll tick: a single shell call
                # returns both the boot-completed flag and the boot ID.
                # A failed shell call means the transport is down, which
                # is the only case that needs an explicit reconnect.
                probe = self.adb_run(
                    [
                        "shell",
                        "getprop sys.boot_completed; "
                        "cat /proc/sys/kernel/random/boot_id",
                    ],
                    timeout=5,
                )
                if probe.returncode != 0:
                    self.run(["adb", "connect", self.serial], timeout=5)
                    time.sleep(3)
                    continue
                answered = True
                fields = probe.stdout.split()
                completed = fields[0] if fields else ""
                observed_boot_id = fields[1] if len(fields) > 1 else ""
                if re.fullmatch(r"[0-9a-fA-F-]{36}", observed_boot_id):
                    last_boot_id = observed_boot_id
                if (
                    completed == "1"
                    and last_boot_id
                    and last_boot_id != before
                ):
                    settle_seconds = self._post_boot_settle_seconds()
                    if settle_seconds:
                        time.sleep(settle_seconds)
                        stable = self.adb_run(
                            ["shell", "getprop", "sys.boot_completed"],
                            timeout=5,
                        )
                        if (
                            stable.returncode != 0
                            or stable.stdout.strip() != "1"
                        ):
                            self.run(
                                ["adb", "connect", self.serial], timeout=5
                            )
                            time.sleep(3)
                            continue
                    return last_boot_id
            except ProvisionError:
                pass
            time.sleep(3)
        adb_hint = ""
        if not last_boot_id:
            adb_hint = (
                "; ADB did not return. If WIRELESS_ADB_OK has not appeared yet, "
                "enable ADB in the Portal Debug menu and run "
                "`adb -d tcpip 5555`, then rerun the same provisioner command"
            )
        raise ProvisionError(
            f"{self.serial} did not complete a new boot after {before}; "
            f"last valid boot ID was {last_boot_id!r}{adb_hint}"
        )
