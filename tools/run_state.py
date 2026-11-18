#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Run state and manifest handling for the host provisioner.

Owns the on-device provisioning state manifest (read/write of
``portal-provision-state-v1.json``), the state dict construction,
and the per-run caches for the tool revision and the selected
artifact hashes. Extracted from PortalProvisioner in Phase M2 of
the monolith split; the provisioner holds a RunState and delegates
through thin wrappers so existing call sites are unchanged. The
byte format of the state file is frozen: recovery runs on
partially provisioned devices depend on compatibility with what
earlier versions wrote.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import shlex
import subprocess
from collections.abc import Callable

from device_session import ProvisionError

STATE_REMOTE = "/data/local/tmp/portal-provision-state-v1.json"

RunCallable = Callable[..., "subprocess.CompletedProcess[str]"]


class RunState:
    """State manifest I/O and per-run cached run metadata."""

    def __init__(
        self,
        root: pathlib.Path,
        run: RunCallable,
        adb_run: RunCallable,
        serial: str,
        log_dir: pathlib.Path,
    ):
        self._root = root
        self._run = run
        self._adb_run = adb_run
        self._serial = serial
        self._log_dir = log_dir
        self._tool_revision_cache: str | None = None
        self._artifact_hashes_cache: dict[str, str] | None = None
        self._artifact_hashes_key: tuple | None = None

    def tool_revision(self) -> str:
        if self._tool_revision_cache is not None:
            return self._tool_revision_cache
        result = self._run(
            ["git", "-C", str(self._root), "rev-parse", "--short", "HEAD"],
            timeout=5,
        )
        if result.returncode != 0:
            self._tool_revision_cache = "unknown"
            return "unknown"
        revision = result.stdout.strip()
        dirty = self._run(
            ["git", "-C", str(self._root), "status", "--porcelain"], timeout=5
        )
        if dirty.returncode == 0 and dirty.stdout.strip():
            revision += "-dirty"
        self._tool_revision_cache = revision
        return revision

    def artifact_hashes(
        self, candidates: list[pathlib.Path]
    ) -> dict[str, str]:
        cache_key = tuple(
            (str(path), path.stat().st_size, path.stat().st_mtime_ns)
            if path.is_file()
            else (str(path), -1, -1)
            for path in candidates
        )
        if self._artifact_hashes_cache is not None and (
            self._artifact_hashes_key == cache_key
        ):
            return dict(self._artifact_hashes_cache)
        hashes: dict[str, str] = {}
        for path in candidates:
            if path.is_file():
                try:
                    name = str(path.relative_to(self._root))
                except ValueError:
                    name = str(path)
                hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self._artifact_hashes_cache = dict(hashes)
        self._artifact_hashes_key = cache_key
        return hashes

    def read_state(self) -> dict[str, object] | None:
        result = self._adb_run(["shell", "cat", STATE_REMOTE], timeout=5)
        if result.returncode != 0:
            return None
        try:
            state = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(f"invalid device state manifest: {exc}") from exc
        if not isinstance(state, dict) or state.get("schema") != 1:
            raise ProvisionError("unrecognized device state manifest")
        return state

    def write_state(
        self,
        state_status: str,
        *,
        fingerprint: str,
        target_key: str | None,
        tool_revision: str,
        artifact_sha256: dict[str, str],
        actions: dict[str, object],
        first_boot: str | None = None,
        second_boot: str | None = None,
        autoroot_key_sha256: str | None = None,
    ) -> None:
        state = {
            "schema": 1,
            "status": state_status,
            "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "serial": self._serial,
            "target": target_key,
            "fingerprint": fingerprint,
            "tool_revision": tool_revision,
            "artifact_sha256": artifact_sha256,
            "actions": actions,
            "verification": {
                "first_boot": first_boot,
                "second_boot": second_boot,
            },
        }
        if autoroot_key_sha256 is not None:
            # Additive field (schema stays 1; readers ignore keys
            # they do not know): the SHA-256 of the public key the
            # run staged into the autoroot helper, recorded so a
            # later "key is not authorized" failure names the key
            # generation that was live.
            state["autoroot_key_sha256"] = autoroot_key_sha256
        self._log_dir.mkdir(parents=True, exist_ok=True)
        local = self._log_dir / "portal-provision-state-v1.json"
        local.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        local.chmod(0o600)
        remote_tmp = STATE_REMOTE + ".tmp"
        self._adb_run(["push", str(local), remote_tmp], timeout=15, check=True)
        self._adb_run(
            [
                "shell",
                f"chmod 0600 {shlex.quote(remote_tmp)} && "
                f"mv {shlex.quote(remote_tmp)} {shlex.quote(STATE_REMOTE)}",
            ],
            timeout=10,
            check=True,
        )
        print(f"STATE_MANIFEST status={state_status} path={STATE_REMOTE}")
