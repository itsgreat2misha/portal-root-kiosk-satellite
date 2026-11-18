#!/usr/bin/env python3
# Copyright (c) 2026 itsgreat2misha
# SPDX-License-Identifier: Apache-2.0
"""ADB keypair rotation: the Shizuku helper and the autoroot helper
share one keypair, and autoroot staging removes the Shizuku helper,
so a later run that reinstalls it finds no pair. These tests pin the
convergence rules that keep the staged pair the authorized one:

- install seeds the Shizuku helper from the autoroot helper's
  already-authorized pair before it may generate a fresh one, and
  generates only when neither helper holds a pair;
- a channel apply that ended up with a freshly generated pair falls
  back to the race run instead of staging it (the channel cannot
  authorize a key);
- autoroot staging compares the pair it is about to copy against
  the saved marker (the last authorized public key) and fails
  loudly on a mismatch;
- the staged pair's SHA-256 lands in the run manifest.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import unittest.mock as mock

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[1] / "tools")
)

import provision_portal as provision_portal_module  # noqa: E402
from portal_targets import TARGETS  # noqa: E402
from provision_portal import PortalProvisioner, ProvisionError  # noqa: E402
from features.payload import AUTOROOT_HELPER_PACKAGE  # noqa: E402
from features.shizuku import (  # noqa: E402
    SHIZUKU_HELPER_PACKAGE,
    SHIZUKU_SAVED_KEY_REMOTE,
    SHIZUKU_VERSION,
)

SERIAL = "192.0.2.1:5555"
ALOHA = next(
    target for target in TARGETS if target.key == "portal-plus-aloha-1041515800015050"
)

PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"
)
PUBLIC_KEY = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 portal@helper"
OTHER_PUBLIC_KEY = "AAAAB3NzaC1yc2EAAAADAQABAAABAQD9 portal@helper"


def make_provisioner(temporary: str, **kwargs) -> PortalProvisioner:
    provisioner = PortalProvisioner(
        SERIAL, 12, pathlib.Path(temporary), **kwargs
    )
    provisioner.target = ALOHA
    return provisioner


def completed(args, stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args, returncode, stdout, "")


class KeypairDevice:
    """Fake device modelling the two helpers' key files and the
    /data/local/tmp staging area install pushes through."""

    def __init__(self) -> None:
        self.files: dict[tuple[str, str], str] = {}
        self.tmp: dict[str, str] = {}

    def adb_run(self, args, timeout=None, check=False):
        del timeout, check
        if args[:1] == ["exec-out"]:
            # ["exec-out", "run-as", PACKAGE, "cat", "files/adbkey[.pub]"]
            return completed(args, self.files.get((args[2], args[4]), ""))
        if args[:1] == ["push"]:
            self.tmp[args[2]] = pathlib.Path(args[1]).read_text(
                encoding="utf-8"
            )
            return completed(args)
        if "dumpsys" in args:
            return completed(args, f"versionName={SHIZUKU_VERSION}\n")
        if args[:3] == ["shell", "run-as", SHIZUKU_HELPER_PACKAGE] and (
            "cp" in args
        ):
            # ["shell", "run-as", PACKAGE, "cp", REMOTE, DESTINATION]
            remote, destination = args[4], args[5]
            self.files[(SHIZUKU_HELPER_PACKAGE, destination)] = self.tmp[
                remote
            ]
            return completed(args)
        return completed(args)


class InstallKeypairSourceTest(unittest.TestCase):
    def run_install(self, provisioner, device):
        keygen_calls: list = []

        def run(args, timeout=None, check=False):
            del timeout, check
            if "keygen" in args:
                keygen_calls.append(args)
                key = pathlib.Path(args[args.index("keygen") + 1])
                key.write_text(PRIVATE_KEY, encoding="utf-8")
                pathlib.Path(str(key) + ".pub").write_text(
                    PUBLIC_KEY + "\n", encoding="utf-8"
                )
            return completed(args)

        apk = pathlib.Path(provisioner.log_dir) / "shizuku.apk"
        apk.parent.mkdir(parents=True, exist_ok=True)
        apk.write_bytes(b"apk")
        stdout = io.StringIO()
        with (
            mock.patch.object(
                provisioner, "adb_run", side_effect=device.adb_run
            ),
            mock.patch.object(provisioner, "run", side_effect=run),
            mock.patch.object(
                provisioner, "resolve_shizuku_apk", return_value=apk
            ),
            mock.patch.object(provisioner, "install_apk_preserving_verifier"),
            mock.patch.object(provisioner, "settle_package_state"),
            mock.patch.object(provisioner, "verify_package_verifier_state"),
            contextlib.redirect_stdout(stdout),
        ):
            provisioner.install_shizuku_payload()
        return keygen_calls, stdout.getvalue()

    def test_existing_pair_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            device = KeypairDevice()
            device.files[(SHIZUKU_HELPER_PACKAGE, "files/adbkey")] = PRIVATE_KEY
            device.files[(SHIZUKU_HELPER_PACKAGE, "files/adbkey.pub")] = PUBLIC_KEY
            keygen_calls, output = self.run_install(provisioner, device)
            self.assertEqual(keygen_calls, [])
            self.assertEqual(provisioner.shizuku_key_source, "existing")
            self.assertIn("key_reused=1", output)

    def test_missing_pair_seeds_from_autoroot_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            device = KeypairDevice()
            device.files[(AUTOROOT_HELPER_PACKAGE, "files/adbkey")] = PRIVATE_KEY
            device.files[(AUTOROOT_HELPER_PACKAGE, "files/adbkey.pub")] = PUBLIC_KEY
            keygen_calls, output = self.run_install(provisioner, device)
            self.assertEqual(keygen_calls, [])
            self.assertEqual(provisioner.shizuku_key_source, "autoroot-seed")
            self.assertIn("SHIZUKU_KEY_SEEDED source=autoroot-helper", output)
            self.assertIn("key_reused=0", output)
            self.assertEqual(
                device.files[(SHIZUKU_HELPER_PACKAGE, "files/adbkey")],
                PRIVATE_KEY,
            )
            self.assertEqual(
                device.files[(SHIZUKU_HELPER_PACKAGE, "files/adbkey.pub")],
                PUBLIC_KEY + "\n",
            )

    def test_keygen_only_when_neither_helper_holds_a_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            device = KeypairDevice()
            keygen_calls, output = self.run_install(provisioner, device)
            self.assertEqual(len(keygen_calls), 1)
            self.assertEqual(provisioner.shizuku_key_source, "keygen")
            self.assertNotIn("SHIZUKU_KEY_SEEDED", output)
            self.assertEqual(
                device.files[(SHIZUKU_HELPER_PACKAGE, "files/adbkey.pub")],
                PUBLIC_KEY + "\n",
            )


class ChannelKeygenGuardTest(unittest.TestCase):
    def run_channel(self, provisioner, key_source: str):
        calls: list = []
        patched = (
            provision_portal_module.android_build_environment,
            provision_portal_module.build,
        )
        provision_portal_module.android_build_environment = (
            lambda target, **_kwargs: None
        )
        provision_portal_module.build = lambda **kwargs: calls.append("build")

        def install() -> None:
            calls.append("install_shizuku_payload")
            provisioner.shizuku_key_source = key_source

        provisioner.resolve_shizuku_apk = lambda: pathlib.Path("s.apk")
        provisioner.install_shizuku_payload = install
        provisioner.stage_autoroot_payload = lambda: calls.append(
            "stage_autoroot_payload"
        )
        provisioner.prepare_exploit_sentinel = lambda: calls.append(
            "prepare_exploit_sentinel"
        )
        provisioner.verify_requested_state = lambda **k: calls.append(
            "verify_requested_state"
        )
        provisioner._shizuku_root_ok = lambda: True
        states: list = []
        provisioner.write_state = lambda status, **k: states.append(status)
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                handled = provisioner._apply_via_channel("dns-drift")
        finally:
            (
                provision_portal_module.android_build_environment,
                provision_portal_module.build,
            ) = patched
        return handled, calls, states, stdout.getvalue()

    def test_keygen_pair_falls_back_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, shizuku=True, autoroot=True
            )
            handled, calls, states, output = self.run_channel(
                provisioner, "keygen"
            )
            self.assertFalse(handled)
            self.assertIn("PROVISION_CHANNEL_FALLBACK", output)
            self.assertIn("install_shizuku_payload", calls)
            self.assertNotIn("stage_autoroot_payload", calls)
            self.assertEqual(states, ["pending"])

    def test_seeded_pair_stages_on_the_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(
                temporary, shizuku=True, autoroot=True
            )
            handled, calls, states, output = self.run_channel(
                provisioner, "autoroot-seed"
            )
            self.assertTrue(handled)
            self.assertIn("PROVISION_CHANNEL_OK", output)
            self.assertIn("stage_autoroot_payload", calls)
            self.assertEqual(states, ["pending", "complete"])


class StagingKeypairCheckTest(unittest.TestCase):
    def run_staging(self, provisioner, *, helper_public: str, marker: str):
        def adb_run(args, timeout=None, check=False):
            del timeout, check
            if args[:1] == ["exec-out"]:
                return completed(args, helper_public + "\n")
            if args == ["shell", "cat", SHIZUKU_SAVED_KEY_REMOTE]:
                return completed(args, marker)
            if args[:3] == ["shell", "pm", "path"]:
                return completed(args, "package:/data/app/~~s/base.apk\n")
            if args[:3] == ["shell", "test", "-f"]:
                return completed(args, "", 0)
            if args and args[0] == "push":
                return completed(args)
            if args and args[0] == "uninstall":
                return completed(args, "Success\n")
            return completed(args)

        stdout = io.StringIO()
        with (
            mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
            mock.patch.object(provisioner, "install_apk_preserving_verifier"),
            mock.patch.object(provisioner, "settle_package_state"),
            mock.patch.object(
                provisioner,
                "package_sets",
                return_value=({SHIZUKU_HELPER_PACKAGE}, set()),
            ),
            contextlib.redirect_stdout(stdout),
        ):
            provisioner.stage_autoroot_payload()
        return stdout.getvalue()

    def build_provisioner(self, temporary: str) -> PortalProvisioner:
        provisioner = make_provisioner(
            temporary,
            shizuku=True,
            autoroot=True,
            custom_payload=pathlib.Path("daemon.bin"),
        )
        apk = pathlib.Path(temporary) / "helper.apk"
        apk.write_bytes(b"apk")
        runner = pathlib.Path(temporary) / "run.sh"
        runner.write_text("#!/bin/sh\n", encoding="utf-8")
        for name, value in (
            ("AUTOROOT_HELPER_LOCAL", apk),
            ("AUTOROOT_RUNNER_LOCAL", runner),
        ):
            patcher = mock.patch.object(provision_portal_module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        return provisioner

    def test_mismatched_pair_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                with self.assertRaisesRegex(
                    ProvisionError, "was never authorized"
                ):
                    self.run_staging(
                        provisioner,
                        helper_public=OTHER_PUBLIC_KEY,
                        marker=PUBLIC_KEY + "\n",
                    )
            self.assertNotIn("AUTOROOT_STAGED_OK", stdout.getvalue())

    def test_matching_pair_stages_and_records_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary)
            output = self.run_staging(
                provisioner,
                helper_public=PUBLIC_KEY,
                marker=PUBLIC_KEY + "\n",
            )
            expected = hashlib.sha256(
                PUBLIC_KEY.encode("utf-8")
            ).hexdigest()
            self.assertEqual(provisioner.staged_autoroot_key_sha256, expected)
            self.assertIn(f"AUTOROOT_KEY_STAGED sha256={expected}", output)
            self.assertIn("AUTOROOT_STAGED_OK", output)

    def test_no_marker_skips_the_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.build_provisioner(temporary)
            output = self.run_staging(
                provisioner, helper_public=PUBLIC_KEY, marker=""
            )
            self.assertIn("AUTOROOT_STAGED_OK", output)


class ManifestKeyHashTest(unittest.TestCase):
    def test_write_state_passes_the_staged_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = make_provisioner(temporary, shizuku=True)
            provisioner.staged_autoroot_key_sha256 = "ab" * 32
            captured: dict = {}

            def fake_write_state(status, **kwargs):
                captured["status"] = status
                captured.update(kwargs)

            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=completed([], "fingerprint\n"),
                ),
                mock.patch.object(
                    provisioner.run_state, "write_state", fake_write_state
                ),
            ):
                provisioner.write_state("complete")
            self.assertEqual(
                captured["autoroot_key_sha256"], "ab" * 32
            )

    def test_run_state_records_the_hash_only_when_staged(self) -> None:
        from run_state import RunState

        with tempfile.TemporaryDirectory() as temporary:
            pushed: dict = {}

            def adb_run(args, timeout=None, check=False):
                del timeout, check
                if args and args[0] == "push":
                    pushed["state"] = json.loads(
                        pathlib.Path(args[1]).read_text(encoding="utf-8")
                    )
                return completed(args)

            state = RunState(
                pathlib.Path(temporary),
                run=lambda args, timeout=None: completed(args),
                adb_run=adb_run,
                serial=SERIAL,
                log_dir=pathlib.Path(temporary),
            )
            state.write_state(
                "complete",
                fingerprint="fp",
                target_key=ALOHA.key,
                tool_revision="rev",
                artifact_sha256={},
                actions={},
                autoroot_key_sha256="cd" * 32,
            )
            self.assertEqual(pushed["state"]["autoroot_key_sha256"], "cd" * 32)
            state.write_state(
                "complete",
                fingerprint="fp",
                target_key=ALOHA.key,
                tool_revision="rev",
                artifact_sha256={},
                actions={},
            )
            self.assertNotIn("autoroot_key_sha256", pushed["state"])


if __name__ == "__main__":
    unittest.main()
