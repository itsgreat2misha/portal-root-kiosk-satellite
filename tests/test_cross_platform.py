# SPDX-License-Identifier: Apache-2.0
# Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
# See LICENSE and NOTICE.

"""Phase F cross-platform host pins.

Each test names the audit finding it holds (cross-platform audit,
2026-11-16). Several are source pins on purpose: newline translation
and select-on-pipe only misbehave on a Windows host, so on a POSIX
runner the behavior is indistinguishable — the pin holds the exact
construct that makes the code portable, and the CI matrix legs on
macOS/Windows hold the behavior.
"""

from __future__ import annotations

import os
import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import provision_portal  # noqa: E402
from provision_portal import ProvisionError  # noqa: E402


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _function_source(relative: str, name: str) -> str:
    """The source of one top-level or method definition, by name."""
    lines = _source(relative).splitlines(keepends=True)
    start = next(
        index
        for index, line in enumerate(lines)
        if line.lstrip().startswith(f"def {name}(")
    )
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = start + 1
    while end < len(lines):
        line = lines[end]
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        end += 1
    return "".join(lines[start:end])


class AttemptStreamingPortabilityTest(unittest.TestCase):
    """B1: the exploit attempt runner must not select() on a pipe."""

    def test_no_select_in_provisioner(self) -> None:
        source = _source("tools/provision_portal.py")
        self.assertNotIn("import select", source)
        self.assertNotIn("select.select", source)
        # The portable replacement: a reader thread feeding a queue.
        self.assertIn("_pump_attempt_output", source)
        self.assertIn("output_queue.get(timeout=1)", source)


class DeviceBoundNewlinesTest(unittest.TestCase):
    """B2: text written for the device must never gain CRLF on a
    Windows host, so every device-bound write_text pins newline="".
    """

    def assert_function_writes_lf(self, relative: str, name: str) -> None:
        body = _function_source(relative, name)
        self.assertIn("write_text(", body, f"{name} writes no local file")
        write_lines = [
            chunk
            for chunk in body.replace("\n", " ").split("write_text(")[1:]
        ]
        for chunk in write_lines:
            call = chunk.split(")")[0]
            self.assertIn(
                'newline=""',
                call,
                f"{relative}:{name} has a write_text without newline=\"\": "
                f"write_text({call})",
            )

    def test_autoroot_env_and_conf_writes(self) -> None:
        self.assert_function_writes_lf(
            "tools/features/payload.py", "stage_autoroot_payload"
        )

    def test_push_text_atomic_writes(self) -> None:
        self.assert_function_writes_lf(
            "tools/provision_portal.py", "push_text_atomic"
        )

    def test_meta_accounts_backup_write(self) -> None:
        self.assert_function_writes_lf(
            "tools/features/settings.py", "meta_accounts_preflight"
        )

    def test_debloat_backup_write(self) -> None:
        self.assert_function_writes_lf(
            "tools/features/settings.py", "ensure_debloat_backup"
        )

    def test_shizuku_keypair_writes(self) -> None:
        self.assert_function_writes_lf(
            "tools/features/shizuku.py", "install_shizuku_payload"
        )


class BuildEnvironmentPlatformTest(unittest.TestCase):
    """B3/B6/D2: host-derived toolchain paths and SDK locations."""

    def test_ndk_host_tag_mapping(self) -> None:
        self.assertEqual(provision_portal.ndk_host_tag("linux"), "linux-x86_64")
        self.assertEqual(provision_portal.ndk_host_tag("darwin"), "darwin-x86_64")
        self.assertEqual(
            provision_portal.ndk_host_tag("win32"), "windows-x86_64"
        )
        self.assertEqual(
            provision_portal.ndk_host_tag("msys"), "windows-x86_64"
        )

    def test_build_tools_filename_mapping(self) -> None:
        self.assertEqual(
            provision_portal.build_tools_filename("aapt", "linux"), "aapt"
        )
        self.assertEqual(
            provision_portal.build_tools_filename("aapt", "darwin"), "aapt"
        )
        self.assertEqual(
            provision_portal.build_tools_filename("aapt", "win32"), "aapt.exe"
        )
        self.assertEqual(
            provision_portal.build_tools_filename("zipalign", "win32"),
            "zipalign.exe",
        )
        self.assertEqual(
            provision_portal.build_tools_filename("apksigner", "win32"),
            "apksigner.bat",
        )
        self.assertEqual(
            provision_portal.build_tools_filename("d8", "win32"), "d8.bat"
        )

    def test_sdk_candidates_include_macos_default(self) -> None:
        with mock.patch.object(sys, "platform", "darwin"):
            candidates = provision_portal.default_sdk_candidates()
        self.assertIn(
            pathlib.Path.home() / "Library/Android/sdk", candidates
        )

    def test_sdk_candidates_include_windows_default(self) -> None:
        with (
            mock.patch.object(sys, "platform", "win32"),
            mock.patch.dict(
                os.environ, {"LOCALAPPDATA": "C:/Users/x/AppData/Local"}
            ),
        ):
            candidates = provision_portal.default_sdk_candidates()
        self.assertIn(
            pathlib.Path("C:/Users/x/AppData/Local") / "Android/Sdk",
            candidates,
        )

    def test_sdk_candidates_linux_has_no_other_platforms(self) -> None:
        with mock.patch.object(sys, "platform", "linux"):
            candidates = provision_portal.default_sdk_candidates()
        self.assertNotIn(
            pathlib.Path.home() / "Library/Android/sdk", candidates
        )

    def test_windows_source_build_is_gated_honestly(self) -> None:
        """B4: native Windows Python gets the bundle/WSL answer up
        front, not a make failure mid-build."""
        with mock.patch.object(sys, "platform", "win32"):
            with self.assertRaises(ProvisionError) as raised:
                provision_portal.android_build_environment()
        self.assertIn("WSL2", str(raised.exception))
        self.assertIn("bundle", str(raised.exception))


class MakefilePlatformTest(unittest.TestCase):
    """B3/B5 at the make layer."""

    def test_no_makefile_hardcodes_linux_toolchain(self) -> None:
        for makefile in ROOT.glob("*/Makefile"):
            self.assertNotIn(
                "linux-x86_64",
                makefile.read_text(encoding="utf-8"),
                f"{makefile} still hardcodes the Linux NDK host tag",
            )
        env = _source("android-env.mk")
        self.assertIn("NDK_HOST_TAG", env)
        self.assertIn("darwin-x86_64", env)

    def test_no_gnu_only_stat_in_makefiles(self) -> None:
        for makefile in ROOT.glob("*/Makefile"):
            self.assertNotIn(
                "stat -c",
                makefile.read_text(encoding="utf-8"),
                f"{makefile} still uses GNU-only stat -c",
            )


class CheckoutAndManifestShapeTest(unittest.TestCase):
    """B7 + D7: LF-pinned checkout files and POSIX manifest keys."""

    def test_gitattributes_pins_device_bound_files(self) -> None:
        attributes = _source(".gitattributes")
        self.assertIn("*.sh text eol=lf", attributes)
        self.assertIn("Makefile text eol=lf", attributes)

    def test_backup_and_diagnostics_keys_are_posix(self) -> None:
        self.assertIn(
            ".as_posix()",
            _function_source(
                "tools/provision_portal.py", "create_backup_bundle"
            ),
        )
        self.assertIn(
            ".as_posix()",
            _function_source(
                "tools/provision_portal.py", "collect_diagnostics_bundle"
            ),
        )

    def test_default_log_dir_uses_tempdir(self) -> None:
        """D1: no hardcoded /tmp default for the run log directory."""
        source = _source("tools/cli.py")
        self.assertIn("tempfile.gettempdir()", source)
        self.assertNotIn("/tmp/portal-provision", source)


if __name__ == "__main__":
    unittest.main()
