# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.
#
# Docs-surface guards: the README documents exactly the exposed CLI
# surface. Every long flag the parser exposes appears in the README,
# every --flag the README names exists on the parser, and the restore
# names listed in the README are exactly RESTORE_NAMES. Added with
# the 2026-11-21 docs review so the docs cannot quietly drift from
# the surface again.

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import cli as cli_module  # noqa: E402


class _ParserCaptured(Exception):
    pass


def _exposed_flags() -> set[str]:
    """Long flags on the real parser, captured before it can parse."""
    config = cli_module.CliConfig(
        version="test",
        default_custom_payload=pathlib.Path("portal-root-daemon"),
        shizuku_version="test",
        banner="",
    )
    captured: list[argparse.ArgumentParser] = []

    def capture(self, args=None, namespace=None):
        captured.append(self)
        raise _ParserCaptured

    with mock.patch.object(argparse.ArgumentParser, "parse_args", capture):
        try:
            cli_module.parse_args(config)
        except _ParserCaptured:
            pass
    flags: set[str] = set()
    for action in captured[0]._actions:
        for option in action.option_strings:
            if option.startswith("--"):
                flags.add(option)
    return flags


def _readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


def _readme_restore_names(readme: str) -> set[str]:
    """Bare backticked names in the Restoring changes section: the
    restore-name list plus the names the notes refer back to."""
    section = readme.split("## Restoring changes", 1)[1].split("\n## ", 1)[0]
    names = set()
    for token in re.findall(r"`([^`]+)`", section):
        if re.fullmatch(r"[a-z][a-z0-9-]*", token):
            names.add(token)
    return names


class DocsSurfaceTests(unittest.TestCase):
    def test_every_exposed_flag_is_documented(self) -> None:
        readme_flags = set(re.findall(r"--[a-z][a-z0-9-]*", _readme()))
        missing = _exposed_flags() - readme_flags
        self.assertEqual(
            missing, set(), f"flags exposed but not in README: {missing}"
        )

    def test_every_documented_flag_exists(self) -> None:
        readme_flags = set(re.findall(r"--[a-z][a-z0-9-]*", _readme()))
        unknown = readme_flags - _exposed_flags()
        self.assertEqual(
            unknown, set(), f"flags named in README but not exposed: {unknown}"
        )

    def test_restore_names_match_the_surface(self) -> None:
        self.assertEqual(
            _readme_restore_names(_readme()),
            set(cli_module.RESTORE_NAMES),
        )


if __name__ == "__main__":
    unittest.main()
