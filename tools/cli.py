#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 itsgreat2misha
#
# Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

"""Command-line shell for the host provisioner.

Owns argument parsing and the top-level run entry: building the
provisioner from the parsed flags and mapping failures to exit codes.
Extracted from provision_portal in Phase M4 of the monolith split;
provision_portal keeps thin parse_args/main wrappers that build a
CliConfig from its module globals on every call and pass its current
PortalProvisioner class, so existing call sites and test seams are
unchanged.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from typing import Any, Callable

from device_session import ProvisionError


@dataclasses.dataclass(frozen=True)
class CliConfig:
    """Provisioner constants this shell slices (built fresh per call)."""

    version: str
    default_custom_payload: pathlib.Path
    shizuku_version: str
    banner: str


#: Names accepted by --restore <name>. Most map onto one of the
#: provisioner's restore attributes (see RESTORE_FLAG_MAP);
#: "debloat" maps onto the whole debloat group (see
#: RESTORE_GROUP_MAP). The four names marked Phase D close
#: restore-completeness gaps the audit found (autoroot,
#: wireless-adb, theme, meta-authenticators).
RESTORE_NAMES = (
    "audio",
    "debloat",
    "presence",
    "presence-fps",
    "adb-auth-timeout",
    "camera-light",
    "autoroot",
    "wireless-adb",
    "theme",
    "meta-authenticators",
)

#: --restore name -> provisioner attribute it sets.
RESTORE_FLAG_MAP = {
    "audio": "restore_audio",
    "presence": "restore_presence_profile",
    "presence-fps": "restore_presence_fps",
    "adb-auth-timeout": "restore_adb_auth_timeout",
    "camera-light": "restore_camera_light",
    "autoroot": "restore_autoroot",
    "wireless-adb": "restore_wireless_adb",
    "theme": "restore_theme",
    "meta-authenticators": "restore_meta_authenticators",
}

#: --restore name -> the provisioner attributes it sets together.
#: Debloat is one command, so its restore is one name covering
#: everything debloat changed: the apps it disabled, the update
#: block, the remote-wipe block, Private DNS, and Meta's app
#: verifier, each back to its recorded original state.
RESTORE_GROUP_MAP = {
    "debloat": (
        "restore_bloat",
        "restore_remote_wipe",
        "enable_updates",
        "restore_privacy_dns",
        "restore_app_verifier",
    ),
}

#: Every restore attribute any --restore name can set.
RESTORE_ATTRIBUTES = tuple(RESTORE_FLAG_MAP.values()) + tuple(
    attribute
    for attributes in RESTORE_GROUP_MAP.values()
    for attribute in attributes
)

#: The documented full-setup line, as --full expands it: attribute ->
#: value. --full is a preset only; it sets exactly these flags and
#: nothing else (the taste opt-ins --presence-fps-cap and
#: --system-theme-control stay out by design). Debloat carries the
#: update block and the remote-wipe block with it (see the fold in
#: parse_args), so they are not preset keys of their own anymore.
FULL_PRESET = {
    "audio": True,
    "debloat": True,
    "remove_meta_accounts": True,
    "optimize_presence": True,
    "disable_adb_auth_timeout": True,
    "autoroot": True,
}


def parse_args(config: CliConfig) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect, back up, provision, recover, and verify supported Meta "
            "Portal devices."
        )
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {config.version}",
    )
    parser.add_argument(
        "--serial",
        default=None,
        help=(
            "adb serial of the target Portal, e.g. 192.0.2.1:5555 for "
            "wireless adb or a USB serial; a bare IP address gets "
            ":5555 added, and with no --serial the only connected "
            "device is used"
        ),
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=12,
        help=(
            "maximum exploit attempts per phase "
            "(default: 12, between 1 and 100)"
        ),
    )
    parser.add_argument(
        "--connect",
        action="store_true",
        help=(
            "guided connect: find the Portal plugged in by USB, "
            "switch it to wireless ADB (adb tcpip 5555), read its "
            "Wi-Fi address from the device and connect to it. With "
            "action flags the run continues on the wireless "
            "connection; on its own it just connects and prints the "
            "serial to use. You still enable ADB in the Portal's "
            "Debug menu and tap Allow on its screen"
        ),
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "apply the full documented setup in one run: audio, "
            "debloat, remove-meta-accounts, optimize-presence, "
            "disable-adb-auth-timeout, and autoroot. Exactly the "
            "long flag line it replaces; the granular flags below "
            "remain for partial setups"
        ),
    )
    parser.add_argument(
        "--restore",
        action="append",
        choices=RESTORE_NAMES,
        default=[],
        metavar="NAME",
        help=(
            "restore one previously applied change to its recorded "
            "original state, or to the factory default when no original "
            "was recorded; repeat for several restores. Names: "
            + ", ".join(RESTORE_NAMES)
        ),
    )
    parser.add_argument(
        "--persistent-wireless-adb",
        action="store_true",
        help=(
            "make wireless ADB on TCP port 5555 survive reboots without "
            "applying any other provisioning feature"
        ),
    )
    parser.add_argument(
        "--disable-adb-auth-timeout",
        action="store_true",
        help=(
            "keep previously approved ADB host keys authorized indefinitely; "
            "this does not disable ADB authentication"
        ),
    )
    parser.add_argument(
        "--audio",
        action="store_true",
        help=(
            "stop the Portal from suppressing microphone audio while "
            "its speaker is playing; this is the default action when "
            "no provisioning action is specified"
        ),
    )
    parser.add_argument(
        "--skip-build", action="store_true", help="use existing build outputs"
    )
    parser.add_argument(
        "--bundle",
        type=pathlib.Path,
        default=None,
        metavar="PATH",
        help=(
            "use a prebuilt release bundle (directory or .zip) instead "
            "of building from source: the bundle is checked against "
            "the Portal's exact build before anything is installed, "
            "so the host needs only Python and adb"
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "redo the full provisioning from the start, even on an "
            "already provisioned Portal, instead of finishing early "
            "or applying only what changed; the provisioner's own "
            "packages are reinstalled even when unchanged"
        ),
    )
    shizuku_group = parser.add_mutually_exclusive_group()
    shizuku_group.add_argument(
        "--shizuku",
        action="store_true",
        help=(
            "install official Shizuku and a device-local boot helper "
            "that starts it after every boot with Android shell "
            "privileges"
        ),
    )
    shizuku_group.add_argument(
        "--remove-shizuku",
        action="store_true",
        help="remove Shizuku, its boot helper, and the helper's authorized ADB key",
    )
    parser.add_argument(
        "--shizuku-apk",
        type=pathlib.Path,
        metavar="PATH",
        help=(
            "use a local Shizuku APK with --shizuku instead of downloading "
            f"the pinned official {config.shizuku_version} release"
        ),
    )
    parser.add_argument(
        "--skip-shizuku-root",
        action="store_true",
        help=(
            "with --autoroot, leave Shizuku running with shell "
            "privileges instead of restarting it as root"
        ),
    )
    parser.add_argument(
        "--autoroot",
        action="store_true",
        help=(
            "root comes back by itself after every reboot, with no "
            "computer involved: the Portal re-roots on each boot and "
            "restarts Shizuku as root. Implies --shizuku"
        ),
    )
    parser.add_argument(
        "--verify-boots",
        type=int,
        choices=(1, 2),
        default=1,
        metavar="{1,2}",
        help=(
            "number of boots to verify the requested state on before "
            "PROVISION_OK (default: 1); 2 adds a second verification "
            "reboot"
        ),
    )
    parser.add_argument(
        "--system-theme-control",
        choices=("light", "dark"),
        metavar="{light,dark}",
        help=(
            "set the Android system theme (light or dark) on builds "
            "whose own settings have no theme switch"
        ),
    )
    parser.add_argument(
        "--debloat",
        action="store_true",
        help=(
            "turn off Meta's control and background services in one "
            "step: disable the tested list of Meta apps and "
            "background services (each one's original state is "
            "saved), block Meta system updates, block Meta remote "
            "wipe, turn Android Private DNS off so the Portal uses "
            "the network's DNS, and disable Meta's app verifier so "
            "non-Meta apps can update normally"
        ),
    )
    parser.add_argument(
        "--remove-meta-accounts",
        action="store_true",
        help=(
            "remove the Portal's local Meta accounts and turn off "
            "their sign-in services. This cannot be undone"
        ),
    )
    parser.add_argument(
        "--optimize-presence",
        action="store_true",
        help=(
            "lower the Smart Camera's processing work while person "
            "detection keeps running on the full camera view"
        ),
    )
    parser.add_argument(
        "--presence-fps-cap",
        type=int,
        metavar="FPS",
        help=(
            "cap only AIService's presence-analysis rate (1-10 FPS); "
            "camera capture keeps its configured frame rate"
        ),
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--status",
        action="store_true",
        help="print a read-only JSON health report without exploiting or rebooting",
    )
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="inspect the device and print the requested plan without changing it",
    )
    mode_group.add_argument(
        "--recover",
        action="store_true",
        help="resume an interrupted run from where it left off",
    )
    mode_group.add_argument(
        "--collect-diagnostics",
        action="store_true",
        help=(
            "collect a read-only diagnostics bundle (identity, bugreport, "
            "page-prep diagnostic) for any build, supported or not, and exit"
        ),
    )
    parser.add_argument(
        "--backup",
        type=pathlib.Path,
        metavar="PATH",
        help="create a timestamped diagnostic and configuration backup archive",
    )
    parser.add_argument(
        "--log-dir",
        type=pathlib.Path,
        help="directory for exploit attempt logs (default: a timestamp under /tmp)",
    )
    args = parser.parse_args()
    if not 1 <= args.attempts <= 100:
        parser.error("--attempts must be between 1 and 100")
    # --restore <name> maps onto the restore attributes the rest of
    # the shell (and the provisioner) already use; initialize them
    # all, then set the requested ones. Most names set one
    # attribute; the group names (RESTORE_GROUP_MAP) set several.
    for attribute in RESTORE_ATTRIBUTES:
        setattr(args, attribute, False)
    for name in args.restore:
        if name in RESTORE_GROUP_MAP:
            for attribute in RESTORE_GROUP_MAP[name]:
                setattr(args, attribute, True)
        else:
            setattr(args, RESTORE_FLAG_MAP[name], True)
    args.privacy_dns = None
    args.dhcp_dns = False
    args.allow_app_updates = False
    # Internal, not user options: these action attributes are set
    # by the debloat fold below (and by --full through it), never
    # by flags of their own anymore.
    args.disable_updates = False
    args.block_remote_wipe = False
    args.disable_camera_light = False
    # Internal, not a user option: the root-payload step always uses
    # the in-repo root daemon. Only the autoroot implication below
    # arms it; there is deliberately no flag (and no PATH override)
    # for it -- forking the repo is the supported way to change the
    # daemon.
    args.custom_payload = None
    # --full expands to exactly the documented full-setup line.
    if args.full:
        for attribute, value in FULL_PRESET.items():
            setattr(args, attribute, value)
    # Debloat is the single Meta-control removal command. It
    # carries four fellow-traveller changes with it: Meta system
    # updates are blocked, Meta remote wipe is blocked, a
    # debloated Portal uses the network's own DNS (Android
    # Private DNS off; no resolver-hostname form), and Meta's app
    # verifier is disabled so non-Meta apps can update. None of
    # them has a flag of its own anymore. The internal attributes
    # set here — disable_updates, block_remote_wipe, dhcp_dns and
    # allow_app_updates — are what the applies, the verifies, the
    # manifest recording and the recorded-state readers all key
    # off, exactly as before.
    if args.debloat:
        args.disable_updates = True
        args.block_remote_wipe = True
        args.dhcp_dns = True
        args.allow_app_updates = True
    # Apply/restore pairs for one feature stay mutually exclusive,
    # as they were when each pair had its own flag group.
    for apply_attribute, restore_name, apply_label in (
        ("audio", "audio", "--audio"),
        ("debloat", "debloat", "--debloat"),
        ("optimize_presence", "presence", "--optimize-presence"),
        (
            "disable_adb_auth_timeout",
            "adb-auth-timeout",
            "--disable-adb-auth-timeout",
        ),
    ):
        if getattr(args, apply_attribute) and restore_name in args.restore:
            parser.error(
                f"{apply_label} cannot be combined with "
                f"--restore {restore_name}"
            )
    if args.optimize_presence and "presence-fps" in args.restore:
        parser.error(
            "--optimize-presence cannot be combined with "
            "--restore presence-fps"
        )
    if "presence" in args.restore and "presence-fps" in args.restore:
        parser.error(
            "--restore presence cannot be combined with "
            "--restore presence-fps"
        )
    if args.persistent_wireless_adb and "wireless-adb" in args.restore:
        parser.error(
            "--persistent-wireless-adb cannot be combined with "
            "--restore wireless-adb"
        )
    if args.autoroot and "autoroot" in args.restore:
        parser.error("--autoroot cannot be combined with --restore autoroot")
    if args.shizuku and "autoroot" in args.restore:
        parser.error(
            "--shizuku cannot be combined with --restore autoroot "
            "(the restore removes the shared helper key)"
        )
    if args.remove_meta_accounts and "meta-authenticators" in args.restore:
        parser.error(
            "--remove-meta-accounts cannot be combined with "
            "--restore meta-authenticators"
        )
    if args.system_theme_control is not None and "theme" in args.restore:
        parser.error(
            "--system-theme-control cannot be combined with --restore theme"
        )
    if args.presence_fps_cap is not None and not 1 <= args.presence_fps_cap <= 10:
        parser.error("--presence-fps-cap must be between 1 and 10")
    if args.presence_fps_cap is not None and (
        args.restore_presence_profile or args.restore_presence_fps
    ):
        parser.error(
            "--presence-fps-cap cannot be combined with a presence rollback"
        )
    if args.presence_fps_cap is not None:
        # The activation activity also applies Meta's other camera toggles.
        # Always pair the cap with the tested full-scene presence profile.
        args.optimize_presence = True
    if args.persistent_wireless_adb:
        if args.restore_adb_auth_timeout:
            parser.error(
                "--persistent-wireless-adb cannot be combined with "
                "--restore adb-auth-timeout"
            )
        args.disable_adb_auth_timeout = True
    if args.autoroot:
        if args.remove_shizuku:
            parser.error("--autoroot cannot be combined with --remove-shizuku")
        # Autoroot's boot helper reuses the Shizuku loopback-ADB key
        # and its runner replays the root payload, so both steps are
        # prerequisites. Imply them instead of silently staging an
        # autoroot setup that can never run (the previous behaviour
        # when either was forgotten).
        args.shizuku = True
        args.custom_payload = config.default_custom_payload
    selected = any(
        (
            args.autoroot,
            args.persistent_wireless_adb,
            args.disable_adb_auth_timeout,
            args.restore_adb_auth_timeout,
            args.audio,
            args.restore_audio,
            args.disable_updates,
            args.enable_updates,
            args.block_remote_wipe,
            args.restore_remote_wipe,
            args.debloat,
            args.restore_bloat,
            args.remove_meta_accounts,
            args.optimize_presence,
            args.restore_presence_profile,
            args.presence_fps_cap is not None,
            args.restore_presence_fps,
            args.privacy_dns,
            args.dhcp_dns,
            args.restore_privacy_dns,
            args.allow_app_updates,
            args.restore_app_verifier,
            args.shizuku,
            args.remove_shizuku,
            args.disable_camera_light,
            args.restore_camera_light,
            args.restore_autoroot,
            args.restore_wireless_adb,
            args.restore_theme,
            args.restore_meta_authenticators,
            args.system_theme_control is not None,
        )
    )
    if args.shizuku_apk and not args.shizuku:
        parser.error("--shizuku-apk requires --shizuku")
    if args.recover and selected:
        parser.error("--recover resumes its saved action set and cannot take action flags")
    if args.recover and args.backup:
        parser.error("--recover cannot be combined with --backup")
    if args.status and selected:
        parser.error("--status cannot be combined with provisioning actions")
    if args.collect_diagnostics and selected:
        parser.error(
            "--collect-diagnostics cannot be combined with provisioning actions"
        )
    if args.collect_diagnostics and args.backup:
        parser.error("--collect-diagnostics cannot be combined with --backup")
    args.backup_only = (
        args.backup is not None
        and not selected
        and not any(
            (args.status, args.dry_run, args.recover, args.collect_diagnostics)
        )
    )
    if not selected and not any(
        (
            args.status,
            args.dry_run,
            args.recover,
            args.backup,
            args.collect_diagnostics,
        )
    ):
        args.audio = True
    return args


_IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _adb_devices() -> list[tuple[str, str]]:
    """(serial, state) pairs `adb devices` reports; empty when adb
    is missing or the listing fails."""
    adb = shutil.which("adb")
    if adb is None:
        return []
    try:
        result = subprocess.run(
            [adb, "devices"], capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError):
        return []
    pairs = []
    for line in result.stdout.splitlines():
        serial, separator, state = line.partition("\t")
        if separator and state.strip():
            pairs.append((serial.strip(), state.strip()))
    return pairs


def _resolve_serial(args: argparse.Namespace) -> tuple[str | None, str | None]:
    """Resolve the target serial: (serial, None) or (None, error).

    A bare IPv4 address gains the default wireless-ADB port. With
    no --serial, the only connected device is used; anything else
    is an error that lists what adb currently sees.
    """
    serial = (args.serial or "").strip()
    if serial:
        if _IPV4_PATTERN.match(serial):
            serial = f"{serial}:5555"
        return serial, None
    devices = _adb_devices()
    usable = [item for item, state in devices if state == "device"]
    if len(usable) == 1:
        print(
            f"Using the only connected Portal: {usable[0]}",
            file=sys.stderr,
        )
        return usable[0], None
    seen = ", ".join(f"{item} ({state})" for item, state in devices) or "none"
    return None, (
        "--serial is required; pass the target Portal's adb serial "
        f"(e.g. --serial 192.0.2.1:5555). adb currently sees: {seen}"
    )


def _adb_command(
    arguments: list[str], timeout: float = 15
) -> subprocess.CompletedProcess:
    adb = shutil.which("adb")
    if adb is None:
        raise ProvisionError("adb was not found on your PATH")
    try:
        return subprocess.run(
            [adb, *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvisionError(f"adb failed: {exc}") from exc


_WIFI_IPV4 = re.compile(r"inet (\d{1,3}(?:\.\d{1,3}){3})/")
_ROUTE_SRC = re.compile(r"\bsrc (\d{1,3}(?:\.\d{1,3}){3})")


def _portal_wifi_ip(usb_serial: str) -> str | None:
    """The Portal's Wi-Fi IPv4 address, read on the device over
    USB: `ip addr show wlan0` first (verified live on aloha and
    omni), the route source address as fallback."""
    result = _adb_command(
        ["-s", usb_serial, "shell", "ip", "addr", "show", "wlan0"]
    )
    match = _WIFI_IPV4.search(result.stdout)
    if match:
        return match.group(1)
    result = _adb_command(["-s", usb_serial, "shell", "ip", "route"])
    match = _ROUTE_SRC.search(result.stdout)
    if match:
        return match.group(1)
    return None


def guided_connect(wait_seconds: int = 180) -> str:
    """Connect to a USB-attached Portal over Wi-Fi ADB and return
    its wireless serial.

    The user-side steps stay the user's: ADB must be enabled in
    the Portal's Debug menu, and the Allow prompt must be tapped
    on the Portal screen. This waits for both, saying what is
    missing while it waits.
    """
    print(
        "Guided connect: plug the Portal in by USB. If ADB is off, "
        "open the Portal's Debug menu and turn ADB on.",
        flush=True,
    )
    deadline = time.monotonic() + wait_seconds
    usb_serial: str | None = None
    said_allow = False
    while time.monotonic() < deadline:
        usb = [
            (serial, state)
            for serial, state in _adb_devices()
            if ":" not in serial
        ]
        ready = [serial for serial, state in usb if state == "device"]
        if len(ready) > 1:
            raise ProvisionError(
                "more than one USB device is connected "
                f"({', '.join(ready)}); unplug the others and run "
                "--connect again"
            )
        if ready:
            usb_serial = ready[0]
            break
        if any(state == "unauthorized" for _, state in usb) and (
            not said_allow
        ):
            print(
                "The Portal is waiting for approval: look at its "
                "screen and tap Allow for this computer.",
                flush=True,
            )
            said_allow = True
        time.sleep(3)
    if usb_serial is None:
        raise ProvisionError(
            f"no USB Portal appeared after {wait_seconds}s; check "
            "the cable, and that ADB is on in the Portal's Debug menu"
        )
    print(
        f"Found the Portal on USB ({usb_serial}); reading its "
        "Wi-Fi address...",
        flush=True,
    )
    address = _portal_wifi_ip(usb_serial)
    if address is None:
        raise ProvisionError(
            "could not read the Portal's Wi-Fi address; is the "
            "Portal connected to Wi-Fi?"
        )
    _adb_command(["-s", usb_serial, "tcpip", "5555"])
    serial = f"{address}:5555"
    deadline = time.monotonic() + 60
    said_allow = False
    while time.monotonic() < deadline:
        _adb_command(["connect", serial])
        state = _adb_command(["-s", serial, "get-state"])
        if state.returncode == 0:
            print(f"Connected: {serial}", flush=True)
            return serial
        if "unauthorized" in (state.stdout + state.stderr) and (
            not said_allow
        ):
            print(
                "Look at the Portal screen and tap Allow for this "
                "computer.",
                flush=True,
            )
            said_allow = True
        time.sleep(3)
    raise ProvisionError(
        f"the Portal did not answer at {serial}; check it is still "
        "on the same Wi-Fi network and run --connect again"
    )


#: Attributes that make a run an action run (as opposed to a bare
#: --connect). Run controls (--force, --attempts, --verify-boots,
#: --log-dir, --bundle, --skip-build) are not actions, and neither
#: is audio: it defaults on, so it cannot mark an explicit ask.
_ACTION_ATTRIBUTES = (
    "full",
    "restore",
    "status",
    "dry_run",
    "backup",
    "recover",
    "collect_diagnostics",
    "debloat",
    "remove_meta_accounts",
    "optimize_presence",
    "presence_fps_cap",
    "system_theme_control",
    "disable_camera_light",
    "autoroot",
    "remove_shizuku",
)


def _connect_only(args: argparse.Namespace) -> bool:
    return not any(getattr(args, name, None) for name in _ACTION_ATTRIBUTES)


def main(
    config: CliConfig, provisioner_factory: Callable[..., Any]
) -> int:
    args = parse_args(config)
    if args.connect:
        if shutil.which("adb") is None:
            print(
                "PROVISION_ERROR: adb was not found on your PATH. "
                "Install the Android platform-tools (they provide "
                "adb), make sure adb is on your PATH, and run this "
                "again.",
                file=sys.stderr,
            )
            return 2
        try:
            args.serial = guided_connect()
        except ProvisionError as exc:
            print(f"PROVISION_ERROR: {exc}", file=sys.stderr)
            return 1
        if _connect_only(args):
            print(
                "To provision it, run:\n"
                f"  python3 tools/provision_portal.py --serial "
                f"{args.serial} --full"
            )
            return 0
    serial, serial_error = _resolve_serial(args)
    if serial is None:
        print(f"PROVISION_ERROR: {serial_error}", file=sys.stderr)
        return 2
    if shutil.which("adb") is None:
        print(
            "PROVISION_ERROR: adb was not found on your PATH. Install "
            "the Android platform-tools (they provide adb), make sure "
            "adb is on your PATH, and run this again.",
            file=sys.stderr,
        )
        return 2
    bundle = args.bundle
    if bundle is None:
        # Running from inside an extracted release bundle: default
        # to that bundle instead of falling into the source-build
        # path, which would demand a toolchain the bundle user
        # does not have.
        tree_root = pathlib.Path(__file__).resolve().parent.parent
        if (tree_root / "bundle-manifest.json").is_file():
            bundle = tree_root
            print(
                f"Using the release bundle in {tree_root} "
                "(bundle-manifest.json found next to the tool)",
                file=sys.stderr,
            )
    print(config.banner, file=sys.stderr, flush=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = args.log_dir or (
        pathlib.Path(tempfile.gettempdir()) / f"portal-provision-{stamp}"
    )
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        provisioner_factory(
            serial,
            args.attempts,
            log_dir,
            audio=args.audio,
            restore_audio=args.restore_audio,
            disable_updates=args.disable_updates,
            enable_updates=args.enable_updates,
            block_remote_wipe=args.block_remote_wipe,
            restore_remote_wipe=args.restore_remote_wipe,
            debloat=args.debloat,
            restore_bloat=args.restore_bloat,
            remove_meta_accounts=args.remove_meta_accounts,
            optimize_presence=args.optimize_presence,
            restore_presence_profile=args.restore_presence_profile,
            presence_fps_cap=args.presence_fps_cap,
            restore_presence_fps=args.restore_presence_fps,
            privacy_dns=args.privacy_dns,
            dhcp_dns=args.dhcp_dns,
            restore_privacy_dns=args.restore_privacy_dns,
            allow_app_updates=args.allow_app_updates,
            restore_app_verifier=args.restore_app_verifier,
            shizuku=args.shizuku,
            remove_shizuku=args.remove_shizuku,
            disable_camera_light=args.disable_camera_light,
            restore_camera_light=args.restore_camera_light,
            system_theme_control=args.system_theme_control,
            shizuku_apk=args.shizuku_apk,
            custom_payload=args.custom_payload,
            skip_shizuku_root=args.skip_shizuku_root,
            autoroot=args.autoroot,
            verify_boots=args.verify_boots,
            status_only=args.status or args.backup_only,
            dry_run=args.dry_run,
            collect_diagnostics=args.collect_diagnostics,
            backup_path=args.backup,
            recover=args.recover,
            skip_build=args.skip_build,
            bundle=bundle,
            force=args.force,
            persistent_wireless_adb=args.persistent_wireless_adb,
            disable_adb_auth_timeout=args.disable_adb_auth_timeout,
            restore_adb_auth_timeout=args.restore_adb_auth_timeout,
            restore_autoroot=args.restore_autoroot,
            restore_wireless_adb=args.restore_wireless_adb,
            restore_theme=args.restore_theme,
            restore_meta_authenticators=args.restore_meta_authenticators,
        ).provision()
    except (ProvisionError, OSError, zipfile.BadZipFile) as exc:
        print(f"PROVISION_ERROR: {exc}", file=sys.stderr)
        return 1
    return 0
