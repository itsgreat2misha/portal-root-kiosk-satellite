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
import sys
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


#: Names accepted by --restore <name>. Each maps onto the provisioner's
#: existing restore attributes (see RESTORE_FLAG_MAP); the four names
#: marked Phase D close restore-completeness gaps the audit found
#: (autoroot, wireless-adb, theme, meta-authenticators).
RESTORE_NAMES = (
    "audio",
    "bloat",
    "remote-wipe",
    "updates",
    "dns",
    "presence",
    "presence-fps",
    "adb-auth-timeout",
    "app-verifier",
    "camera-light",
    "autoroot",
    "wireless-adb",
    "theme",
    "meta-authenticators",
)

#: --restore name -> provisioner attribute it sets.
RESTORE_FLAG_MAP = {
    "audio": "restore_audio",
    "bloat": "restore_bloat",
    "remote-wipe": "restore_remote_wipe",
    "updates": "enable_updates",
    "dns": "restore_privacy_dns",
    "presence": "restore_presence_profile",
    "presence-fps": "restore_presence_fps",
    "adb-auth-timeout": "restore_adb_auth_timeout",
    "app-verifier": "restore_app_verifier",
    "camera-light": "restore_camera_light",
    "autoroot": "restore_autoroot",
    "wireless-adb": "restore_wireless_adb",
    "theme": "restore_theme",
    "meta-authenticators": "restore_meta_authenticators",
}

#: The documented full-setup line, as --full expands it: attribute ->
#: value. --full is a preset only; it sets exactly these flags and
#: nothing else (the taste opt-ins --presence-fps-cap and
#: --system-theme-control stay out by design).
FULL_PRESET = {
    "audio": True,
    "disable_updates": True,
    "block_remote_wipe": True,
    "debloat": True,
    "remove_meta_accounts": True,
    "optimize_presence": True,
    "allow_app_updates": True,
    "disable_adb_auth_timeout": True,
    "dhcp_dns": True,
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
            "adb serial of the target Portal (required), e.g. "
            "192.0.2.1:5555 for wireless adb or a USB serial"
        ),
    )
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "apply the full documented setup in one run: audio, "
            "disable-updates, block-remote-wipe, debloat, "
            "remove-meta-accounts, optimize-presence, allow-app-updates, "
            "disable-adb-auth-timeout, DHCP DNS (Private DNS off), and "
            "autoroot. Exactly the long flag line it replaces; the "
            "granular flags below remain for partial setups"
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
            "install the persistent hardware AEC/NS watchdog; this remains "
            "the default action when no provisioning action is specified"
        ),
    )
    parser.add_argument(
        "--skip-build", action="store_true", help="use existing build outputs"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "bypass the re-run fast paths (the already-provisioned no-op "
            "exit and the root-channel apply) and run the full race-based "
            "provision, re-installing the provisioner's own packages even "
            "when they are byte-identical; the autoroot guard still applies"
        ),
    )
    shizuku_group = parser.add_mutually_exclusive_group()
    shizuku_group.add_argument(
        "--shizuku",
        action="store_true",
        help=(
            "install official Shizuku and a device-local boot helper that "
            "starts it with Android shell privileges through loopback ADB"
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
        "--custom-payload",
        type=pathlib.Path,
        nargs="?",
        const=config.default_custom_payload,
        default=None,
        metavar="PATH",
        help=(
            "start a prebuilt binary inside one privileged window: it "
            "is installed under /data/portal-root, started detached as "
            "root, and verified over its loopback socket for the rest "
            "of the current boot (no post-run reboot). The PATH is "
            "optional: a bare --custom-payload builds and uses this "
            "repository's root daemon (root-daemon/portal-root-daemon); "
            "pass an explicit PATH to use a different binary instead"
        ),
    )
    parser.add_argument(
        "--skip-shizuku-root",
        action="store_true",
        help=(
            "with --shizuku and --custom-payload, leave shizuku_server "
            "running with shell privileges instead of restarting it as "
            "uid 0 through the root payload"
        ),
    )
    parser.add_argument(
        "--autoroot",
        action="store_true",
        help=(
            "stage the on-device autoroot runner and boot helper so "
            "the root payload returns by itself after later reboots, "
            "with no host watcher (the exploit sentinel app stays "
            "installed). Implies --shizuku and --custom-payload (a "
            "bare --custom-payload, i.e. the in-repo root daemon, "
            "unless one was given explicitly)"
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
            "set the live Android system theme; on locked Android 10 builds, "
            "install or reuse the constrained UID-1000 theme controller"
        ),
    )
    parser.add_argument(
        "--allow-app-updates",
        action="store_true",
        help=(
            "persistently disable Meta's certificate allowlist so "
            "third-party and other non-Meta apps can update"
        ),
    )
    parser.add_argument(
        "--disable-updates",
        action="store_true",
        help=(
            "disable Meta's OTA UI/test packages and install a persistent "
            "MobileConfig override for the native OTA daemon"
        ),
    )
    parser.add_argument(
        "--block-remote-wipe",
        action="store_true",
        help=(
            "disable Meta's two known factory-reset and remote-wipe receivers "
            "without disabling the rest of the device-admin package"
        ),
    )
    parser.add_argument(
        "--disable-camera-light",
        action="store_true",
        help=(
            "retired unsafe action; Meta's camera provider rejects capture "
            "while its green indicator is cleared"
        ),
    )
    parser.add_argument(
        "--debloat",
        action="store_true",
        help=(
            "persistently disable the conservative Meta app/telemetry "
            "profile and save each package's original state"
        ),
    )
    parser.add_argument(
        "--remove-meta-accounts",
        action="store_true",
        help=(
            "remove the three Portal user accounts locally and persistently "
            "disable only their authenticator service components"
        ),
    )
    parser.add_argument(
        "--optimize-presence",
        action="store_true",
        help=(
            "disable Smart Camera background segmentation, liveness scoring, "
            "and re-identification, force full-frame capture, and require "
            "AIService's analysis and pose pipeline to remain live"
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
    parser.add_argument(
        "--dns",
        metavar="off|HOSTNAME",
        help=(
            "set Android Private DNS: 'off' uses the DNS servers supplied "
            "by the connected network (DHCP); any other value is a "
            "DNS-over-TLS resolver hostname, and that resolver controls "
            "the actual domain block list"
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
        help="clean stale staging and resume actions from a pending state manifest",
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
    # all, then set the requested ones.
    for attribute in RESTORE_FLAG_MAP.values():
        setattr(args, attribute, False)
    for name in args.restore:
        setattr(args, RESTORE_FLAG_MAP[name], True)
    args.privacy_dns = None
    args.dhcp_dns = False
    # --full expands to exactly the documented full-setup line.
    if args.full:
        for attribute, value in FULL_PRESET.items():
            setattr(args, attribute, value)
    # --dns replaces --dhcp-dns / --privacy-dns: "off" is the DHCP
    # mode, anything else is the resolver hostname. An explicit
    # --dns also replaces the --full preset's DNS component: the
    # pair is reset before the value is applied, so a composed
    # config never carries two contradictory DNS intents (the
    # applies, the verify, the manifest recording and the
    # recorded-state readers all key off this pair and cannot
    # agree on one that holds both).
    if args.dns is not None:
        args.privacy_dns = None
        args.dhcp_dns = False
        if args.dns.lower() == "off":
            args.dhcp_dns = True
        elif args.dns.strip():
            args.privacy_dns = args.dns
        else:
            parser.error("--dns needs 'off' or a resolver hostname")
    # Apply/restore pairs for one feature stay mutually exclusive,
    # as they were when each pair had its own flag group.
    for apply_attribute, restore_name, apply_label in (
        ("audio", "audio", "--audio"),
        ("disable_updates", "updates", "--disable-updates"),
        ("block_remote_wipe", "remote-wipe", "--block-remote-wipe"),
        ("debloat", "bloat", "--debloat"),
        ("optimize_presence", "presence", "--optimize-presence"),
        ("allow_app_updates", "app-verifier", "--allow-app-updates"),
        (
            "disable_adb_auth_timeout",
            "adb-auth-timeout",
            "--disable-adb-auth-timeout",
        ),
        ("disable_camera_light", "camera-light", "--disable-camera-light"),
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
    if (args.privacy_dns or args.dhcp_dns) and "dns" in args.restore:
        parser.error("--dns cannot be combined with --restore dns")
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
        # and its runner replays the custom payload, so both steps are
        # prerequisites. Imply them instead of silently staging an
        # autoroot setup that can never run (the previous behaviour
        # when either was forgotten).
        args.shizuku = True
        if args.custom_payload is None:
            args.custom_payload = config.default_custom_payload
    selected = any(
        (
            args.custom_payload is not None,
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
    if args.disable_camera_light:
        parser.error(
            "--disable-camera-light has been retired because it breaks camera "
            "capture. Run --restore camera-light on previously provisioned "
            "devices."
        )
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


def main(
    config: CliConfig, provisioner_factory: Callable[..., Any]
) -> int:
    args = parse_args(config)
    if not args.serial:
        print(
            "PROVISION_ERROR: --serial is required; pass the target Portal's "
            "adb serial (e.g. --serial 192.0.2.1:5555)",
            file=sys.stderr,
        )
        return 2
    print(config.banner, file=sys.stderr, flush=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = args.log_dir or pathlib.Path(f"/tmp/portal-provision-{stamp}")
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        provisioner_factory(
            args.serial,
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
