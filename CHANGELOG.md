# Changelog

All notable changes to this project are recorded here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).
The provisioner's version string lives in
`tools/provision_portal.py` (`PROVISIONER_VERSION`) and release tags
must match it.

## [Unreleased]

Pre-release development toward 1.0.0 in this fork. Highlights since
the fork diverged from upstream:

### Added

- On-device autoroot: after a one-time provisioning, the device
  re-roots itself after every reboot with no host attached (Shizuku
  started as root by the autoroot helper).
- Root-mode Shizuku integration, root daemon with lock repair, and
  the exploit sentinel package.
- NOTICE file, per-file Apache-2.0 SPDX headers, SECURITY.md,
  CONTRIBUTING.md, issue/PR templates, CI, and a tag-driven release
  workflow that publishes CI-built binaries with SHA-256 checksums.
- `--collect-diagnostics`: read-only mode that works on any build,
  supported or not, and writes one zip bundle (identity props,
  bugreport archive, the sibling target's write-free page-prep
  diagnostic, MobileConfig backend inventory, best-effort kernel
  config/kallsyms, and a manifest) so support for a new firmware
  build can be evaluated without owning the device.
- Exploit attempts now log their subprocess return code and how the
  output stream ended (`INSTALL_ATTEMPT_EXIT`), and a KernelSnitch
  mm_struct leak failure is classified as an attempt failure instead
  of ending the attempt silently.

### Fixed

- Aloha OTA block: the local MobileConfig override was never read by
  the native OTA daemon, because the native MobileConfig util selects
  a legacy backend service that does not exist on Aloha (upstream
  issue #31, reported and fixed by feynmanliang). On Aloha,
  `--disable-updates` now pins the platform backend inside the
  managed override and sets
  `persist.sys.mobileconfigutil.usePlatformMobileConfig=true` in a
  separate system-identity phase; the original value is saved and
  restored by `--enable-updates`. Overrides installed by earlier
  versions are upgraded in place. OTA verification on Aloha now
  requires positive evidence the override is in effect and records
  the action as unverified when that evidence is absent, instead of
  reporting success from the gate value alone.

### Changed

- `--verify-boots` now defaults to 1 (one verification boot).
- `--serial` is required: the hardcoded default (a personal LAN
  address) was removed.
- Streamlined run internals: identical APKs are no longer
  reinstalled, repeat artifact hashing is cached per run, settle
  sleeps happen only before reboots, reboot waits poll with a single
  adb probe, and verify loops read logcat incrementally.

### Removed

- The de-Kiosk scrub: all Kiosk Satellite profile/home/device-owner
  flags and their backing code. Kiosk setup now lives in the
  operator's own bootstrap tooling, not in this provisioner.
- `docs/` (upstream lab journals that described removed features as
  current and carried personal network details).
- Upstream donation links (`.github/funding.yml`, README support
  section). Credit to the original author is unchanged.

## [1.0.0] - TBD

First tagged release, to be cut in the standalone successor
repository. Nothing is tagged in this fork.
