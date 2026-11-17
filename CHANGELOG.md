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

- A failed run's error cleanup uninstalled the exploit sentinel
  package even when autoroot staging was in place (staged by that
  run or an earlier one). Staged autoroot replays the exploit on
  every boot and needs the sentinel, so the device was left with
  autoroot that could never win until a later host run reinstalled
  the package. The failure paths now retain the sentinel whenever
  autoroot is staged, matching the success path.
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
- OTA block: the local override now also stops the OTA daemon's
  update polling. With only the firmware gate off, the daemon still
  contacted Meta's update servers every few minutes; the override now
  also sets the poll intervals to 1000000 minutes and points the
  update query URL at a closed local port (ported from upstream
  5c2c531d). Gate-only overrides installed by earlier versions are
  upgraded in place. OTA preflight and verification now read the
  daemon's config with retries (a dump cut off while the daemon is
  starting no longer reads as a stock value) and require both the
  gate and polling to be off.
- OTA block and presence profile actions leaked into the main flow's
  standard-install attempts on targets where a dedicated phase owns
  them. When the dedicated phase's verification stayed unverified,
  the main flow continued with the action still marked unconfigured,
  so its attempts carried the action under init's credential; the
  native action writes inside an app-private directory, failed with
  EACCES, and every race those attempts won was discarded. Both keys
  are now phase-gated to the dedicated phases on targets that have
  one; targets without a dedicated credential phase are unchanged.
  Attempts now log their credential source and GHOSTLOCK_* keys, the
  watch verdict names the failed action next to its step number, and
  the action child's log output is captured through shared memory
  into the per-attempt log.

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
