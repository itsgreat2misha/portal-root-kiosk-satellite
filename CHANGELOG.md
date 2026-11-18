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
- Autoroot failure budget: the on-device helper counts only truly
  incomplete attempts across boots (an attempt that started but
  never recorded a verdict - the crash/freeze signature; clean race
  losses never count) and stands itself down after 10 in a row,
  posting a persistent notification instead of crash-looping the
  device on every boot. The user can re-enable autoroot from the
  helper screen, where the risk is stated; the budget re-arms after
  a re-enable, and a provisioner re-stage also clears the
  stand-down. Provision runs report a found stand-down
  (`AUTOROOT_STOOD_DOWN`) when they connect.
- otad.nodemon on Aloha: `--disable-updates` now also sets the OTA
  daemon's own `otad.nodemon` property for the current boot. While
  set, otad's loop never calls its update path, so the daemon makes
  no periodic check-ins and applies no updates; this is independent
  of the MobileConfig override, whose verification is unchanged.
  The property service accepts the write only from init's SELinux
  context, so the native payload performs the set in an action
  child carrying that context (the standard-install phase's own
  child, or a dedicated child when the main child preserves the
  shell domain), and the run reports the child's read-back
  (`OTA_NODEMON_SET` / `OTA_NODEMON_SET_FAILED`); `--status`
  reports the property's current value. The property is not
  persistent, so the staged autoroot payload re-asserts it after
  every boot when the staged config records updates as disabled
  (`OTA_NODEMON=1`, cleared by `--enable-updates`, preserved
  across unrelated re-staging).
- Project debug signing key: the debug keystore is committed at the
  repository root (`debug.keystore`) and every build must sign with
  it. The build-environment check verifies the active keystore's
  certificate fingerprint and fails on a mismatch or a missing
  keystore instead of letting a replacement key be generated, since
  devices refuse signature-mismatched APK updates.
- Private DNS end-state invariant: a completed run's manifest
  records the Private DNS end state it established, and every
  later run enforces that record. Final verification compares the
  live `private_dns_mode`/`private_dns_specifier` to the recorded
  state even when the run requested no DNS change; on drift the
  recorded state is re-written, the repair is logged
  (`PRIVACY_DNS_DRIFT` / `PRIVACY_DNS_REPAIRED`), and the result
  is re-read before the run completes. The no-op fast path reads
  live DNS and may not pass over drift: drift routes to the
  root-channel apply path, whose final verification performs the
  repair.

### Changed

- The autoroot failure-budget stand-down threshold rises from 5 to
  10 consecutive truly incomplete boots. Live sessions showed the
  verdict-less (crash/freeze) loss shape is common enough on a
  healthy unit that a streak of 5 was within reach of ordinary bad
  luck; 10 keeps the cross-boot bound on a deterministically
  wedging unit while making a false stand-down far less likely.
  The helper screen, the stand-down notification and the docs state
  the new number. Autoroot helper 1.9 (versionCode 10).
- The race path and the root-channel path now run one shared
  host shell-level apply sequence instead of two hand-mirrored
  copies, so their end states cannot drift apart. As part of the
  merge, the stages path's Private DNS write moves from before
  the races to final verification, where a race crash-reboot can
  no longer discard its SettingsProvider flush.
- Exploit environment gating: `GHOSTLOCK_RESTORE_OTA_BLOCK`,
  `GHOSTLOCK_RESTORE_PRESENCE_PROFILE`,
  `GHOSTLOCK_RESTORE_PRESENCE_FPS` and the presence FPS cap keys
  now follow the same phase-ownership predicates as their apply
  counterparts, so they are carried only by the phase whose
  credential can perform them (or by the main flow on targets
  with no dedicated phase). `GHOSTLOCK_UID1000_PRESENCE_FPS`
  stays in the main flow by design: its consumers are the
  uid1000 runtime feature configuration and the retained-FPS
  carriage, not the app-private write the cap keys drive.

### Fixed

- A winning autoroot attempt whose process tree wedged (spinning
  or ptrace-stopped) held the Shizuku handoff for ~13 minutes
  until the processes happened to exit: the service now sweeps
  the attempt's leftover process tree after every attempt's
  verdict (the root daemon and Shizuku server are never swept),
  and the handoff's post-starter wait is bounded by a 120 s
  wall-clock deadline with a re-sweep and one retry before the
  handoff is left for the next service start. Autoroot helper
  1.9 (versionCode 10) in this release.
- The post-attempt sweep above could not shorten a winning
  attempt's stall: it runs only after the attempt's foreground
  shell call returns, and that call returns only at its own
  600 s socket timeout, which is itself what tears the wedged
  session down (live validation showed win-to-handoff still
  ~9 minutes, resolved by the timeout, with the sweep never
  finding a live target). The attempt watchdog now also sweeps
  from its own poll loop, the one thread alive during the
  stall: once a win verdict is 120 s old and the call is still
  outstanding, and once more 120 s later, it sweeps the
  attempt's leftover tree and logs the outcome whether or not
  anything was killed. A win verdict is still never cut, the
  600 s timeout remains the backstop, and verdict accounting
  is unchanged. Autoroot helper 1.10 (versionCode 11).
- The orphan sweep's ps snapshot read the COMM column, which
  on this device's toybox ps carries the executable name, not
  the task name: the /system/bin/true host reported as
  "toybox" (its exe resolves to the toybox binary), so the
  sweep's kill set was always empty against a real wedged
  tree. Invisible while the sweep only ran after a stall had
  already ended; the win-stall sweep above exposed it on its
  first live run against a live tree, logging empty kill sets
  while the tree stood in ps under NAME as "true". The
  snapshot now reads the NAME column. Autoroot helper 1.11
  (versionCode 12).
- The autoroot guard's restore could print
  `AUTOROOT_GUARD_RESTORED` over a disable flag that was still
  on disk: issued into an adbd disruption (Run 34), its rm never
  landed and the exit-code presence check read the broken
  transport as "absent". The flag probe now answers with an
  explicit token (a tokenless answer is a transport failure,
  never a state), and the restore applies and verifies in a
  bounded retry loop, reporting `AUTOROOT_GUARD_RESTORE_FAILED`
  whenever the wanted end state is not verified on the device.
- The autoroot failure budget counted clean race losses as
  incomplete attempts whenever the loss's reboot outran the
  helper service's own verdict write (three such boots stood a
  healthy unit down in live testing). The race's verdict is
  already in attempt.log by then, so the in-progress mark now
  records the attempt's attempt.log offset and boot-time
  accounting recovers a fail verdict from the log, counting the
  attempt as the completed loss it was; the offset is consumed
  with the mark, so a recovered verdict can never cover for a
  later attempt. The stand-down threshold also rises from 3 to 5
  consecutive truly incomplete boots.
- A `--force` run hard-failed the autoroot staging install with
  `INSTALL_FAILED_UPDATE_INCOMPATIBLE` when the on-device helper
  was signed by an older build host's keystore: the provisioner
  wrapper nulled the package name to bypass the byte-identical
  install skip, and the signature-mismatch retry is gated on that
  same name, so the retry was silently disarmed for every install
  in a force run. `--force` now bypasses only the skip (an explicit
  flag into the install seam); the package always goes through, so
  the retry stays armed for the provisioner's own packages in
  every run mode.
- `--remove-meta-accounts` aborted at final verification when the
  alohausers package itself was disabled (a legitimate prior state:
  a user trial, another tool), wasting the run's completed race
  work. Preflight now detects the disabled package and no longer
  treats the device as already clean; the native action then
  enables the package from its own credential context (shell
  `pm enable` is denied for uid 2000 on this build) before applying
  the authenticator state, logging
  `META_ACCOUNTS_PACKAGE_ENABLED prior=disabled`. The final
  verification is unchanged and now passes because the action
  produces the designed state (package enabled, authenticators
  disabled); a failed enable fails the action at that point.
- A failed run's error cleanup uninstalled the exploit sentinel
  package even when autoroot staging was in place (staged by that
  run or an earlier one). Staged autoroot replays the exploit on
  every boot and needs the sentinel, so the device was left with
  autoroot that could never win until a later host run reinstalled
  the package. The failure paths now retain the sentinel whenever
  autoroot is staged, matching the success path.
- An abort landing after a phase's own cleanup had already removed
  the exploit sentinel (run37b: a verification failure after the
  install loop's phase-end removal) still stranded staged autoroot,
  because no later phase re-staged the package. A run-exit guarantee
  now enforces the sentinel's end state on every exit of the
  outermost run: when autoroot is staged, the sentinel is left
  installed, reinstalled when a phase-end removal was the last word,
  and a failed reinstall fails the run instead of being swallowed.
  This closes the phase-end-removal case flagged as ambiguous in the
  earlier sentinel-retention fix.
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
- OTA block install: three early returns in the native install
  function (existing override not a regular file, absence-marker
  write failure, temp-file open failure) returned failure without
  logging, so the captured per-attempt log had nothing to recover
  on exactly those paths. They now log the failing operation and
  errno, as does the OTA backend function's invalid-value return.

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
