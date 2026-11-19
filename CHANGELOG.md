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

- Per-boot recorded-state drift pass (Phase C3-A): after autoroot
  recovers root, the helper (1.12, versionCode 13) compares the
  live device against the end state recorded in `autoroot.conf`
  and repairs what drifted - Private DNS through its loopback ADB
  shell (uid 2000, the same SettingsProvider parity the host
  uses), the alohausers package posture through the root daemon
  before its window closes, and `otad.nodemon` as a read-only
  check (no post-win channel can set it). The pass is fail-open,
  logs `DRIFT_OK` / `DRIFT_REPAIRED` / `DRIFT_UNREPAIRED` per
  item, never touches the failure-budget state, and never runs
  during a host provisioning run. Desired state rides new
  `autoroot.conf` keys (`DNS_MODE`, `DNS_SPECIFIER`,
  `ALOHAUSERS_DISABLED`) with the `OTA_NODEMON` preserve/sync
  discipline, and the run manifest records it additively as
  `desired_state` (schema unchanged, no new flag). A run that
  removes Meta accounts and starts with the package disabled
  records that posture as the desired end state: the final
  accounts verification accepts it, an end-of-run apply through
  the payload daemon restores it after the last verification
  with no reboot after it, and later boots keep it. Live
  validation of the alohausers leg is deferred until the aloha
  test unit returns to the network.
- Failed exploit attempts now capture the on-device watch result
  before the runner reboots the device: a `WATCH_RESULT_EVIDENCE`
  line records whether
  `/data/local/tmp/ghostlock-watch-result.txt` was readable, its
  `STEP` value, and the current boot id. This preserves the
  evidence that separates a kernel panic from a whole-process
  death when a won attempt's stream dies before the stage returns
  (the discarded-win shape diagnosed Nov 18, 2026). The read is
  best-effort and never affects the run. Live validation is
  deferred until a test unit returns to the network.
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

- CLI flag consolidation (Phase D), a clean break with no aliases
  for the old spellings: `--full` is now a preset expanding to the
  documented full-setup line plus `--autoroot`; DNS is one flag,
  `--dns off` (network-provided DNS) or `--dns HOSTNAME` (strict
  Private DNS), replacing `--dhcp-dns` and `--privacy-dns HOSTNAME`;
  and every restore is one repeatable flag, `--restore <name>`
  (audio, bloat, remote-wipe, updates, dns, presence, presence-fps,
  adb-auth-timeout, app-verifier, camera-light, autoroot,
  wireless-adb, theme, meta-authenticators), replacing the nine
  `--restore-*` flags and `--enable-updates`. Internal action ids
  and the run manifest are unchanged.
- The updates restore now replays the OTA packages' recorded
  pre-disable states (enabled, disabled or absent) instead of
  enabling both unconditionally; the disable path records them
  first at `/data/local/tmp/portal-ota-packages-before-v1.json`.
  Devices disabled before this change have no record and keep the
  previous all-enabled behavior.
- Restores that had no complete undo now do, under the two-tier
  recorded-original / factory-default rule: `--restore autoroot`
  unstages autoroot (helper, staging, saved keys, the authorized
  ADB key, staged daemon files); `--restore wireless-adb` clears
  the persisted ADB port (runtime and persist-property file) and
  removes the wireless-ADB and ADB-framework boot-enforcement
  markers; `--restore theme` returns `ui_night_mode` to its
  recorded original (deleting the key when the original state had
  none) and removes the theme controller's marker and helper;
  `--restore meta-authenticators` returns the three Meta account
  authenticator components to their recorded states. The accounts
  themselves remain one-way: the README now marks Meta-account
  removal as the only feature that cannot be undone.
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

- Autoroot staging through the channel path rendered the frozen
  on-device exploit environments outside the custom-payload
  phase, so the staged env files silently lacked the payload
  block (`GHOSTLOCK_CUSTOM_PAYLOAD`, `GHOSTLOCK_LOCK_REPAIR`,
  and companions): on-device wins then skipped the custom
  payload and the lock repair while still reporting success
  (found in the guest Mini's post-C3-A boots). Staging now
  renders in the payload-phase context regardless of the
  caller's phase, and refuses to stage a rendered environment
  that is missing the payload keys when a custom payload is
  configured. Live validation is deferred until the Mini is
  restaged.
- Re-runs on a device in the recorded alohausers-disabled
  posture refused themselves: the no-op and channel gates
  re-derived the OTA block from the live MobileConfig dump,
  which reads unconfigured by design while the package is
  disabled, so a posture device could never take a fast path
  again (found in C3-B validation). The gates now trust the
  manifest's posture-judged completion, and the channel-path OTA
  verification checks the four posture criteria directly,
  falling back to the dump verification when the posture no
  longer holds. The Private DNS no-op gate also confirms a lone
  mismatching sample with one re-read before calling it drift -
  a single disagreeing read on a device verified minutes earlier
  refused a healthy unit - and logs the live values behind the
  verdict either way.
- A bootstrap phase's failure was judged where it happened in the
  run's ordering instead of against the device's end state: in the
  combined flow the OTA bootstrap's verification failure aborted
  the run before the custom payload phase even when later phases
  put the device in exactly the state the check wants (Run 37C),
  and the payload-only path never reported deferred failures at
  all. Deferred failures are now re-judged at the run's final
  report — `ota_preflight()` against the end state — with the
  raise deferred past a pending payload phase and the final report
  made after the payload apply on both payload paths. When the run
  ends in the alohausers-disabled posture, where the MobileConfig
  service is absent by design and override provenance can never
  verify, the OTA item is judged by the posture's own criteria
  instead (nodemon config staged, `otad.nodemon` set, alohausers
  disabled, override file present), logged as `OTA_POSTURE_JUDGED`
  with the per-criterion results; all four true records the action
  done, any one false leaves it `unverified`, and a completed
  manifest that claimed it done is corrected in place
  (`OTA_MANIFEST_CORRECTED`), preserving the verification boots.
  The correction runs in both directions: a manifest the run's own
  mid-run provenance verification recorded as `unverified` is
  likewise repaired when the end-state judgment judges the action
  done, so the record matches the judgment and the device can
  qualify for the no-op path on later runs.
- The Shizuku/autoroot ADB keypair could rotate away from the
  authorized key and strand recovery: the two helpers share one
  keypair, autoroot staging removes the Shizuku helper, and the
  next run's install generated a fresh pair — which a root-channel
  apply then staged into the autoroot helper with no authorization
  (the channel cannot write adb_keys), so the next unguarded boot
  failed with "Portal helper ADB key is not authorized". Install
  now seeds the Shizuku helper from the autoroot helper's
  already-authorized pair before generating a new one; a channel
  apply that still ends up with a freshly generated pair falls
  back to the race run instead of staging it; autoroot staging
  compares the pair it is about to copy against the saved marker
  (the last authorized public key) and fails loudly on a mismatch;
  and the staged pair's SHA-256 is recorded in the run manifest
  (`autoroot_key_sha256`) and shown by `--status`, so a future
  authorization failure names the key generation that was live.
- The saved marker that comparison judges against could itself
  lag the authorized key: on non-buffered targets the marker is
  written by the native authorize from the staged scratch file,
  so in the reuse path a run that rotated the helper's pair and
  aborted could leave the marker naming a key that matches no
  surviving record, and the comparison then aborted a later run
  whose pair was in fact authorized. The install loop now records
  the key its win actually authorized, and staging judges the
  pair it copies against that record; the marker remains only as
  the fallback for runs that authorized nothing (channel and
  payload-only runs), is read through the root daemon first (on
  those targets it is root-owned, so a shell read silently
  returned nothing unless adbd was in root mode), and the channel
  guard now also refuses a pair that is not the recorded
  authorized key, not just a freshly generated one. When a win
  proves the reused pair was already in adb_keys, the install
  phase rewrites the marker from that pair, so the helper, the
  staged file, and the marker end the phase on one generation.
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
