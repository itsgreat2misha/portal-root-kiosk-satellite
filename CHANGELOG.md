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

- Cross-platform host support, first half (Phase F): the exploit
  attempt runner streams process output through a reader thread and
  a queue instead of `select()` on a pipe (Windows accepts sockets
  only, so provisioning could not run at all on a Windows host).
  Every file written for the device (autoroot env/conf, staged
  state, account and debloat backups, helper keypairs) is now
  written with LF line endings pinned, so a Windows host no longer
  stages CRLF files the device shell cannot parse; a new
  `.gitattributes` pins LF for shell scripts, Python sources and
  Makefiles in every checkout. The build environment resolves the
  NDK host tag (linux/darwin/windows), the Windows build-tools
  program names (`.exe`/`.bat`), and the standard macOS/Windows SDK
  locations; the Makefiles take the NDK host tag from
  `android-env.mk` and the uid1000 size gates use a portable
  `wc -c` check instead of GNU `stat -c`. Native Windows Python
  gets an honest up-front answer for source builds (use the
  prebuilt bundle, or WSL2) instead of a mid-build make failure.
  The default run log directory uses the platform temp directory,
  the dry-run report probes the running interpreter instead of a
  `python3` PATH entry, and backup/diagnostics bundle manifests
  record POSIX path keys on every host.
- Cross-platform host support, second half (Phase F): CI now runs
  the test suite on Ubuntu, macOS and Windows runners, so the
  per-platform requirements the README states are the ones CI
  proves. The suite's fake attempt processes are `sys.executable`
  children instead of `/bin/sh` scripts, so the suite itself runs
  on Windows. Releases ship the bundle as a `.zip` alongside the
  `.tar.gz` (same signed manifest and hashes), and `--bundle`
  accepts the `.zip` directly, for hosts whose stock tooling has
  no tar. The README's host requirements are stated per platform,
  including the Windows difference that POSIX file modes (0600 on
  the local state file and backup bundles) are not enforced there.
  The matrix then found and fixed a second byte-fidelity class the
  audit missed: the provision state file, backup/diagnostics
  records and the signed bundle manifest are written with LF
  pinned (they are compared or verified byte-for-byte), and the
  state manifest's artifact hash keys are POSIX paths so a manifest
  recorded on one host OS verifies on another.
- Prebuilt release bundle (Phase E): release CI builds all five
  target payloads plus the model-independent APK set into one bundle
  with a SHA-256 hash manifest (`tools/build_release_bundle.py`),
  and a new `--bundle PATH` flag runs the provisioner from it — the
  manifest is verified against the device's selected target
  (fingerprint match, per-file hashes, fail-closed on a missing or
  mismatched payload) and the artifacts are installed in place of
  the local build, so a bundle run needs only Python and adb on the
  host. Release bundles carry a detached signature over the manifest
  made with the new project release signing key (private key in CI
  secrets only; the certificate is committed as
  `release-signing-cert.pem` and its fingerprint is pinned in
  `tools/prebuilt_bundle.py`). The version line moves to 0.9.x for
  the fork's preview releases.
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

- README verification claims corrected to the code: a run
  verifies on one boot by default (`--verify-boots 1`), and the
  feature table, the step-by-step ending line, and the
  per-feature sections (audio, update blocking, remote wipe,
  debloat, presence, app updates, Shizuku) no longer state
  unconditional two-boot verification. The theme-control
  example now shows the full `adb shell setprop` command, and
  the bundle section notes the bundle is a runnable checkout
  on its own. FORK.md lost the owner's first name, the
  test-device room references, and the stale claim that all
  changes live in `tools/provision_portal.py`.
- The autoroot helper's root-daemon check ran a single probe
  and silently reported "daemon absent" on any failure. The
  verdict-time decisions that consume it (the post-verdict cut
  and the fail-stall sweep) could therefore act on a daemon
  that was still binding, and a genuinely absent daemon left
  no evidence of why. The check now retries the ID probe up
  to three times with 500 ms pauses and, on giving up, logs
  the failure reason (unexpected response or exception) plus
  a TCP reachability probe of the daemon port. Ported from
  PR #49, whose remaining content this supersedes; helper
  bumped to 1.16/vc17.
- Two bundle-mode defects caught by the v0.9.0 live proof
  (Nov 20, 2026) after the certificate fix: the bundle did not
  ship `autoroot-helper/run.sh`, which the runtime stages
  on-device from the tree, so the channel path fell back to a
  full install; and the nested phase provisioners (OTA
  bootstrap, OTA backend, presence, remote wipe, and the other
  per-action phases) did not inherit `--bundle`, so their
  address discovery lost the bundled simpleperf and demanded an
  NDK on a host that by design has none. The builder now ships
  run.sh (hash-listed like the other artifacts) and every nested
  construction receives the parent run's bundle.
- The release bundle now ships `release-signing-cert.pem`. The
  runtime looks for the pinned release certificate in the running
  tree, and a bundle run standalone is its own running tree, so a
  signed bundle used on its own refused to verify. Caught by the
  v0.9.0 live bundle proof (Nov 20, 2026) before any device run;
  the certificate is public material whose fingerprint is pinned
  in code, so shipping it does not weaken the check.
- The release workflow's Android SDK setup: the setup-android
  action's internal sdkmanager call for the legacy `tools`
  package fails on current cmdline-tools distributions, so the
  workflow now installs the pinned SDK components directly from
  the runner image's SDK, invoking sdkmanager by its full path
  under the SDK root (it is not on PATH without the action)
  (first exercised by the v0.9.0 tag runs, Nov 20, 2026).
- A won autoroot race whose verdict line a late post-root
  action failure flipped to FAIL wedged the on-device cycle
  until the 600 s runner timeout (Defect N, Phase D closure
  session 19, Nov 19, 2026). The native verdict line reports
  the whole post-root action chain, not just the race: on
  two consecutive host-free boots of a freshly restaged set,
  the winning attempt's only verdict line was
  `WATCH_CFI_OK=0 STEP=151` (audio persistence; ERRNO=111,
  then ERRNO=30) printed after the lock repair succeeded,
  the payload started, and the root daemon came up. The
  watchdog latched FAIL and correctly refused to cut (the
  daemon was present), but the win-stall sweep required a
  WIN verdict, so the attempt's leftover process tree held
  the foreground shell call to its socket timeout and the
  Shizuku handoff, the drift pass, and the budget close all
  waited with it; on one boot the device rebooted first and
  the next boot recovered the mark as a clean loss. The
  watchdog now sweeps a fail-verdict attempt's leftover
  tree on the win-stall schedule (120 s, then 240 s, at
  most two) once the root daemon is confirmed serving -
  the daemon's presence is the attempt's own proof that
  its real work completed, and the sweep spares the daemon
  and the Shizuku server by construction. The verdict and
  its accounting are untouched: the 300 s no-verdict
  cutoff, the fail-plus-daemon-absent post-verdict cut,
  and the win-stall sweep behave exactly as before, and
  genuine failure verdicts still read as failures in the
  attempt-scoped log tail. Helper 1.15 (versionCode 16)
  so a restage picks the change up. Live validation is
  the next host-free boot cycle on the test unit (the
  coded path was verified by the executed Java decision
  table and the unit suite).
- A later run's completion write could downgrade or erase
  verification-grade facts an earlier run established
  (Defect M, Phase D closure session 18, Nov 19, 2026). Two
  losses, one root shape — the merged record trusted the
  completing run's weaker view over the recorded one. (1) A
  full run verified the OTA block directly and recorded it
  done; a later channel run whose own end-of-run judgment
  was "unverified" — a win-less boot cannot read the
  posture's per-boot `otad.nodemon` property or stat the
  override file, so the posture criteria were unobservable,
  not failed — merged that weaker judgment over the verified
  value, leaving the record claiming `unverified` for a
  block that was positively verified. Verification-grade
  values now merge monotonically: a run whose OTA judgment
  is "unverified" no longer replaces a recorded verified
  `disable_updates`; only a run that itself verifies
  (records the action done) or positively refutes it (the
  enable-updates restore, whose apply/restore pair hygiene
  drops the key) changes the recorded value. Nothing
  creates a verified value — with no verified prior,
  "unverified" records exactly as before, and the
  fast-path gates' recorded-posture trust is unchanged.
  (2) The same full run's payload terminal write dropped
  the two verification boots its install phase had just
  recorded: the run had started from a pending record (a
  recovered run), and the fill that supplies a run's own
  verified boots to a write lived inside the manifest
  merge, which a non-complete start record gates off — so
  the terminal write replaced the verification write's
  good record with null boots. The fill now happens for
  every write, before the merge: the boots a run itself
  established fill any the caller did not supply, explicit
  caller boots still win, and the start record's block
  still carries over where the run verified none.
- A `--restore wireless-adb` run connected over wireless ADB
  itself stranded the device mid-run (Defect L, Phase D
  closure session 16, Nov 19, 2026): the restore executed
  fully on-device, the runner's post-attempt reboot brought
  the unit up with the persisted wireless port cleared, and
  the host-side verify could never run — the run failed
  waiting for ADB and left the autoroot guard flag set. The
  provisioner now refuses the combination before any state
  change: when a run requests the wireless-ADB restore and
  the current serial is the wireless endpoint the restore
  removes (a host:port serial on the persisted wireless
  port), it prints a refusal line and errors, telling the
  user to connect the Portal by USB and re-run. The refusal
  sits in `provision()` before the autoroot guard engages,
  so every path that could reach the restore (the no-op
  gate, the channel gate, the subset exits, the stages) is
  downstream of it, and `_provision_stages` re-checks after
  `--recover` adopts the restore from a pending manifest's
  recorded actions. Over USB the restore is unchanged: USB
  ADB does not depend on the persisted wireless port, so
  the host survives the reboot. A sweep of the other
  actions found no second instance: the payload's
  `restore_wireless_adb()` is the only code that clears an
  adb tcp port property, `adb_enabled` is only ever written
  `1` (by the ADB-framework ensure), and no action performs
  a wipe or reset.
- The channel PortalComponentCtl execution still failed with
  the rish transport working (Phase D closure session 15,
  Nov 19, 2026): the run reported exit=0 with empty output and
  fell back to the race path. Two stacked causes, both proven
  live. (1) The meta-authenticators restore staged its actions
  with bare class names, but the jar validates each entry
  against ComponentName.flattenToString() and rejects a bare
  class name; the restore now writes the flattened
  package/class form (the recorded package, or the alohausers
  package by default) like every other component list. (2) The
  rish transport returns only the remote command's stdout and
  reports exit 0 whatever the command's real exit code, and
  stderr never arrives — while the jar sends every failure to
  stderr with exit 1 — so the rejection was invisible. The
  executor now captures the jar's output and exit code to a
  file on the device (in a host-created subdirectory of
  /data/local/tmp, which is drwxrwx--x and not creatable-in by
  the uid-0 server shell) and judges the run on that capture;
  a failed jar run now surfaces its real error and exit code,
  and the app_process fallback keys on the captured 127.
- The root-channel PortalComponentCtl execution (Defect G's
  rish transport) timed out against the root-mode Shizuku
  server (Phase D closure sessions 9.5 and 14, Nov 19, 2026).
  The assumption recorded with the executor — that the
  root-mode server simply accepts a rish client from an adb
  shell — was wrong: rish's loader receives the server binder
  from the Shizuku manager app, but the Shell then attaches
  as a server client under com.android.shell (uid 2000),
  which needs a Shizuku permission grant. With no allowed
  entry for that uid in the server config, the server starts
  the manager's on-screen permission confirmation and blocks
  the attach; the loader's fixed 5-second watchdog kills it
  and prints a misleading "Request timeout ... disable all
  battery optimization features" message (diagnosed live:
  the binder is delivered in milliseconds, a permission
  activity START from uid 0 follows every blocked probe, and
  the probe exits at exactly +5 s; a shell-mode server
  exempts its own uid, which is why manual shell-mode tests
  passed). The channel executor now prepares the transport
  before running the jar: it adds the manager and the shell
  to the deviceidle whitelist, merges the persisted grant
  for uid 2000 into the server config file (shell-owned, so
  the shell channel writes it directly; every later server
  start loads it), and probes the transport with a trivial
  rish command — repairing the already-running server by
  failure shape (tapping "Allow all the time" on the
  permission dialog, bounds read live from a uiautomator
  dump, for the timeout shape; starting the manager
  activity for the cold-manager shape) — and only runs the
  jar once a probe answers as uid 0. If no probe answers,
  the step raises and claims nothing, so verification and
  the race fallback are unchanged, as is the
  no-Shizuku-root skip.
- A combined (stages + custom payload) run's final manifest
  recorded null verification boots although the run had
  verified two distinct boots (Defect K, Phase D closure
  session 13, Nov 19, 2026). The standard install phase's
  verification writes the boots it established; the payload
  phase's terminal write then merges into the manifest the
  run STARTED from, whose verification block predates the
  run's own verification, and carried its nulls forward over
  the recorded boots. (This also corrects the assumption
  stated when the payload terminal write gained merge
  semantics: that the final record was unaffected in
  combined runs. It was not — the merged write is the last
  write of a combined run, and its merge base is the start
  snapshot.) `verify_across_two_reboots` now records the
  boots it establishes on the run, merged completion writes
  take the run's own boots over the start record's block
  (which still carries over when the run verified none, and
  a run that verified none records nulls, never fabricated
  boots), and the OTA manifest-correction re-writes fall
  back to the run's boots where the record's block is
  missing them.
- A full run starting from a drifted aloha device never entered
  the decided alohausers-disabled posture (Defect J, Phase D
  closure session 13, Nov 19, 2026). `desired_state` was
  recorded only by a run that requested
  `--remove-meta-accounts` AND started with the package already
  disabled; every other run only preserved an earlier record.
  A device whose package had drifted back to enabled therefore
  completed with the package still enabled, no `desired_state`
  in the manifest, and no `ALOHAUSERS_DISABLED` key in the
  staged conf, so the per-boot drift pass had nothing to
  enforce for alohausers and OTA was judged by the enabled
  posture's override path. The end-of-run posture step now
  also engages for a run that stages the OTA posture (a
  `--disable-updates` run): it disables the package through
  the payload daemon, and a verified disabled end state backed
  by the posture conf is recorded as `desired_state` from the
  run's own end state, whatever the start state or the flags
  requested; completion writes on paths that never run that
  step observe the same end state. A run ending enabled
  records no disabled desire, and a posture that cannot be
  established (no payload daemon channel) stays visibly the
  enabled-posture fallback: the `ALOHAUSERS_POSTURE_DEFERRED`
  line, OTA judged by the override path, and no
  `desired_state` recorded.
- A re-provision after `--restore autoroot` died before any race
  (Defect I, Phase D closure session 12, Nov 19, 2026). The
  restore removes the whole staging directory, but the early
  autoroot.conf syncs (OTA_NODEMON and the drift keys) wrote
  into it assuming it existed — only autoroot staging creates
  it, later in the run — and adb push cannot create it (its
  secure_mkdirs is refused on these devices). The syncs also
  read the staged config without checking the read's return
  code, so the removed config's cat error text (the command
  runner merges stderr into stdout) was treated as config
  lines and "synced". Both syncs now share one read/write
  pair: a failed or empty read means no staged config to sync,
  and the write creates the staging directory first. A sweep
  of every other host push site found no other instance: the
  remaining subdirectory writers (presence, camera-light and
  audio backup markers) already create their directory at the
  write site, the app-private key copies create theirs via
  run-as, and every other push target is a flat file in
  /data/local/tmp, which no restore removes.
- The two audio preflights disagreed about the same boot, and a
  repair demanded mid-run had no channel route (Defect H, Phase D
  closure session 9.5, Nov 19, 2026). The channel gate read the
  durable signals (marker, staged artifact, aiservice alive) and
  reported skip, while the apply path's health half was a logcat
  probe for the current boot's watchdog lines — rotated out on
  the session's long-uptime boot — so minutes later the same
  device read repair, and a `--full` run that had engaged the
  channel fell into the race path for a repair nothing needed.
  Both preflights now print from one verdict, `audio_health()`:
  the durable + live signals are the criteria for every reader,
  and the logcat probe keeps only its boot-age-independent roles
  (post-reboot verification on the race path, and the
  marker-absent private-install probe, which also writes the
  marker). Repair routing is decided before the channel engages:
  a repair verdict is the up-front channel blocker
  `audio-repair-bootstrap`, because no channel mechanism performs
  the repair — the install is a private installer-credential
  action, re-pushing the staged artifact would not make the
  running watchdog load it, and nothing on the channel path
  restarts aiservice — so the dedicated bootstrap stays race-only
  and owns the repair from the start. The final report names the
  outcome (`AUDIO_REPAIR_OUTCOME route=bootstrap
  result=performed|deferred`), judged against the device's end
  state; a deferred repair fails the run.
- The root-channel apply path staged the PortalComponentCtl
  actions file but never executed the jar, so any channel run
  that had to actually change component state failed its own
  verification and fell back to the race path (Defect G,
  Phase D closure session 8, Nov 19, 2026). The jar's only
  executor was the payload's post-win sequence; loopback-ADB
  shell cannot substitute (PackageManager's binder caller
  check excludes uid 2000). The channel path now executes
  the jar after staging, through Shizuku's own shell client
  (rish, extracted from the pinned, hash-verified Shizuku
  APK): the root-mode server spawns it, so it runs as uid 0
  with the same arguments the payload passes, and the
  payload's package-state settle (15 s + sync) runs before
  verification reads the state back. Without Shizuku root
  (--skip-shizuku-root, or the server not answering as
  uid 0) the step does not run and claims nothing, so the
  verify-and-fallback behaviour is unchanged. This covers
  every channel run carrying component actions: debloat,
  bloat restore, remote-wipe block/restore, the Meta
  authenticator restore, and the presence FPS/profile jar
  action on targets where the jar is its only carrier.
- The system-theme restore left the ui_night_mode key and
  UiModeManager diverged on shell-uimode targets (Defect F,
  Phase D closure session 7, Nov 19, 2026). The restore set
  or deleted the key truthfully but never transitioned the
  manager, so after a factory-default restore the key read
  absent while `cmd uimode night` still reported the applied
  mode; the next same-state apply was then a no-op that
  never rewrote the key, and its key-based verify failed
  permanently. Both restore tiers now drive the end state
  through the uimode transport on shell-uimode targets: a
  recorded mode is replayed through `cmd uimode night` (the
  transport writes the key itself), and the absent tier
  transitions the manager to the absent key's boot-time
  default (night off) before deleting the key. Theme
  verification (apply and restore) now checks the key AND
  the manager state and fails as diverged when they
  disagree. The apply itself heals a diverged pair: when
  the manager already reports the target state but the key
  disagrees, it transitions through the opposite state
  first so the transport rewrites the key. UID-1000 targets
  are unchanged.
- A recorded restore could satisfy itself, so a repeated
  restore silently no-oped against a changed live state
  (Defect E, Phase D closure session 6, Nov 19, 2026).
  Restores were recorded as persistent manifest actions, and
  the no-op gate satisfies requested actions from the record:
  after `--restore theme` completed and recorded
  `restore_theme`, a channel theme apply set the live
  `ui_night_mode`, and a second `--restore theme` reported
  already-provisioned without executing. Three fixes. Gate
  semantics: operation actions (every `--restore` action,
  plus the Shizuku removal — operations, not states) are
  excluded from record-only satisfaction in the no-op gate,
  so a requested operation always executes and verifies its
  live end state; non-restore actions keep the record
  comparison exactly as before. Record hygiene, mirroring
  the Defect D DNS family drop: a completion write whose run
  established one side of an apply/restore pair now drops
  the recorded other side from the merged record, so the
  record never carries the contradictory pair (the same
  session's record held `system_theme_control: "dark"`
  beside `restore_theme: true`); autoroot's apply side is
  its staging request rather than an action key and drops a
  recorded `restore_autoroot` the same way. Recording order:
  the theme preflight applies the theme as its probe, and
  the channel gate calls it before the stages path's record
  step, so on the channel route the recorded original could
  never engage; the preflight now records the original at
  the apply point, before applying (first record wins, so
  the stages path is unchanged). The other
  recorded-original features were checked for the same
  channel-applies-before-record shape and do not share it:
  Private DNS, the ADB authorization timeout, the app
  verifier and debloat each record inside their apply
  function, Meta accounts record inside the preflight both
  routes call before any removal, and remote wipe ensures
  its backup inside the shared apply sequence. Live
  validation is deferred to the next device session.
- An explicit `--dns` request could silently no-op against a
  contradicting live state (Defect D, Phase D closure session 3,
  Nov 19, 2026). A manifest recorded by a pre-#64 run can carry
  both DNS intents (`dhcp_dns` plus `privacy_dns`); the manifest
  merges preserve prior actions per key, so the pair survived
  every later run, and the recorded-expectation readers resolve
  the pair dhcp-first. A bare `--dns HOSTNAME` run whose record
  held that hostname therefore compared the live state against
  "off", matched a live-off device, and reported
  already-provisioned with its request unapplied — and had the
  device been live on the requested hostname, the same verdict
  would have "repaired" it to off. Two fixes. Gate semantics:
  when a run carries a DNS intent of its own, the fast path's
  drift evaluation judges the live state against the requested
  intent (`_requested_dns_expectation`, resolved from the run's
  requested actions with the recorded expectation's rules); runs
  carrying no intent keep the recorded pair's dhcp-first
  resolution exactly as before, and `--full` with no explicit
  `--dns` is unchanged (the preset's dhcp intent and the pair's
  dhcp-first resolution coincide). Record hygiene: a completion
  write whose run established exactly one DNS intent now drops
  the family's other keys from the merged record, so a
  dual-intent record converges on its next DNS run instead of
  shadowing it forever. The drop lives in the one `write_state`
  every completion path funnels through (channel, stages subset
  exits, payload terminal write, recovery exits, the full run's
  completion write, the OTA correction re-writes), so no call
  site needed its own copy; a run carrying no DNS intent leaves
  the recorded DNS actions untouched. Live validation is
  deferred to the next device session.
- The WiFi flush guard's boot-age floor is 60 s on both sides
  (host `RACE_BOOT_MIN_AGE_SECONDS` and the autoroot helper's
  `BootFlushGuard.MIN_BOOT_AGE_MS`, helper 1.14, versionCode
  15), down from the 120 s the guard shipped with. The step-down
  is grounded in the 2026-11-19 timing measurement
  (wifi-guard-timing-measurement-2026-11-19): the device
  framework's WifiConfigStore deferred flush is a fixed 10.0 s
  alarm (`BUFFERED_WRITE_ALARM_INTERVAL_MS` = 10,000 ms), live
  change-to-write-complete measured 10.1-11.5 s, and the modeled
  heavy-load worst case lands the flush by ~52 s. On-device,
  the lower floor also halves the per-boot time-to-root on
  finished devices. Live validation is deferred to the next
  device session.
- A finished unit in the recorded alohausers-disabled posture
  fell out of both re-run fast paths on any boot where autoroot
  had not won yet. `otad.nodemon` is per-boot and set only by a
  payload win, and the MobileConfig override is inert behind
  the disabled package, so a channel run ending on such a boot
  recorded `disable_updates` as "unverified" from its posture
  judgment — and the next run's no-op gate refused on that
  action while its channel gate refused `ota-not-configured`,
  sending the finished device into a full race. The two gates
  now extend the recorded-posture trust to that record shape:
  when the manifest records the disabled posture, the staged
  autoroot conf carries `OTA_NODEMON`, and the alohausers
  package is actually disabled, the OTA action counts as
  satisfied for gating. The trust is gating-only — a run that
  applies or re-applies OTA still ends in the unchanged
  end-of-run verification and posture judgment, and nothing
  records the action verified from the trust path. Live
  validation is deferred to a later session.
- The presence runtime verification demanded a live, streaming
  pipeline, but with the camera lens cover closed the pipeline
  is off by design — it configures, starts, and pauses without
  ever opening the camera — so a healthy covered unit failed
  the whole run (the guest Mini's repeated presence failures,
  Nov 18, 2026; its cover was closed throughout). Both
  verification variants now read `shutter_state` from
  `dumpsys platform_state_service` first (the privacy signals
  the check already sampled do not track the cover). Cover
  open — or the state unreadable, as on aloha — the live check
  runs exactly as before. Cover closed, the durable end state
  is verified instead (aiservice running, CAMERA appop
  allowed, the profile evidenced by the installed marker or
  this boot's config-load lines, the FPS cap by its marker)
  and the verification returns a distinct deferred outcome
  (`PRESENCE_VERIFY_DEFERRED reason=shutter_closed`) instead
  of failing; a durable failure still fails the run. A
  deferred verification never records as verified: the
  manifest records the presence actions as `"deferred"` (the
  OTA `"unverified"` pattern), the no-op gate's exact-match
  comparison therefore refuses a later no-op claim, and a
  later run with the cover open re-attempts the streaming
  verification. The final report surfaces the deferral
  without failing the run. Live validation is deferred until
  a covered unit is next provisioned.
- The stages path's single-action exits kept the replace
  semantics the channel fix below left behind: a theme-only,
  presence-only or similar subset run that found its action
  already configured completed by rewriting the recorded
  manifest with only its own action, dropping the other
  recorded actions, artifact hashes and `autoroot_key_sha256`
  even though the run had un-applied nothing — the same silent
  fast-path loss the channel completion write was fixed for.
  Those exits (theme-only, camera-light-restore-only, the
  resumed audio / disable-updates / meta-accounts / debloat /
  remote-wipe exits, presence-only, the unprivileged
  adb-auth-timeout/theme subset exit) and the custom-payload
  phase's terminal write now pass the same `merge_prior` flag
  and merge into the manifest the run started from when that
  record is complete, the run's own values winning per key.
  The full run's completion write keeps its replace semantics,
  so the channel entry's note below now applies only to it.
  Live validation is deferred to a later session.
- A delta run on the root-channel path replaced the recorded
  state manifest with a record of itself: a bare `--dns
  one.one.one.one` channel run on a fully provisioned unit
  rewrote the manifest with only the DNS action, a third of the
  artifact hashes, and no `autoroot_key_sha256`, even though the
  run had un-applied nothing. The manifest is the device's
  accumulated recorded state — the no-op and channel gates, the
  OTA posture trust and `--status` all read it — so the next
  `--full` run failed both fast paths
  (`PROVISION_CHANNEL_SKIP reason=ota-not-configured`, because
  `disable_updates` was no longer recorded) and had to race.
  The channel completion write now merges into the manifest the
  run started from: prior actions and artifact hashes are
  preserved with the completing run's values winning per key,
  the recorded autoroot key hash survives unless the run
  restaged autoroot, and the recorded verification boots carry
  over; the tool revision and desired state follow the
  completing run as before. The race/stages completion writes
  keep their replace semantics. Live validation is deferred to
  a later session.
- `--full --dns <hostname>` could never complete through the
  channel: the preset expansion ran after the `--dns` translation
  and set `dhcp_dns` on top of it, so the composed config carried
  both DNS intents. The hostname apply persisted, then the
  dhcp-first verify expectation failed the run
  (`PROVISION_CHANNEL_FALLBACK reason=Private DNS did not
  persist: mode='hostname'/'off'`). An explicit `--dns` now
  replaces the preset's DNS component at CLI composition, so a
  composed config holds exactly one DNS intent and the apply,
  verify, manifest recording and recorded-state readers all see
  the same one. `--full` alone keeps the preset's DHCP intent
  and `--full --dns off` matches it. Live validation is deferred
  to the gate completion session.
- `--dns <hostname>` crashed every run after the live Private DNS
  settings had already been changed: the apply normalized the
  hostname and wrote it back into the frozen SettingsConfig,
  raising FrozenInstanceError before verification and the
  completion write (found live in the Phase D gate re-run;
  `--dns off` was unaffected because its apply mutates nothing).
  The apply no longer writes the config, and the verification
  derives its expected hostname in the same normalized form the
  applies write to the device, so the hostname path completes on
  the channel and stages paths alike. Live validation is
  deferred to the gate completion session.
- Race-heavy runs could cost a unit its saved WiFi network: every
  boot auto-connects within seconds, which makes system_server
  update the saved-network record and schedule an asynchronous
  WifiConfigStore write, and attempt boots die young and uncleanly
  (race panics, watchdog cuts, the runner's own reboots) inside
  that write's flush window — four episodes on the library unit,
  each ending with the store loading empty and the password
  needing re-entry (investigation 2026-11-19). The run mechanism
  now guards the window on both sides: the host attempt loops
  wait until the boot is at least 120 s old and sync before a
  race attempt starts (failing toward waiting when the boot-age
  read does not answer), the host runner syncs before every
  reboot it issues, and the autoroot helper (1.13, versionCode
  14) applies the same age-and-sync guard before an on-device
  attempt and syncs before its clean-attempt reboot. The README's
  troubleshooting section also records the operator rule: no
  smart-plug power cut into a failed-boot state until the unit
  has had one clean boot or the pre-revival capture
  (`dumpsys wifi` + logcat) is taken. Live validation is
  deferred to the Phase D gate re-run.
- The channel gate refused every device in the recorded
  alohausers-disabled posture that requested Meta account
  removal: the meta-accounts preflight's already-clean requires
  the package NOT disabled, which the posture makes unreachable
  even though the removal's end state (accounts absent,
  authenticators disabled) holds (found in the Phase D gate
  re-run). The channel gate now gives the meta clause the same
  recorded-posture trust the OTA clause already had: the
  manifest's recorded disabled posture satisfies the package
  clause when the preflight's live reads still hold. The
  preflight itself is unchanged, so the stages path's
  enable-then-remove flow is unaffected. Live validation is
  deferred to the Phase D gate re-run once the test unit
  returns.
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
