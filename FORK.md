# Fork notes — itsgreat2misha/portal-root-kiosk-satellite

Fork of [jxlarrea/portal-root-kiosk-satellite](https://github.com/jxlarrea/portal-root-kiosk-satellite)
(created Nov 2, 2026 from upstream `main` @ f941b57). Mikhail's `bootstrap.sh`
points at this fork. All changes are in `tools/provision_portal.py`:

1. **A failed bootstrap phase no longer starves the rest of the run.**
   Each dedicated bootstrap phase (audio, OTA, Meta accounts,
   debloat, remote-wipe, presence, presence FPS) is wrapped in
   `bootstrap_guard()`. In a multi-action run a
   phase failure is recorded, `PHASE_FAILED` is printed, the remaining
   phases and the main pass still run, and the run fails at the end via
   `report_deferred_failures()` with the collected list. Previously, e.g.
   the Meta authenticator guard failing aborted the run before debloat,
   remote-wipe, presence and Shizuku were ever attempted. Runs requesting
   a single action keep the original fail-fast behaviour.

2. **Meta authenticator guard error now carries diagnostics.**
   "Meta authenticator guard did not persist" includes the missing
   disabled components, the full disabled set, and whether the hardware
   authenticator was wrongly disabled. (The underlying guard-persistence
   failure on aloha — component states revert across the verification
   reboots — is still open; this makes the next diagnosis possible
   without re-reading the code.)

3. **Audio watchdog verification writes the install marker.**
   On `WATCHDOG_OK`, `verify_watchdog()` now also writes
   `/data/local/tmp/portal-audio-backup/installed-v1`, the marker
   `--status` reports as `installed_marker`. Previously the marker was
   never written for installer-credential (aloha) targets, so audio
   health rested entirely on the current logcat buffer, which rotates
   on long uptimes and made preflight/--status flap.

## 4. Custom payload + lock repair

With --custom-payload [binary] the provisioner stages the binary at /data/local/tmp and starts it inside the exploit's privileged window (GHOSTLOCK_CUSTOM_PAYLOAD=1). The payload runs as uid 0 in the shell SELinux domain, which cannot create files anywhere (open(O_CREAT) fails with EACCES) - so the payload is executed in place from its staged path, and success is detected by its observable effect, never by files it writes. Marker: CUSTOM_PAYLOAD_OK.

The exploit intentionally damages the proc_uid futex lock waiter tree; without repair the kernel panics 25-60 s after a successful landing. With PORTAL_LOCK_REPAIR=1 (default) the payload performs the solo-sentinel restore before returning: it verifies the exact waiter pattern, restores the sentinel node as tree root/leftmost, detaches the forged waiter, and only then clears the lock owner, with full read-back verification. Any mismatch aborts with PORTAL_LOCK_REPAIR_ABORT and writes nothing. Marker: PORTAL_LOCK_REPAIR_OK. A repaired boot reboots later only for normal reasons.

## 5. Root-mode Shizuku

With --shizuku and a verified custom payload, after CUSTOM_PAYLOAD_OK the provisioner asks the payload (loopback control channel, 127.0.0.1:37373) to restart the Shizuku server as root: it resolves the server starter and apk path on-device, kills any shell-uid server, and starts a new one, then polls until the server process reports uid 0. Marker: SHIZUKU_ROOT_OK. --skip-shizuku-root opts out. Note: the payload control channel on 127.0.0.1:37373 has NO authentication - any local app with INTERNET permission could use it while the payload runs. This is a known, accepted risk for a home kiosk device; do not expose the port beyond loopback.

## 6. On-device autoroot (--autoroot)

--autoroot makes a provisioned device self-sustaining: after one provisioning run, no host watcher is needed. It implies --shizuku and --custom-payload (see section 12). After the payload and root-mode Shizuku verify, the provisioner stages the on-device helper and keeps the exploit sentinel installed. Marker: AUTOROOT_STAGED_OK.

Staged under /data/local/tmp/portal-autoroot/: the autoroot-helper app (dev.portal.autoroothelper), run.sh, per-parity environment files env-odd.sh and env-even.sh (per-boot addresses are discovered at runtime, never frozen into these files), autoroot.conf (attempt cap, session window), and a copy of the Shizuku helper's device ADB keypair so the helper can open a loopback ADB shell after boot. Staging refuses to proceed if a per-boot live-resolved value would be baked into the staged files.

Boot flow: BOOT_COMPLETED starts AutorootService. If the payload already answers as uid 0, it only ensures Shizuku runs as root and records the boot done. Otherwise it measures this boot's addresses on-device, launches the attempt detached, and polls the payload channel for up to 5 minutes. Success: Shizuku is switched to root and the boot is marked done. Failure: it reboots and retries on a clean boot, up to the staged cap (default 4 attempts) within a 2-hour session window. Create /data/local/tmp/portal-autoroot.disable to turn autoroot off without uninstalling. Logs: logcat tag PortalAutoroot; files service.log and attempt.log in the staged directory.

## 7. Live-test findings (Nov 4, 2026)

Validated end-to-end on the library Portal+ (build 1041515800015050):
a single fork provisioning run (Run 14) followed by two independent
reboots, each recovering the root daemon (127.0.0.1:37373, uid 0) and
root-mode Shizuku with no host involvement and the sandbox watcher
stopped.

Findings folded back into the code above:

- Detached (nohup) attempt launches die with their launching ADB
  shell session: no banner, no result, no surviving process. The
  helper now runs run.sh in the foreground of a long-timeout shell
  call (600 s), the same shape as the host provisioner's attempts.
- run.sh housekeeping must precede sourcing the parity env files:
  the env exports LD_PRELOAD, and the first external command after
  sourcing (am force-stop) otherwise runs the exploit inside the
  am process and the script never proceeds.
- A completed boot (done_boot) ends its session. Without that
  reset, a second reboot inside the session window inherits the
  previous boot's spent attempts and caps out with no recovery.
- Attempt budget is 8 per 60-minute session window. Observed
  attempt outcomes include clean misses, mid-attempt kernel panics
  (the damaged proc_uid lock), and hangs past 600 s; the two
  validated recoveries landed on attempts 4 and 6 respectively.
- A winning attempt's launcher call may still end in a read
  timeout (the native run outlives it); the service treats the
  post-call daemon check as authoritative.

## 8. Streamlined build: helper UI and shizuku-helper removal (2026-11-04)

Two changes on top of the validated autoroot system, both live-tested
the same day (provision run 15 plus a full control-surface pass):

**The shizuku helper is gone from the autoroot flow.** It only ever
existed to hold the loopback ADB keypair, and staging already copies
that keypair into the autoroot helper's own files. At the end of
`stage_autoroot_payload()` the provisioner now uninstalls
`dev.portal.shizukuhelper` and prints
`SHIZUKU_HELPER_REMOVED reason=autoroot-keypair-merged`. The
authorized public key in `adb_keys` is a plain line in a file and is
unaffected. The plain `--shizuku` flow (no `--autoroot`) still
installs and uses the helper as before. Deployed package set for an
autoroot device: exploit sentinel, Shizuku, autoroot helper.

**The autoroot helper has a status/control activity (v1.1).** The
service publishes its phase (attempt n of m, detail) to
SharedPreferences; `AutorootActivity` polls it while visible. The
service opens the activity itself when an attempt session starts, so
the screen warns "do not use the device yet - it may reboot without
warning" while an attempt runs; it can also be opened from the
launcher at any time. Buttons send intents to the service, which
stays the single owner of shell work and session state:

- **Cancel (this boot)** - the service closes the tracked ADB client
  of the in-flight attempt; the blocked read throws, the runner dies
  with its session (the detached-launch teardown, used on purpose),
  the boot is recorded in `cancelled_boot`, and no reboot follows.
  Later boots are unaffected.
- **Disable / Enable autoroot** - creates or removes the existing
  `/data/local/tmp/portal-autoroot.disable` flag. Disabling mid-
  session also cancels the in-flight attempt.
- **Run now** - starts a session with a fresh attempt budget,
  ignoring a spent budget, a cancelled boot, or an unexpired session
  window.

Live results: reprovision passed end to end including the helper
removal; the next reboot recovered on attempt 5 with no
shizuku-helper package present (the autoroot helper's own keypair
authenticated loopback for discovery and the root Shizuku restart).
Cancel was exercised with a real tap on the on-screen button
mid-attempt: the attempt died instantly and the device stayed up,
unrooted, for that boot. Disable produced a boot that logged
"disabled by flag" and made no attempts; Enable + Run Now started a
fresh session on the same boot.

Session data point: of the four full recovery sessions observed on
2026-11-04, three landed inside the 8-attempt budget (attempts 5, 6,
and 3) and one capped at 0/8, after which Run Now recovered on
attempt 3 of a fresh session. A timeout-cut attempt can still panic
the device a minute or so later from the lock damage; the session
machinery absorbs that as just another failed attempt.

## 9. Helper 1.2: Stop is disable + reboot (corrects section 8's Cancel)

Section 8's "Cancel (this boot)" was replaced the same day. The in-place
cancel is only safe during discovery: once a race has run, the damaged
proc_uid lock stays damaged until a reboot (only a win repairs it), so
stopping in place left the user sitting on exactly the unstable state
the UI warns about. The delayed panic after the capped session's final
attempt (section 8) is that failure mode observed live.

Helper 1.2 (versionCode 3):

- The button is now "Stop autoroot & reboot". It kills any in-flight
  attempt (same socket-close mechanism), sets the disable flag, and
  reboots immediately. Disable toggled mid-session does the same;
  toggled while idle it just sets the flag. The cancelled_boot state
  and the CANCELLED phase are gone; the terminal phase is STOPPED.

Live test (library Portal, 2026-11-04): a real UI tap ~3 s into
attempt 1's race ran the full sequence (runner killed, flag set,
"stop from UI: disabled, rebooting" logged) -- but the reboot itself
wedged in the race's hot phase and the device hung until a smart-plug
power cycle ~6 minutes later. The post-cycle boot came up disabled
with zero attempts: the intended end state, reached via the power
backstop. Lesson: no userspace stop can make a mid-race halt fully
graceful -- the kernel state is the hazard, not the sequencing -- and
a power cycle is the documented recovery, after which the device is
guaranteed clean and quiet. Re-enable + Run Now then landed attempt 1
of 8, leaving the device rooted with autoroot enabled.
## 10. Daemon lifecycle: a bootstrap bridge, stopped after the handoff (2026-11-04)

Owner's question: with Shizuku running in root mode, apps get their root
interface from Shizuku itself - so does the custom-payload daemon need to
exist at all? Answer: only for the handoff. Something running as uid 0 has
to start `shizuku_server` as root, on the provisioning boot (the host
provisioner's post-payload steps) and on every autoroot boot (the helper).
That is the daemon's whole job. Once `shizuku_server` is verified as
uid 0, the daemon has no remaining consumer, and leaving an
unauthenticated root EXEC listener on loopback up for the rest of the
boot is pure exposure. Helper 1.3 and the provisioner now both stop it
at exactly that point:

- Provisioner (`apply_post_payload_root_steps`): after root-mode Shizuku
  is verified and autoroot staging (if any) has completed, it sends the
  daemon the `STOP` verb and prints `PAYLOAD_DAEMON_STOPPED
  reason=shizuku-root-ok`; a failed stop prints `PAYLOAD_DAEMON_STOP_FAILED`
  and does not fail the run. The stop happens only when root-mode Shizuku
  was requested and verified - with `--skip-shizuku-root` or without
  `--shizuku`, the daemon is the run's root channel and stays up.
- Helper 1.3 (versionCode 4): `ensureShizukuRoot()` now reports success;
  on both the win path and the daemon-already-up path the helper sends
  `STOP` immediately after a verified handoff (`daemon stopped after
  shizuku handoff` in service.log). If the handoff fails, the daemon
  stays up - it is the only root channel left for a retry.
- The helper's boot check is now Shizuku-first: if `shizuku_server`
  already runs as uid 0, the boot is done with no daemon involvement
  (`shizuku already root boot=<id>`). The daemon-up check remains as the
  mid-handoff recovery path (provisioning boot, or a session interrupted
  between the win and the handoff).

Side effect: the unexplained daemon death on the basement-couchassistant
provisioning boot (section 7 era; still unexplained under the old code)
becomes moot - under this lifecycle a daemon that exits after its
handoff is expected, by design. The couchassistant still runs helper 1.2
until its next bootstrap run; its on-device session continues under the
old rules meanwhile.

Live validation (library Portal+, 2026-11-04, helper 1.3 installed in
place over 1.2): reboot -> session attempts 1-3 missed (attempt 3 fast),
attempt 4 won; the win's foreground call resolved at the 600 s timeout
with the daemon already serving; 6 s later `shizuku root ok pid=13457`,
and in the same second `daemon stopped after shizuku handoff`.
Post-state verified from the host: daemon port closed, `shizuku_server`
uid 0, `done_boot` = the win boot. A manual service re-trigger then took
the new fast path with the daemon down (`shizuku already root`), leaving
attempts and done_boot untouched. Unit suite: 86 green (6 new: STOP
protocol + post-payload stop gating).

## 11. Planned: root stack consolidation (root adb, CLI streamlining, de-Kiosk)

Upstream declined feature PRs (section: the maintainer is limiting the
project to maintenance), so this fork is the release vehicle; once the
work below is validated, it will likely move to a new repo under a new
name. Full plan: maintained with the goal workspace
(root-adb-plan.md); the decisions:

- Autoroot stays intentionally opt-in (--autoroot). Lock repair is
  not optional - it always runs in the payload path. Root adb is not
  optional either: establishing root means adbd runs as uid 0 too,
  matching Shizuku. Mechanism (to be spiked first on the library
  unit): flip ro.debuggable in the shared property area from the
  uid-0 daemon and restart adbd - per-boot, since the property area
  is rebuilt every boot; RSA auth (ro.adb.secure=1) stays on.
- Shizuku root stays optional and on by default (--skip-shizuku-root,
  recorded per boot as SHIZUKU_ROOT=0 in autoroot.conf). Daemon stop
  rule generalizes: it stops once every enabled promotion is
  verified (Shizuku unless opted out, plus root adb); a failed
  enabled promotion leaves it up as the fallback channel.
- CLI: --autoroot will imply --custom-payload and --shizuku;
  --custom-payload becomes an optional-value flag (bare = build/use
  the in-repo daemon, path = override). After root adb lands, the
  provisioner's post-handoff host steps move to plain root adb shell
  and its daemon-protocol client is deleted.
- Audio tuning (--audio) is opt-in only, default off, never bundled
  into a profile - it serves voice flows, not root/debloat.
- De-Kiosk: the kiosk feature flags, the kiosk profile bundle,
  and the Kiosk framing in the README all go - this becomes a
  general Portal root provisioner. One deliberate survivor: a
  credits line in the README naming the original creator. The root
  stack itself never referenced Kiosk and needs no changes for
  this. (Done early — see section 13; only dropping
  "kiosk-satellite" from the repo name waits for the clean
  relaunch.)

## 12. Adjusted plan: root adb removed, CLI streamlining (2026-11-05)

Section 11's root-adb work is **removed from the plan entirely**
(owner decision, 2026-11-05 — not deferred and not an
operator-supplied step). Everything that depended on it is dropped
or reverted:

- **Goal state:** a provisioned Portal ends every boot with Shizuku
  as uid 0 (unless opted out) and the unauthenticated root daemon
  stopped. adbd stays shell (uid 2000) — accepted.
- **Daemon stop rule:** the section 10 rule stands as-is — the
  daemon stops once Shizuku root is verified. It does **not**
  generalize to a second promotion, because there is none.
- **Helper:** stays at 1.3 behavior. There is no 1.4 adbd work and
  no adbd fast-path check.
- **Daemon protocol client:** retained in the provisioner. It
  remains the host's root channel inside the provisioning window;
  the post-handoff move to plain root `adb shell` is cancelled.

**Loud consequence of opting out of Shizuku root:** with
`--skip-shizuku-root` (or without `--shizuku`) there is no second
root channel to fall back on. That configuration keeps the section
10 behavior — the daemon stays up for the rest of the boot as the
run's only root channel, with its unauthenticated loopback EXEC
surface (section 5) exposed for that whole boot. It must not be
presented as equivalent to the default Shizuku-root configuration.

**CLI streamlining (this change):**

- `--autoroot` now implies `--shizuku` and `--custom-payload`
  instead of silently staging an autoroot setup that could never
  run when either prerequisite was forgotten. Combining
  `--autoroot` with `--remove-shizuku` is an error.
- `--custom-payload` is an optional-value flag. Bare
  `--custom-payload` builds (via `root-daemon/Makefile`, as part of
  the normal build step) and uses this repository's root daemon at
  `root-daemon/portal-root-daemon`; `--custom-payload <path>` keeps
  using the given prebuilt binary as an override, unchanged.
- A standalone `--custom-payload` no longer falls through to the
  default audio action.

The de-Kiosk scrub followed (section 13). Next: the release
polish. Live validation of this change is recorded in the goal
workspace log.

## 13. De-Kiosk scrub (2026-11-06)

The provisioner is now a general Portal root provisioner. The whole
Kiosk Satellite feature surface was removed from
`tools/provision_portal.py`:

- Flags gone: `--profile` (its only choice was `kiosk`),
  `--install-kiosk-satellite`, `--kiosk-permissions`, `--kiosk-home`,
  `--restore-kiosk-home`, and `--device-owner`.
- Backing code gone: the KS package/component constants, the
  Kiosk Satellite GitHub-release APK fetch/install, permission
  apply/verify/status, home configure/verify, the device-owner flow
  (preflight, verify, the exploit-environment promotion, and its
  bootstrap-guard sub-run), and the `kiosk_satellite` section of
  `--status` output. The two target fields that only served those
  features (`kiosk_permission_settle_seconds`,
  `device_owner_system_credentials`) were removed from
  `tools/portal_targets.py` as well.
- `PROJECT_URL` now points at this fork; the product banner reads
  "Meta Portal Root Provisioner". (The only User-Agent strings in
  the provisioner belonged to the deleted release fetch.)
- README repositioned: no Kiosk framing in the title, intro, or
  usage; the four Kiosk feature sections and the profile are gone.
  One deliberate survivor, per the section 11 decision: the credits
  line naming jxlarrea as the original creator this was forked
  from. Apache-2.0 notices in modified files are unchanged.

Everything generic is untouched: the standard install/exploit flow,
lock repair, debloat, Meta-account removal, update blocking,
remote-wipe blocking, presence optimization, app updates, ADB auth
timeout, DNS, audio (still opt-in only, never bundled), Shizuku
install/root, custom payload, autoroot, and verify reboots.

The Kiosk steps the provisioner used to own now live in the owner's
`bootstrap.sh`, next to its existing non-Portal flow: it passes the
provisioner the explicit generic flag set the `kiosk` profile used
to expand to (minus the Kiosk flags), and after the Portal kiosk
setup it sets Kiosk Satellite as device owner (`dpm
set-active-admin` + `dpm set-device-owner`, best-effort) and as the
default launcher (`cmd package set-home-activity`).

Deliberately kept, and why:

- The repo name still contains "kiosk-satellite" (clone URL,
  `PROJECT_URL`, the banner's URL line). The rename happens at the
  Phase 5 clean relaunch, not now.
- The exploit's native device-owner install branch
  (`GHOSTLOCK_KIOSK_DEVICE_OWNER` in `exploit/src/fops.c` and its
  per-target copy) is now unreachable — the provisioner no longer
  sets that variable — but the native code is left in place:
  removing it would mean rebuilding and re-validating the exploit
  payloads for zero runtime effect.
- `docs/` keeps its historical Kiosk references; those are dated
  status/findings records, not product framing.
