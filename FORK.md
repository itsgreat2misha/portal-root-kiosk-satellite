# Fork notes — itsgreat2misha/portal-root-kiosk-satellite

Fork of [jxlarrea/portal-root-kiosk-satellite](https://github.com/jxlarrea/portal-root-kiosk-satellite)
(created Nov 2, 2026 from upstream `main` @ f941b57). Mikhail's `bootstrap.sh`
points at this fork. All changes are in `tools/provision_portal.py`:

1. **A failed bootstrap phase no longer starves the rest of the run.**
   Each dedicated bootstrap phase (audio, device owner, OTA, Meta accounts,
   debloat, remote-wipe, presence, presence FPS) is wrapped in
   `bootstrap_guard()`. In a multi-action run (e.g. `--profile kiosk`) a
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

With --custom-payload <binary> the provisioner stages the binary at /data/local/tmp and starts it inside the exploit's privileged window (GHOSTLOCK_CUSTOM_PAYLOAD=1). The payload runs as uid 0 in the shell SELinux domain, which cannot create files anywhere (open(O_CREAT) fails with EACCES) - so the payload is executed in place from its staged path, and success is detected by its observable effect, never by files it writes. Marker: CUSTOM_PAYLOAD_OK.

The exploit intentionally damages the proc_uid futex lock waiter tree; without repair the kernel panics 25-60 s after a successful landing. With PORTAL_LOCK_REPAIR=1 (default) the payload performs the solo-sentinel restore before returning: it verifies the exact waiter pattern, restores the sentinel node as tree root/leftmost, detaches the forged waiter, and only then clears the lock owner, with full read-back verification. Any mismatch aborts with PORTAL_LOCK_REPAIR_ABORT and writes nothing. Marker: PORTAL_LOCK_REPAIR_OK. A repaired boot reboots later only for normal reasons.

## 5. Root-mode Shizuku

With --shizuku and a verified custom payload, after CUSTOM_PAYLOAD_OK the provisioner asks the payload (loopback control channel, 127.0.0.1:37373) to restart the Shizuku server as root: it resolves the server starter and apk path on-device, kills any shell-uid server, and starts a new one, then polls until the server process reports uid 0. Marker: SHIZUKU_ROOT_OK. --skip-shizuku-root opts out. Note: the payload control channel on 127.0.0.1:37373 has NO authentication - any local app with INTERNET permission could use it while the payload runs. This is a known, accepted risk for a home kiosk device; do not expose the port beyond loopback.

## 6. On-device autoroot (--autoroot)

--autoroot makes a provisioned device self-sustaining: after one provisioning run, no host watcher is needed. Requires --shizuku and --custom-payload. After the payload and root-mode Shizuku verify, the provisioner stages the on-device helper and keeps the exploit sentinel installed. Marker: AUTOROOT_STAGED_OK.

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
