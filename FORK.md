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
