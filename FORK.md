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
