// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

/**
 * Flush-and-age policy for on-device race attempts (F1, 2026-11-19).
 *
 * Every boot auto-connects WiFi within seconds. The connection makes
 * system_server update the saved-network record (association count,
 * last connected, selection status) and schedule an asynchronous
 * WifiConfigStore write on a background thread. Attempt boots then
 * die young and uncleanly - race panics, watchdog cuts, the
 * clean-attempt reboot - inside that write's flush window, and
 * repeated episodes on the most-raced unit in the fleet lost its
 * saved network outright: the first clean boot afterwards loaded an
 * empty store, and the store's next save cemented the empty state.
 *
 * The guard therefore requires an attempt boot to reach
 * MIN_BOOT_AGE_MS before an attempt starts - by then the
 * connect-time write has long been scheduled - and the service
 * issues a sync at that point, so the write is durable before the
 * boot is allowed to die. Post-connect writes (selection-status
 * flips) do not empty the store; only the connect-time write needs
 * the protection.
 *
 * The floor started at 120 s and is 60 s since the 2026-11-19
 * timing measurement (wifi-guard-timing-measurement-2026-11-19):
 * the store's deferred flush is a fixed 10.0 s alarm in the device
 * framework (BUFFERED_WRITE_ALARM_INTERVAL_MS = 10,000 ms), live
 * change-to-write-complete measured 10.1-11.5 s, and the modeled
 * heavy-load worst case lands the flush by ~52 s.
 *
 * Pure policy, like AttemptWatchdog: the service supplies the boot
 * age from SystemClock.elapsedRealtime() and performs the wait and
 * the sync itself. An unknown age (a negative reading) fails toward
 * waiting the full window, never toward starting early.
 */
final class BootFlushGuard {

    static final long MIN_BOOT_AGE_MS = 60_000L;

    private BootFlushGuard() {
    }

    /** Whether an attempt may start on a boot of the given age. */
    static boolean attemptMayStart(long bootAgeMs) {
        return bootAgeMs >= MIN_BOOT_AGE_MS;
    }

    /** Milliseconds still to wait before an attempt may start. */
    static long remainingWaitMs(long bootAgeMs) {
        if (bootAgeMs < 0L) {
            return MIN_BOOT_AGE_MS;
        }
        return Math.max(0L, MIN_BOOT_AGE_MS - bootAgeMs);
    }
}
