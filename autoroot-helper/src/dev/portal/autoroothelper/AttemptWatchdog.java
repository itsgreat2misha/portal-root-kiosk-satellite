// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

/**
 * Fail-fast policy for recovery-session attempts.
 *
 * Measured on Runs 21-27 (2026-11-14): attempts that never reach a
 * race verdict hang until the runner's 600 s socket timeout, and
 * those timeout-class attempts were ~47% of all recovery
 * wall-clock. Attempts that do reach a verdict write it to
 * attempt.log early - a winning attempt's WATCH_CFI_OK=1 was
 * observed ~2 min in, even though its handoff only completes at
 * the timeout edge - so the cutoff keys on the ABSENCE of a
 * verdict, never on elapsed time alone: an attempt whose verdict
 * has appeared is never cut, however long its collection runs.
 *
 * The 300 s cutoff sits in the measured empty band between the
 * slowest verdict-resolved fail (~244 s, and those return on
 * their own before the cutoff matters) and the fastest
 * timeout-class fail (600 s).
 *
 * Pure logic, no Android dependencies, so the policy is unit
 * testable off-device.
 */
final class AttemptWatchdog {
    static final long CUTOFF_MS = 300_000L;
    static final String VERDICT_MARKER = "WATCH_CFI_OK=";

    private AttemptWatchdog() {
    }

    /** True when the attempt should be cut: cutoff reached, no verdict yet. */
    static boolean shouldCut(long elapsedMs, boolean verdictSeen) {
        return !verdictSeen && elapsedMs >= CUTOFF_MS;
    }

    /** True when the given attempt.log tail contains a race verdict. */
    static boolean verdictIn(String attemptLogTail) {
        return attemptLogTail != null && attemptLogTail.contains(VERDICT_MARKER);
    }
}
