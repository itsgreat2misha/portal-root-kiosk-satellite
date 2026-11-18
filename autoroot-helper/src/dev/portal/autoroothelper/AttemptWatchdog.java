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
 * the timeout edge - so the no-verdict cutoff keys on the ABSENCE
 * of a verdict, never on elapsed time alone: an attempt whose
 * verdict has appeared is never cut by that rule, however long
 * its collection runs.
 *
 * The 300 s cutoff sits in the measured empty band between the
 * slowest verdict-resolved fail (~244 s, and those return on
 * their own before the cutoff matters) and the fastest
 * timeout-class fail (600 s).
 *
 * Post-verdict extension (2026-11-15, Run 30 evidence): a FAIL
 * verdict (WATCH_CFI_OK=0) can also be followed by a runner hang
 * to the full 600 s - the race is lost but nothing collects the
 * result. A fail-verdict attempt may therefore be cut too, but
 * only under two conditions: a grace period after the verdict
 * (FAIL_GRACE_MS, mirroring the service's post-attempt daemon
 * wait window, so a daemon that is still coming up has its full
 * window to appear), and the root daemon known-absent at the
 * moment of the cut. A WIN verdict is still never cut, and a
 * fail verdict with the daemon present is never cut - that
 * attempt's handoff belongs to the normal post-attempt path.
 *
 * Win-stall sweep (2026-11-17, C1b): a WIN verdict is never cut,
 * but live validation of the post-attempt orphan sweep showed it
 * cannot shorten a winning attempt's stall: the sweep runs only
 * after the foreground shell call returns, and the call returns
 * only at its own 600 s socket timeout, which is itself what
 * tears the wedged session down - by then the tree is already
 * gone and the sweep finds nothing. The watchdog poll loop is
 * the one thread alive during the stall, so the sweep also runs
 * from there: once a win verdict is WIN_SWEEP_GRACE_MS old and
 * the call is still outstanding, the attempt's leftover tree is
 * debris by the same argument as the post-attempt sweep (the
 * verdict is written only after the attempt's real work
 * completes) and is swept early - at most WIN_SWEEP_MAX times,
 * one grace period apart - instead of holding the handoff until
 * the timeout edge. The 600 s timeout remains the backstop.
 *
 * Pure logic, no Android dependencies, so the policy is unit
 * testable off-device.
 */
final class AttemptWatchdog {
    static final long CUTOFF_MS = 300_000L;
    static final long FAIL_GRACE_MS = 30_000L;
    static final long WIN_SWEEP_GRACE_MS = 120_000L;
    static final int WIN_SWEEP_MAX = 2;
    static final String VERDICT_MARKER = "WATCH_CFI_OK=";

    static final int VERDICT_NONE = -1;
    static final int VERDICT_FAIL = 0;
    static final int VERDICT_WIN = 1;

    private AttemptWatchdog() {
    }

    /** True when the attempt should be cut: cutoff reached, no verdict yet. */
    static boolean shouldCut(long elapsedMs, boolean verdictSeen) {
        return !verdictSeen && elapsedMs >= CUTOFF_MS;
    }

    /**
     * True when a fail-verdict attempt should be cut: the grace
     * period since the fail verdict has elapsed AND the root
     * daemon is known-absent. Never true for a win (callers only
     * consult this on a fail verdict) and never true while the
     * daemon is present.
     */
    static boolean shouldCutFailVerdict(long sinceFailVerdictMs,
            boolean daemonAbsent) {
        return daemonAbsent && sinceFailVerdictMs >= FAIL_GRACE_MS;
    }

    /**
     * True when a win-verdict attempt whose foreground shell call
     * is still outstanding should have its leftover process tree
     * swept from the watchdog thread: the grace period for the
     * next sweep has elapsed since the win verdict. Sweeps are
     * due at WIN_SWEEP_GRACE_MS intervals after the verdict, at
     * most WIN_SWEEP_MAX of them; after that the attempt's own
     * 600 s shell timeout remains the backstop. Never true
     * without a win verdict and never true once the call has
     * returned. This is not a cut: the verdict and its
     * accounting are untouched, only the orphaned tree is
     * collected early.
     */
    static boolean shouldSweepWinStall(int verdict, long sinceWinVerdictMs,
            int sweepsDone, boolean callReturned) {
        if (verdict != VERDICT_WIN || callReturned) {
            return false;
        }
        if (sweepsDone < 0 || sweepsDone >= WIN_SWEEP_MAX) {
            return false;
        }
        return sinceWinVerdictMs >= WIN_SWEEP_GRACE_MS * (sweepsDone + 1);
    }

    /** True when the given attempt.log tail contains a race verdict. */
    static boolean verdictIn(String attemptLogTail) {
        return verdictValue(attemptLogTail) != VERDICT_NONE;
    }

    /**
     * The race verdict in the given attempt.log tail: VERDICT_WIN
     * for WATCH_CFI_OK=1, VERDICT_FAIL for WATCH_CFI_OK=0,
     * VERDICT_NONE when no verdict line is present. When several
     * verdict lines appear, the last one governs.
     */
    static int verdictValue(String attemptLogTail) {
        if (attemptLogTail == null) {
            return VERDICT_NONE;
        }
        int markerAt = attemptLogTail.lastIndexOf(VERDICT_MARKER);
        if (markerAt < 0) {
            return VERDICT_NONE;
        }
        int valueAt = markerAt + VERDICT_MARKER.length();
        if (valueAt >= attemptLogTail.length()) {
            return VERDICT_NONE;
        }
        char value = attemptLogTail.charAt(valueAt);
        if (value == '1') {
            return VERDICT_WIN;
        }
        if (value == '0') {
            return VERDICT_FAIL;
        }
        return VERDICT_NONE;
    }
}
