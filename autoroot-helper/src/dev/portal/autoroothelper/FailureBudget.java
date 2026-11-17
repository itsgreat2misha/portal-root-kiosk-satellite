// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

/**
 * Cross-boot failure budget for autoroot attempts (2026-11-17).
 *
 * The per-attempt watchdogs and the per-session attempt cap bound
 * a single boot, but nothing bounded the cross-boot case: a fault
 * that deterministically crashes or freezes the device mid-attempt
 * reboots into a fresh session and loops forever, the device dying
 * mid-use on every cycle. This budget is the cross-boot bound.
 *
 * Only truly incomplete attempts count. The service writes an
 * in-progress mark when an attempt starts; an attempt that
 * completes under service control - a win OR a clean loss - writes
 * its verdict and clears the mark. A later boot (or service pass)
 * that finds the mark still set therefore knows the previous
 * attempt never completed: the device crashed, froze, or lost
 * power mid-attempt. That verdict-less signature is the only thing
 * counted. Clean race losses never count: the measured per-attempt
 * win rate is ~18%, so loss streaks are normal operation on a
 * healthy device, not pathology.
 *
 * One refinement (2026-11-17): a clean loss on some units reboots
 * the device before the service regains control, so the service
 * verdict is never written and the loss masquerades as an
 * incomplete attempt - three such boots stood a healthy unit down
 * in the posture test that day. The race itself, though, writes
 * its verdict (WATCH_CFI_OK) into attempt.log early, before the
 * runner returns. The mark therefore also records the attempt.log
 * offset at which the attempt's output begins, and boot-time
 * accounting first checks the log from that offset: a fail
 * verdict there means the attempt did complete, as a clean loss,
 * and counts as completed. The offset is cleared with the mark,
 * so a recovered verdict is consumed exactly once and can never
 * cover for a later attempt that died before writing anything.
 *
 * At THRESHOLD consecutive incomplete attempts the budget stands
 * the service down: it stops racing on that and later boots until
 * the user re-enables it on the device (which clears the counter
 * and re-arms the budget) or a host re-stage clears the state.
 *
 * The state lives in the autoroot state file under the keys below,
 * alongside - not as - the disable flag, so the provisioner's run
 * guard (which saves and restores the flag) cannot resurrect a
 * stand-down. A host re-stage deletes the state file, which is
 * what clears the budget from the host side.
 *
 * Pure logic, no Android dependencies, so the accounting is unit
 * testable off-device.
 */
final class FailureBudget {
    static final int THRESHOLD = 10;

    static final String KEY_STREAK = "budget_streak";
    static final String KEY_OPEN = "budget_open";
    static final String KEY_STOOD_DOWN = "budget_stood_down";
    static final String KEY_LOG_OFFSET = "budget_log_offset";

    private int incompleteStreak;
    private boolean attemptOpen;
    private boolean stoodDown;
    private long openLogOffset;

    FailureBudget(int incompleteStreak, boolean attemptOpen,
            boolean stoodDown, long openLogOffset) {
        this.incompleteStreak = incompleteStreak;
        this.attemptOpen = attemptOpen;
        this.stoodDown = stoodDown;
        this.openLogOffset = openLogOffset;
    }

    /** Boot-time accounting with no recovered verdict to apply. */
    boolean accountBoot() {
        return accountBoot(false);
    }

    /**
     * Boot-time accounting, run before any new attempt starts: an
     * open mark with no verdict means the previous attempt never
     * completed, so it counts as one incomplete and the mark is
     * consumed. Reaching the threshold stands the service down.
     *
     * When lossVerdictRecovered is set, the caller found the
     * previous attempt's own fail verdict in attempt.log (scoped
     * to the offset recorded with the mark): the attempt completed
     * as a clean loss and only the service verdict was lost, so it
     * is accounted as a completed attempt instead. The flag is
     * ignored when no attempt is open, so a stale verdict can
     * never be applied twice.
     *
     * Returns true when the persisted state changed.
     */
    boolean accountBoot(boolean lossVerdictRecovered) {
        boolean changed = false;
        if (attemptOpen) {
            attemptOpen = false;
            openLogOffset = -1;
            if (lossVerdictRecovered) {
                incompleteStreak = 0;
            } else {
                incompleteStreak++;
            }
            changed = true;
        }
        if (incompleteStreak >= THRESHOLD && !stoodDown) {
            stoodDown = true;
            changed = true;
        }
        return changed;
    }

    /**
     * Mark an attempt in progress; written before the race runs.
     * logOffset is the attempt.log size at this moment - the byte
     * offset at which this attempt's output begins - or -1 when it
     * could not be measured (verdict recovery is then disabled for
     * this attempt and a verdict-less mark counts as before).
     */
    void attemptStarted(long logOffset) {
        attemptOpen = true;
        openLogOffset = logOffset;
    }

    /**
     * Record a completed attempt (win or clean loss): clears the
     * mark and resets the streak - any completed attempt breaks a
     * run of incomplete ones.
     */
    void attemptCompleted() {
        attemptOpen = false;
        openLogOffset = -1;
        incompleteStreak = 0;
    }

    /**
     * User re-enable from the helper screen (or the equivalent
     * fresh state a host re-stage leaves behind): clears the
     * counter and the stand-down. The budget re-arms, so a
     * persisting fault stands down again after THRESHOLD more
     * incomplete boots.
     */
    void reenable() {
        incompleteStreak = 0;
        attemptOpen = false;
        openLogOffset = -1;
        stoodDown = false;
    }

    int incompleteStreak() {
        return incompleteStreak;
    }

    boolean attemptOpen() {
        return attemptOpen;
    }

    /** attempt.log offset recorded with the open mark, or -1. */
    long openLogOffset() {
        return openLogOffset;
    }

    boolean stoodDown() {
        return stoodDown;
    }
}
