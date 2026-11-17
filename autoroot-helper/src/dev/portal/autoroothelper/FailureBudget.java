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
 * win rate is ~18%, so loss streaks of 3+ are normal operation on
 * a healthy device, not pathology.
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
    static final int THRESHOLD = 3;

    static final String KEY_STREAK = "budget_streak";
    static final String KEY_OPEN = "budget_open";
    static final String KEY_STOOD_DOWN = "budget_stood_down";

    private int incompleteStreak;
    private boolean attemptOpen;
    private boolean stoodDown;

    FailureBudget(int incompleteStreak, boolean attemptOpen,
            boolean stoodDown) {
        this.incompleteStreak = incompleteStreak;
        this.attemptOpen = attemptOpen;
        this.stoodDown = stoodDown;
    }

    /**
     * Boot-time accounting, run before any new attempt starts: an
     * open mark with no verdict means the previous attempt never
     * completed, so it counts as one incomplete and the mark is
     * consumed. Reaching the threshold stands the service down.
     * Returns true when the persisted state changed.
     */
    boolean accountBoot() {
        boolean changed = false;
        if (attemptOpen) {
            attemptOpen = false;
            incompleteStreak++;
            changed = true;
        }
        if (incompleteStreak >= THRESHOLD && !stoodDown) {
            stoodDown = true;
            changed = true;
        }
        return changed;
    }

    /** Mark an attempt in progress; written before the race runs. */
    void attemptStarted() {
        attemptOpen = true;
    }

    /**
     * Record a completed attempt (win or clean loss): clears the
     * mark and resets the streak - any completed attempt breaks a
     * run of incomplete ones.
     */
    void attemptCompleted() {
        attemptOpen = false;
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
        stoodDown = false;
    }

    int incompleteStreak() {
        return incompleteStreak;
    }

    boolean attemptOpen() {
        return attemptOpen;
    }

    boolean stoodDown() {
        return stoodDown;
    }
}
