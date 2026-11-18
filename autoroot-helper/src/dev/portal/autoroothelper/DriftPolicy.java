// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

/**
 * Per-boot drift policy for the recorded-state pass (C3-A,
 * 2026-11-18).
 *
 * After autoroot recovers root, the service compares the live
 * device state against the end state the provisioner recorded in
 * autoroot.conf and repairs what drifted. This class is the pure
 * decision half: recorded expectation + live readings + which
 * channels are live at this exit -> one action per item. The
 * service performs the actions; nothing here touches the device.
 *
 * The channels differ by proven on-device walls, and the policy
 * encodes them rather than pretending every channel is root:
 *
 * - Private DNS is SettingsProvider state: the helper's loopback
 *   ADB shell (uid 2000) reads and writes it exactly as the host
 *   does, so DNS repair is available at every root-established
 *   exit.
 * - The alohausers package state can only be changed from the
 *   root daemon's EXEC window (the loopback shell's pm disable is
 *   refused with a SecurityException), so without a live daemon
 *   the item is report-only and its repair waits for the next
 *   win exit.
 * - otad.nodemon has no post-win writer at all (the property
 *   service refuses the shell domain; only the payload's
 *   init-context child sets it, attempt-coupled), so the pass
 *   checks it read-only and reports a staged-but-unset property
 *   instead of pretending to enforce it.
 *
 * An item with nothing recorded is a no-op: the pass enforces
 * recorded state, it does not invent desires.
 */
final class DriftPolicy {
    static final int NONE = 0;
    static final int REPAIR_VIA_SHELL = 1;
    static final int REPAIR_VIA_DAEMON = 2;
    static final int REPORT_ONLY = 3;

    private DriftPolicy() {
    }

    /** Absent-setting spellings: unset reads back as "null". */
    static String normalize(String value) {
        if (value == null) {
            return "null";
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? "null" : trimmed;
    }

    /**
     * Private DNS: expectedMode null means the run recorded no DNS
     * action (nothing to enforce). A live read that failed
     * (liveMode null) is report-only - the pass never writes a
     * setting it could not first read.
     */
    static int dnsAction(String expectedMode, String expectedSpecifier,
            String liveMode, String liveSpecifier) {
        if (expectedMode == null) {
            return NONE;
        }
        if (liveMode == null) {
            return REPORT_ONLY;
        }
        if (normalize(expectedMode).equals(normalize(liveMode))
                && normalize(expectedSpecifier)
                        .equals(normalize(liveSpecifier))) {
            return NONE;
        }
        return REPAIR_VIA_SHELL;
    }

    /**
     * alohausers package state: the only recorded desire is
     * "disabled" (the aloha end-state posture). No desire recorded
     * or the package already disabled is a no-op; drift with the
     * daemon window live repairs through it; drift without it is
     * report-only until the next win exit.
     */
    static int alohausersAction(boolean desireDisabled,
            boolean liveDisabled, boolean daemonAvailable) {
        if (!desireDisabled || liveDisabled) {
            return NONE;
        }
        return daemonAvailable ? REPAIR_VIA_DAEMON : REPORT_ONLY;
    }

    /**
     * otad.nodemon: check-only. Nothing staged -> nothing to
     * check; staged and set -> fine; staged but not set on this
     * boot -> report (enforcement stays with the payload's
     * win-time set, which already ran or failed before this pass).
     */
    static int nodemonAction(boolean staged, boolean propertyTrue) {
        if (!staged || propertyTrue) {
            return NONE;
        }
        return REPORT_ONLY;
    }
}
