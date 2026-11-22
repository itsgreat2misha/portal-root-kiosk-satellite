// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

/**
 * Per-boot build gate for autoroot (2026-11-22).
 *
 * The staged runner and its offsets are build-specific: after a
 * firmware update the staged payload no longer matches the running
 * kernel, and racing it anyway is at best useless and at worst the
 * crash/freeze class the failure budget exists to bound. At staging
 * time the provisioner therefore records the build fingerprint it
 * staged for in autoroot.conf (EXPECTED_FINGERPRINT), and on every
 * boot the service compares it against Build.FINGERPRINT before any
 * rooting attempt. On a mismatch the service makes no attempts,
 * persists the stood-down state in the state file under the keys
 * below, and surfaces it (notification, helper status naming the
 * build found, and the service log the host --status reads).
 *
 * The gate is not a latch: it is re-evaluated from the live
 * fingerprint on every boot, so it clears by itself when the build
 * matches again (for example after a rollback), and a host re-stage
 * rewrites autoroot.conf with the new build expectation and
 * deletes the state file, which clears the persisted stand-down.
 *
 * A config with no recorded expectation (staged before this gate
 * existed) is not gated: there is nothing to compare against, and
 * standing those units down would strand them until a re-stage
 * they may never get. The next staging records the expectation.
 *
 * Pure logic, no Android dependencies, so the comparison is unit
 * testable off-device.
 */
final class BuildGate {
    static final String CONF_KEY = "EXPECTED_FINGERPRINT";

    static final String KEY_STOOD_DOWN = "build_gate_stood_down";
    static final String KEY_EXPECTED = "build_gate_expected";
    static final String KEY_FOUND = "build_gate_found";

    private BuildGate() {
    }

    /** Whether an expectation was recorded at staging time. */
    static boolean hasExpectation(String expected) {
        return expected != null && !expected.trim().isEmpty();
    }

    /**
     * Whether this boot may run attempts: true when nothing was
     * recorded (ungated legacy staging) or when the live build
     * fingerprint is exactly the recorded one. A recorded
     * expectation with an unreadable live fingerprint (null) does
     * not match - the gate fails closed rather than racing a build
     * it cannot identify.
     */
    static boolean matches(String expected, String found) {
        if (!hasExpectation(expected)) {
            return true;
        }
        return found != null && expected.trim().equals(found.trim());
    }

    /** Whether this boot stands down under the gate. */
    static boolean stoodDown(String expected, String found) {
        return !matches(expected, found);
    }
}
