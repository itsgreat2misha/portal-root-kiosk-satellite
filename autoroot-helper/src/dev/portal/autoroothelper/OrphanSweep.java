// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Post-attempt orphan sweep policy.
 *
 * A race attempt runs as a /system/bin/true host process (the
 * staged runner execs it with the exploit preload) plus whatever
 * children it spawns. When the attempt's verdict lands, the host
 * process is supposed to exit - but twice in the 2026-11-17
 * posture sessions a winning attempt's tree wedged instead
 * (spinning in one case, ptrace-stopped in the other) and held
 * the Shizuku handoff for ~13 minutes until the processes
 * happened to exit on their own; in Run 33 a pair of spinning
 * orphans starved the handoff the same way until they were
 * killed by hand, after which it completed in ~90 s. The sweep
 * therefore runs after every attempt, once its verdict is in:
 * any true-rooted tree still alive at that point is debris by
 * definition, because the verdict is written only after the
 * attempt's real work (post-root actions included) completes.
 *
 * The kill set is every "true" process plus its descendants,
 * computed from a ps snapshot. Two exclusions are load-bearing:
 * the root daemon (comm portal-root-daemon, possibly truncated
 * by the kernel) is the handoff's own bridge and must never be
 * swept - it is not attempt debris even if it still sits under
 * a true ancestor in the snapshot, so excluded processes are
 * neither killed nor traversed through; and shizuku_server is
 * the handoff's destination. The service's own pid and pid 1
 * are never killed either.
 *
 * Pure logic, no Android dependencies, so the policy is unit
 * testable off-device.
 */
final class OrphanSweep {
    static final String HOST_COMM = "true";
    static final String DAEMON_COMM_PREFIX = "portal-root-d";
    static final String SHIZUKU_COMM = "shizuku_server";

    private OrphanSweep() {
    }

    /**
     * Selects the pids to kill from `ps -A -o pid,ppid,comm`
     * output. Malformed lines (including the header) are ignored.
     * Returns the kill set sorted ascending, possibly empty.
     */
    static List<Integer> selectKillPids(String psOutput, int selfPid) {
        List<Integer> result = new ArrayList<>();
        if (psOutput == null) {
            return result;
        }
        Map<Integer, String> commByPid = new HashMap<>();
        Map<Integer, List<Integer>> childrenByPid = new HashMap<>();
        for (String line : psOutput.split("\n")) {
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 3) {
                continue;
            }
            int pid;
            int ppid;
            try {
                pid = Integer.parseInt(parts[0]);
                ppid = Integer.parseInt(parts[1]);
            } catch (NumberFormatException ignored) {
                continue;
            }
            commByPid.put(pid, parts[2]);
            childrenByPid.computeIfAbsent(ppid, key -> new ArrayList<>())
                    .add(pid);
        }
        Set<Integer> kill = new HashSet<>();
        ArrayDeque<Integer> frontier = new ArrayDeque<>();
        for (Map.Entry<Integer, String> entry : commByPid.entrySet()) {
            if (HOST_COMM.equals(entry.getValue())
                    && !isExcluded(entry.getKey(), entry.getValue(),
                            selfPid)) {
                frontier.add(entry.getKey());
            }
        }
        while (!frontier.isEmpty()) {
            int pid = frontier.remove();
            if (!kill.add(pid)) {
                continue;
            }
            for (int child : childrenByPid.getOrDefault(
                    pid, Collections.emptyList())) {
                if (!isExcluded(child,
                        commByPid.getOrDefault(child, ""), selfPid)) {
                    frontier.add(child);
                }
            }
        }
        result.addAll(kill);
        Collections.sort(result);
        return result;
    }

    private static boolean isExcluded(int pid, String comm, int selfPid) {
        return pid <= 1
                || pid == selfPid
                || comm.startsWith(DAEMON_COMM_PREFIX)
                || SHIZUKU_COMM.equals(comm);
    }
}
