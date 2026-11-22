// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Boot trigger for the on-device autoroot runner.
 *
 * On BOOT_COMPLETED this service first checks whether Shizuku already
 * serves as uid 0; if it does, the boot is done - the root daemon is a
 * bootstrap bridge only and is stopped as soon as the Shizuku handoff
 * completes. If the daemon is up but Shizuku is not root yet, the
 * service finishes the handoff through the daemon and then stops it.
 * Otherwise it performs the same discovery the host provisioner does
 * (bugreport for the memory start, staged simpleperf for the KASLR
 * base), launches the staged runner script, and waits for the daemon
 * to answer.
 * Attempts are counted in a state file under /data/local/tmp so the
 * per-session cap survives the reboots a failed attempt can cause.
 * The same state file carries the cross-boot failure budget (see
 * FailureBudget): attempts that never complete - the crash/freeze
 * signature - are counted across boots, and after 10 in a row the
 * service stands down instead of looping the fault forever.
 */
public final class AutorootService extends Service {
    private static final String TAG = "PortalAutoroot";
    private static final String DIR = "/data/local/tmp/portal-autoroot";
    private static final String CONF = DIR + "/autoroot.conf";
    private static final String STATE = DIR + "/state";
    private static final String RESULT = DIR + "/result";
    private static final String RUN_SH = DIR + "/run.sh";
    private static final String SERVICE_LOG = DIR + "/service.log";
    private static final String DISABLE_FLAG = "/data/local/tmp/portal-autoroot.disable";
    private static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";
    private static final String ALOHAUSERS_PACKAGE =
            "com.facebook.alohaservices.alohausers";
    private static final int DAEMON_PORT = 37373;
    // Bound on the post-starter wait of one Shizuku handoff try.
    // The poll loop's individual shell calls can each stall for
    // minutes when a wedged attempt tree is starving the device
    // (the ~13-minute handoff stalls of 2026-11-17), so the
    // iteration count alone does not bound the wait; the wall
    // clock does. A try that hits the bound fails, and
    // finishShizukuHandoff retries once after an orphan sweep; a
    // handoff still incomplete after that is retried by the next
    // service start's daemon-up path.
    private static final long HANDOFF_WAIT_MS = 120_000L;

    // Control surface for AutorootActivity. The activity only sends
    // intents; this service stays the single owner of shell work and
    // session state.
    public static final String ACTION_STOP_REBOOT =
            "dev.portal.autoroothelper.STOP_REBOOT";
    public static final String ACTION_SET_DISABLED =
            "dev.portal.autoroothelper.SET_DISABLED";
    public static final String ACTION_RUN_NOW =
            "dev.portal.autoroothelper.RUN_NOW";
    public static final String ACTION_STATUS_QUERY =
            "dev.portal.autoroothelper.STATUS_QUERY";
    public static final String ACTION_REENABLE =
            "dev.portal.autoroothelper.REENABLE";
    public static final String EXTRA_ENABLED = "enabled";

    public static final String PREFS_NAME = "autoroot_status";
    public static final String PREF_PHASE = "phase";
    public static final String PREF_ATTEMPT = "attempt";
    public static final String PREF_MAX = "max";
    public static final String PREF_DETAIL = "detail";
    public static final String PREF_DISABLED = "disabled";
    public static final String PREF_STOOD_DOWN = "stood_down";
    public static final String PREF_BUILD_MISMATCH = "build_mismatch";

    // The failure-budget stand-down notification: posted on the
    // stood-down boot and kept while stood down (see FailureBudget).
    private static final String NOTIFY_CHANNEL_ID = "autoroot_stood_down";
    private static final int NOTIFY_ID_STOOD_DOWN = 1;
    private static final int NOTIFY_ID_BUILD_GATE = 2;

    private volatile boolean workerRunning;
    private volatile boolean stopRequested;
    private volatile boolean forceFreshSession;
    private volatile boolean budgetAttemptOpen;
    private volatile AdbClient activeClient;
    private volatile String lastPhase = "IDLE";
    private volatile int lastAttempt;
    private volatile int lastMax;
    private volatile String lastDetail = "";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP_REBOOT.equals(action)) {
            new Thread(this::handleStopReboot, "portal-autoroot-ctl").start();
            return START_STICKY;
        }
        if (ACTION_SET_DISABLED.equals(action)) {
            boolean enabled = intent.getBooleanExtra(EXTRA_ENABLED, true);
            new Thread(() -> setDisabled(!enabled), "portal-autoroot-ctl").start();
            return START_STICKY;
        }
        if (ACTION_STATUS_QUERY.equals(action)) {
            new Thread(this::refreshDisabledPref, "portal-autoroot-ctl").start();
            return START_STICKY;
        }
        if (ACTION_REENABLE.equals(action)) {
            // The user accepted the risk on the helper screen:
            // clear the stand-down, then start a session.
            new Thread(() -> handleReenable(startId),
                    "portal-autoroot-ctl").start();
            return START_STICKY;
        }
        if (ACTION_RUN_NOW.equals(action)) {
            forceFreshSession = true;
        }
        startWorkerIfIdle(startId);
        return START_STICKY;
    }

    private void startWorkerIfIdle(int startId) {
        if (!workerRunning) {
            workerRunning = true;
            stopRequested = false;
            new Thread(() -> run(startId), "portal-autoroot").start();
        }
    }

    private void run(int startId) {
        try {
            runAutoroot();
        } catch (Exception error) {
            Log.e(TAG, "autoroot pass failed", error);
            logFile("error " + error);
            completeOpenAttemptAfterError();
        } finally {
            workerRunning = false;
            stopSelf(startId);
        }
    }

    private void runAutoroot() throws Exception {
        // The stand-down notification follows the persisted budget
        // state on every service start, ahead of every early return
        // below: it is kept while stood down and cleared only when
        // the stand-down itself clears.
        refreshStandDownNotification();
        refreshBuildGateNotification();
        if (!shell("test -f " + DISABLE_FLAG + " && echo yes").contains("yes")) {
            // not disabled: fall through
        } else {
            Log.i(TAG, "autoroot disabled by flag " + DISABLE_FLAG);
            logFile("disabled by flag");
            publishStatus("DISABLED", 0, 0, "disabled by flag");
            return;
        }
        publishStatus("WORKING", lastAttempt, lastMax, "checking");
        String bootId = shell("cat /proc/sys/kernel/random/boot_id").trim();
        Map<String, String> conf = readKeyValues(CONF);
        // Per-boot build gate (2026-11-22): before any rooting
        // attempt - ahead of the root-already-up exits, discovery
        // and the race - compare the fingerprint recorded at
        // staging time against the build of this boot. On a
        // mismatch the staged payload targets a different kernel:
        // make no attempts, persist the stood-down state, and
        // surface it. The gate re-evaluates every boot, so it
        // clears when the build matches again; a re-stage rewrites
        // the expectation and deletes the state file, clearing it
        // from the host side.
        String expectedBuild = conf.get(BuildGate.CONF_KEY);
        String foundBuild = Build.FINGERPRINT;
        if (BuildGate.stoodDown(expectedBuild, foundBuild)) {
            Map<String, String> gateState = readKeyValues(STATE);
            gateState.put(BuildGate.KEY_STOOD_DOWN, "1");
            gateState.put(BuildGate.KEY_EXPECTED,
                    expectedBuild == null ? "" : expectedBuild.trim());
            gateState.put(BuildGate.KEY_FOUND,
                    foundBuild == null ? "" : foundBuild);
            writeState(gateState);
            Log.w(TAG, "autoroot stood down by build gate: expected "
                    + expectedBuild + " but this boot is " + foundBuild);
            logFile("build gate stood down expected=" + expectedBuild
                    + " found=" + foundBuild);
            publishStatus("BUILD_MISMATCH", lastAttempt, lastMax,
                    "unsupported build " + foundBuild
                            + " (staged for " + expectedBuild + ")");
            refreshBuildGateNotification();
            return;
        }
        clearBuildGateState();
        int maxAttempts = parseInt(conf.get("MAX_ATTEMPTS"), 4);
        long sessionWindowSec = parseLong(conf.get("SESSION_WINDOW_SEC"), 7200);
        String simpleperf = conf.getOrDefault("SIMPLEPERF", "/data/local/tmp/portal-simpleperf");
        String[] offsetParts = conf.getOrDefault("KASLR_OFFSETS", "0x3354").split(",");
        long[] offsets = new long[offsetParts.length];
        for (int i = 0; i < offsetParts.length; i++) {
            offsets[i] = Long.parseLong(offsetParts[i].trim().replace("0x", ""), 16);
        }

        if (shizukuServingRoot()) {
            logFile("shizuku already root boot=" + bootId);
            // Root is already up, so no race and no win window:
            // the loopback shell is the only channel the drift
            // pass has here (package repair waits for a win).
            enforceRecordedState(false, conf);
            publishStatus("DONE", lastAttempt, lastMax, "root active (shizuku)");
            Map<String, String> state = readKeyValues(STATE);
            state.put("done_boot", bootId);
            // Root is active, so an attempt left open by a previous
            // boot did complete in effect - record its verdict
            // instead of counting it incomplete at the accounting
            // below.
            completeBudgetAttempt(state);
            writeState(state);
            return;
        }
        if (daemonServingRoot()) {
            // Daemon up but Shizuku not root yet (the provisioning
            // boot, or a session interrupted mid-handoff): finish the
            // handoff through the daemon, then stop it - with Shizuku
            // serving as root the daemon has no further job.
            logFile("daemon already up boot=" + bootId);
            publishStatus("DONE", lastAttempt, lastMax, "root active");
            boolean handedOff = finishShizukuHandoff();
            // The daemon window closes below; run the drift pass
            // first so its package leg can use it.
            enforceRecordedState(true, conf);
            if (handedOff) {
                stopDaemon();
            }
            Map<String, String> state = readKeyValues(STATE);
            state.put("done_boot", bootId);
            completeBudgetAttempt(state);
            writeState(state);
            return;
        }

        Map<String, String> state = readKeyValues(STATE);
        // Failure-budget accounting for the previous attempt, then
        // the stand-down gate - both before any new attempt starts.
        // A verdict-less mark counts one incomplete; at the
        // threshold the service stands down and does not race.
        // First, though, recover the race's own verdict when one
        // exists: the native attempt writes WATCH_CFI_OK into
        // attempt.log early, so a clean loss whose reboot outran
        // this service's verdict still left its record behind.
        // The check is scoped to the log offset recorded with the
        // mark, so the verdict consulted is the open attempt's
        // own, and clearing the mark consumes it. Only a fail
        // verdict recovers - a win verdict with no root active
        // means the attempt died after the race, which stays in
        // the counted crash/freeze class.
        FailureBudget budget = loadBudget(state);
        boolean lossVerdictRecovered = budget.attemptOpen()
                && budget.openLogOffset() >= 0
                && attemptVerdict(budget.openLogOffset())
                        == AttemptWatchdog.VERDICT_FAIL;
        if (budget.accountBoot(lossVerdictRecovered)) {
            storeBudget(state, budget);
            writeState(state);
            logFile(lossVerdictRecovered
                    ? "failure budget: loss verdict recovered from"
                            + " attempt.log; attempt counted completed"
                    : "failure budget: verdict-less attempt counted,"
                            + " streak=" + budget.incompleteStreak());
        }
        if (budget.stoodDown()) {
            Log.w(TAG, "autoroot stood down by failure budget streak="
                    + budget.incompleteStreak());
            logFile("stood down streak=" + budget.incompleteStreak());
            publishStatus("STOOD_DOWN", lastAttempt, lastMax,
                    "crashed or froze " + budget.incompleteStreak()
                            + " boots running");
            refreshStandDownNotification();
            return;
        }
        long now = System.currentTimeMillis() / 1000;
        long sessionStart = parseLong(state.get("session_start"), 0);
        int attempts = parseInt(state.get("attempts"), 0);
        if (forceFreshSession) {
            // RUN_NOW from the UI: start over with a full budget even
            // if this window's session capped out.
            forceFreshSession = false;
            sessionStart = now;
            attempts = 0;
            state.remove("done_boot");
        }
        String doneBoot = state.get("done_boot");
        if (doneBoot != null && !doneBoot.isEmpty() && !doneBoot.equals(bootId)) {
            // A previous boot completed autoroot (done_boot set): that
            // session is over, so this boot starts a fresh session with
            // a full attempt budget. Without this, two reboots inside
            // one session window leave the second boot capped out by
            // the first boot's spent attempts (found live 2026-11-04:
            // the recovery session landed on attempt 4 of 4, leaving
            // attempts=4 on disk for the next boot).
            sessionStart = now;
            attempts = 0;
            state.remove("done_boot");
        }
        if (sessionStart == 0 || now - sessionStart > sessionWindowSec) {
            sessionStart = now;
            attempts = 0;
        }
        if (attempts >= maxAttempts) {
            Log.w(TAG, "autoroot attempt cap reached attempts=" + attempts);
            logFile("capped attempts=" + attempts);
            publishStatus("CAPPED", attempts, maxAttempts,
                    "attempt cap reached");
            return;
        }
        // Flush-and-age guard (F1, 2026-11-19): the attempt may not
        // start until this boot is old enough for its connect-time
        // WiFi store write to be flushed. Runs before the attempt is
        // counted and before the failure budget's in-progress mark
        // is written, so a stop during the wait leaves both
        // untouched.
        if (!waitForBootFlushWindow()) {
            logFile("stopped by user during wifi flush guard");
            return;
        }
        attempts++;
        state.put("session_start", Long.toString(sessionStart));
        state.put("attempts", Integer.toString(attempts));
        // The failure budget's in-progress mark, written before the
        // attempt runs: from here on, every controlled exit records
        // the attempt's verdict via completeBudgetAttempt, so a
        // mark still set on a later boot means this attempt never
        // completed (the crash/freeze signature). The mark records
        // the current attempt.log size with it: attempt.log is
        // append-only and nothing writes it between here and the
        // attempt's launch, so that offset is exactly where this
        // attempt's output begins, which is what lets a later boot
        // recover this attempt's own race verdict from the log.
        budget.attemptStarted(attemptLogSizeForBudget());
        storeBudget(state, budget);
        budgetAttemptOpen = true;
        writeState(state);
        logFile("attempt " + attempts + " of " + maxAttempts + " boot=" + bootId);
        publishStatus("ATTEMPT", attempts, maxAttempts, "discovering addresses");
        showStatusUi();

        String memstart = discoverMemstart();
        String kaslr = memstart == null ? null : discoverKaslr(simpleperf, offsets);
        if (stopRequested) {
            logFile("stopped by user");
            completeBudgetAttempt(state, budget);
            return;
        }
        if (memstart == null || kaslr == null) {
            Log.w(TAG, "discovery failed memstart=" + memstart + " kaslr=" + kaslr);
            logFile("discovery failed memstart=" + memstart + " kaslr=" + kaslr);
            publishStatus("FAILED", attempts, maxAttempts, "discovery failed");
            completeBudgetAttempt(state, budget);
            rebootForCleanAttempt(attempts, maxAttempts);
            return;
        }
        logFile("discovered kaslr=" + kaslr + " memstart=" + memstart);
        publishStatus("ATTEMPT", attempts, maxAttempts, "attempt running");

        shell("rm -f " + RESULT);
        // Run the attempt in the FOREGROUND of a long-timeout shell
        // call. The detached nohup launch did not survive: across the
        // first live sessions (2026-11-04) no service-launched attempt
        // ever wrote its banner or result file, and no runner process
        // was alive minutes into the poll window - the runner dies
        // with its launching shell session. A foreground call keeps
        // the session open for the whole attempt, the same shape as
        // the host provisioner's per-attempt adb shell and as the
        // long discovery calls above. run.sh redirects the exploit
        // output to attempt.log itself and writes the result file
        // before it returns. The 600 s timeout sits above the native
        // run's long pole (the socket-watch phase alone waited ~305 s
        // in the first landed attempt, and that win concluded by
        // ~500 s); a hung attempt - one ran past 900 s with no
        // verdict - is cut at 600 s instead of eating the session,
        // and the kernel panic its damaged lock causes bounds it
        // independently.
        //
        // Fail-fast watchdog (2026-11-14): the launch runs on its
        // own thread while this thread polls attempt.log for the
        // race verdict. An attempt with NO verdict after
        // AttemptWatchdog.CUTOFF_MS is cut by closing the tracked
        // client - the same teardown the stop path uses - instead
        // of riding to the 600 s timeout. A WIN verdict is never
        // cut, but its leftover tree is swept from the watchdog
        // thread once the verdict is 120 s old and the call is
        // still outstanding (C1b, 2026-11-17): the post-attempt
        // sweep cannot reach a wedged winning tree before the
        // call returns at the 600 s timeout, so without the
        // in-loop sweep a wedged win holds the handoff to the
        // timeout edge. Post-verdict extension
        // (2026-11-15): a FAIL verdict followed by a runner hang
        // is cut too, but only after the watchdog's grace period
        // and only while the root daemon is known-absent (see
        // AttemptWatchdog).
        long attemptLogOffset = attemptLogSize();
        runAttemptWithWatchdog(kaslr, memstart, attempts, attemptLogOffset);
        if (stopRequested) {
            logFile("stopped by user");
            completeBudgetAttempt(state, budget);
            return;
        }
        // The attempt's verdict is in, so any of its process tree
        // still alive is an orphan: sweep before the handoff,
        // whose shell calls the orphans would otherwise starve.
        sweepAttemptOrphans("post-attempt");
        boolean up = false;
        for (int waited = 0; waited < 30; waited += 5) {
            if (daemonServingRoot()) {
                up = true;
                break;
            }
            if (stopRequested) {
                logFile("stopped by user");
                completeBudgetAttempt(state, budget);
                return;
            }
            Thread.sleep(5000);
        }
        if (up) {
            Log.i(TAG, "daemon up after attempt " + attempts);
            logFile("daemon up attempt=" + attempts);
            publishStatus("DONE", attempts, maxAttempts, "root active");
            boolean handedOff = finishShizukuHandoff();
            // The daemon window closes below; run the drift pass
            // first so its package leg can use it.
            enforceRecordedState(true, conf);
            if (handedOff) {
                stopDaemon();
            }
            state.put("done_boot", bootId);
            completeBudgetAttempt(state, budget);
            writeState(state);
            return;
        }
        Log.w(TAG, "attempt " + attempts + " did not bring the daemon up");
        logFile("attempt failed n=" + attempts);
        publishStatus("FAILED", attempts, maxAttempts, "attempt failed");
        completeBudgetAttempt(state, budget);
        rebootForCleanAttempt(attempts, maxAttempts);
    }

    // ---- attempt watchdog ----------------------------------------------

    private static final String ATTEMPT_LOG = DIR + "/attempt.log";
    private static final long WATCHDOG_POLL_MS = 5000;

    /**
     * Runs one attempt via the tracked foreground shell call on a
     * launch thread, polling attempt.log for the verdict marker in
     * the meantime. Cuts the attempt at the watchdog cutoff when no
     * verdict has appeared, and cuts a fail-verdict attempt after
     * the grace period while the root daemon is known-absent. A win
     * verdict is never cut, but once it is 120 s old and the call
     * is still outstanding this loop sweeps the attempt's leftover
     * process tree itself (at most twice, 120 s apart): the
     * post-attempt sweep cannot reach a wedged winning tree until
     * the call returns at its 600 s socket timeout, so without
     * this the stall always lasts to the timeout edge. A FAIL
     * verdict with the root daemon serving gets the same sweep
     * treatment (the verdict line reports the whole post-root
     * action chain, so a late action failure can flip a won
     * race's line to FAIL; see AttemptWatchdog's fail-stall
     * policy). Otherwise the launch rides to its own completion
     * or the 600 s shell timeout, exactly as the pre-watchdog
     * code did.
     */
    private void runAttemptWithWatchdog(String kaslr, String memstart,
            int attempts, long attemptLogOffset) {
        final Exception[] launchError = new Exception[1];
        Thread launch = new Thread(() -> {
            try {
                shellTracked("sh " + RUN_SH + " " + kaslr + " " + memstart
                        + " " + attempts, 600000);
            } catch (Exception error) {
                launchError[0] = error;
            }
        }, "portal-autoroot-attempt");
        long startedMs = System.currentTimeMillis();
        launch.start();
        int verdict = AttemptWatchdog.VERDICT_NONE;
        long failVerdictAtMs = 0;
        long winVerdictAtMs = 0;
        int winSweepsDone = 0;
        int failSweepsDone = 0;
        boolean daemonPresent = false;
        while (launch.isAlive()) {
            if (stopRequested) {
                break;
            }
            if (verdict == AttemptWatchdog.VERDICT_NONE) {
                verdict = attemptVerdict(attemptLogOffset);
                if (verdict == AttemptWatchdog.VERDICT_FAIL) {
                    failVerdictAtMs = System.currentTimeMillis();
                } else if (verdict == AttemptWatchdog.VERDICT_WIN) {
                    winVerdictAtMs = System.currentTimeMillis();
                }
            }
            long nowMs = System.currentTimeMillis();
            if (verdict == AttemptWatchdog.VERDICT_WIN
                    && AttemptWatchdog.shouldSweepWinStall(verdict,
                            nowMs - winVerdictAtMs, winSweepsDone,
                            !launch.isAlive())) {
                // Win-stall sweep: the verdict is in, so the
                // attempt's real work is done and any of its tree
                // still alive is debris - but the post-attempt
                // sweep only runs once this foreground call
                // returns, and the call returns only at its
                // 600 s socket timeout. Sweep from here, the one
                // thread alive during the stall. The call itself
                // is never cut and the verdict accounting is
                // untouched; the outcome is logged whether or
                // not anything was killed, so a future stall is
                // self-explaining.
                winSweepsDone++;
                List<Integer> killed = sweepAttemptOrphans(
                        "win-stall-" + winSweepsDone);
                Log.w(TAG, "win-stall sweep attempt=" + attempts
                        + " sweep=" + winSweepsDone + " killed=" + killed);
                logFile("win-stall sweep attempt=" + attempts
                        + " sweep=" + winSweepsDone
                        + " killed=" + (killed == null ? "error" : killed));
            }
            if (verdict == AttemptWatchdog.VERDICT_FAIL && daemonPresent
                    && AttemptWatchdog.shouldSweepFailStall(verdict,
                            daemonPresent, nowMs - failVerdictAtMs,
                            failSweepsDone, !launch.isAlive())) {
                // Fail-stall sweep: the verdict is FAIL but the
                // root daemon is serving, so the race itself was
                // won and the verdict line is reporting a late
                // post-root action's failure instead (see
                // AttemptWatchdog). The attempt is never cut,
                // but its leftover tree is debris by the same
                // argument as the win-stall sweep, and it holds
                // this foreground call - and with it the
                // handoff - to the 600 s socket timeout. Sweep
                // from here; the post-attempt path then finds
                // the daemon up and proceeds as for a win. The
                // verdict and its accounting are untouched; the
                // outcome is logged whether or not anything was
                // killed.
                failSweepsDone++;
                List<Integer> killed = sweepAttemptOrphans(
                        "fail-stall-" + failSweepsDone);
                Log.w(TAG, "fail-stall sweep attempt=" + attempts
                        + " sweep=" + failSweepsDone + " killed=" + killed);
                logFile("fail-stall sweep attempt=" + attempts
                        + " sweep=" + failSweepsDone
                        + " killed=" + (killed == null ? "error" : killed));
            }
            boolean cut = false;
            String cutLog = null;
            if (verdict == AttemptWatchdog.VERDICT_FAIL && !daemonPresent) {
                // Post-verdict hang: the race is lost, but the
                // runner may still be bringing the daemon up in
                // its final steps. Give it the grace window (the
                // same 30 s the post-attempt path waits for the
                // daemon), then cut only while the daemon is
                // known-absent. If the daemon IS serving, this
                // attempt is never cut - the post-attempt daemon
                // check owns its handoff.
                long sinceFailMs = nowMs - failVerdictAtMs;
                if (sinceFailMs >= AttemptWatchdog.FAIL_GRACE_MS) {
                    if (daemonServingRoot()) {
                        daemonPresent = true;
                        logFile("fail verdict attempt=" + attempts
                                + " but daemon present; not cutting");
                    } else if (AttemptWatchdog.shouldCutFailVerdict(
                            sinceFailMs, true)) {
                        cut = true;
                        cutLog = "fail-fast cutoff attempt=" + attempts
                                + " fail verdict, daemon absent";
                    }
                }
            } else if (AttemptWatchdog.shouldCut(
                    nowMs - startedMs, verdict != AttemptWatchdog.VERDICT_NONE)) {
                cut = true;
                cutLog = "fail-fast cutoff attempt=" + attempts
                        + " no verdict after "
                        + (AttemptWatchdog.CUTOFF_MS / 1000) + "s";
            }
            if (cut) {
                AdbClient client = activeClient;
                if (client != null) {
                    Log.w(TAG, cutLog + ", cutting attempt " + attempts);
                    logFile(cutLog);
                    try {
                        client.close();
                    } catch (Exception ignored) {
                    }
                    break;
                }
                // The launch thread has not registered its client
                // yet; keep polling rather than cutting blind.
            }
            try {
                Thread.sleep(WATCHDOG_POLL_MS);
            } catch (InterruptedException error) {
                break;
            }
        }
        if (winSweepsDone > 0) {
            logFile("win-stall outcome attempt=" + attempts
                    + " sweeps=" + winSweepsDone
                    + " callReturned=" + !launch.isAlive());
        }
        if (failSweepsDone > 0) {
            logFile("fail-stall outcome attempt=" + attempts
                    + " sweeps=" + failSweepsDone
                    + " callReturned=" + !launch.isAlive());
        }
        try {
            launch.join(30000);
        } catch (InterruptedException ignored) {
        }
        if (launchError[0] != null) {
            Log.w(TAG, "attempt runner error", launchError[0]);
            logFile("attempt runner error " + launchError[0]);
        }
    }

    /**
     * attempt.log is append-only across attempts and sessions, so
     * the verdict check is scoped to the bytes written since this
     * attempt started (the offset captured just before launch).
     * tail -c +N is 1-based: +offset+1 starts exactly at the first
     * byte this attempt can write. A shrunken log (fresh staging)
     * yields an empty tail, never a stale verdict.
     */
    private int attemptVerdict(long attemptLogOffset) {
        try {
            String tail = shell("tail -c +" + (attemptLogOffset + 1)
                    + " " + ATTEMPT_LOG + " 2>/dev/null");
            return AttemptWatchdog.verdictValue(tail);
        } catch (Exception ignored) {
            return AttemptWatchdog.VERDICT_NONE;
        }
    }

    private long attemptLogSize() {
        try {
            String out = shell("stat -c %s " + ATTEMPT_LOG
                    + " 2>/dev/null").trim();
            return Long.parseLong(out);
        } catch (Exception ignored) {
            return 0;
        }
    }

    /**
     * attemptLogSize for the failure budget's mark: -1 when the
     * size cannot be measured, so verdict recovery is disabled for
     * that attempt instead of consulting the log from a guessed
     * offset (a guess could reach an earlier attempt's verdict).
     */
    private long attemptLogSizeForBudget() {
        try {
            String out = shell("stat -c %s " + ATTEMPT_LOG
                    + " 2>/dev/null").trim();
            return Long.parseLong(out);
        } catch (Exception ignored) {
            return -1;
        }
    }

    // ---- failure budget ----------------------------------------------

    private FailureBudget loadBudget(Map<String, String> state) {
        return new FailureBudget(
                parseInt(state.get(FailureBudget.KEY_STREAK), 0),
                "1".equals(state.get(FailureBudget.KEY_OPEN)),
                "1".equals(state.get(FailureBudget.KEY_STOOD_DOWN)),
                parseLong(state.get(FailureBudget.KEY_LOG_OFFSET), -1));
    }

    private void storeBudget(Map<String, String> state,
            FailureBudget budget) {
        state.put(FailureBudget.KEY_STREAK,
                Integer.toString(budget.incompleteStreak()));
        state.put(FailureBudget.KEY_OPEN, budget.attemptOpen() ? "1" : "0");
        state.put(FailureBudget.KEY_STOOD_DOWN,
                budget.stoodDown() ? "1" : "0");
        state.put(FailureBudget.KEY_LOG_OFFSET,
                Long.toString(budget.openLogOffset()));
    }

    /**
     * Records the verdict of the attempt this pass opened: the
     * attempt completed under service control (win or clean loss),
     * so its mark clears and the incomplete streak resets. Called
     * on every controlled exit after the mark was written.
     */
    private void completeBudgetAttempt(Map<String, String> state,
            FailureBudget budget) {
        budget.attemptCompleted();
        storeBudget(state, budget);
        budgetAttemptOpen = false;
        writeState(state);
    }

    /** Verdict for an open mark, loading the budget from the map. */
    private void completeBudgetAttempt(Map<String, String> state) {
        completeBudgetAttempt(state, loadBudget(state));
    }

    /**
     * Safety net for a service-level failure (an exception out of
     * runAutoroot): the device did not crash - this process caught
     * the failure - so an attempt left open is closed as completed
     * rather than counted incomplete on the next boot. Best effort:
     * if the device is actually dying, the write simply fails and
     * the mark survives, which is the correct outcome then.
     */
    private void completeOpenAttemptAfterError() {
        if (!budgetAttemptOpen) {
            return;
        }
        budgetAttemptOpen = false;
        try {
            Map<String, String> state = readKeyValues(STATE);
            FailureBudget budget = loadBudget(state);
            budget.attemptCompleted();
            storeBudget(state, budget);
            writeState(state);
            logFile("attempt closed by error handler"
                    + " (service-level failure)");
        } catch (Exception ignored) {
        }
    }

    /**
     * User re-enable from the helper screen (the notification's
     * target): clears the counter and the stand-down, removes the
     * notification, and starts a session. The budget re-arms - a
     * persisting fault stands down again after 10 more incomplete
     * boots. No provisioner run is needed; a host re-stage also
     * clears the state (it deletes the state file).
     */
    private void handleReenable(int startId) {
        try {
            Map<String, String> state = readKeyValues(STATE);
            FailureBudget budget = loadBudget(state);
            budget.reenable();
            storeBudget(state, budget);
            writeState(state);
            logFile("failure budget cleared by user re-enable");
            publishStatus("IDLE", lastAttempt, lastMax, "re-enabled");
            refreshStandDownNotification();
        } catch (Exception error) {
            Log.w(TAG, "re-enable failed", error);
            return;
        }
        forceFreshSession = true;
        startWorkerIfIdle(startId);
    }

    /**
     * Keeps the stand-down notification and the published
     * stood-down pref in step with the persisted budget state:
     * posted while stood down, cancelled when not.
     */
    private void refreshStandDownNotification() {
        boolean stoodDown = false;
        int streak = 0;
        try {
            FailureBudget budget = loadBudget(readKeyValues(STATE));
            stoodDown = budget.stoodDown();
            streak = budget.incompleteStreak();
        } catch (Exception ignored) {
        }
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                .putBoolean(PREF_STOOD_DOWN, stoodDown).apply();
        if (stoodDown) {
            postStandDownNotification(streak);
        } else {
            cancelStandDownNotification();
        }
    }

    private void postStandDownNotification(int streak) {
        try {
            NotificationManager manager = (NotificationManager)
                    getSystemService(NOTIFICATION_SERVICE);
            if (manager == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 26) {
                manager.createNotificationChannel(new NotificationChannel(
                        NOTIFY_CHANNEL_ID, "Autoroot stand-down",
                        NotificationManager.IMPORTANCE_DEFAULT));
            }
            Intent intent = new Intent(this, AutorootActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            PendingIntent pending = PendingIntent.getActivity(
                    this, 0, intent,
                    Build.VERSION.SDK_INT >= 23
                            ? PendingIntent.FLAG_IMMUTABLE : 0);
            Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                    ? new Notification.Builder(this, NOTIFY_CHANNEL_ID)
                    : new Notification.Builder(this);
            Notification notification = builder
                    .setSmallIcon(android.R.drawable.ic_dialog_alert)
                    .setContentTitle("Autoroot is off")
                    .setContentText("Autoroot crashed or froze " + streak
                            + " boots in a row and turned itself off."
                            + " Tap to review and re-enable.")
                    .setContentIntent(pending)
                    .setOngoing(true)
                    .build();
            manager.notify(NOTIFY_ID_STOOD_DOWN, notification);
        } catch (Exception error) {
            Log.w(TAG, "stand-down notification failed", error);
        }
    }

    private void cancelStandDownNotification() {
        try {
            NotificationManager manager = (NotificationManager)
                    getSystemService(NOTIFICATION_SERVICE);
            if (manager != null) {
                manager.cancel(NOTIFY_ID_STOOD_DOWN);
            }
        } catch (Exception ignored) {
        }
    }

    /**
     * Clears a persisted build-gate stand-down once the live build
     * matches the staged expectation again (or none is recorded):
     * drops the gate keys from the state file and the notification.
     * A no-op when the gate never stood this unit down, so a normal
     * boot does not rewrite the state file.
     */
    private void clearBuildGateState() {
        try {
            Map<String, String> state = readKeyValues(STATE);
            if (!"1".equals(state.get(BuildGate.KEY_STOOD_DOWN))) {
                return;
            }
            state.remove(BuildGate.KEY_STOOD_DOWN);
            state.remove(BuildGate.KEY_EXPECTED);
            state.remove(BuildGate.KEY_FOUND);
            writeState(state);
            logFile("build gate cleared: build matches again");
        } catch (Exception ignored) {
        }
        refreshBuildGateNotification();
    }

    /**
     * Keeps the build-gate notification and the published mismatch
     * pref in step with the persisted gate state: posted while the
     * gate stands the unit down, cancelled when it does not.
     */
    private void refreshBuildGateNotification() {
        boolean stoodDown = false;
        String found = "";
        try {
            Map<String, String> state = readKeyValues(STATE);
            stoodDown = "1".equals(state.get(BuildGate.KEY_STOOD_DOWN));
            found = state.getOrDefault(BuildGate.KEY_FOUND, "");
        } catch (Exception ignored) {
        }
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                .putBoolean(PREF_BUILD_MISMATCH, stoodDown).apply();
        if (stoodDown) {
            postBuildGateNotification(found);
        } else {
            cancelBuildGateNotification();
        }
    }

    private void postBuildGateNotification(String foundBuild) {
        try {
            NotificationManager manager = (NotificationManager)
                    getSystemService(NOTIFICATION_SERVICE);
            if (manager == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 26) {
                manager.createNotificationChannel(new NotificationChannel(
                        NOTIFY_CHANNEL_ID, "Autoroot stand-down",
                        NotificationManager.IMPORTANCE_DEFAULT));
            }
            Intent intent = new Intent(this, AutorootActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            PendingIntent pending = PendingIntent.getActivity(
                    this, 0, intent,
                    Build.VERSION.SDK_INT >= 23
                            ? PendingIntent.FLAG_IMMUTABLE : 0);
            Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                    ? new Notification.Builder(this, NOTIFY_CHANNEL_ID)
                    : new Notification.Builder(this);
            Notification notification = builder
                    .setSmallIcon(android.R.drawable.ic_dialog_alert)
                    .setContentTitle("Autoroot is off")
                    .setContentText("This Portal updated to an"
                            + " unsupported build (" + foundBuild + "),"
                            + " so autoroot turned itself off."
                            + " Re-run the provisioner to set it up"
                            + " for the new build.")
                    .setContentIntent(pending)
                    .setOngoing(true)
                    .build();
            manager.notify(NOTIFY_ID_BUILD_GATE, notification);
        } catch (Exception error) {
            Log.w(TAG, "build gate notification failed", error);
        }
    }

    private void cancelBuildGateNotification() {
        try {
            NotificationManager manager = (NotificationManager)
                    getSystemService(NOTIFICATION_SERVICE);
            if (manager != null) {
                manager.cancel(NOTIFY_ID_BUILD_GATE);
            }
        } catch (Exception ignored) {
        }
    }

    // ---- UI control surface -------------------------------------------

    /**
     * The Stop control: disable autoroot, kill any in-flight
     * attempt, and reboot. Stopping in place is deliberately not
     * offered: once the race has run, the kernel lock it damages
     * stays damaged until a reboot (in the 2026-11-04 live tests a
     * timeout-cut attempt panic-rebooted the device about a minute
     * later), so a stop that left the device on the same boot would
     * leave it in exactly the unstable state the UI warns about.
     * The reboot clears the damage; the disable flag makes the
     * fresh boot come up quiet, with autoroot off until the user
     * re-enables it.
     */
    private void handleStopReboot() {
        stopRequested = true;
        AdbClient client = activeClient;
        if (client != null) {
            try {
                client.close();
            } catch (Exception ignored) {
            }
        }
        try {
            shell("touch " + DISABLE_FLAG);
            getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                    .putBoolean(PREF_DISABLED, true).apply();
            publishStatus("STOPPED", lastAttempt, lastMax,
                    "autoroot off - rebooting to a clean state");
            logFile("stop from UI: disabled, rebooting");
            shell("reboot");
        } catch (Exception error) {
            Log.w(TAG, "stop/reboot failed", error);
        }
    }

    private void setDisabled(boolean disabled) {
        try {
            if (disabled) {
                shell("touch " + DISABLE_FLAG);
                if (workerRunning) {
                    // An in-flight attempt may have damaged the
                    // kernel lock; reboot so the disabled state
                    // starts from a clean boot.
                    stopRequested = true;
                    AdbClient client = activeClient;
                    if (client != null) {
                        try {
                            client.close();
                        } catch (Exception ignored) {
                        }
                    }
                    logFile("disabled mid-session: rebooting");
                    shell("reboot");
                }
            } else {
                shell("rm -f " + DISABLE_FLAG);
            }
            getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                    .putBoolean(PREF_DISABLED, disabled).apply();
            logFile(disabled ? "disabled from UI" : "enabled from UI");
            if (!disabled) {
                publishStatus("IDLE", lastAttempt, lastMax, "enabled");
            } else {
                publishStatus("DISABLED", lastAttempt, lastMax,
                        "disabled from UI");
            }
        } catch (Exception error) {
            Log.w(TAG, "setDisabled failed", error);
        }
    }

    private void refreshDisabledPref() {
        try {
            boolean disabled = shell(
                    "test -f " + DISABLE_FLAG + " && echo yes").contains("yes");
            getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                    .putBoolean(PREF_DISABLED, disabled).apply();
        } catch (Exception ignored) {
        }
    }

    private void publishStatus(String phase, int attempt, int max,
            String detail) {
        lastPhase = phase;
        lastAttempt = attempt;
        lastMax = max;
        lastDetail = detail;
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                .putString(PREF_PHASE, phase)
                .putInt(PREF_ATTEMPT, attempt)
                .putInt(PREF_MAX, max)
                .putString(PREF_DETAIL, detail)
                .apply();
    }

    private void showStatusUi() {
        try {
            Intent intent = new Intent(this, AutorootActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent.putExtra("auto_shown", true);
            startActivity(intent);
        } catch (Exception error) {
            Log.w(TAG, "could not show status UI", error);
        }
    }

    // ---- wifi flush guard ----------------------------------------------

    /**
     * Waits until this boot reaches BootFlushGuard.MIN_BOOT_AGE_MS,
     * then issues a sync so the boot's connect-time WifiConfigStore
     * write is durable before the attempt is allowed to end the boot
     * (see BootFlushGuard for the mechanism). Returns false when a
     * stop was requested during the wait; the caller then returns
     * before the attempt is counted and before the failure budget's
     * in-progress mark is written, so neither is disturbed.
     */
    private boolean waitForBootFlushWindow() {
        long remaining = BootFlushGuard.remainingWaitMs(
                SystemClock.elapsedRealtime());
        if (remaining > 0) {
            logFile("wifi flush guard waiting ms=" + remaining);
            while (remaining > 0) {
                if (stopRequested) {
                    return false;
                }
                try {
                    Thread.sleep(Math.min(remaining, 5000L));
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    return false;
                }
                remaining = BootFlushGuard.remainingWaitMs(
                        SystemClock.elapsedRealtime());
            }
        }
        if (stopRequested) {
            return false;
        }
        try {
            shell("sync");
        } catch (Exception error) {
            // Best-effort, like the sync before the clean-attempt
            // reboot: a failed flush is logged, but the aged boot is
            // still the safest state this guard can offer.
            logFile("wifi flush guard sync failed: " + error);
        }
        logFile("wifi flush guard ok boot_age_ms="
                + SystemClock.elapsedRealtime());
        return true;
    }

    private void rebootForCleanAttempt(int attempts, int maxAttempts) {
        if (attempts >= maxAttempts) {
            return;
        }
        try {
            logFile("rebooting for clean attempt " + (attempts + 1));
            // Flush before rebooting (F1, 2026-11-19): the boot's
            // asynchronous writes — the WiFi config store's
            // connect-time write above all — must be durable before
            // the boot ends. Best-effort, exactly like the reboot
            // itself, whose result the teardown may not let us see.
            try {
                shell("sync");
            } catch (Exception ignored) {
            }
            shell("reboot");
        } catch (Exception ignored) {
            // The reboot itself tears the connection down; failure to
            // observe its result is expected, not an error.
        }
    }

    // ---- discovery ----------------------------------------------------

    private String discoverMemstart() {
        // A bugreport on this device takes ~1 minute (the host provisioner
        // allows 180 s), and dumpstate can reset the connection mid-run,
        // leaving only the BEGIN line; the archive still lands on disk.
        for (int tries = 0; tries < 2; tries++) {
            String found = discoverMemstartOnce();
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private String discoverMemstartOnce() {
        try {
            String out = shell("bugreportz -p", 200000);
            Matcher okMatch = Pattern.compile("OK:(\\S+\\.zip)").matcher(out);
            String zipPath;
            if (okMatch.find()) {
                zipPath = okMatch.group(1);
            } else {
                Matcher beginMatch = Pattern.compile("BEGIN:(\\S+\\.zip)").matcher(out);
                if (!beginMatch.find()) {
                    return null;
                }
                zipPath = beginMatch.group(1);
                if (!awaitStableFile(zipPath, 120000)) {
                    return null;
                }
            }
            try {
                String b64 = shell("base64 " + zipPath, 120000);
                byte[] zip = java.util.Base64.getMimeDecoder()
                        .decode(b64.replaceAll("\\s", ""));
                String text = extractBugreportText(zip);
                if (text == null) {
                    return null;
                }
                Matcher memMatch = Pattern.compile("memory\\s+: (0x[0-9a-fA-F]+) -")
                        .matcher(text);
                if (!memMatch.find()) {
                    return null;
                }
                long virtualStart = Long.parseUnsignedLong(
                        memMatch.group(1).substring(2), 16);
                long memstart = 0x80000000L - (virtualStart - 0xFFFFFFC000000000L);
                return "0x" + Long.toHexString(memstart);
            } finally {
                shell("rm -f " + zipPath);
            }
        } catch (Exception error) {
            Log.w(TAG, "memstart discovery failed", error);
            return null;
        }
    }

    private boolean awaitStableFile(String path, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        long lastSize = -1;
        while (System.currentTimeMillis() < deadline) {
            try {
                String out = shell("stat -c %s " + path + " 2>/dev/null").trim();
                long size = Long.parseLong(out);
                if (size > 0 && size == lastSize) {
                    return true;
                }
                lastSize = size;
            } catch (Exception ignored) {
            }
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                return false;
            }
        }
        return false;
    }

    private String extractBugreportText(byte[] zip) throws Exception {
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                String name = entry.getName();
                String base = name.substring(name.lastIndexOf('/') + 1);
                if (base.startsWith("bugreport-") && base.endsWith(".txt")) {
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(zin, StandardCharsets.UTF_8));
                    String line;
                    StringBuilder found = new StringBuilder();
                    while ((line = reader.readLine()) != null) {
                        if (line.contains("memory") && line.contains(": 0x")) {
                            found.append(line).append('\n');
                            if (found.length() > 4096) {
                                break;
                            }
                        }
                    }
                    return found.toString();
                }
            }
        }
        return null;
    }

    private String discoverKaslr(String simpleperf, long[] offsets) {
        Pattern valuePattern = Pattern.compile("vaddr_in_file: (ffffff[0-9a-f]+)");
        for (int sampleTry = 0; sampleTry < 3; sampleTry++) {
            try {
                String remote = DIR + "/perf-" + sampleTry + ".data";
                shell(simpleperf + " record -g -e cpu-clock -f 4000 --duration 2 -o "
                        + remote + " -- /system/bin/dd if=/dev/zero of=/dev/null bs=4096",
                        60000);
                String report = shell(simpleperf + " report-sample -i " + remote
                        + " | grep -m 512 'vaddr_in_file: ffffff'", 60000);
                shell("rm -f " + remote);
                Map<Long, int[]> candidates = new HashMap<>();
                Matcher matcher = valuePattern.matcher(report);
                while (matcher.find()) {
                    long value = Long.parseUnsignedLong(matcher.group(1), 16);
                    for (long offset : offsets) {
                        long base = value - offset;
                        if (Long.compareUnsigned(base, 0xFFFFFF8000000000L) >= 0
                                && ((base - 0xFFFFFF8008080000L) & 0x1FFFFFL) == 0) {
                            candidates.computeIfAbsent(base, k -> new int[1])[0]++;
                        }
                    }
                }
                long best = 0;
                int bestCount = 0;
                for (Map.Entry<Long, int[]> e : candidates.entrySet()) {
                    if (e.getValue()[0] > bestCount) {
                        bestCount = e.getValue()[0];
                        best = e.getKey();
                    }
                }
                if (bestCount > 0) {
                    return "0x" + Long.toHexString(best);
                }
            } catch (Exception error) {
                Log.w(TAG, "kaslr sample " + sampleTry + " failed", error);
            }
        }
        return null;
    }

    // ---- post-attempt orphan sweep + bounded handoff ---------------

    /**
     * Kills the just-finished attempt's leftover process tree
     * (see OrphanSweep for the selection policy). Runs from this
     * service's shell context (uid 2000, the same uid the attempt
     * processes run as), which can signal them - the root daemon
     * cannot (its shell SELinux domain gets EPERM, observed live
     * 2026-11-17). Best effort: a failed sweep is logged, never
     * fatal - the bounded handoff and its retry are the backstop.
     *
     * Returns the kill set (empty when nothing was selected), or
     * null when the sweep itself failed; the failure is logged
     * either way. Callers that must explain a stall (the
     * watchdog's win-stall sweep) log the returned set
     * unconditionally, including the empty case.
     */
    private List<Integer> sweepAttemptOrphans(String when) {
        try {
            // The snapshot must read the NAME column, not COMM:
            // this device's toybox ps prints the executable name
            // in COMM (the /system/bin/true host reports as
            // "toybox", since its exe resolves to the toybox
            // binary), while NAME is the kernel task name the
            // OrphanSweep policy matches on ("true"). With COMM
            // the kill set was always empty against a real wedged
            // tree - invisible until the C1b win-stall sweep first
            // ran while the tree was alive (2026-11-18).
            String ps = shell("ps -A -o pid,ppid,name");
            List<Integer> kill = OrphanSweep.selectKillPids(
                    ps, android.os.Process.myPid());
            if (kill.isEmpty()) {
                return kill;
            }
            StringBuilder command = new StringBuilder("kill -9");
            for (int pid : kill) {
                command.append(' ').append(pid);
            }
            shell(command.toString());
            Log.w(TAG, "orphan sweep (" + when + ") killed " + kill);
            logFile("orphan sweep when=" + when + " killed=" + kill);
            return kill;
        } catch (Exception error) {
            Log.w(TAG, "orphan sweep failed (" + when + ")", error);
            logFile("orphan sweep failed when=" + when + " " + error);
            return null;
        }
    }

    /**
     * The Shizuku handoff: one bounded try, then - if it did not
     * complete - a re-sweep of the attempt's orphans and exactly
     * one retry before giving up. Giving up is survivable by
     * design: the daemon stays up, and the next service start
     * takes the daemon-up path above and tries the handoff again.
     */
    private boolean finishShizukuHandoff() {
        if (ensureShizukuRoot()) {
            return true;
        }
        logFile("handoff incomplete; re-sweeping orphans, retrying once");
        sweepAttemptOrphans("handoff-retry");
        return ensureShizukuRoot();
    }

    // ---- root daemon --------------------------------------------------

    private boolean daemonServingRoot() {
        // Retry briefly: the daemon may still be binding when the
        // attempt's verdict is read. Log the failure reason so a
        // "daemon absent" report is actionable (port state, exception).
        String lastReason = "no-attempt";
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                String response = daemonRequest("ID\n", 1);
                if (response != null && response.startsWith("ID uid=0")) {
                    return true;
                }
                lastReason = "unexpected-response="
                        + (response == null ? "null" : response.trim());
            } catch (Exception e) {
                lastReason = "exception=" + e.getClass().getSimpleName()
                        + ":" + e.getMessage();
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        logFile("daemon check failed reason=" + lastReason
                + " port=" + daemonPortState());
        return false;
    }

    /** TCP reachability of the daemon port, for diagnostics only. */
    private String daemonPortState() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getByName("127.0.0.1"), DAEMON_PORT), 500);
            return "listening";
        } catch (Exception e) {
            return e.getClass().getSimpleName() + ":" + e.getMessage();
        }
    }

    private boolean shizukuServingRoot() {
        try {
            String pid = shell("pidof shizuku_server").trim().split("\\s+")[0];
            return !pid.isEmpty() && pid.matches("\\d+") && shizukuUid(pid) == 0;
        } catch (Exception ignored) {
            return false;
        }
    }

    /**
     * The daemon is a bootstrap bridge: it exists to carry root from
     * the exploit's privileged window to the Shizuku server. Once
     * Shizuku serves as uid 0 the bridge has no further job, and an
     * unauthenticated root EXEC listener should not outlive it.
     */
    private void stopDaemon() {
        try {
            daemonRequest("STOP\n", 1);
            Log.i(TAG, "root daemon stopped after shizuku handoff");
            logFile("daemon stopped after shizuku handoff");
        } catch (Exception error) {
            Log.w(TAG, "daemon stop failed", error);
            logFile("daemon stop failed " + error);
        }
    }

    private String daemonExec(String command) throws Exception {
        String response = daemonRequest("EXEC " + command + "\n", 64 * 1024);
        return response == null ? "" : response;
    }

    /** Sends one request line; returns response lines up to END. */
    private String daemonRequest(String request, int maxLines) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getByName("127.0.0.1"), DAEMON_PORT), 3000);
            socket.setSoTimeout(30000);
            socket.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            String line;
            int lines = 0;
            while ((line = reader.readLine()) != null && lines++ < maxLines) {
                if (line.equals("END")) {
                    break;
                }
                result.append(line).append('\n');
                if (request.startsWith("ID") && lines >= 1) {
                    break;
                }
            }
            return result.toString();
        }
    }

    private static String abiDirFor(String abi) {
        switch (abi) {
            case "arm64-v8a":
                return "arm64";
            case "armeabi-v7a":
            case "armeabi":
                return "arm";
            case "x86_64":
                return "x86_64";
            case "x86":
                return "x86";
            default:
                return null;
        }
    }

    private static String resolveShizukuStarter(String dump) {
        Matcher nativeMatch = Pattern.compile("nativeLibraryDir=(\\S+)").matcher(dump);
        if (nativeMatch.find()) {
            return nativeMatch.group(1) + "/libshizuku.so";
        }
        // Android 9 package dumps carry only legacyNativeLibraryDir (the
        // extraction root); the libraries live under its per-ABI
        // subdirectory, e.g. lib/arm64/libshizuku.so.
        Matcher legacyMatch = Pattern.compile("legacyNativeLibraryDir=(\\S+)").matcher(dump);
        Matcher abiMatch = Pattern.compile("primaryCpuAbi=(\\S+)").matcher(dump);
        if (legacyMatch.find() && abiMatch.find()) {
            String abiDir = abiDirFor(abiMatch.group(1));
            if (abiDir != null) {
                return legacyMatch.group(1) + "/" + abiDir + "/libshizuku.so";
            }
        }
        return null;
    }

    private boolean ensureShizukuRoot() {
        try {
            String pid = shell("pidof shizuku_server").trim().split("\\s+")[0];
            if (!pid.isEmpty() && pid.matches("\\d+") && shizukuUid(pid) == 0) {
                Log.i(TAG, "shizuku already root pid=" + pid);
                logFile("shizuku already root pid=" + pid);
                return true;
            }
            String dump = shell("dumpsys package " + SHIZUKU_PACKAGE);
            String pmPath = shell("pm path " + SHIZUKU_PACKAGE);
            Matcher apkMatch = Pattern.compile("package:(\\S+)").matcher(pmPath);
            String starter = resolveShizukuStarter(dump);
            if (starter == null || !apkMatch.find()) {
                Log.w(TAG, "could not resolve shizuku paths");
                return false;
            }
            // Kill any shell-mode server from THIS shell context
            // first: shell() runs as uid 2000, the same uid as the
            // helper-started server, so the signal is permitted. The
            // uid-0 daemon's shell SELinux domain gets EPERM signaling
            // that server, so the daemon-side kill loop and the
            // starter both fail against it (provisioner run 13,
            // 2026-11-04; same-uid kill proven manually that boot).
            shell("for p in $(pidof shizuku_server); do kill $p; done; true");
            for (int waited = 0; waited < 10; waited++) {
                Thread.sleep(500);
                if (shell("pidof shizuku_server").trim().isEmpty()) {
                    break;
                }
            }
            // Kill via pidof, never "pkill -f shizuku_server": the
            // daemon EXEC shell's own command line contains that
            // pattern, so pkill -f would kill the shell itself before
            // the starter runs. pidof matches the process name only.
            String command = "for p in $(pidof shizuku_server); do kill $p; done; sleep 1; "
                    + quote(starter) + " --apk=" + quote(apkMatch.group(1))
                    + "; sleep 1; pidof shizuku_server";
            daemonExec(command);
            // Bounded by the wall clock, not the iteration count:
            // under a wedged attempt tree each shell() poll can
            // itself take minutes, so a fixed 30-iteration loop
            // was the unbounded wait behind the ~13-minute
            // handoff stalls. finishShizukuHandoff owns the retry.
            long deadlineMs = System.currentTimeMillis() + HANDOFF_WAIT_MS;
            while (System.currentTimeMillis() < deadlineMs) {
                Thread.sleep(2000);
                String newPid = shell("pidof shizuku_server").trim().split("\\s+")[0];
                if (!newPid.isEmpty() && newPid.matches("\\d+")
                        && shizukuUid(newPid) == 0) {
                    Log.i(TAG, "shizuku root ok pid=" + newPid);
                    logFile("shizuku root ok pid=" + newPid);
                    return true;
                }
            }
            Log.w(TAG, "shizuku did not come up as uid 0");
            logFile("shizuku root failed");
        } catch (Exception error) {
            Log.w(TAG, "ensureShizukuRoot failed", error);
        }
        return false;
    }

    private int shizukuUid(String pid) {
        try {
            String status = shell("cat /proc/" + pid + "/status");
            Matcher uidMatch = Pattern.compile("^Uid:\\s+(\\d+)", Pattern.MULTILINE)
                    .matcher(status);
            return uidMatch.find() ? Integer.parseInt(uidMatch.group(1)) : -1;
        } catch (Exception error) {
            return -1;
        }
    }

    // ---- recorded-state drift pass (C3-A) ---------------------------

    /**
     * Enforces the provisioner's recorded end state on this boot:
     * Private DNS, the alohausers package posture, and a read-only
     * otad.nodemon check, per DriftPolicy. Invoked at every
     * root-established exit, after root is up and (on the win
     * exits) before the daemon window closes.
     *
     * Fail-open by construction: every item is attempted inside
     * its own try/catch, a failure is logged and never propagates,
     * and the pass writes nothing but log lines - in particular it
     * never touches the failure-budget state file, which is owned
     * by the race accounting around it. It also never runs during
     * a host provisioning run: the disable-guard flag check at the
     * top of runAutoroot returns before any of the exits that call
     * this, exactly as the race itself is suppressed there.
     */
    private void enforceRecordedState(boolean daemonAvailable,
            Map<String, String> conf) {
        try {
            enforceRecordedDns(conf);
        } catch (Exception e) {
            logFile("DRIFT_REPAIR_FAILED item=private_dns error="
                    + e.getClass().getSimpleName());
        }
        try {
            enforceAlohausersPosture(conf, daemonAvailable);
        } catch (Exception e) {
            logFile("DRIFT_REPAIR_FAILED item=alohausers error="
                    + e.getClass().getSimpleName());
        }
        try {
            checkNodemon(conf);
        } catch (Exception e) {
            logFile("DRIFT_CHECK_FAILED item=otad_nodemon error="
                    + e.getClass().getSimpleName());
        }
    }

    private void enforceRecordedDns(Map<String, String> conf)
            throws Exception {
        String expectedMode = conf.get("DNS_MODE");
        if (expectedMode == null) {
            return;
        }
        String expectedSpecifier = conf.get("DNS_SPECIFIER");
        String liveMode = shellSetting("private_dns_mode");
        String liveSpecifier = shellSetting("private_dns_specifier");
        int action = DriftPolicy.dnsAction(
                expectedMode, expectedSpecifier, liveMode, liveSpecifier);
        if (action == DriftPolicy.NONE) {
            logFile("DRIFT_OK item=private_dns");
            return;
        }
        if (action == DriftPolicy.REPORT_ONLY) {
            logFile("DRIFT_UNREPAIRED item=private_dns"
                    + " reason=live-state-unreadable");
            return;
        }
        writePrivateDnsField("private_dns_mode", expectedMode);
        writePrivateDnsField("private_dns_specifier", expectedSpecifier);
        String afterMode = shellSetting("private_dns_mode");
        String afterSpecifier = shellSetting("private_dns_specifier");
        if (DriftPolicy.dnsAction(expectedMode, expectedSpecifier,
                afterMode, afterSpecifier) == DriftPolicy.NONE) {
            logFile("DRIFT_REPAIRED item=private_dns mode="
                    + DriftPolicy.normalize(expectedMode)
                    + " specifier="
                    + DriftPolicy.normalize(expectedSpecifier));
        } else {
            logFile("DRIFT_REPAIR_FAILED item=private_dns mode="
                    + afterMode + " specifier=" + afterSpecifier);
        }
    }

    /** One settings read through the loopback shell; null on failure. */
    private String shellSetting(String key) {
        try {
            String value = shell("settings get global " + key);
            return value == null ? null : value.trim();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Writes one Private DNS field with the host's put-or-delete
     * rule: the absent spellings delete the key, anything else is
     * stored verbatim.
     */
    private void writePrivateDnsField(String key, String value)
            throws Exception {
        String normalized = DriftPolicy.normalize(value);
        if ("null".equals(normalized)) {
            shell("settings delete global " + key);
        } else {
            shell("settings put global " + key + " " + normalized);
        }
    }

    private void enforceAlohausersPosture(Map<String, String> conf,
            boolean daemonAvailable) throws Exception {
        boolean desireDisabled = "1".equals(conf.get("ALOHAUSERS_DISABLED"));
        if (!desireDisabled) {
            return;
        }
        boolean liveDisabled = packageDisabled(ALOHAUSERS_PACKAGE);
        int action = DriftPolicy.alohausersAction(
                true, liveDisabled, daemonAvailable);
        if (action == DriftPolicy.NONE) {
            logFile("DRIFT_OK item=alohausers");
            return;
        }
        if (action == DriftPolicy.REPORT_ONLY) {
            logFile("DRIFT_UNREPAIRED item=alohausers"
                    + " reason=no-root-channel");
            return;
        }
        String result = daemonExec(
                "pm disable --user 0 " + ALOHAUSERS_PACKAGE);
        if (packageDisabled(ALOHAUSERS_PACKAGE)) {
            logFile("DRIFT_REPAIRED item=alohausers state=disabled");
        } else {
            logFile("DRIFT_REPAIR_FAILED item=alohausers result="
                    + (result == null ? "" : result.trim()));
        }
    }

    private boolean packageDisabled(String pkg) throws Exception {
        String listing = shell("pm list packages -d");
        return listing != null
                && listing.contains("package:" + pkg);
    }

    /**
     * otad.nodemon is check-only on device: no post-win channel
     * can set the property, so a staged-but-unset boot is
     * reported, never repaired here.
     */
    private void checkNodemon(Map<String, String> conf) throws Exception {
        boolean staged = "1".equals(conf.get("OTA_NODEMON"));
        if (!staged) {
            return;
        }
        String property = shell("getprop otad.nodemon");
        boolean propertyTrue = property != null
                && "true".equals(property.trim());
        if (DriftPolicy.nodemonAction(true, propertyTrue)
                == DriftPolicy.NONE) {
            logFile("DRIFT_OK item=otad_nodemon");
        } else {
            logFile("DRIFT_UNREPAIRED item=otad_nodemon"
                    + " reason=no-post-win-channel");
        }
    }

    // ---- plumbing -----------------------------------------------------

    private String shell(String command) throws Exception {
        return shell(command, 15000);
    }

    private String shell(String command, int soTimeoutMs) throws Exception {
        try (AdbClient client = new AdbClient(getFilesDir(), soTimeoutMs)) {
            client.connect();
            return client.shell(command);
        }
    }

    /**
     * Like shell(), but registers the client so the stop path can
     * close it from another thread. Closing the socket breaks the
     * blocked read, and the runner on the far end dies with its ADB
     * session - the same teardown that made detached launches fail,
     * used here on purpose as the kill mechanism.
     */
    private String shellTracked(String command, int soTimeoutMs) throws Exception {
        AdbClient client = new AdbClient(getFilesDir(), soTimeoutMs);
        activeClient = client;
        try {
            client.connect();
            return client.shell(command);
        } finally {
            activeClient = null;
            try {
                client.close();
            } catch (Exception ignored) {
            }
        }
    }

    private Map<String, String> readKeyValues(String path) {
        Map<String, String> values = new HashMap<>();
        try {
            String text = shell("cat " + path + " 2>/dev/null");
            for (String line : text.split("\n")) {
                int eq = line.indexOf('=');
                if (eq > 0) {
                    values.put(line.substring(0, eq).trim(),
                            line.substring(eq + 1).trim());
                }
            }
        } catch (Exception ignored) {
        }
        return values;
    }

    private void writeState(Map<String, String> state) {
        try {
            StringBuilder body = new StringBuilder();
            for (Map.Entry<String, String> e : state.entrySet()) {
                body.append(e.getKey()).append('=').append(e.getValue()).append('\n');
            }
            shell("printf %s " + quote(body.toString()) + " > " + STATE + ".tmp"
                    + " && mv " + STATE + ".tmp " + STATE);
        } catch (Exception ignored) {
        }
    }

    private void logFile(String message) {
        try {
            shell("echo " + quote(System.currentTimeMillis() / 1000 + " " + message)
                    + " >> " + SERVICE_LOG);
        } catch (Exception ignored) {
        }
    }

    private static int parseInt(String value, int fallback) {
        try {
            return value == null ? fallback : Integer.parseInt(value);
        } catch (NumberFormatException error) {
            return fallback;
        }
    }

    private static long parseLong(String value, long fallback) {
        try {
            return value == null ? fallback : Long.parseLong(value);
        } catch (NumberFormatException error) {
            return fallback;
        }
    }

    private static String quote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
