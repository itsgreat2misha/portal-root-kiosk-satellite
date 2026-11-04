package dev.portal.autoroothelper;

import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.IBinder;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
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
    private static final int DAEMON_PORT = 37373;

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
    public static final String EXTRA_ENABLED = "enabled";

    public static final String PREFS_NAME = "autoroot_status";
    public static final String PREF_PHASE = "phase";
    public static final String PREF_ATTEMPT = "attempt";
    public static final String PREF_MAX = "max";
    public static final String PREF_DETAIL = "detail";
    public static final String PREF_DISABLED = "disabled";

    private volatile boolean workerRunning;
    private volatile boolean stopRequested;
    private volatile boolean forceFreshSession;
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
        if (ACTION_RUN_NOW.equals(action)) {
            forceFreshSession = true;
        }
        if (!workerRunning) {
            workerRunning = true;
            stopRequested = false;
            new Thread(() -> run(startId), "portal-autoroot").start();
        }
        return START_STICKY;
    }

    private void run(int startId) {
        try {
            runAutoroot();
        } catch (Exception error) {
            Log.e(TAG, "autoroot pass failed", error);
            logFile("error " + error);
        } finally {
            workerRunning = false;
            stopSelf(startId);
        }
    }

    private void runAutoroot() throws Exception {
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
            publishStatus("DONE", lastAttempt, lastMax, "root active (shizuku)");
            Map<String, String> state = readKeyValues(STATE);
            state.put("done_boot", bootId);
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
            if (ensureShizukuRoot()) {
                stopDaemon();
            }
            Map<String, String> state = readKeyValues(STATE);
            state.put("done_boot", bootId);
            writeState(state);
            return;
        }

        Map<String, String> state = readKeyValues(STATE);
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
        attempts++;
        state.put("session_start", Long.toString(sessionStart));
        state.put("attempts", Integer.toString(attempts));
        writeState(state);
        logFile("attempt " + attempts + " of " + maxAttempts + " boot=" + bootId);
        publishStatus("ATTEMPT", attempts, maxAttempts, "discovering addresses");
        showStatusUi();

        String memstart = discoverMemstart();
        String kaslr = memstart == null ? null : discoverKaslr(simpleperf, offsets);
        if (stopRequested) {
            logFile("stopped by user");
            return;
        }
        if (memstart == null || kaslr == null) {
            Log.w(TAG, "discovery failed memstart=" + memstart + " kaslr=" + kaslr);
            logFile("discovery failed memstart=" + memstart + " kaslr=" + kaslr);
            publishStatus("FAILED", attempts, maxAttempts, "discovery failed");
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
        try {
            shellTracked("sh " + RUN_SH + " " + kaslr + " " + memstart + " " + attempts,
                    600000);
        } catch (Exception launchError) {
            Log.w(TAG, "attempt runner error", launchError);
            logFile("attempt runner error " + launchError);
        }
        if (stopRequested) {
            logFile("stopped by user");
            return;
        }
        boolean up = false;
        for (int waited = 0; waited < 30; waited += 5) {
            if (daemonServingRoot()) {
                up = true;
                break;
            }
            if (stopRequested) {
                logFile("stopped by user");
                return;
            }
            Thread.sleep(5000);
        }
        if (up) {
            Log.i(TAG, "daemon up after attempt " + attempts);
            logFile("daemon up attempt=" + attempts);
            publishStatus("DONE", attempts, maxAttempts, "root active");
            if (ensureShizukuRoot()) {
                stopDaemon();
            }
            state.put("done_boot", bootId);
            writeState(state);
            return;
        }
        Log.w(TAG, "attempt " + attempts + " did not bring the daemon up");
        logFile("attempt failed n=" + attempts);
        publishStatus("FAILED", attempts, maxAttempts, "attempt failed");
        rebootForCleanAttempt(attempts, maxAttempts);
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

    private void rebootForCleanAttempt(int attempts, int maxAttempts) {
        if (attempts >= maxAttempts) {
            return;
        }
        try {
            logFile("rebooting for clean attempt " + (attempts + 1));
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

    // ---- root daemon --------------------------------------------------

    private boolean daemonServingRoot() {
        try {
            String response = daemonRequest("ID\n", 1);
            return response != null && response.startsWith("ID uid=0");
        } catch (Exception ignored) {
            return false;
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
            for (int waited = 0; waited < 30; waited += 2) {
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
