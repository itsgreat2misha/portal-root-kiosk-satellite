// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Status and control screen for the autoroot helper.
 *
 * The service publishes its phase to SharedPreferences; this activity
 * polls that record while visible and renders it. It is shown
 * automatically by the service while an attempt session is active so
 * nobody uses the device mid-attempt (an attempt can panic-reboot
 * it), and it can also be opened from the launcher at any time.
 * Buttons do not act directly: each one sends an intent to
 * AutorootService, which remains the single owner of shell work and
 * session state.
 */
public final class AutorootActivity extends Activity {
    private static final long REFRESH_MS = 1500;

    private TextView statusView;
    private TextView detailView;
    private Button stopButton;
    private Button disableButton;
    private Button runNowButton;
    private Button reenableButton;
    private Handler handler;
    private boolean autoShown;
    private boolean finishScheduled;
    private final Runnable refreshTask = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, REFRESH_MS);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        autoShown = getIntent().getBooleanExtra("auto_shown", false);

        float density = getResources().getDisplayMetrics().density;
        int pad = (int) (24 * density);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("Portal Autoroot");
        title.setTextSize(26);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        statusView = new TextView(this);
        statusView.setTextSize(20);
        statusView.setGravity(Gravity.CENTER);
        statusView.setPadding(0, pad, 0, 0);
        root.addView(statusView);

        detailView = new TextView(this);
        detailView.setTextSize(15);
        detailView.setGravity(Gravity.CENTER);
        detailView.setPadding(0, pad / 2, 0, pad);
        root.addView(detailView);

        stopButton = new Button(this);
        stopButton.setText("Stop autoroot & reboot");
        stopButton.setOnClickListener(v -> sendAction(
                AutorootService.ACTION_STOP_REBOOT));
        root.addView(stopButton);

        disableButton = new Button(this);
        disableButton.setOnClickListener(v -> {
            boolean disabled = prefs().getBoolean(
                    AutorootService.PREF_DISABLED, false);
            Intent intent = new Intent(this, AutorootService.class);
            intent.setAction(AutorootService.ACTION_SET_DISABLED);
            intent.putExtra(AutorootService.EXTRA_ENABLED, !disabled);
            startService(intent);
        });
        root.addView(disableButton);

        runNowButton = new Button(this);
        runNowButton.setText("Run now");
        runNowButton.setOnClickListener(v -> sendAction(
                AutorootService.ACTION_RUN_NOW));
        root.addView(runNowButton);

        // Shown only in the stood-down state: the failure budget
        // turned autoroot off after repeated crashed/frozen boots,
        // and this screen is where the user re-enables it (the
        // stand-down notification opens this screen too).
        reenableButton = new Button(this);
        reenableButton.setText("Re-enable autoroot");
        reenableButton.setOnClickListener(v -> sendAction(
                AutorootService.ACTION_REENABLE));
        root.addView(reenableButton);

        Button closeButton = new Button(this);
        closeButton.setText("Close");
        closeButton.setOnClickListener(v -> finish());
        root.addView(closeButton);

        setContentView(root);
        sendAction(AutorootService.ACTION_STATUS_QUERY);

        handler = new Handler();
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(refreshTask);
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(refreshTask);
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(AutorootService.PREFS_NAME, MODE_PRIVATE);
    }

    private void sendAction(String action) {
        Intent intent = new Intent(this, AutorootService.class);
        intent.setAction(action);
        startService(intent);
    }

    private void refresh() {
        SharedPreferences prefs = prefs();
        String phase = prefs.getString(AutorootService.PREF_PHASE, "IDLE");
        int attempt = prefs.getInt(AutorootService.PREF_ATTEMPT, 0);
        int max = prefs.getInt(AutorootService.PREF_MAX, 0);
        String detail = prefs.getString(AutorootService.PREF_DETAIL, "");
        boolean disabled = prefs.getBoolean(AutorootService.PREF_DISABLED, false);
        boolean stoodDown = prefs.getBoolean(
                AutorootService.PREF_STOOD_DOWN, false);

        boolean running = "WORKING".equals(phase) || "ATTEMPT".equals(phase);
        String status;
        switch (phase) {
            case "WORKING":
                status = "Autoroot is working\u2026";
                break;
            case "ATTEMPT":
                status = "Root attempt " + attempt + " of " + max
                        + " in progress";
                break;
            case "DONE":
                status = "Root is active";
                break;
            case "CAPPED":
                status = "Autoroot gave up for now";
                break;
            case "DISABLED":
                status = "Autoroot is disabled";
                break;
            case "STOPPED":
                status = "Autoroot stopped - rebooting";
                break;
            case "FAILED":
                status = "Autoroot attempt failed";
                break;
            case "STOOD_DOWN":
                status = "Autoroot stopped itself";
                break;
            default:
                status = "Autoroot idle";
                break;
        }
        if (stoodDown) {
            // The stand-down is its own state, distinct from the
            // user's disable toggle: the normal controls are
            // meaningless while it holds, so the only action
            // offered is re-enabling, with the risk stated.
            status = "Autoroot stopped itself";
            statusView.setText(status);
            detailView.setText(
                    "Autoroot crashed or froze during its last 10 boots"
                    + " in a row, so it turned itself off. It will not"
                    + " run again on its own.\n\n"
                    + "Re-enabling starts autoroot again, at your own"
                    + " risk: if the fault is still there, the device"
                    + " may crash or freeze again. Autoroot will turn"
                    + " itself off again after 10 more bad boots.");
            stopButton.setVisibility(View.GONE);
            disableButton.setVisibility(View.GONE);
            runNowButton.setVisibility(View.GONE);
            reenableButton.setVisibility(View.VISIBLE);
            return;
        }
        reenableButton.setVisibility(View.GONE);
        stopButton.setVisibility(View.VISIBLE);
        disableButton.setVisibility(View.VISIBLE);
        runNowButton.setVisibility(View.VISIBLE);
        statusView.setText(status);
        detailView.setText(running
                ? "Please do not use the device yet - it may reboot "
                        + "without warning while an attempt runs.\n" + detail
                : detail);
        stopButton.setEnabled(running);
        disableButton.setText(disabled ? "Enable autoroot" : "Disable autoroot");
        runNowButton.setEnabled(!running && !disabled);

        if (autoShown && !running && !finishScheduled
                && ("DONE".equals(phase) || "CAPPED".equals(phase)
                        || "STOPPED".equals(phase))) {
            finishScheduled = true;
            handler.postDelayed(this::finish, 4000);
        }
    }
}
