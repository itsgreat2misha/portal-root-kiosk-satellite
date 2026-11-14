// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 itsgreat2misha
//
// Part of the Meta Portal Root Provisioner fork; see LICENSE and NOTICE.

package dev.portal.autoroothelper;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public final class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "PortalAutoroot";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "autoroot requested action=" + intent.getAction());
        context.startService(new Intent(context, AutorootService.class));
    }
}
