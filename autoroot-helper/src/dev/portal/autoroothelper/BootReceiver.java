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
