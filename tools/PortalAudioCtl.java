// SPDX-License-Identifier: Apache-2.0
// Originally by Xavier Larrea (jxlarrea); modified by itsgreat2misha.
// See LICENSE and NOTICE.

import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.util.Log;
import java.lang.reflect.Method;

/** Direct Binder client for the Portal audio-processing service. */
public final class PortalAudioCtl {
    private static final String TAG = "PortalAudioCtl";
    private static final String MANAGER_NAME =
            "com.facebook.IAudioServiceManager";
    private static final String MANAGER_DESCRIPTOR =
            "com.facebook.alohasdk.IAudioServiceManager";
    private static final String AUDIO_DESCRIPTOR =
            "com.facebook.alohasdk.IAudioService";
    private static final String CONNECTION_DESCRIPTOR =
            "com.facebook.alohasdk.IAudioServiceConnection";

    private static final int MANAGER_GET_AUDIO_SERVICE = 3;
    private static final int AUDIO_GET_PROCESSING_PARAM = 3;
    private static final int AUDIO_SET_PROCESSING_PARAM = 4;

    /* Omni uses MHA rather than the VoiceParam backend.  Its patched tuning
     * blob keeps the stereo capture engine active while disabling the
     * double-talk/echo suppressor and both uplink noise suppressors. */
    private static final String[] MHA_DISABLED_CONTROLS = {
        "Proc_TPL_Mode",
        "Proc_TPL_Enable",
        "Proc_TPL_MaxSup",
        "Post_ResEnable",
        "Post_NsEnable",
        "Post_NsAttDB",
        "ML_Post_ResEnable",
        "ML_Post_NsEnable",
        "ML_Post_NsAttDB",
    };

    private static final class Connection extends Binder implements IInterface {
        Connection() {
            attachInterface(this, CONNECTION_DESCRIPTOR);
        }

        @Override
        public IBinder asBinder() {
            return this;
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) {
            if (code == INTERFACE_TRANSACTION) {
                if (reply != null) {
                    reply.writeString(CONNECTION_DESCRIPTOR);
                }
                return true;
            }
            if (code == 1) {
                data.enforceInterface(CONNECTION_DESCRIPTOR);
                data.readStrongBinder();
                return true;
            }
            try {
                return super.onTransact(code, data, reply, flags);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static IBinder getService(String name) throws Exception {
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getService = serviceManager.getDeclaredMethod(
                "getService", String.class);
        return (IBinder) getService.invoke(null, name);
    }

    private static IBinder getAudioService(IBinder manager) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(MANAGER_DESCRIPTOR);
            data.writeStrongBinder(new Connection());
            if (!manager.transact(MANAGER_GET_AUDIO_SERVICE, data, reply, 0)) {
                throw new IllegalStateException("manager transaction rejected");
            }
            reply.readException();
            IBinder audio = reply.readStrongBinder();
            if (audio == null) {
                throw new IllegalStateException("manager returned null audio service");
            }
            return audio;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static float getParam(IBinder audio, int id) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AUDIO_DESCRIPTOR);
            data.writeInt(id);
            if (!audio.transact(AUDIO_GET_PROCESSING_PARAM, data, reply, 0)) {
                throw new IllegalStateException("get transaction rejected");
            }
            reply.readException();
            return reply.readFloat();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static void setParam(IBinder audio, int id, float value)
            throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AUDIO_DESCRIPTOR);
            data.writeInt(id);
            data.writeFloat(value);
            if (!audio.transact(AUDIO_SET_PROCESSING_PARAM, data, reply, 0)) {
                throw new IllegalStateException("set transaction rejected");
            }
            reply.readException();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static boolean requestedRestore(String[] requested) {
        boolean sawZero = false;
        boolean sawNonzero = false;
        for (int i = 1; i < requested.length; i += 2) {
            float value = Float.parseFloat(requested[i]);
            if (Float.compare(value, 0.0f) == 0) {
                sawZero = true;
            } else {
                sawNonzero = true;
            }
        }
        if (sawZero && sawNonzero) {
            throw new IllegalArgumentException(
                    "mixed disabled/default requests are not supported on MHA");
        }
        return sawNonzero;
    }

    private static String getAudioSystemParameter(Method getParameters,
                                                   String name)
            throws Exception {
        Object result = getParameters.invoke(null, name);
        return result == null ? "" : result.toString().trim();
    }

    private static String parameterValue(String response, String name) {
        if (response == null || response.isEmpty()) {
            return null;
        }
        for (String entry : response.split(";")) {
            int equals = entry.indexOf('=');
            if (equals >= 0
                    && name.equals(entry.substring(0, equals).trim())) {
                return entry.substring(equals + 1).trim();
            }
        }
        return null;
    }

    private static boolean numericValueMatches(String actual,
                                               String requested) {
        if (actual == null) {
            return false;
        }
        try {
            return Double.compare(Double.parseDouble(actual),
                    Double.parseDouble(requested)) == 0;
        } catch (NumberFormatException ignored) {
            return requested.equals(actual);
        }
    }

    private static String getMhaValues(Method getParameters) throws Exception {
        return getAudioSystemParameter(getParameters, "mh_algo_params_get_1")
                + ";" + getAudioSystemParameter(
                        getParameters, "mh_algo_params_get_2");
    }

    private static boolean mhaControlsDisabled(String values) {
        for (String name : MHA_DISABLED_CONTROLS) {
            if (!numericValueMatches(parameterValue(values, name), "0")) {
                return false;
            }
        }
        return true;
    }

    private static void verifyMhaParameters(String[] requested)
            throws Exception {
        boolean restore = requestedRestore(requested);
        if (restore) {
            System.out.println(
                    "PORTAL_AUDIO_MHA_RESTORE_DEFERRED verification=post-reboot");
            return;
        }
        Class<?> audioSystem = Class.forName("android.media.AudioSystem");
        Method getParameters = audioSystem.getDeclaredMethod(
                "getParameters", String.class);
        Method setParameters = audioSystem.getDeclaredMethod(
                "setParameters", String.class);
        String values = getMhaValues(getParameters);
        if (!mhaControlsDisabled(values)) {
            int transitionStatus = ((Integer) setParameters.invoke(
                    null, "voice_call_type=4")).intValue();
            Thread.sleep(100);
            int status = ((Integer) setParameters.invoke(
                    null, "voice_call_type=0")).intValue();
            String profileResult = "PORTAL_AUDIO_MHA_PROFILE action=reload"
                    + " transition_profile=4 transition_status="
                    + transitionStatus + " profile=0 status=" + status;
            System.out.println(profileResult);
            Log.i(TAG, profileResult);
            Thread.sleep(500);
            values = getMhaValues(getParameters);
        }
        int verified = 0;
        for (String name : MHA_DISABLED_CONTROLS) {
            String actual = parameterValue(values, name);
            boolean match = numericValueMatches(actual, "0");
            System.out.println("PORTAL_AUDIO_MHA_CONTROL action=verify-disabled"
                    + " name=" + name + " actual=" + actual
                    + " match=" + match);
            if (!match) {
                throw new IllegalStateException("MHA readback mismatch for "
                        + name + ": expected=0 actual=" + actual);
            }
            verified++;
        }
        System.out.println("PORTAL_AUDIO_MHA_VERIFIED action=disabled controls="
                + verified);
    }

    private static void applyVoiceParameters(String[] requested)
            throws Exception {
        IBinder manager = getService(MANAGER_NAME);
        if (manager == null) {
            throw new IllegalStateException("audio manager service is absent");
        }
        IBinder audio = getAudioService(manager);
        boolean allMatch = true;
        for (int i = 0; i < requested.length; i += 2) {
            int id = Integer.decode(requested[i]);
            float value = Float.parseFloat(requested[i + 1]);
            float before = getParam(audio, id);
            setParam(audio, id, value);
            float after = getParam(audio, id);
            boolean match = Float.compare(after, value) == 0;
            allMatch &= match;
            System.out.println("PORTAL_AUDIO_CTL_OK id=" + id
                    + " before=" + before + " requested=" + value
                    + " after=" + after + " match=" + match);
        }
        if (!allMatch) {
            throw new IllegalStateException("audio parameter readback mismatch");
        }
    }

    public static void main(String[] args) {
        String[] requested = args.length == 0
                ? new String[] {"3001", "0"} : args;
        if ((requested.length & 1) != 0) {
            System.err.println("usage: PortalAudioCtl [id value]...");
            System.exit(64);
        }
        try {
            if ("omni".equals(Build.DEVICE)) {
                verifyMhaParameters(requested);
            } else {
                applyVoiceParameters(requested);
            }
        } catch (Throwable t) {
            System.err.println("PORTAL_AUDIO_CTL_ERROR " + t);
            Log.e(TAG, "audio processing apply failed", t);
            Throwable cause = t.getCause();
            if (cause != null) {
                System.err.println("caused by: " + cause);
            }
            t.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
