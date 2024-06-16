package com.android.internal.util;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import dalvik.system.PathClassLoader;

public final class Utils {
    private static final String TAG = "chiteroman";
    private static final Map<String, String> map = new HashMap<>();
    private static Method method = null;

    static {
        map.put("MANUFACTURER", "Google");
        map.put("MODEL", "Pixel");
        map.put("FINGERPRINT", "google/sailfish/sailfish:8.1.0/OPM1.171019.011/4448085:user/release-keys");
        map.put("BRAND", "google");
        map.put("PRODUCT", "sailfish");
        map.put("DEVICE", "sailfish");
        map.put("RELEASE", "8.1.0");
        map.put("ID", "OPM1.171019.011");
        map.put("INCREMENTAL", "4448085");
        map.put("SECURITY_PATCH", "2017-12-05");
        map.put("TYPE", "user");
        map.put("TAGS", "release-keys");
    }

    private static Field getField(String fieldName) {
        Field field = null;
        try {
            field = Build.class.getDeclaredField(fieldName);
        } catch (Throwable ignored) {
            try {
                field = Build.VERSION.class.getDeclaredField(fieldName);
            } catch (Throwable t) {
                Log.e(TAG, "Couldn't find field " + fieldName);
            }
        }
        return field;
    }

    public static void onNewApplication(Context context) {
        if (context == null)
            return;

        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName))
            return;

        if (!"com.google.android.gms".equals(packageName) || !"com.google.android.gms.unstable".equals(processName))
            return;

        map.forEach((fieldName, value) -> {
            Field field = getField(fieldName);
            if (field == null)
                return;
            field.setAccessible(true);
            try {
                field.set(null, value);
            } catch (Throwable t) {
                Log.e(TAG, t.toString());
            }
            field.setAccessible(false);
        });
    }

    public static Certificate[] onEngineGetCertificateChain(Certificate[] caList, boolean isDroidGuard) {
        if (caList == null) {
            Log.d(TAG, "caList is null");
            return null;
        }
        try {
            if (((X509Certificate) caList[0]).getExtensionValue("1.3.6.1.4.1.11129.2.1.17") == null) {
                Log.d(TAG, "Leaf certificate doesn't have attestation extension!");
                return caList;
            }

            if (method == null) {
                PathClassLoader pathClassLoader = new PathClassLoader("/system/framework/miui.jar",
                        ClassLoader.getSystemClassLoader());
                Class<?> clazz = pathClassLoader.loadClass("com.android.internal.util.framework.Android");
                method = clazz.getDeclaredMethod("engineGetCertificateChain", Certificate[].class, boolean.class);
                method.setAccessible(true);
            }

            Log.d(TAG, "isDroidGuard? " + isDroidGuard);

            return (Certificate[]) method.invoke(null, caList, isDroidGuard);

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return caList;
    }
}
