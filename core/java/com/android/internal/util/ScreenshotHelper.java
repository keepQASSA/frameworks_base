package com.android.internal.util;

import static android.view.WindowManager.TAKE_SCREENSHOT_SELECTED_REGION;
import static android.content.Intent.ACTION_USER_SWITCHED;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.os.UserHandle;
import android.util.Log;
import android.view.WindowManager;

import com.android.internal.custom.screenshot.StitchImageUtility;

import java.util.function.Consumer;

public class ScreenshotHelper {
    private static final String TAG = "ScreenshotHelper";

    private static final String SYSUI_PACKAGE = "com.android.systemui";
    private static final String SYSUI_SCREENSHOT_SERVICE =
            "com.android.systemui.screenshot.TakeScreenshotService";
    private static final String SYSUI_SCREENSHOT_ERROR_RECEIVER =
            "com.android.systemui.screenshot.ScreenshotServiceErrorReceiver";

    // Time until we give up on the screenshot & show an error instead.
    private final int SCREENSHOT_TIMEOUT_MS = 10000;

    private final Object mScreenshotLock = new Object();
    private ServiceConnection mScreenshotConnection = null;
    private final Context mContext;
    private final StitchImageUtility mStitchImageUtility;

    private final BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            synchronized (mScreenshotLock) {
                if (ACTION_USER_SWITCHED.equals(intent.getAction())) {
                    resetConnection();
                }
            }
        }
    };

    public ScreenshotHelper(Context context) {
        mContext = context;
        mStitchImageUtility = new StitchImageUtility(mContext);
        IntentFilter filter = new IntentFilter(ACTION_USER_SWITCHED);
        mContext.registerReceiver(mBroadcastReceiver, filter);
    }

    /**
     * Request a screenshot be taken with a specific timeout.
     *
     * Added to support reducing unit test duration; the method variant without a timeout argument
     * is recommended for general use.
     *
     * @param screenshotType     The type of screenshot, for example either
     *                           {@link android.view.WindowManager.TAKE_SCREENSHOT_FULLSCREEN}
     *                           or
     *                           {@link android.view.WindowManager.TAKE_SCREENSHOT_SELECTED_REGION}
     * @param hasStatus          {@code true} if the status bar is currently showing. {@code false}
     *                           if
     *                           not.
     * @param hasNav             {@code true} if the navigation bar is currently showing. {@code
     *                           false}
     *                           if not.
     * @param handler            A handler used in case the screenshot times out
     * @param completionConsumer Consumes `false` if a screenshot was not taken, and `true` if the
     *                           screenshot was taken.
     */
    public void takeScreenshot(final int screenshotType, final boolean hasStatus,
            final boolean hasNav, @NonNull Handler handler,
            @Nullable Consumer<Uri> completionConsumer) {
        takeScreenshot(screenshotType, hasStatus, hasNav, SCREENSHOT_TIMEOUT_MS, handler,
                completionConsumer, null);
    }

    /**
     * Request a screenshot be taken.
     *
     * Added to support reducing unit test duration; the method variant without a timeout argument
     * is recommended for general use.
     *
     * @param screenshotType     The type of screenshot, for example either
     *                           {@link android.view.WindowManager.TAKE_SCREENSHOT_FULLSCREEN}
     *                           or
     *                           {@link android.view.WindowManager.TAKE_SCREENSHOT_SELECTED_REGION}
     * @param hasStatus          {@code true} if the status bar is currently showing. {@code false}
     *                           if
     *                           not.
     * @param hasNav             {@code true} if the navigation bar is currently showing. {@code
     *                           false}
     *                           if not.
     * @param handler            A handler used in case the screenshot times out
     * @param completionConsumer Consumes `null` if a screenshot was not taken, and the URI of the
     *                           screenshot if the screenshot was taken.
     * @param focusedPackageName The focused package name
     */
    public void takeScreenshot(final int screenshotType, final boolean hasStatus,
            final boolean hasNav, @NonNull Handler handler,
            @Nullable Consumer<Uri> completionConsumer,
            final String focusedPackageName) {
        takeScreenshot(screenshotType, hasStatus, hasNav, SCREENSHOT_TIMEOUT_MS, handler,
                completionConsumer, focusedPackageName);
    }

    /**
     * Request a screenshot be taken.
     *
     * Added to support reducing unit test duration; the method variant without a timeout argument
     * is recommended for general use.
     *
     * @param screenshotType     The type of screenshot, for example either
     *                           {@link android.view.WindowManager.TAKE_SCREENSHOT_FULLSCREEN}
     *                           or
     *                           {@link android.view.WindowManager.TAKE_SCREENSHOT_SELECTED_REGION}
     * @param hasStatus          {@code true} if the status bar is currently showing. {@code false}
     *                           if
     *                           not.
     * @param hasNav             {@code true} if the navigation bar is currently showing. {@code
     *                           false}
     *                           if not.
     * @param timeoutMs          If the screenshot hasn't been completed within this time period,
     *                           the screenshot attempt will be cancelled and `completionConsumer`
     *                           will be run.
     * @param handler            A handler used in case the screenshot times out
     * @param completionConsumer Consumes `null` if a screenshot was not taken, and the URI of the
     *                           screenshot if the screenshot was taken.
     * @param focusedPackageName The focused package name
     */
    public void takeScreenshot(final int screenshotType, final boolean hasStatus,
            final boolean hasNav, long timeoutMs, @NonNull Handler handler,
            @Nullable Consumer<Uri> completionConsumer,
            final String focusedPackageName) {
        synchronized (mScreenshotLock) {
            if (screenshotType == WindowManager.TAKE_SCREENSHOT_FULLSCREEN &&
                    mStitchImageUtility.takeScreenShot(focusedPackageName)){
                return;
            }
            if (mScreenshotConnection != null) {
                return;
            }
            final ComponentName serviceComponent = new ComponentName(SYSUI_PACKAGE,
                    SYSUI_SCREENSHOT_SERVICE);
            final Intent serviceIntent = new Intent();

            final Runnable mScreenshotTimeout = () -> {
                synchronized (mScreenshotLock) {
                    if (mScreenshotConnection != null) {
                        Log.e(TAG, "Timed out before getting screenshot capture response");
                        resetConnection();
                        notifyScreenshotError();
                    }
                    if (completionConsumer != null) {
                        completionConsumer.accept(null);
                    }
                }
            };

            serviceIntent.setComponent(serviceComponent);
            ServiceConnection conn = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                    synchronized (mScreenshotLock) {
                        if (mScreenshotConnection != this) {
                            return;
                        }
                        Messenger messenger = new Messenger(service);
                        Message msg = Message.obtain(null, screenshotType);
                        final ServiceConnection myConn = this;
                        Handler h = new Handler(handler.getLooper()) {
                            @Override
                            public void handleMessage(Message msg) {
                                synchronized (mScreenshotLock) {
                                    if (mScreenshotConnection == myConn) {
                                        resetConnection();
                                        handler.removeCallbacks(mScreenshotTimeout);
                                    }
                                }

                                if (completionConsumer != null) {
                                    completionConsumer.accept((Uri) msg.obj);
                                }
                            }
                        };
                        msg.replyTo = new Messenger(h);
                        msg.arg1 = hasStatus ? 1 : 0;
                        msg.arg2 = hasNav ? 1 : 0;

                        try {
                            messenger.send(msg);
                        } catch (RemoteException e) {
                            Log.e(TAG, "Couldn't take screenshot: " + e);
                            if (completionConsumer != null) {
                                completionConsumer.accept(null);
                            }
                        }
                    }
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    synchronized (mScreenshotLock) {
                        if (mScreenshotConnection != null) {
                            resetConnection();
                            handler.removeCallbacks(mScreenshotTimeout);
                            notifyScreenshotError();
                        }
                    }
                }
            };
            if (mContext.bindServiceAsUser(serviceIntent, conn,
                    Context.BIND_AUTO_CREATE | Context.BIND_FOREGROUND_SERVICE_WHILE_AWAKE,
                    UserHandle.CURRENT)) {
                mScreenshotConnection = conn;
                if (screenshotType != TAKE_SCREENSHOT_SELECTED_REGION) {
                    handler.postDelayed(mScreenshotTimeout, timeoutMs);
                }
            }
        }
    }

    /**
     * Unbinds the current screenshot connection (if any).
     */
    private void resetConnection() {
        if (mScreenshotConnection != null) {
            mContext.unbindService(mScreenshotConnection);
            mScreenshotConnection = null;
        }
    }

    /**
     * Notifies the screenshot service to show an error.
     */
    private void notifyScreenshotError() {
        // If the service process is killed, then ask it to clean up after itself
        final ComponentName errorComponent = new ComponentName(SYSUI_PACKAGE,
                SYSUI_SCREENSHOT_ERROR_RECEIVER);
        // Broadcast needs to have a valid action.  We'll just pick
        // a generic one, since the receiver here doesn't care.
        Intent errorIntent = new Intent(Intent.ACTION_USER_PRESENT);
        errorIntent.setComponent(errorComponent);
        errorIntent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT |
                Intent.FLAG_RECEIVER_FOREGROUND);
        mContext.sendBroadcastAsUser(errorIntent, UserHandle.CURRENT);
    }

}
