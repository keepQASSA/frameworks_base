/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.systemui.statusbar.notification;

import static com.android.systemui.statusbar.StatusBarState.SHADE;

import android.app.Notification;
import android.app.NotificationManager;
import android.content.Context;
import android.database.ContentObserver;
import android.hardware.display.AmbientDisplayConfiguration;
import android.os.Build;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.provider.Settings;
import android.service.dreams.DreamService;
import android.service.dreams.IDreamManager;
import android.service.notification.StatusBarNotification;
import android.util.Log;
import android.text.TextUtils;

import com.android.internal.annotations.VisibleForTesting;
import com.android.systemui.Dependency;
import com.android.systemui.plugins.statusbar.StatusBarStateController;
import com.android.systemui.statusbar.NotificationPresenter;
import com.android.systemui.statusbar.StatusBarState;
import com.android.systemui.statusbar.notification.collection.NotificationEntry;
import com.android.systemui.statusbar.policy.BatteryController;
import com.android.systemui.statusbar.policy.HeadsUpManager;

import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Provides heads-up and pulsing state for notification entries.
 */
@Singleton
public class NotificationInterruptionStateProvider {

    private static final String TAG = "InterruptionStateProvider";
    private static final boolean DEBUG = false;
    private static final boolean DEBUG_HEADS_UP = false;
    private static final boolean ENABLE_HEADS_UP = true;
    private static final String SETTING_HEADS_UP_TICKER = "ticker_gets_heads_up";

    private final StatusBarStateController mStatusBarStateController;
    private final NotificationFilter mNotificationFilter;
    private final AmbientDisplayConfiguration mAmbientDisplayConfiguration;

    private final Context mContext;
    private final PowerManager mPowerManager;
    private final IDreamManager mDreamManager;
    private final BatteryController mBatteryController;

    private NotificationPresenter mPresenter;
    private HeadsUpManager mHeadsUpManager;
    private HeadsUpSuppressor mHeadsUpSuppressor;

    private ContentObserver mHeadsUpObserver;
    @VisibleForTesting
    protected boolean mUseHeadsUp = false;
    private boolean mDisableNotificationAlerts;

    private boolean mGamingModeNoAlert = false;

    private boolean mPartialScreenshot;
    private boolean mLessBoringHeadsUp;
    private boolean mSkipHeadsUp;

    @Inject
    public NotificationInterruptionStateProvider(Context context, NotificationFilter filter,
            StatusBarStateController stateController, BatteryController batteryController) {
        this(context,
                (PowerManager) context.getSystemService(Context.POWER_SERVICE),
                IDreamManager.Stub.asInterface(
                        ServiceManager.checkService(DreamService.DREAM_SERVICE)),
                new AmbientDisplayConfiguration(context),
                filter,
                batteryController,
                stateController);
    }

    @VisibleForTesting
    protected NotificationInterruptionStateProvider(
            Context context,
            PowerManager powerManager,
            IDreamManager dreamManager,
            AmbientDisplayConfiguration ambientDisplayConfiguration,
            NotificationFilter notificationFilter,
            BatteryController batteryController,
            StatusBarStateController statusBarStateController) {
        mContext = context;
        mPowerManager = powerManager;
        mDreamManager = dreamManager;
        mBatteryController = batteryController;
        mAmbientDisplayConfiguration = ambientDisplayConfiguration;
        mNotificationFilter = notificationFilter;
        mStatusBarStateController = statusBarStateController;
    }

    /** Sets up late-binding dependencies for this component. */
    public void setUpWithPresenter(
            NotificationPresenter notificationPresenter,
            HeadsUpManager headsUpManager,
            HeadsUpSuppressor headsUpSuppressor) {
        setUpWithPresenter(notificationPresenter, headsUpManager, headsUpSuppressor,
                new ContentObserver(Dependency.get(Dependency.MAIN_HANDLER)) {
                    @Override
                    public void onChange(boolean selfChange) {
                        boolean wasUsing = mUseHeadsUp;
                        mUseHeadsUp = ENABLE_HEADS_UP && !mDisableNotificationAlerts
                                && Settings.Global.HEADS_UP_OFF != Settings.Global.getInt(
                                mContext.getContentResolver(),
                                Settings.Global.HEADS_UP_NOTIFICATIONS_ENABLED,
                                Settings.Global.HEADS_UP_OFF);
                        Log.d(TAG, "heads up is " + (mUseHeadsUp ? "enabled" : "disabled"));
                        if (wasUsing != mUseHeadsUp) {
                            if (!mUseHeadsUp) {
                                Log.d(TAG,
                                        "dismissing any existing heads up notification on disable"
                                                + " event");
                                mHeadsUpManager.releaseAllImmediately();
                            }
                        }
                    }
                });
    }

    /** Sets up late-binding dependencies for this component. */
    public void setUpWithPresenter(
            NotificationPresenter notificationPresenter,
            HeadsUpManager headsUpManager,
            HeadsUpSuppressor headsUpSuppressor,
            ContentObserver observer) {
        mPresenter = notificationPresenter;
        mHeadsUpManager = headsUpManager;
        mHeadsUpSuppressor = headsUpSuppressor;
        mHeadsUpObserver = observer;

        if (ENABLE_HEADS_UP) {
            mContext.getContentResolver().registerContentObserver(
                    Settings.Global.getUriFor(Settings.Global.HEADS_UP_NOTIFICATIONS_ENABLED),
                    true,
                    mHeadsUpObserver);
            mContext.getContentResolver().registerContentObserver(
                    Settings.Global.getUriFor(SETTING_HEADS_UP_TICKER), true,
                    mHeadsUpObserver);
        }
        mHeadsUpObserver.onChange(true); // set up
    }

    /**
     * Whether the notification should appear as a bubble with a fly-out on top of the screen.
     *
     * @param entry the entry to check
     * @return true if the entry should bubble up, false otherwise
     */
    public boolean shouldBubbleUp(NotificationEntry entry) {
        if (entry.rowExists() && entry.getRow().isAppLocked()) {
            return false;
        }

        final StatusBarNotification sbn = entry.notification;

        if (!canAlertCommon(entry)) {
            return false;
        }

        if (!canAlertAwakeCommon(entry)) {
            return false;
        }

        if (!entry.canBubble) {
            if (DEBUG) {
                Log.d(TAG, "No bubble up: not allowed to bubble: " + sbn.getKey());
            }
            return false;
        }

        if (!entry.isBubble()) {
            if (DEBUG) {
                Log.d(TAG, "No bubble up: notification " + sbn.getKey()
                        + " is bubble? " + entry.isBubble());
            }
            return false;
        }

        final Notification n = sbn.getNotification();
        if (n.getBubbleMetadata() == null || n.getBubbleMetadata().getIntent() == null) {
            if (DEBUG) {
                Log.d(TAG, "No bubble up: notification: " + sbn.getKey()
                        + " doesn't have valid metadata");
            }
            return false;
        }

        return true;
    }

    public boolean shouldLaunchFullScreenIntentWhenAdded(NotificationEntry entry) {
        if (entry.notification.getNotification().fullScreenIntent == null) {
            return false;
        }

        // Never show FSI when suppressed by DND
        if (entry.shouldSuppressFullScreenIntent()) {
            if (DEBUG) {
                Log.d(TAG, "No FullScreenIntent: Suppressed by DND: " + entry.key);
            }
            return false;
        }

        // Never show FSI if importance is not HIGH
        if (entry.importance < NotificationManager.IMPORTANCE_HIGH) {
            if (DEBUG) {
                Log.d(TAG, "No FullScreenIntent: Not important enough: " + entry.key);
            }
            return false;
        }

        // If the notification has suppressive GroupAlertBehavior, block FSI and warn.
        StatusBarNotification sbn = entry.notification;
        if (sbn.isGroup() && sbn.getNotification().suppressAlertingDueToGrouping()) {
            // b/231322873: Detect and report an event when a notification has both an FSI and a
            // suppressive groupAlertBehavior, and now correctly block the FSI from firing.
            final int uid = entry.notification.getUid();
            android.util.EventLog.writeEvent(0x534e4554, "231322873", uid, "groupAlertBehavior");
            if (DEBUG) {
                Log.w(TAG, "No FullScreenIntent: WARNING: GroupAlertBehavior will prevent HUN: "
                        + entry.key);
            }
            return false;
        }

        // If the notification has suppressive BubbleMetadata, block FSI and warn.
        Notification.BubbleMetadata bubbleMetadata = sbn.getNotification().getBubbleMetadata();
        if (bubbleMetadata != null && bubbleMetadata.isNotificationSuppressed()) {
            // b/274759612: Detect and report an event when a notification has both an FSI and a
            // suppressive BubbleMetadata, and now correctly block the FSI from firing.
            final int uid = entry.notification.getUid();
            android.util.EventLog.writeEvent(0x534e4554, "274759612", uid, "bubbleMetadata");
            if (DEBUG) {
                Log.w(TAG, "No FullScreenIntent: WARNING: BubbleMetadata may prevent HUN: "
                        + entry.key);
            }
            return false;
        }

        // If the screen is off, then launch the FullScreenIntent
        if (!mPowerManager.isInteractive()) {
            if (DEBUG) {
                Log.d(TAG, "FullScreenIntent: Device is not interactive: " + entry.key);
            }
            return true;
        }

        // If the device is currently dreaming, then launch the FullScreenIntent
        if (isDreaming()) {
            if (DEBUG) {
                Log.d(TAG, "FullScreenIntent: Device is dreaming: " + entry.key);
            }
            return true;
        }

        // If the keyguard is showing, then launch the FullScreenIntent
        if (mStatusBarStateController.getState() == StatusBarState.KEYGUARD) {
            if (DEBUG) {
                Log.d(TAG, "FullScreenIntent: Keyguard is showing: " + entry.key);
            }
            return true;
        }

        // If the notification should HUN, then we don't need FSI
        if (shouldHeadsUp(entry)) {
            if (DEBUG) {
                Log.d(TAG, "No FullScreenIntent: Expected to HUN: " + entry.key);
            }
            return false;
        }

        // If the notification won't HUN for some other reason (DND/snooze/etc), launch FSI.
        if (DEBUG) {
            Log.d(TAG, "FullScreenIntent: Expected not to HUN: " + entry.key);
        }
        return true;
    }

    private boolean isDreaming() {
        try {
            return mDreamManager.isDreaming();
        } catch (RemoteException e) {
            Log.e(TAG, "Failed to query dream manager.", e);
            return false;
        }
    }

    /**
     * Whether the notification should peek in from the top and alert the user.
     *
     * @param entry the entry to check
     * @return true if the entry should heads up, false otherwise
     */
    public boolean shouldHeadsUp(NotificationEntry entry) {
        if (mStatusBarStateController.isDozing()) {
            return shouldHeadsUpWhenDozing(entry);
        } else {
            return shouldHeadsUpWhenAwake(entry);
        }
    }

    public void setGamingModeNoAlert(boolean value) {
        mGamingModeNoAlert = value;
    }

    private boolean shouldHeadsUpWhenAwake(NotificationEntry entry) {
        if (mStatusBarStateController.getState() != StatusBarState.KEYGUARD
                && entry.rowExists() && entry.getRow().blockHeadsUp()) {
            return false;
        }

        StatusBarNotification sbn = entry.notification;

        if (!mUseHeadsUp) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No heads up: no huns");
            }
            return false;
        }

        if (!canAlertCommon(entry)) {
            return false;
        }

        if (!canAlertAwakeCommon(entry)) {
            return false;
        }

        boolean inShade = mStatusBarStateController.getState() == SHADE;
        if (entry.isBubble() && inShade) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No heads up: in unlocked shade where notification is shown as a "
                        + "bubble: " + sbn.getKey());
            }
            return false;
        }

        if (entry.shouldSuppressPeek() || mPartialScreenshot) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No heads up: suppressed by DND: " + sbn.getKey());
            }
            return false;
        }

        if (entry.importance < NotificationManager.IMPORTANCE_HIGH) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No heads up: unimportant notification: " + sbn.getKey());
            }
            return false;
        }

        boolean inUse = mPowerManager.isScreenOn() && !isDreaming();

        if (!inUse) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No heads up: not in use: " + sbn.getKey());
            }
            return false;
        }

        if (!mHeadsUpSuppressor.canHeadsUp(entry, sbn)) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No heads up: aborted by suppressor: " + sbn.getKey());
            }
            return false;
        }

        return true;
    }

    /**
     * Whether or not the notification should "pulse" on the user's display when the phone is
     * dozing.  This displays the ambient view of the notification.
     *
     * @param entry the entry to check
     * @return true if the entry should ambient pulse, false otherwise
     */
    private boolean shouldHeadsUpWhenDozing(NotificationEntry entry) {
        StatusBarNotification sbn = entry.notification;

        if (!mAmbientDisplayConfiguration.pulseOnNotificationEnabled(UserHandle.USER_CURRENT)) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No pulsing: disabled by setting: " + sbn.getKey());
            }
            return false;
        }

        if (mBatteryController.isAodPowerSave()) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No pulsing: disabled by battery saver: " + sbn.getKey());
            }
            return false;
        }

        if (!canAlertCommon(entry)) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No pulsing: notification shouldn't alert: " + sbn.getKey());
            }
            return false;
        }

        if (entry.shouldSuppressAmbient()) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No pulsing: ambient effect suppressed: " + sbn.getKey());
            }
            return false;
        }

        if (entry.importance < NotificationManager.IMPORTANCE_DEFAULT) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No pulsing: not important enough: " + sbn.getKey());
            }
            return false;
        }
         return true;
    }

    /**
     * Common checks between regular & AOD heads up and bubbles.
     *
     * @param entry the entry to check
     * @return true if these checks pass, false if the notification should not alert
     */
    @VisibleForTesting
    public boolean canAlertCommon(NotificationEntry entry) {
        StatusBarNotification sbn = entry.notification;

        if (mNotificationFilter.shouldFilterOut(entry)) {
            if (DEBUG || DEBUG_HEADS_UP) {
                Log.d(TAG, "No alerting: filtered notification: " + sbn.getKey());
            }
            return false;
        }

        // Don't alert notifications that are suppressed due to group alert behavior
        if (sbn.isGroup() && sbn.getNotification().suppressAlertingDueToGrouping()) {
            if (DEBUG || DEBUG_HEADS_UP) {
                Log.d(TAG, "No alerting: suppressed due to group alert behavior");
            }
            return false;
        }
        return true;
    }

    public void setPartialScreenshot(boolean active) {
        mPartialScreenshot = active;
    }

    public void setUseLessBoringHeadsUp(boolean lessBoring) {
        mLessBoringHeadsUp = lessBoring;
    }

    public boolean shouldSkipHeadsUp(StatusBarNotification sbn) {
        boolean isImportantHeadsUp = false;
        String notificationPackageName = sbn.getPackageName().toLowerCase();
        isImportantHeadsUp = notificationPackageName.contains("dialer") ||
                notificationPackageName.contains("messaging") ||
                notificationPackageName.contains("clock");
        return (mLessBoringHeadsUp || mSkipHeadsUp) && !isImportantHeadsUp;
    }

    /**
     * Common checks between alerts that occur while the device is awake (heads up & bubbles).
     *
     * @param entry the entry to check
     * @return true if these checks pass, false if the notification should not alert
     */
    @VisibleForTesting
    public boolean canAlertAwakeCommon(NotificationEntry entry) {
        StatusBarNotification sbn = entry.notification;

        if (mGamingModeNoAlert && 
            (!TextUtils.equals(sbn.getNotification().category, Notification.CATEGORY_CALL) &&
             !TextUtils.equals(sbn.getNotification().category, Notification.CATEGORY_ALARM))) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No alerting: gaming mode, category is not alarm or call");
            }
            return false;
        }

        if (mPresenter.isDeviceInVrMode() || shouldSkipHeadsUp(sbn)) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No alerting: no huns or vr mode or less boring headsup enabled or gaming mode");
            }
            return false;
        }

        if (isSnoozedPackage(sbn)) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No alerting: snoozed package: " + sbn.getKey());
            }
            return false;
        }

        if (entry.hasJustLaunchedFullScreenIntent()) {
            if (DEBUG_HEADS_UP) {
                Log.d(TAG, "No alerting: recent fullscreen: " + sbn.getKey());
            }
            return false;
        }

        return true;
    }

    private boolean isSnoozedPackage(StatusBarNotification sbn) {
        return mHeadsUpManager.isSnoozed(sbn.getPackageName());
    }

    /** Sets whether to disable all alerts. */
    public void setDisableNotificationAlerts(boolean disableNotificationAlerts) {
        mDisableNotificationAlerts = disableNotificationAlerts;
        mHeadsUpObserver.onChange(true);
    }

    /** Whether all alerts are disabled. */
    @VisibleForTesting
    public boolean areNotificationAlertsDisabled() {
        return mDisableNotificationAlerts;
    }

    /** Whether HUNs should be used. */
    @VisibleForTesting
    public boolean getUseHeadsUp() {
        return mUseHeadsUp;
    }

    protected NotificationPresenter getPresenter() {
        return mPresenter;
    }

    /** A component which can suppress heads-up notifications due to the overall state of the UI. */
    public interface HeadsUpSuppressor {
        /**
         * Returns false if the provided notification is ineligible for heads-up according to this
         * component.
         *
         * @param entry entry of the notification that might be heads upped
         * @param sbn   notification that might be heads upped
         * @return false if the notification can not be heads upped
         */
        boolean canHeadsUp(NotificationEntry entry, StatusBarNotification sbn);

    }

}
