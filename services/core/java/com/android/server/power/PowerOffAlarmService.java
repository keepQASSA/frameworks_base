/*
 * Copyright (C) 2023 Yet Another AOSP Project
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
package com.android.server.power;

import static android.provider.AlarmClock.ACTION_SHOW_ALARMS;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.os.UserHandle;
import android.util.Slog;

import com.android.internal.R;
import com.android.server.SystemService;

import java.io.File;

/**
 * A service that makes use of qcom's power off alarm feature
 * Eliminates the need of app specific implementation for said feature
 * Should work with any alarm app that uses {@link AlarmManager.setAlarmClock}
 */
public class PowerOffAlarmService extends SystemService {

    private static final String TAG = "PowerOffAlarmService";

    private static final String PREF_DIR_NAME = "shared_prefs";
    private static final String PREF_FILE_NAME = TAG + "_preferences.xml";
    private static final String PREF_NEXT_ALARM = TAG + "next_alarm_millis";

    private static final String EXTRA_TIME = "time";
    private static final String ACTION_SET = "org.codeaurora.poweroffalarm.action.SET_ALARM";
    private static final String ACTION_CANCEL = "org.codeaurora.poweroffalarm.action.CANCEL_ALARM";
    private static final String ALARM_PACKAGE = "com.qualcomm.qti.poweroffalarm";

    private static final int NOTIFICATION_ID = 0;

    private final Context mContext;
    private AlarmManager mAlarmManager;
    private NotificationManager mNotificationManager;
    private Notification mNotification;
    private SharedPreferences mSharedPreferences;
    private boolean mIsAvailable = false;
    private boolean mSystemReady = false;

    public PowerOffAlarmService(Context context) {
        super(context);
        mContext = context;
    }

    @Override
    public void onStart() {
        Slog.v(TAG, "Starting " + TAG);
        publishLocalService(PowerOffAlarmService.class, this);
        final PackageManager pm = mContext.getPackageManager();
        try {
            final ApplicationInfo info = pm.getApplicationInfo(ALARM_PACKAGE,
                    PackageManager.PERMISSION_GRANTED);
            if (!info.enabled) {
                Slog.v(TAG, "Package " + ALARM_PACKAGE + " is disabled - stopping");
                return;
            }
        } catch (PackageManager.NameNotFoundException e) {
            // no power off alarm package found
            Slog.v(TAG, "Could not find " + ALARM_PACKAGE + " - stopping");
            return;
        }
        mIsAvailable = true;
        final IntentFilter intentFilter = new IntentFilter(Intent.ACTION_TIME_CHANGED);
        intentFilter.addAction(AlarmManager.ACTION_NEXT_ALARM_CLOCK_CHANGED);
        mContext.registerReceiver(mAlarmChangedReceiver, intentFilter);
        Slog.v(TAG, "Registered alarm receiver");
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase != SystemService.PHASE_BOOT_COMPLETED || !mIsAvailable)
            return;
        Slog.v(TAG, "onBootPhase PHASE_BOOT_COMPLETED");
        mAlarmManager = (AlarmManager) mContext.getSystemService(Context.ALARM_SERVICE);
        mNotificationManager = (NotificationManager) mContext.getSystemService(Context.NOTIFICATION_SERVICE);
        mSystemReady = true;
        setupNotification();
        updateAlarms(mAlarmManager);
    }

    private final BroadcastReceiver mAlarmChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!mSystemReady) {
                return;
            }
            Slog.v(TAG, "mAlarmChangedReceiver onReceive");
            updateAlarms(mAlarmManager, true);
        }
    };

    private synchronized SharedPreferences getSharedPreferences() {
        if (mSharedPreferences == null) {
            final File prefsFile = new File(
                    new File(Environment.getDataSystemDeDirectory(
                        UserHandle.USER_SYSTEM), PREF_DIR_NAME), PREF_FILE_NAME);
            mSharedPreferences = mContext.createDeviceProtectedStorageContext()
                    .getSharedPreferences(prefsFile, Context.MODE_PRIVATE);
        }
        return mSharedPreferences;
    }

    private synchronized void updateAlarms(AlarmManager alarmManager) {
        updateAlarms(alarmManager, false);
    }

    private synchronized void updateAlarms(AlarmManager alarmManager, boolean user) {
        final AlarmManager.AlarmClockInfo alarmInfo = alarmManager.getNextAlarmClock();
        cancelPowerOffAlarm();
        final boolean isSet = alarmInfo != null;
        if (isSet) setPowerOffAlarm(alarmInfo);
        updateNotification(isSet && user);
    }

    private synchronized void cancelPowerOffAlarm() {
        final SharedPreferences sharedPrefs = getSharedPreferences();
        if (sharedPrefs == null) {
            Slog.e(TAG, "cancelPowerOffAlarm: SharedPreferences is null!");
            return;
        }
        final long time = sharedPrefs.getLong(PREF_NEXT_ALARM, 0);
        Slog.i(TAG, "Cancel power off alarm, Time: " + time);
        mContext.sendBroadcastAsUser(getIntent(ACTION_CANCEL, time), UserHandle.SYSTEM);
        sharedPrefs.edit().remove(PREF_NEXT_ALARM).commit();
    }

    private synchronized void setPowerOffAlarm(AlarmManager.AlarmClockInfo info) {
        final SharedPreferences sharedPrefs = getSharedPreferences();
        if (sharedPrefs == null) {
            Slog.e(TAG, "setPowerOffAlarm: SharedPreferences is null!");
            return;
        }
        final long time = info.getTriggerTime();
        Slog.i(TAG, "Set next power off alarm. Time: " + time);
        mContext.sendBroadcastAsUser(getIntent(ACTION_SET, time), UserHandle.SYSTEM);
        sharedPrefs.edit().putLong(PREF_NEXT_ALARM, time).commit();
    }

    private synchronized void updateNotification(boolean isSet) {
        if (!mSystemReady) {
            return;
        }
        if (mNotificationManager == null) {
            Slog.e(TAG, "updateNotification: mNotificationManager is null!");
            return;
        }
        mNotificationManager.cancel(NOTIFICATION_ID);
        if (!isSet) return;
        if (mNotification == null) {
            Slog.e(TAG, "updateNotification: mNotification is null!");
            return;
        }
        mNotificationManager.notify(NOTIFICATION_ID, mNotification);
    }

    private void setupNotification() {
        if (!mSystemReady) {
            return;
        }
        final Intent intent = (new Intent(ACTION_SHOW_ALARMS))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        final PendingIntent pendingIntent = PendingIntent.getActivity(mContext, 0, intent,
                PendingIntent.FLAG_IMMUTABLE);
        final NotificationChannel channel = new NotificationChannel(TAG /* channel id */,
                mContext.getText(R.string.notification_channel_poweroff_alarm),
                NotificationManager.IMPORTANCE_LOW);
        channel.setBlockableSystem(true);
        mNotificationManager.createNotificationChannel(channel);
        mNotification = new Notification.Builder(mContext, TAG /* channel id */)
                .setContentTitle(mContext.getText(R.string.poweroff_alarm_title))
                .setContentText(mContext.getText(R.string.poweroff_alarm_body))
                .setSmallIcon(R.drawable.ic_alarm_on)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setShowWhen(false)
                .build();
    }

    private static Intent getIntent(String action, long time) {
        Intent intent = new Intent(action);
        intent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND);
        intent.setPackage(ALARM_PACKAGE);
        intent.putExtra(EXTRA_TIME, time);
        return intent;
    }
}
