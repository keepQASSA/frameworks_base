/*
 * Copyright (C) 2016 The Android Open Source Project
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

package com.android.server.twilight;

import android.annotation.NonNull;
import android.app.AlarmManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.icu.impl.CalendarAstronomer;
import android.icu.util.Calendar;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.ArrayMap;
import android.util.Slog;

import com.android.internal.annotations.GuardedBy;
import com.android.server.SystemService;

import java.io.File;
import java.util.Objects;
import java.text.SimpleDateFormat;

/**
 * Figures out whether it's twilight time based on the user's location.
 * <p>
 * Used by the UI mode manager and other components to adjust night mode
 * effects based on sunrise and sunset.
 */
public final class TwilightService extends SystemService
        implements AlarmManager.OnAlarmListener, Handler.Callback, LocationListener {

    private static final String TAG = "TwilightService";
    private static final String PREF_FILE_NAME = TAG + "_preferences.xml";
    private static final String LONG_PREF_KEY = TAG + "_LONGITUDE";
    private static final String LATI_PREF_KEY = TAG + "_LATITUDE";
    private static final boolean DEBUG = false;

    private static final int MSG_START_LISTENING = 1;
    private static final int MSG_STOP_LISTENING = 2;

    @GuardedBy("mListeners")
    private final ArrayMap<TwilightListener, Handler> mListeners = new ArrayMap<>();

    private final Handler mHandler;

    protected AlarmManager mAlarmManager;
    private LocationManager mLocationManager;

    private boolean mBootCompleted;
    private boolean mHasListeners;

    private BroadcastReceiver mTimeChangedReceiver;
    protected Location mLastLocation;

    @GuardedBy("mListeners")
    protected TwilightState mLastTwilightState;
    private static final SimpleDateFormat mDateFormatFilter = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    private SharedPreferences mSharedPreferences;

    public TwilightService(Context context) {
        super(context);
        mHandler = new Handler(Looper.getMainLooper(), this);
    }

    @Override
    public void onStart() {
        publishLocalService(TwilightManager.class, new TwilightManager() {
            @Override
            public void registerListener(@NonNull TwilightListener listener,
                    @NonNull Handler handler) {
                synchronized (mListeners) {
                    final boolean wasEmpty = mListeners.isEmpty();
                    mListeners.put(listener, handler);

                    if (wasEmpty && !mListeners.isEmpty()) {
                        mHandler.sendEmptyMessage(MSG_START_LISTENING);
                    }
                }
            }

            @Override
            public void unregisterListener(@NonNull TwilightListener listener) {
                synchronized (mListeners) {
                    final boolean wasEmpty = mListeners.isEmpty();
                    mListeners.remove(listener);

                    if (!wasEmpty && mListeners.isEmpty()) {
                        mHandler.sendEmptyMessage(MSG_STOP_LISTENING);
                    }
                }
            }

            @Override
            public TwilightState getLastTwilightState() {
                synchronized (mListeners) {
                    return mLastTwilightState;
                }
            }
        });
    }

    @Override
    public void onBootPhase(int phase) {
        if (phase == PHASE_BOOT_COMPLETED) {
            final Context c = getContext();
            mAlarmManager = (AlarmManager) c.getSystemService(Context.ALARM_SERVICE);
            mLocationManager = (LocationManager) c.getSystemService(Context.LOCATION_SERVICE);

            mBootCompleted = true;
            if (mHasListeners) {
                startListening();
            }
        }
    }

    @Override
    public boolean handleMessage(Message msg) {
        switch (msg.what) {
            case MSG_START_LISTENING:
                if (!mHasListeners) {
                    mHasListeners = true;
                    if (mBootCompleted) {
                        startListening();
                    }
                }
                return true;
            case MSG_STOP_LISTENING:
                if (mHasListeners) {
                    mHasListeners = false;
                    if (mBootCompleted) {
                        stopListening();
                    }
                }
                return true;
        }
        return false;
    }

    private void startListening() {
        Slog.d(TAG, "startListening");

        if (!mLocationManager.isLocationEnabled()) {
            Slog.d(TAG, "locations service is disabled");
            return;
        }
        // Start listening for location updates (default: low power, max 1h, min 10m).
        mLocationManager.requestLocationUpdates(
                null /* default */, this, Looper.getMainLooper());

        // Request the device's location immediately if a previous location isn't available.
        Location location = mLocationManager.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER);
        if (location == null) {
            Slog.d(TAG, "requestSingleUpdate");
            try {
                mLocationManager.requestSingleUpdate(
                        LocationManager.NETWORK_PROVIDER, this, Looper.getMainLooper());
            } catch (Exception e) {
                Slog.e(TAG, "requestSingleUpdate", e);
            }
        } else {
            Slog.d(TAG, "getLastKnownLocation:"
                    + " provider=" + location.getProvider()
                    + " accuracy=" + location.getAccuracy()
                    + " time=" + location.getTime());
            mLastLocation = location;
        }

        // Update whenever the system clock is changed.
        if (mTimeChangedReceiver == null) {
            mTimeChangedReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    Slog.d(TAG, "onReceive: " + intent);
                    updateTwilightState();
                }
            };

            final IntentFilter intentFilter = new IntentFilter(Intent.ACTION_TIME_CHANGED);
            intentFilter.addAction(Intent.ACTION_TIMEZONE_CHANGED);
            getContext().registerReceiver(mTimeChangedReceiver, intentFilter);
        }

        // Force an update now that we have listeners registered.
        updateTwilightState();
    }

    private void stopListening() {
        Slog.d(TAG, "stopListening");

        if (mTimeChangedReceiver != null) {
            getContext().unregisterReceiver(mTimeChangedReceiver);
            mTimeChangedReceiver = null;
        }

        if (mLastTwilightState != null) {
            mAlarmManager.cancel(this);
        }

        mLocationManager.removeUpdates(this);
        mLastLocation = null;
    }

    private void updateTwilightState() {
        // Calculate the twilight state based on the current time and location.
        final long currentTimeMillis = System.currentTimeMillis();
        Location location = mLastLocation != null ? mLastLocation
                : mLocationManager.getLastLocation();

        if (location == null && mSharedPreferences != null) {
            // try using last fetched location
            final Long spLong = mSharedPreferences.getLong(LONG_PREF_KEY, 0);
            final Long spLati = mSharedPreferences.getLong(LATI_PREF_KEY, 0);
            if (spLong != 0 && spLati != 0) {
                location = new Location("");
                location.setLongitude(Double.longBitsToDouble(spLong));
                location.setLatitude(Double.longBitsToDouble(spLati));
                if (DEBUG) Slog.i(TAG, "Fetched saved location: "
                        + location.getLongitude() + " : " + location.getLatitude());
            }
        } else if (mSharedPreferences != null) {
            // save last fetched location for offline usage
            mSharedPreferences.edit().putLong(LONG_PREF_KEY,
                    Double.doubleToRawLongBits(location.getLongitude())).apply();
            mSharedPreferences.edit().putLong(LATI_PREF_KEY,
                    Double.doubleToRawLongBits(location.getLatitude())).apply();
            if (DEBUG) Slog.i(TAG, "Saved location: "
                    + location.getLongitude() + " : " + location.getLatitude());
        }

        final TwilightState state = calculateTwilightState(location, currentTimeMillis);
        if (DEBUG) {
            Slog.d(TAG, "updateTwilightState: " + state);
        }

        // Notify listeners if the state has changed.
        synchronized (mListeners) {
            if (!Objects.equals(mLastTwilightState, state)) {
                mLastTwilightState = state;

                for (int i = mListeners.size() - 1; i >= 0; --i) {
                    final TwilightListener listener = mListeners.keyAt(i);
                    final Handler handler = mListeners.valueAt(i);
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            listener.onTwilightStateChanged(state);
                        }
                    });
                }
            }
        }

        // Schedule an alarm to update the state at the next sunrise or sunset.
        if (state != null) {
            final long triggerAtMillis = state.isNight()
                    ? state.sunriseTimeMillis() : state.sunsetTimeMillis();
            Slog.d(TAG, "setAlarm " + mDateFormatFilter.format(triggerAtMillis));
            mAlarmManager.setExact(AlarmManager.RTC, triggerAtMillis, TAG, this, mHandler);
        }
    }

    @Override
    public void onAlarm() {
        Slog.d(TAG, "onAlarm");
        updateTwilightState();
    }

    @Override
    public void onLocationChanged(Location location) {
        // Location providers may erroneously return (0.0, 0.0) when they fail to determine the
        // device's location. These location updates can be safely ignored since the chance of a
        // user actually being at these coordinates is quite low.
        if (location != null
                && !(location.getLongitude() == 0.0 && location.getLatitude() == 0.0)) {
            Slog.d(TAG, "onLocationChanged:"
                    + " provider=" + location.getProvider()
                    + " accuracy=" + location.getAccuracy()
                    + " time=" + location.getTime());
            mLastLocation = location;
            updateTwilightState();
        }
    }

    @Override
    public void onStatusChanged(String provider, int status, Bundle extras) {
    }

    @Override
    public void onProviderEnabled(String provider) {
    }

    @Override
    public void onProviderDisabled(String provider) {
    }

    @Override
    public void onUnlockUser(int userHandle) {
        mSharedPreferences = getContext().getSharedPreferences(
                new File(Environment.getUserSystemDirectory(
                        userHandle), PREF_FILE_NAME), Context.MODE_PRIVATE);
        updateTwilightState();
    }

    /**
     * Calculates the twilight state for a specific location and time.
     *
     * @param location the location to use
     * @param timeMillis the reference time to use
     * @return the calculated {@link TwilightState}, or {@code null} if location is {@code null}
     */
    private static TwilightState calculateTwilightState(Location location, long timeMillis) {
        if (location == null) {
            return getManualTwilightState(timeMillis);
        }

        final CalendarAstronomer ca = new CalendarAstronomer(
                location.getLongitude(), location.getLatitude());

        final Calendar noon = Calendar.getInstance();
        noon.setTimeInMillis(timeMillis);
        noon.set(Calendar.HOUR_OF_DAY, 12);
        noon.set(Calendar.MINUTE, 0);
        noon.set(Calendar.SECOND, 0);
        noon.set(Calendar.MILLISECOND, 0);
        ca.setTime(noon.getTimeInMillis());

        long sunriseTimeMillis = ca.getSunRiseSet(true /* rise */);
        long sunsetTimeMillis = ca.getSunRiseSet(false /* rise */);

        if (sunsetTimeMillis < timeMillis) {
            noon.add(Calendar.DATE, 1);
            ca.setTime(noon.getTimeInMillis());
            sunriseTimeMillis = ca.getSunRiseSet(true /* rise */);
        } else if (sunriseTimeMillis > timeMillis) {
            noon.add(Calendar.DATE, -1);
            ca.setTime(noon.getTimeInMillis());
            sunsetTimeMillis = ca.getSunRiseSet(false /* rise */);
        }

        return new TwilightState(sunriseTimeMillis, sunsetTimeMillis);
    }

    private static TwilightState getManualTwilightState(long timeMillis) {
        final Calendar sunrise = Calendar.getInstance();
        sunrise.setTimeInMillis(timeMillis);
        sunrise.set(Calendar.HOUR_OF_DAY, 5);
        sunrise.set(Calendar.MINUTE, 0);
        sunrise.set(Calendar.SECOND, 0);
        sunrise.set(Calendar.MILLISECOND, 0);
        final Calendar sunset = Calendar.getInstance();
        sunset.setTimeInMillis(timeMillis);
        sunset.set(Calendar.HOUR_OF_DAY, 19);
        sunset.set(Calendar.MINUTE, 0);
        sunset.set(Calendar.SECOND, 0);
        sunset.set(Calendar.MILLISECOND, 0);
        long sunriseMillis = sunrise.getTimeInMillis();
        long sunsetMillis = sunset.getTimeInMillis();
        if (sunsetMillis < timeMillis) {
            sunrise.add(Calendar.DATE, 1);
            sunriseMillis = sunrise.getTimeInMillis();
        } else if (sunriseMillis > timeMillis) {
            sunset.add(Calendar.DATE, -1);
            sunsetMillis = sunset.getTimeInMillis();
        }
        return new TwilightState(sunriseMillis, sunsetMillis);
    }
}
