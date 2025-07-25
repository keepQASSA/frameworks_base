/*
 * Copyright (C) 2018 crDroid Android Project
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

package com.android.systemui.qassa.batterybar;

import android.content.Context;
import android.content.SharedPreferences;

public class Prefs {
    private static final String SHARED_PREFS_NAME = "status_bar";

    public static final String LAST_BATTERY_LEVEL = "last_battery_level";

    public static SharedPreferences read(Context context) {
        return context.getSharedPreferences(Prefs.SHARED_PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static SharedPreferences.Editor edit(Context context) {
        return context.getSharedPreferences(Prefs.SHARED_PREFS_NAME, Context.MODE_PRIVATE).edit();
    }

    public static void setLastBatteryLevel(Context context, int level) {
        edit(context).putInt(LAST_BATTERY_LEVEL, level).commit();
    }

    public static int getLastBatteryLevel(Context context) {
        return read(context).getInt(LAST_BATTERY_LEVEL, 50);
    }

}
