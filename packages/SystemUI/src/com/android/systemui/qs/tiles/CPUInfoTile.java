/*
 * Copyright (C) 2017-2018 Benzo Rom
 *           (C) 2017-2019 crDroidAndroid Project
 *           (C) 2022 QASSA
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

package com.android.systemui.qs.tiles;

import android.content.Intent;
import android.provider.Settings;
import android.provider.Settings.Global;
import android.service.quicksettings.Tile;

import com.android.systemui.plugins.qs.QSTile.BooleanState;
import com.android.systemui.qs.GlobalSetting;
import com.android.systemui.qs.QSHost;
import com.android.systemui.qs.tileimpl.QSTileImpl;
import com.android.systemui.R;

import com.android.internal.logging.nano.MetricsProto.MetricsEvent;

import javax.inject.Inject;

/** Quick settings tile: CPUInfo overlay **/
public class CPUInfoTile extends QSTileImpl<BooleanState> {

    private final GlobalSetting mSetting;
    private final Icon mIcon = ResourceIcon.get(R.drawable.ic_qs_cpuinfo);

    @Inject
    public CPUInfoTile(QSHost host) {
        super(host);

        mSetting = new GlobalSetting(mContext, mHandler, Global.SHOW_CPU_OVERLAY) {
            @Override
            protected void handleValueChanged(int value) {
                handleRefreshState(value);
            }
        };
    }

    @Override
    public BooleanState newTileState() {
        BooleanState state = new BooleanState();
        state.handlesLongClick = false;
        return state;
    }

    @Override
    protected void handleClick() {
        mSetting.setValue(mState.value ? 0 : 1);
        refreshState();
        toggleState();
    }

    protected void toggleState() {
        Intent service = (new Intent())
                .setClassName("com.android.systemui",
                "com.android.systemui.CPUInfoService");
        if (mSetting.getValue() == 0) {
            mContext.stopService(service);
        } else {
            mContext.startService(service);
        }
    }

    @Override
    public Intent getLongClickIntent() {
        return null;
    }

    @Override
    protected void handleUpdateState(BooleanState state, Object arg) {
        if (mSetting == null) return;
        final int value = arg instanceof Integer ? (Integer)arg : mSetting.getValue();
        final boolean cpuInfoEnabled = value != 0;
        state.value = cpuInfoEnabled;
        state.label = mContext.getString(R.string.quick_settings_cpuinfo_label);
        state.icon = mIcon;
        state.contentDescription =  mContext.getString(
                R.string.quick_settings_cpuinfo_label);
        if (cpuInfoEnabled) {
            state.state = Tile.STATE_ACTIVE;
        } else {
            state.state = Tile.STATE_INACTIVE;
        }
    }

    @Override
    public CharSequence getTileLabel() {
        return mContext.getString(R.string.quick_settings_cpuinfo_label);
    }

    @Override
    protected String composeChangeAnnouncement() {
        return mContext.getString(R.string.quick_settings_cpuinfo_label);
    }

    @Override
    public int getMetricsCategory() {
        return MetricsEvent.QASSA;
    }

    @Override
    public void handleSetListening(boolean listening) {
        // Do nothing
    }
}
