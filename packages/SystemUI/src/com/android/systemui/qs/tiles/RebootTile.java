/*
 * Copyright (C) 2019 crDroid Android Project
 * Copyright (C) 2022 QASSA
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

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.PowerManager;
import android.service.quicksettings.Tile;

import com.android.internal.logging.MetricsLogger;
import com.android.internal.logging.nano.MetricsProto.MetricsEvent;
import com.android.systemui.Dependency;
import com.android.systemui.R;
import com.android.systemui.plugins.ActivityStarter;
import com.android.systemui.plugins.qs.QSTile.BooleanState;
import com.android.systemui.qs.QSHost;
import com.android.systemui.qs.tileimpl.QSTileImpl;
import com.android.systemui.statusbar.policy.KeyguardMonitor;

import javax.inject.Inject;

public class RebootTile extends QSTileImpl<BooleanState> {

    private int mRebootToRecovery = 0;
    private final ActivityStarter mActivityStarter;

    private final KeyguardMonitor mKeyguard;
    private final KeyguardCallback mKeyguardCallback = new KeyguardCallback();

    @Inject
    public RebootTile(QSHost host,
        ActivityStarter activityStarter) {
        super(host);
        mActivityStarter = activityStarter;
        mKeyguard = Dependency.get(KeyguardMonitor.class);
    }

    @Override
    public BooleanState newTileState() {
        return new BooleanState();
    }

    void handleClickInner() {
        if (mRebootToRecovery == 0) {
            mRebootToRecovery = 1;
        } else if (mRebootToRecovery == 1) {
            mRebootToRecovery = 2;
        } else {
            mRebootToRecovery = 0;
        }
        refreshState();
    }

    @Override
    protected void handleLongClick() {
        mHost.collapsePanels();
        Handler handler = new Handler();
        handler.postDelayed(new Runnable() {
            public void run() {
                PowerManager pm =
                    (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
                if (mRebootToRecovery == 1) {
                    pm.rebootCustom(PowerManager.REBOOT_RECOVERY);
                } else if (mRebootToRecovery == 2) {
                    pm.shutdown(false, pm.SHUTDOWN_USER_REQUESTED, false);
                } else {
                    pm.reboot("");
                }
            }
        }, 500);
    }

    @Override
    public Intent getLongClickIntent() {
        return null;
    }

    @Override
    protected void handleClick() {
        if (mKeyguard.isSecure() && mKeyguard.isShowing()) {
            Dependency.get(ActivityStarter.class).postQSRunnableDismissingKeyguard(() -> {
                mHost.openPanels();
                handleClickInner();
            });
            return;
        }
        handleClickInner();
    }

    @Override
    public CharSequence getTileLabel() {
        return mContext.getString(R.string.quick_settings_reboot_label);
    }

    @Override
    public int getMetricsCategory() {
        return MetricsEvent.QASSA;
    }

    @Override
    protected void handleUpdateState(BooleanState state, Object arg) {
        if (mRebootToRecovery == 1) {
            state.label = mContext.getString(R.string.quick_settings_reboot_recovery_label);
            state.icon = ResourceIcon.get(R.drawable.ic_qs_reboot_recovery);
        } else if (mRebootToRecovery == 2) {
            state.label = mContext.getString(R.string.quick_settings_poweroff_label);
            state.icon = ResourceIcon.get(R.drawable.ic_qs_poweroff);
        } else {
            state.label = mContext.getString(R.string.quick_settings_reboot_label);
            state.icon = ResourceIcon.get(R.drawable.ic_qs_reboot);
        }
        state.state = Tile.STATE_INACTIVE;
    }

    @Override
    public void handleSetListening(boolean listening) {
        if (listening) {
            mKeyguard.addCallback(mKeyguardCallback);
        } else {
            mKeyguard.removeCallback(mKeyguardCallback);
        }
    }

    private final class KeyguardCallback implements KeyguardMonitor.Callback {
        @Override
        public void onKeyguardShowingChanged() {
            refreshState();
        }
    };
}
