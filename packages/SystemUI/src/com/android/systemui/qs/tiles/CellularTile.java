/*
 * Copyright (C) 2014 The Android Open Source Project
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

import static com.android.systemui.Prefs.Key.QS_HAS_TURNED_OFF_MOBILE_DATA;

import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.provider.Settings;
import android.service.quicksettings.Tile;
import android.telephony.SubscriptionManager;
import android.text.Html;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager.LayoutParams;
import android.widget.Switch;

import com.android.internal.logging.MetricsLogger;
import com.android.internal.logging.nano.MetricsProto.MetricsEvent;
import com.android.settingslib.net.DataUsageController;
import com.android.settingslib.net.DataUsageUtils;
import com.android.systemui.Prefs;
import com.android.systemui.Dependency;
import com.android.systemui.R;
import com.android.systemui.plugins.ActivityStarter;
import com.android.systemui.plugins.qs.DetailAdapter;
import com.android.systemui.plugins.qs.QSIconView;
import com.android.systemui.plugins.qs.QSTile.SignalState;
import com.android.systemui.qs.QSHost;
import com.android.systemui.qs.SignalTileView;
import com.android.systemui.qs.tileimpl.QSTileImpl;
import com.android.systemui.statusbar.phone.SystemUIDialog;
import com.android.systemui.statusbar.phone.UnlockMethodCache;
import com.android.systemui.statusbar.policy.KeyguardMonitor;
import com.android.systemui.statusbar.policy.NetworkController;
import com.android.systemui.statusbar.policy.NetworkController.IconState;
import com.android.systemui.statusbar.policy.NetworkController.SignalCallback;
import com.android.systemui.statusbar.policy.KeyguardMonitor;

import javax.inject.Inject;

/** Quick settings tile: Cellular **/
public class CellularTile extends QSTileImpl<SignalState> {
    private static final String ENABLE_SETTINGS_DATA_PLAN = "enable.settings.data.plan";

    private final NetworkController mController;
    private final DataUsageController mDataController;
    private final CellularDetailAdapter mDetailAdapter;

    private final CellSignalCallback mSignalCallback = new CellSignalCallback();
    private final ActivityStarter mActivityStarter;
    private final KeyguardMonitor mKeyguardMonitor;
    private final UnlockMethodCache mUnlockMethodCache;

    private final KeyguardMonitor mKeyguard;
    private final KeyguardCallback mKeyguardCallback = new KeyguardCallback();

    @Inject
    public CellularTile(QSHost host, NetworkController networkController,
            ActivityStarter activityStarter, KeyguardMonitor keyguardMonitor) {
        super(host);
        mController = networkController;
        mActivityStarter = activityStarter;
        mKeyguardMonitor = keyguardMonitor;
        mUnlockMethodCache = UnlockMethodCache.getInstance(mHost.getContext());
        mDataController = mController.getMobileDataController();
        mDetailAdapter = new CellularDetailAdapter();
        mKeyguard = Dependency.get(KeyguardMonitor.class);
        mController.observe(getLifecycle(), mSignalCallback);
    }

    @Override
    public SignalState newTileState() {
        return new SignalState();
    }

    @Override
    public QSIconView createTileView(Context context) {
        return new SignalTileView(context);
    }

    @Override
    public DetailAdapter getDetailAdapter() {
        return mDetailAdapter;
    }

    @Override
    public void handleSetListening(boolean listening) {
        if (listening) {
            mKeyguard.addCallback(mKeyguardCallback);
        } else {
            mKeyguard.removeCallback(mKeyguardCallback);
        }
    }

    @Override
    public Intent getLongClickIntent() {
        return getCellularSettingIntent();
    }

    @Override
    protected void handleClick() {
        if (getState().state == Tile.STATE_UNAVAILABLE) {
            return;
        }
        if (mDataController.isMobileDataEnabled()) {
            if (mKeyguard.isSecure() && mKeyguard.isShowing()) {
                mActivityStarter.postQSRunnableDismissingKeyguard(this::maybeShowDisableDialog);
            } else {
                maybeShowDisableDialog();
            }
        } else {
            if (mKeyguard.isSecure() && mKeyguard.isShowing()) {
                Dependency.get(ActivityStarter.class).postQSRunnableDismissingKeyguard(() -> {
                    mHost.openPanels();
                    mDataController.setMobileDataEnabled(true);
                });
                return;
            }
            mDataController.setMobileDataEnabled(true);
        }
    }

    private void maybeShowDisableDialog() {
        if (Prefs.getBoolean(mContext, QS_HAS_TURNED_OFF_MOBILE_DATA, true)) {
            // Directly turn off mobile data if the user has seen the dialog before.
            mDataController.setMobileDataEnabled(false);
            return;
        }
        String carrierName = mController.getMobileDataNetworkName();
        if (TextUtils.isEmpty(carrierName)) {
            carrierName = mContext.getString(R.string.mobile_data_disable_message_default_carrier);
        }
        AlertDialog dialog = new Builder(mContext)
                .setTitle(R.string.mobile_data_disable_title)
                .setMessage(mContext.getString(R.string.mobile_data_disable_message, carrierName))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(
                        com.android.internal.R.string.alert_windows_notification_turn_off_action,
                        (d, w) -> {
                            mDataController.setMobileDataEnabled(false);
                            Prefs.putBoolean(mContext, QS_HAS_TURNED_OFF_MOBILE_DATA, true);
                        })
                .create();
        dialog.getWindow().setType(LayoutParams.TYPE_KEYGUARD_DIALOG);
        SystemUIDialog.setShowForAllUsers(dialog, true);
        SystemUIDialog.registerDismissListener(dialog);
        SystemUIDialog.setWindowOnTop(dialog);
        dialog.show();
    }

    @Override
    protected void handleSecondaryClick() {
        if (getState().state == Tile.STATE_UNAVAILABLE) {
            return;
        }
        if (mDataController.isMobileDataSupported()) {
            if (mKeyguardMonitor.isSecure() && !mUnlockMethodCache.canSkipBouncer()) {
                mActivityStarter.postQSRunnableDismissingKeyguard(() -> {
                    showDetail(true);
                });
                return;
            }
            showDetail(true);
        } else {
            mActivityStarter
                    .postStartActivityDismissingKeyguard(getCellularSettingIntent(),0 /* delay */);
        }
    }

    @Override
    public CharSequence getTileLabel() {
        return mContext.getString(R.string.quick_settings_cellular_detail_title);
    }

    @Override
    protected void handleUpdateState(SignalState state, Object arg) {
        CallbackInfo cb = (CallbackInfo) arg;
        if (cb == null) {
            cb = mSignalCallback.mInfo;
        }

        DataUsageController.DataUsageInfo carrierLabelInfo = mDataController.getDataUsageInfo();
        final Resources r = mContext.getResources();
        state.dualTarget = true;
        boolean mobileDataEnabled = mDataController.isMobileDataSupported()
                && mDataController.isMobileDataEnabled();
        state.value = mobileDataEnabled;
        state.activityIn = mobileDataEnabled && cb.activityIn;
        state.activityOut = mobileDataEnabled && cb.activityOut;
        state.expandedAccessibilityClassName = Switch.class.getName();
        if (cb.noSim) {
            state.label = r.getString(R.string.mobile_data);
            state.icon = ResourceIcon.get(R.drawable.ic_qs_no_sim);
        } else {
            if (carrierLabelInfo != null) {
                state.label = carrierLabelInfo.carrier;
            } else {
                state.label = r.getString(R.string.mobile_data);
            }
            state.icon = ResourceIcon.get(R.drawable.ic_swap_vert);
        }

        if (cb.noSim) {
            state.state = Tile.STATE_UNAVAILABLE;
            state.secondaryLabel = r.getString(R.string.keyguard_missing_sim_message_short);
        } else if (cb.airplaneModeEnabled) {
            state.state = Tile.STATE_UNAVAILABLE;
            state.secondaryLabel = r.getString(R.string.status_bar_airplane);
        } else if (mobileDataEnabled) {
            state.state = Tile.STATE_ACTIVE;
            state.secondaryLabel = appendMobileDataType(
                    // Only show carrier name if there are more than 1 subscription
                    cb.multipleSubs ? cb.dataSubscriptionName : "",
                    getMobileDataContentName(cb));
        } else {
            state.state = Tile.STATE_INACTIVE;
            state.secondaryLabel = r.getString(R.string.cell_data_off);
        }


        // TODO(b/77881974): Instead of switching out the description via a string check for
        // we need to have two strings provided by the MobileIconGroup.
        final CharSequence contentDescriptionSuffix;
        if (state.state == Tile.STATE_INACTIVE) {
            contentDescriptionSuffix = r.getString(R.string.cell_data_off_content_description);
        } else {
            contentDescriptionSuffix = state.secondaryLabel;
        }

        state.contentDescription = state.label + ", " + contentDescriptionSuffix;
    }

    private CharSequence appendMobileDataType(CharSequence current, CharSequence dataType) {
        if (TextUtils.isEmpty(dataType)) {
            return Html.fromHtml(current.toString(), 0);
        }
        if (TextUtils.isEmpty(current)) {
            return Html.fromHtml(dataType.toString(), 0);
        }
        String concat = mContext.getString(R.string.mobile_carrier_text_format, current, dataType);
        return Html.fromHtml(concat, 0);
    }

    private CharSequence getMobileDataContentName(CallbackInfo cb) {
        if (cb.roaming && !TextUtils.isEmpty(cb.dataContentDescription)) {
            String roaming = mContext.getString(R.string.data_connection_roaming);
            String dataDescription = cb.dataContentDescription.toString();
            return mContext.getString(R.string.mobile_data_text_format, roaming, dataDescription);
        }
        if (cb.roaming) {
            return mContext.getString(R.string.data_connection_roaming);
        }
        return cb.dataContentDescription;
    }

    @Override
    public int getMetricsCategory() {
        return MetricsEvent.QS_CELLULAR;
    }

    @Override
    public boolean isAvailable() {
        return mController.hasMobileDataFeature();
    }

    private static final class CallbackInfo {
        boolean airplaneModeEnabled;
        CharSequence dataSubscriptionName;
        CharSequence dataContentDescription;
        boolean activityIn;
        boolean activityOut;
        boolean noSim;
        boolean roaming;
        boolean multipleSubs;
    }

    private final class CellSignalCallback implements SignalCallback {
        private final CallbackInfo mInfo = new CallbackInfo();

        @Override
        public void setMobileDataIndicators(IconState statusIcon, IconState qsIcon, int statusType,
                int qsType, boolean activityIn, boolean activityOut, int stackedVoiceIcon,
                CharSequence typeContentDescription,
                CharSequence typeContentDescriptionHtml, CharSequence description,
                boolean isWide, int subId, boolean roaming) {
            if (qsIcon == null) {
                // Not data sim, don't display.
                return;
            }
            mInfo.dataSubscriptionName = mController.getMobileDataNetworkName();
            mInfo.dataContentDescription =
                    (description != null) ? typeContentDescriptionHtml : null;
            mInfo.activityIn = activityIn;
            mInfo.activityOut = activityOut;
            mInfo.roaming = roaming;
            mInfo.multipleSubs = mController.getNumberSubscriptions() > 1;
            refreshState(mInfo);
        }

        @Override
        public void setNoSims(boolean show, boolean simDetected) {
            mInfo.noSim = show;
            refreshState(mInfo);
        }

        @Override
        public void setIsAirplaneMode(IconState icon) {
            mInfo.airplaneModeEnabled = icon.visible;
            refreshState(mInfo);
        }

        @Override
        public void setMobileDataEnabled(boolean enabled) {
            mDetailAdapter.setMobileDataEnabled(enabled);
        }
    }

    static Intent getCellularSettingIntent() {
        return new Intent(Settings.Panel.ACTION_MOBILE_DATA);
    }

    private final class CellularDetailAdapter implements DetailAdapter {

        @Override
        public CharSequence getTitle() {
            return mContext.getString(R.string.quick_settings_cellular_detail_title);
        }

        @Override
        public Boolean getToggleState() {
            return mDataController.isMobileDataSupported()
                    ? mDataController.isMobileDataEnabled()
                    : null;
        }

        @Override
        public Intent getSettingsIntent() {
            return getCellularSettingIntent();
        }

        @Override
        public void setToggleState(boolean state) {
            MetricsLogger.action(mContext, MetricsEvent.QS_CELLULAR_TOGGLE, state);
            mDataController.setMobileDataEnabled(state);
        }

        @Override
        public int getMetricsCategory() {
            return MetricsEvent.QS_DATAUSAGEDETAIL;
        }

        @Override
        public View createDetailView(Context context, View convertView, ViewGroup parent) {
            final DataUsageDetailView v = (DataUsageDetailView) (convertView != null
                    ? convertView
                    : LayoutInflater.from(mContext).inflate(R.layout.data_usage, parent, false));

            DataUsageController.DataUsageInfo info = null;
            int defaultSubId = SubscriptionManager.getDefaultDataSubscriptionId();
            if (defaultSubId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
                info = mDataController.getDataUsageInfo();
            } else {
                info = mDataController.getDataUsageInfo(
                        DataUsageUtils.getMobileTemplate(mContext, defaultSubId));
            }
            if (info == null) return v;
            v.bind(info);
            v.findViewById(R.id.roaming_text).setVisibility(mSignalCallback.mInfo.roaming
                    ? View.VISIBLE : View.INVISIBLE);
            return v;
        }

        public void setMobileDataEnabled(boolean enabled) {
            fireToggleStateChanged(enabled);
        }
    }

    private final class KeyguardCallback implements KeyguardMonitor.Callback {
        @Override
        public void onKeyguardShowingChanged() {
            refreshState();
        }
    };
}
