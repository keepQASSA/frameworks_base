/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.android.systemui.statusbar.phone;

import static android.app.StatusBarManager.DISABLE_CLOCK;
import static android.app.StatusBarManager.DISABLE_NOTIFICATION_ICONS;
import static android.app.StatusBarManager.DISABLE_SYSTEM_INFO;

import android.annotation.Nullable;
import android.app.Fragment;
import android.os.Bundle;
import android.os.Parcelable;
import android.provider.Settings;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.widget.ImageSwitcher;
import android.widget.LinearLayout;

import com.android.systemui.Dependency;
import com.android.systemui.Interpolators;
import com.android.systemui.R;
import com.android.systemui.SysUiServiceProvider;
import com.android.systemui.plugins.statusbar.StatusBarStateController;
import com.android.systemui.statusbar.CommandQueue;
import com.android.systemui.statusbar.StatusBarState;
import com.android.systemui.statusbar.phone.StatusBarIconController.DarkIconManager;
import com.android.systemui.statusbar.phone.TickerView;
import com.android.systemui.statusbar.policy.EncryptionHelper;
import com.android.systemui.statusbar.policy.KeyguardMonitor;
import com.android.systemui.statusbar.policy.NetworkController;
import com.android.systemui.statusbar.policy.NetworkController.SignalCallback;
import com.android.systemui.tuner.TunerService;

/**
 * Contains the collapsed status bar and handles hiding/showing based on disable flags
 * and keyguard state. Also manages lifecycle to make sure the views it contains are being
 * updated by the StatusBarIconController and DarkIconManager while it is attached.
 */
public class CollapsedStatusBarFragment extends Fragment implements CommandQueue.Callbacks,
        StatusBarStateController.StateListener, TunerService.Tunable {

    public static final String TAG = "CollapsedStatusBarFragment";
    private static final String EXTRA_PANEL_STATE = "panel_state";
    public static final String STATUS_BAR_ICON_MANAGER_TAG = "status_bar_icon_manager";
    public static final int FADE_IN_DURATION = 320;
    public static final int FADE_IN_DELAY = 50;
    private PhoneStatusBarView mStatusBar;
    private StatusBarStateController mStatusBarStateController;
    private KeyguardMonitor mKeyguardMonitor;
    private NetworkController mNetworkController;
    private LinearLayout mSystemIconArea;
    private LinearLayout mCustomIconArea;
    private LinearLayout mCenterClockLayout;
    private View mNotificationIconAreaInner;
    private View mCenteredIconArea;
    private View mClockView;
    private View mCenterClockView;
    private View mRightClockView;
    private int mDisabled1;
    private StatusBar mStatusBarComponent;
    private DarkIconManager mDarkIconManager;
    private View mOperatorNameFrame;
    private CommandQueue mCommandQueue;
    private ClockController mClockController;

    private boolean mShowSBClockBg;

    private int mTickerEnabled;
    private View mTickerViewFromStub;
    private View mTickerViewContainer;
    private boolean mLyricEnabled;
    private View mLyricViewFromStub;
    private View mLyricViewContainer;

    private static final String STATUS_BAR_SHOW_TICKER =
            "system:" + Settings.System.STATUS_BAR_SHOW_TICKER;

    private static final String STATUS_BAR_SHOW_LYRIC =
            "system:" + Settings.System.STATUS_BAR_SHOW_LYRIC;

    private View mBatteryBar;

    private static final String STATUSBAR_CLOCK_CHIP =
            "system:" + Settings.System.STATUSBAR_CLOCK_CHIP;

    private SignalCallback mSignalCallback = new SignalCallback() {
        @Override
        public void setIsAirplaneMode(NetworkController.IconState icon) {
            mCommandQueue.recomputeDisableFlags(getContext().getDisplayId(), true /* animate */);
        }
    };

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mKeyguardMonitor = Dependency.get(KeyguardMonitor.class);
        mNetworkController = Dependency.get(NetworkController.class);
        mStatusBarStateController = Dependency.get(StatusBarStateController.class);
        mStatusBarComponent = SysUiServiceProvider.getComponent(getContext(), StatusBar.class);
        mCommandQueue = SysUiServiceProvider.getComponent(getContext(), CommandQueue.class);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container,
            Bundle savedInstanceState) {

         if(isDualStatusbarEnabled()) {
            return inflater.inflate(R.layout.status_bar_dual, container, false);
         } else {
             return inflater.inflate(R.layout.status_bar, container, false);
         }
    }

    private boolean isDualStatusbarEnabled() {
        return Settings.System.getInt(getContext().getContentResolver(),
            Settings.System.STATUSBAR_DUAL_ROW, 0) == 1;
    }

    @Override
    public void onViewCreated(View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        mStatusBar = (PhoneStatusBarView) view;
        if (savedInstanceState != null && savedInstanceState.containsKey(EXTRA_PANEL_STATE)) {
            mStatusBar.restoreHierarchyState(
                    savedInstanceState.getSparseParcelableArray(EXTRA_PANEL_STATE));
        }
        mDarkIconManager = new DarkIconManager(view.findViewById(R.id.statusIcons));
        mDarkIconManager.setShouldLog(true);
        Dependency.get(StatusBarIconController.class).addIconGroup(mDarkIconManager);
        mSystemIconArea = mStatusBar.findViewById(R.id.system_icon_area);
        mCustomIconArea = mStatusBar.findViewById(R.id.left_icon_area);
        mCenterClockLayout = (LinearLayout) mStatusBar.findViewById(R.id.center_clock_layout);
        mBatteryBar = mStatusBar.findViewById(R.id.battery_bar);
        mClockController = new ClockController(mStatusBar);
        mClockView = mStatusBar.findViewById(R.id.clock);
        mCenterClockView = mStatusBar.findViewById(R.id.clock_center);
        mRightClockView = mStatusBar.findViewById(R.id.clock_right);
        showSystemIconArea(false);
        initEmergencyCryptkeeperText();
        initOperatorName();
        Dependency.get(TunerService.class).addTunable(this,
                STATUS_BAR_SHOW_TICKER);
        Dependency.get(TunerService.class).addTunable(this,
                STATUS_BAR_SHOW_LYRIC);
    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        SparseArray<Parcelable> states = new SparseArray<>();
        mStatusBar.saveHierarchyState(states);
        outState.putSparseParcelableArray(EXTRA_PANEL_STATE, states);
    }

    @Override
    public void onResume() {
        super.onResume();
        mCommandQueue.addCallback(this);
        mStatusBarStateController.addCallback(this);
        Dependency.get(TunerService.class).addTunable(this, STATUSBAR_CLOCK_CHIP);
    }

    @Override
    public void onPause() {
        super.onPause();
        mCommandQueue.removeCallback(this);
        mStatusBarStateController.removeCallback(this);
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        Dependency.get(TunerService.class).removeTunable(this);
        Dependency.get(StatusBarIconController.class).removeIconGroup(mDarkIconManager);
        if (mNetworkController.hasEmergencyCryptKeeperText()) {
            mNetworkController.removeCallback(mSignalCallback);
        }
    }

    @Override
    public void onTuningChanged(String key, String newValue) {
        switch (key) {
            case STATUS_BAR_SHOW_TICKER:
                mTickerEnabled =
                        TunerService.parseInteger(newValue, 0);
                initTickerView();
                break;
            case STATUS_BAR_SHOW_LYRIC:
                mLyricEnabled = TunerService.parseIntegerSwitch(newValue, false);
                initLyricView();
                break;
            case STATUSBAR_CLOCK_CHIP:
                mShowSBClockBg =
                        TunerService.parseIntegerSwitch(newValue, false);
                updateStatusBarClock();
                break;
            default:
                break;
        }
    }

    private void updateStatusBarClock() {
        if (mShowSBClockBg) {
            mClockView.setBackgroundResource(R.drawable.sb_date_bg);
            mClockView.setPadding(10,2,10,2);
            mCenterClockView.setBackgroundResource(R.drawable.sb_date_bg);
            mCenterClockView.setPadding(10,2,10,2);
            mRightClockView.setBackgroundResource(R.drawable.sb_date_bg);
            mRightClockView.setPadding(10,2,10,2);
        } else {
            int clockPaddingStart = getResources().getDimensionPixelSize(
                    R.dimen.status_bar_clock_starting_padding);
            int clockPaddingEnd = getResources().getDimensionPixelSize(
                    R.dimen.status_bar_clock_end_padding);
            int leftClockPaddingStart = getResources().getDimensionPixelSize(
                    R.dimen.status_bar_left_clock_starting_padding);
            int leftClockPaddingEnd = getResources().getDimensionPixelSize(
                    R.dimen.status_bar_left_clock_end_padding);
            mClockView.setBackgroundResource(0);
            mClockView.setPaddingRelative(leftClockPaddingStart, 0, leftClockPaddingEnd, 0);
            mCenterClockView.setBackgroundResource(0);
            mCenterClockView.setPaddingRelative(0,0,0,0);
            mRightClockView.setBackgroundResource(0);
            mRightClockView.setPaddingRelative(clockPaddingStart, 0, clockPaddingEnd, 0);
        }
    }

    public void initNotificationIconArea(NotificationIconAreaController
            notificationIconAreaController) {
        ViewGroup notificationIconArea = mStatusBar.findViewById(R.id.notification_icon_area);
        mNotificationIconAreaInner =
                notificationIconAreaController.getNotificationInnerAreaView();
        if (mNotificationIconAreaInner.getParent() != null) {
            ((ViewGroup) mNotificationIconAreaInner.getParent())
                    .removeView(mNotificationIconAreaInner);
        }
        notificationIconArea.addView(mNotificationIconAreaInner);

        ViewGroup statusBarCenteredIconArea = mStatusBar.findViewById(R.id.centered_icon_area);
        mCenteredIconArea = notificationIconAreaController.getCenteredNotificationAreaView();
        if (mCenteredIconArea.getParent() != null) {
            ((ViewGroup) mCenteredIconArea.getParent())
                    .removeView(mCenteredIconArea);
        }
        statusBarCenteredIconArea.addView(mCenteredIconArea);

        // Default to showing until we know otherwise.
        showNotificationIconArea(false);
    }

    @Override
    public void disable(int displayId, int state1, int state2, boolean animate) {
        if (displayId != getContext().getDisplayId()) {
            return;
        }
        state1 = adjustDisableFlags(state1);
        final int old1 = mDisabled1;
        final int diff1 = state1 ^ old1;
        mDisabled1 = state1;
        if ((diff1 & DISABLE_SYSTEM_INFO) != 0) {
            if ((state1 & DISABLE_SYSTEM_INFO) != 0) {
                hideSystemIconArea(animate);
                hideOperatorName(animate);
                hideTicker(animate);
                hideLyric(animate);
            } else {
                showSystemIconArea(animate);
                showOperatorName(animate);
                showTicker(animate);
                showLyric(animate);
            }
        }
        if ((diff1 & DISABLE_NOTIFICATION_ICONS) != 0) {
            if ((state1 & DISABLE_NOTIFICATION_ICONS) != 0) {
                hideNotificationIconArea(animate);
            } else {
                showNotificationIconArea(animate);
            }
        }
    }

    protected int adjustDisableFlags(int state) {
        boolean headsUpVisible = mStatusBarComponent.headsUpShouldBeVisible();
        if (headsUpVisible) {
            View clockView = mClockController.getClock();
            if (clockView == null) {
                state |= DISABLE_CLOCK;
            } else {
                boolean isRightClock = clockView.getId() == R.id.clock_right;
                if (!isRightClock) {
                    state |= DISABLE_CLOCK;
                }
            }
        }

        if (!mKeyguardMonitor.isLaunchTransitionFadingAway()
                && !mKeyguardMonitor.isKeyguardFadingAway()
                && shouldHideNotificationIcons()
                && !(mStatusBarStateController.getState() == StatusBarState.KEYGUARD
                        && headsUpVisible)) {
            state |= DISABLE_NOTIFICATION_ICONS;
            state |= DISABLE_SYSTEM_INFO;
            state |= DISABLE_CLOCK;
        }

        if (mNetworkController != null && EncryptionHelper.IS_DATA_ENCRYPTED) {
            if (mNetworkController.hasEmergencyCryptKeeperText()) {
                state |= DISABLE_NOTIFICATION_ICONS;
            }
            if (!mNetworkController.isRadioOn()) {
                state |= DISABLE_SYSTEM_INFO;
            }
        }

        // The shelf will be hidden when dozing with a custom clock, we must show notification
        // icons in this occasion.
        if (mStatusBarStateController.isDozing()
                && mStatusBarComponent.getPanel().hasCustomClock()) {
            state |= DISABLE_CLOCK | DISABLE_SYSTEM_INFO;
        }

        return state;
    }

    private boolean shouldHideNotificationIcons() {
        if (!mStatusBar.isClosed() && mStatusBarComponent.hideStatusBarIconsWhenExpanded()) {
            return true;
        }
        if (mStatusBarComponent.hideStatusBarIconsForBouncer()) {
            return true;
        }
        return false;
    }

    public void hideSystemIconArea(boolean animate) {
        animateHide(mBatteryBar, animate);
        animateHide(mSystemIconArea, animate);
    }

    public void showSystemIconArea(boolean animate) {
        animateShow(mBatteryBar, animate);
        animateShow(mSystemIconArea, animate);
    }

    public void showLyric(boolean animate) {
        if (mLyricViewContainer != null) {
            animateShow(mLyricViewContainer, animate);
        }
    }

    public void hideLyric(boolean animate) {
        if (mLyricViewContainer != null) {
            animateHide(mLyricViewContainer, animate);
        }
    }

    public void showTicker(boolean animate) {
        if (mTickerViewContainer != null) {
            animateShow(mTickerViewContainer, animate);
        }
    }

    public void hideTicker(boolean animate) {
        if (mTickerViewContainer != null) {
            animateHide(mTickerViewContainer, animate);
        }
    }

    /**
     * If panel is expanded/expanding it usually means QS shade is opening, so
     * don't set the clock GONE otherwise it'll mess up the animation.
     */
    private int clockHiddenMode() {
        if (!mStatusBar.isClosed() && !mKeyguardMonitor.isShowing()
                && !mStatusBarStateController.isDozing()
                && mClockController.getClock().shouldBeVisible()) {
            return View.INVISIBLE;
        }
        return View.GONE;
    }

    public void hideNotificationIconArea(boolean animate) {
        animateHide(mNotificationIconAreaInner, animate);
        animateHide(mCenteredIconArea, animate);
        animateHide(mCustomIconArea, animate);
        animateHide(mCenterClockLayout, animate);
    }

    public void showNotificationIconArea(boolean animate) {
        animateShow(mNotificationIconAreaInner, animate);
        animateShow(mCenteredIconArea, animate);
        animateShow(mCustomIconArea, animate);
        animateShow(mCenterClockLayout, animate);
    }

    public void hideOperatorName(boolean animate) {
        if (mOperatorNameFrame != null) {
            animateHide(mOperatorNameFrame, animate);
        }
    }

    public void showOperatorName(boolean animate) {
        if (mOperatorNameFrame != null) {
            animateShow(mOperatorNameFrame, animate);
        }
    }

    /**
     * Animate a view to INVISIBLE or GONE
     */
    private void animateHiddenState(final View v, int state, boolean animate) {
        v.animate().cancel();
        if (!animate) {
            v.setAlpha(0f);
            v.setVisibility(state);
            return;
        }

        v.animate()
                .alpha(0f)
                .setDuration(160)
                .setStartDelay(0)
                .setInterpolator(Interpolators.ALPHA_OUT)
                .withEndAction(() -> v.setVisibility(state));
    }

    /**
     * Hides a view.
     */
    private void animateHide(final View v, boolean animate) {
        animateHiddenState(v, View.INVISIBLE, animate);
    }

    /**
     * Shows a view, and synchronizes the animation with Keyguard exit animations, if applicable.
     */
    private void animateShow(View v, boolean animate) {
        v.animate().cancel();
        v.setVisibility(View.VISIBLE);
        if (!animate) {
            v.setAlpha(1f);
            return;
        }
        v.animate()
                .alpha(1f)
                .setDuration(FADE_IN_DURATION)
                .setInterpolator(Interpolators.ALPHA_IN)
                .setStartDelay(FADE_IN_DELAY)

                // We need to clean up any pending end action from animateHide if we call
                // both hide and show in the same frame before the animation actually gets started.
                // cancel() doesn't really remove the end action.
                .withEndAction(null);

        // Synchronize the motion with the Keyguard fading if necessary.
        if (mKeyguardMonitor.isKeyguardFadingAway()) {
            v.animate()
                    .setDuration(mKeyguardMonitor.getKeyguardFadingAwayDuration())
                    .setInterpolator(Interpolators.LINEAR_OUT_SLOW_IN)
                    .setStartDelay(mKeyguardMonitor.getKeyguardFadingAwayDelay())
                    .start();
        }
    }

    private void initEmergencyCryptkeeperText() {
        View emergencyViewStub = mStatusBar.findViewById(R.id.emergency_cryptkeeper_text);
        if (mNetworkController.hasEmergencyCryptKeeperText()) {
            if (emergencyViewStub != null) {
                ((ViewStub) emergencyViewStub).inflate();
            }
            mNetworkController.addCallback(mSignalCallback);
        } else if (emergencyViewStub != null) {
            ViewGroup parent = (ViewGroup) emergencyViewStub.getParent();
            parent.removeView(emergencyViewStub);
        }
    }

    private void initOperatorName() {
        if (getResources().getBoolean(R.bool.config_showOperatorNameInStatusBar)) {
            ViewStub stub = mStatusBar.findViewById(R.id.operator_name);
            mOperatorNameFrame = stub.inflate();
        }
    }

    @Override
    public void onStateChanged(int newState) {

    }

    @Override
    public void onDozingChanged(boolean isDozing) {
        disable(getContext().getDisplayId(), mDisabled1, mDisabled1, false /* animate */);
    }

    private void initTickerView() {
        if (mTickerEnabled != 0) {
            mTickerViewContainer = mStatusBar.findViewById(R.id.ticker_container);
            View tickerStub = mStatusBar.findViewById(R.id.ticker_stub);
            if (mTickerViewFromStub == null && tickerStub != null) {
                mTickerViewFromStub = ((ViewStub) tickerStub).inflate();
            }
            TickerView tickerView = (TickerView) mStatusBar.findViewById(R.id.tickerText);
            ImageSwitcher tickerIcon = (ImageSwitcher) mStatusBar.findViewById(R.id.tickerIcon);
            mStatusBarComponent.createTicker(
                    mTickerEnabled, getContext(), mStatusBar, tickerView, tickerIcon, mTickerViewFromStub);
        } else {
            mStatusBarComponent.disableTicker();
        }
    }

    private void initLyricView() {
        if (mLyricEnabled) {
            mLyricViewContainer = mStatusBar.findViewById(R.id.lyric_container);
            View lyricStub = mStatusBar.findViewById(R.id.lyric_stub);
            if (mLyricViewFromStub == null && lyricStub != null) {
                mLyricViewFromStub = ((ViewStub) lyricStub).inflate();
            }
            TickerView tickerView = (TickerView) mStatusBar.findViewById(R.id.lyricText);
            ImageSwitcher tickerIcon = (ImageSwitcher) mStatusBar.findViewById(R.id.lyricIcon);
            mStatusBarComponent.createLyricTicker(getContext(), mStatusBar, tickerView, tickerIcon, mLyricViewFromStub);
        } else {
            mStatusBarComponent.disableLyricTicker();
        }
    }
}
