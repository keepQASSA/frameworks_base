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
 * limitations under the License
 */

package com.android.systemui.statusbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.Point;
import android.hardware.biometrics.BiometricSourceType;
import android.hardware.face.FaceManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.BatteryManager;
import android.os.BatteryStats;
import android.os.Handler;
import android.os.Message;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.Settings;
import android.text.TextUtils;
import android.text.format.Formatter;
import android.util.Log;
import android.view.Display;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;

import com.airbnb.lottie.LottieAnimationView;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.app.IBatteryStats;
import com.android.internal.logging.nano.MetricsProto;
import com.android.internal.util.custom.fod.FodUtils;
import com.android.internal.widget.LockPatternUtils;
import com.android.internal.widget.ViewClippingUtil;
import com.android.keyguard.KeyguardUpdateMonitor;
import com.android.keyguard.KeyguardUpdateMonitorCallback;
import com.android.settingslib.Utils;
import com.android.systemui.Dependency;
import com.android.systemui.Interpolators;
import com.android.systemui.R;
import com.android.systemui.dock.DockManager;
import com.android.systemui.plugins.statusbar.StatusBarStateController;
import com.android.systemui.plugins.statusbar.StatusBarStateController.StateListener;
import com.android.systemui.statusbar.phone.KeyguardIndicationTextView;
import com.android.systemui.statusbar.phone.LockIcon;
import com.android.systemui.statusbar.phone.LockscreenGestureLogger;
import com.android.systemui.statusbar.phone.ShadeController;
import com.android.systemui.statusbar.phone.StatusBarKeyguardViewManager;
import com.android.systemui.statusbar.phone.UnlockMethodCache;
import com.android.systemui.statusbar.policy.AccessibilityController;
import com.android.systemui.statusbar.policy.UserInfoController;
import com.android.systemui.tuner.TunerService;
import com.android.systemui.util.wakelock.SettableWakeLock;
import com.android.systemui.util.wakelock.WakeLock;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.text.NumberFormat;
import java.util.IllegalFormatConversionException;

import vendor.lineage.biometrics.fingerprint.inscreen.V1_0.IFingerprintInscreen;

/**
 * Controls the indications and error messages shown on the Keyguard
 */
public class KeyguardIndicationController implements StateListener,
        UnlockMethodCache.OnUnlockMethodChangedListener, TunerService.Tunable {

    private static final String TAG = "KeyguardIndication";
    private static final boolean DEBUG_CHARGING_SPEED = false;

    private static final int MSG_HIDE_TRANSIENT = 1;
    private static final int MSG_CLEAR_BIOMETRIC_MSG = 2;
    private static final int MSG_SWIPE_UP_TO_UNLOCK = 3;
    private static final long TRANSIENT_BIOMETRIC_ERROR_TIMEOUT = 1300;
    private static final float BOUNCE_ANIMATION_FINAL_Y = 0f;

    private static final String LOCKSCREEN_CHARGING_ANIMATION_STYLE =
            "system:" + Settings.System.LOCKSCREEN_CHARGING_ANIMATION_STYLE;
    private static final String LOCKSCREEN_BATTERY_INFO =
            "system:" + Settings.System.LOCKSCREEN_BATTERY_INFO;
    private final Context mContext;
    private final ShadeController mShadeController;
    private final AccessibilityController mAccessibilityController;
    private final UnlockMethodCache mUnlockMethodCache;
    private final StatusBarStateController mStatusBarStateController;
    private final KeyguardUpdateMonitor mKeyguardUpdateMonitor;
    private ViewGroup mIndicationArea;
    private KeyguardIndicationTextView mTextView;
    private KeyguardIndicationTextView mDisclosure;
    private LottieAnimationView mChargingIndicationView;
    private int mChargingIndication = 1;
    private int mFODPositionY = 0;
    private final UserManager mUserManager;
    private final IBatteryStats mBatteryInfo;
    private final SettableWakeLock mWakeLock;
    private final LockPatternUtils mLockPatternUtils;
    private final DockManager mDockManager;

    private final int mSlowThreshold;
    private final int mFastThreshold;
    private final LockIcon mLockIcon;
    private StatusBarKeyguardViewManager mStatusBarKeyguardViewManager;
    private LockscreenGestureLogger mLockscreenGestureLogger = new LockscreenGestureLogger();

    private String mRestingIndication;
    private String mAlignmentIndication = "";
    private CharSequence mTransientIndication;
    private ColorStateList mTransientTextColorState;
    private ColorStateList mInitialTextColorState;
    private boolean mVisible;
    private boolean mHideTransientMessageOnScreenOff;

    private boolean mPowerPluggedIn;
    private boolean mPowerPluggedInWired;
    private boolean mPowerCharged;
    private int mChargingSpeed;
    private double mChargingWattage;
    private int mBatteryLevel;
    private int mChargingCurrent;
    private double mChargingVoltage;
    private float mTemperature;
    private String mMessageToShowOnScreenOn;

    private boolean mShowBatteryInfo;

    private KeyguardUpdateMonitorCallback mUpdateMonitorCallback;

    private final DevicePolicyManager mDevicePolicyManager;
    private boolean mDozing;
    private final ViewClippingUtil.ClippingParameters mClippingParams =
            new ViewClippingUtil.ClippingParameters() {
                @Override
                public boolean shouldFinish(View view) {
                    return view == mIndicationArea;
                }
            };

    /**
     * Creates a new KeyguardIndicationController and registers callbacks.
     */
    public KeyguardIndicationController(Context context, ViewGroup indicationArea,
            LockIcon lockIcon) {
        this(context, indicationArea, lockIcon, new LockPatternUtils(context),
                WakeLock.createPartial(context, "Doze:KeyguardIndication"),
                Dependency.get(ShadeController.class),
                Dependency.get(AccessibilityController.class),
                UnlockMethodCache.getInstance(context),
                Dependency.get(StatusBarStateController.class),
                KeyguardUpdateMonitor.getInstance(context),
                Dependency.get(DockManager.class));
    }

    /**
     * Creates a new KeyguardIndicationController for testing.
     */
    @VisibleForTesting
    KeyguardIndicationController(Context context, ViewGroup indicationArea, LockIcon lockIcon,
            LockPatternUtils lockPatternUtils, WakeLock wakeLock, ShadeController shadeController,
            AccessibilityController accessibilityController, UnlockMethodCache unlockMethodCache,
            StatusBarStateController statusBarStateController,
            KeyguardUpdateMonitor keyguardUpdateMonitor,
            DockManager dockManager) {
        mContext = context;
        mLockIcon = lockIcon;
        mShadeController = shadeController;
        mAccessibilityController = accessibilityController;
        mUnlockMethodCache = unlockMethodCache;
        mStatusBarStateController = statusBarStateController;
        mKeyguardUpdateMonitor = keyguardUpdateMonitor;
        mDockManager = dockManager;
        mDockManager.addAlignmentStateListener(
                alignState -> mHandler.post(() -> handleAlignStateChanged(alignState)));
        // lock icon is not used on all form factors.
        if (mLockIcon != null) {
            mLockIcon.setOnLongClickListener(this::handleLockLongClick);
            mLockIcon.setOnClickListener(this::handleLockClick);
        }
        mWakeLock = new SettableWakeLock(wakeLock, TAG);
        mLockPatternUtils = lockPatternUtils;

        Resources res = context.getResources();
        mSlowThreshold = res.getInteger(R.integer.config_chargingSlowlyThreshold);
        mFastThreshold = res.getInteger(R.integer.config_chargingFastThreshold);

        mUserManager = context.getSystemService(UserManager.class);
        mBatteryInfo = IBatteryStats.Stub.asInterface(
                ServiceManager.getService(BatteryStats.SERVICE_NAME));

        mDevicePolicyManager = (DevicePolicyManager) context.getSystemService(
                Context.DEVICE_POLICY_SERVICE);
        setIndicationArea(indicationArea);
        updateDisclosure();

        mKeyguardUpdateMonitor.registerCallback(getKeyguardCallback());
        mKeyguardUpdateMonitor.registerCallback(mTickReceiver);
        mStatusBarStateController.addCallback(this);
        mUnlockMethodCache.addListener(this);

        final TunerService tunerService = Dependency.get(TunerService.class);
        tunerService.addTunable(this, LOCKSCREEN_CHARGING_ANIMATION_STYLE);
        tunerService.addTunable(this, LOCKSCREEN_BATTERY_INFO);
    }

    @Override
    public void onTuningChanged(String key, String newValue) {
        switch (key) {
            case LOCKSCREEN_CHARGING_ANIMATION_STYLE:
                mChargingIndication =
                        TunerService.parseInteger(newValue, 1);
                if (mChargingIndicationView != null) updateChargingIndicationStyle();
                break;
            case LOCKSCREEN_BATTERY_INFO:
                mShowBatteryInfo =
                        TunerService.parseIntegerSwitch(newValue, true);
                break;
            default:
                break;
        }
    }

    public void setIndicationArea(ViewGroup indicationArea) {
        mIndicationArea = indicationArea;
        mTextView = indicationArea.findViewById(R.id.keyguard_indication_text);
        mInitialTextColorState = mTextView != null ?
                mTextView.getTextColors() : ColorStateList.valueOf(Color.WHITE);
        mDisclosure = indicationArea.findViewById(R.id.keyguard_indication_enterprise_disclosure);
        mChargingIndicationView = (LottieAnimationView) indicationArea.findViewById(
                R.id.charging_indication);
        updateChargingIndicationStyle();
        if (hasActiveInDisplayFp()) {
            try {
                IFingerprintInscreen daemon = IFingerprintInscreen.getService();
                mFODPositionY = daemon.getPositionY();
            } catch (RemoteException e) {
                // do nothing
            }
            if (mFODPositionY <= 0) {
                mFODPositionY = 0;
            }
        }
        updateIndication(false /* animate */);
    }

    private boolean handleLockLongClick(View view) {
        mLockscreenGestureLogger.write(MetricsProto.MetricsEvent.ACTION_LS_LOCK,
                0 /* lengthDp - N/A */, 0 /* velocityDp - N/A */);
        showTransientIndication(R.string.keyguard_indication_trust_disabled);
        mKeyguardUpdateMonitor.onLockIconPressed();
        mLockPatternUtils.requireCredentialEntry(KeyguardUpdateMonitor.getCurrentUser());

        return true;
    }

    private void handleLockClick(View view) {
        if (!mAccessibilityController.isAccessibilityEnabled()) {
            return;
        }
        mShadeController.animateCollapsePanels(CommandQueue.FLAG_EXCLUDE_NONE, true /* force */);
    }

    private void handleAlignStateChanged(int alignState) {
        String alignmentIndication = "";
        if (alignState == DockManager.ALIGN_STATE_POOR) {
            alignmentIndication =
                    mContext.getResources().getString(R.string.dock_alignment_slow_charging);
        } else if (alignState == DockManager.ALIGN_STATE_TERRIBLE) {
            alignmentIndication =
                    mContext.getResources().getString(R.string.dock_alignment_not_charging);
        }
        if (!alignmentIndication.equals(mAlignmentIndication)) {
            mAlignmentIndication = alignmentIndication;
            updateIndication(false);
        }
    }

    /**
     * Gets the {@link KeyguardUpdateMonitorCallback} instance associated with this
     * {@link KeyguardIndicationController}.
     *
     * <p>Subclasses may override this method to extend or change the callback behavior by extending
     * the {@link BaseKeyguardCallback}.
     *
     * @return A KeyguardUpdateMonitorCallback. Multiple calls to this method <b>must</b> return the
     * same instance.
     */
    protected KeyguardUpdateMonitorCallback getKeyguardCallback() {
        if (mUpdateMonitorCallback == null) {
            mUpdateMonitorCallback = new BaseKeyguardCallback();
        }
        return mUpdateMonitorCallback;
    }

    private void updateDisclosure() {
        if (mDevicePolicyManager == null) {
            return;
        }

        if (!mDozing && mDevicePolicyManager.isDeviceManaged()) {
            final CharSequence organizationName =
                    mDevicePolicyManager.getDeviceOwnerOrganizationName();
            if (organizationName != null) {
                mDisclosure.switchIndication(mContext.getResources().getString(
                        R.string.do_disclosure_with_name, organizationName));
            } else {
                mDisclosure.switchIndication(R.string.do_disclosure_generic);
            }
            mDisclosure.setVisibility(View.VISIBLE);
        } else {
            mDisclosure.setVisibility(View.GONE);
        }
    }

    public void setVisible(boolean visible) {
        mVisible = visible;
        mIndicationArea.setVisibility(visible ? View.VISIBLE : View.GONE);
        if (visible) {
            // If this is called after an error message was already shown, we should not clear it.
            // Otherwise the error message won't be shown
            if (!mHandler.hasMessages(MSG_HIDE_TRANSIENT)) {
                hideTransientIndication();
            }
            updateIndication(false);
        } else if (!visible) {
            // If we unlock and return to keyguard quickly, previous error should not be shown
            hideTransientIndication();
        }
    }

    /**
     * Sets the indication that is shown if nothing else is showing.
     */
    public void setRestingIndication(String restingIndication) {
        mRestingIndication = restingIndication;
        updateIndication(false);
    }

    /**
     * Sets the active controller managing changes and callbacks to user information.
     */
    public void setUserInfoController(UserInfoController userInfoController) {
    }

    /**
     * Returns the indication text indicating that trust has been granted.
     *
     * @return {@code null} or an empty string if a trust indication text should not be shown.
     */
    @VisibleForTesting
    String getTrustGrantedIndication() {
        return mContext.getString(R.string.keyguard_indication_trust_unlocked);
    }

    /**
     * Sets if the device is plugged in
     */
    @VisibleForTesting
    void setPowerPluggedIn(boolean plugged) {
        mPowerPluggedIn = plugged;
    }

    /**
     * Returns the indication text indicating that trust is currently being managed.
     *
     * @return {@code null} or an empty string if a trust managed text should not be shown.
     */
    private String getTrustManagedIndication() {
        return null;
    }

    /**
     * Hides transient indication in {@param delayMs}.
     */
    public void hideTransientIndicationDelayed(long delayMs) {
        mHandler.sendMessageDelayed(
                mHandler.obtainMessage(MSG_HIDE_TRANSIENT), delayMs);
    }

    /**
     * Shows {@param transientIndication} until it is hidden by {@link #hideTransientIndication}.
     */
    public void showTransientIndication(int transientIndication) {
        showTransientIndication(mContext.getResources().getString(transientIndication));
    }

    /**
     * Shows {@param transientIndication} until it is hidden by {@link #hideTransientIndication}.
     */
    public void showTransientIndication(CharSequence transientIndication) {
        showTransientIndication(transientIndication, mInitialTextColorState,
                false /* hideOnScreenOff */);
    }

    /**
     * Shows {@param transientIndication} until it is hidden by {@link #hideTransientIndication}.
     */
    private void showTransientIndication(CharSequence transientIndication,
            ColorStateList textColorState, boolean hideOnScreenOff) {
        mTransientIndication = transientIndication;
        mHideTransientMessageOnScreenOff = hideOnScreenOff && transientIndication != null;
        mTransientTextColorState = textColorState;
        mHandler.removeMessages(MSG_HIDE_TRANSIENT);
        mHandler.removeMessages(MSG_SWIPE_UP_TO_UNLOCK);
        if (mDozing && !TextUtils.isEmpty(mTransientIndication)) {
            // Make sure this doesn't get stuck and burns in. Acquire wakelock until its cleared.
            mWakeLock.setAcquired(true);
            hideTransientIndicationDelayed(BaseKeyguardCallback.HIDE_DELAY_MS);
        }

        updateIndication(false);
    }

    /**
     * Hides transient indication.
     */
    public void hideTransientIndication() {
        if (mTransientIndication != null) {
            mTransientIndication = null;
            mHideTransientMessageOnScreenOff = false;
            mHandler.removeMessages(MSG_HIDE_TRANSIENT);
            updateIndication(false);
        }
    }

    protected final void updateIndication(boolean animate) {
        if (TextUtils.isEmpty(mTransientIndication)) {
            mWakeLock.setAcquired(false);
        }

        if (mVisible) {
            // Walk down a precedence-ordered list of what indication
            // should be shown based on user or device state
            if (mDozing) {
                // When dozing we ignore any text color and use white instead, because
                // colors can be hard to read in low brightness.
                mTextView.setTextColor(Color.WHITE);
                if (!TextUtils.isEmpty(mTransientIndication)) {
                    mTextView.switchIndication(mTransientIndication);
                } else if (!TextUtils.isEmpty(mAlignmentIndication)) {
                    mTextView.switchIndication(mAlignmentIndication);
                    mTextView.setTextColor(Utils.getColorError(mContext));
                } else if (mPowerPluggedIn) {
                    String indication = computePowerIndication();
                    if (animate) {
                        animateText(mTextView, indication);
                    } else {
                        mTextView.switchIndication(indication);
                    }
                } else {
                    // Use the high voltage symbol ⚡ (u26A1 unicode) but prevent the system
                    // to load its emoji colored variant with the uFE0E flag
                    boolean showAmbientBattery = Settings.System.getIntForUser(mContext.getContentResolver(),
                        Settings.System.AMBIENT_BATTERY_PERCENT, 0, UserHandle.USER_CURRENT) != 0;
                    if (showAmbientBattery) {
                        String bolt = "\u26A1\uFE0E";
                        CharSequence chargeIndicator = (mPowerPluggedIn ? (bolt + " ") : "") +
                                NumberFormat.getPercentInstance().format(mBatteryLevel / 100f);
                        mTextView.switchIndication(chargeIndicator);
                    } else {
                        mTextView.switchIndication(null);
                    }
                }
                updateChargingIndication();
                return;
            }

            int userId = KeyguardUpdateMonitor.getCurrentUser();
            String trustGrantedIndication = getTrustGrantedIndication();
            String trustManagedIndication = getTrustManagedIndication();

            String powerIndication = null;
            if (mPowerPluggedIn) {
                powerIndication = computePowerIndication();
            }

            if (!mUserManager.isUserUnlocked(userId)) {
                mTextView.switchIndication(com.android.internal.R.string.lockscreen_storage_locked);
                mTextView.setTextColor(mInitialTextColorState);
            } else if (!TextUtils.isEmpty(mTransientIndication)) {
                mTextView.switchIndication(mTransientIndication);
                mTextView.setTextColor(mTransientTextColorState);
            } else if (!TextUtils.isEmpty(trustGrantedIndication)
                    && mKeyguardUpdateMonitor.getUserHasTrust(userId)) {
                if (powerIndication != null) {
                    String indication = mContext.getResources().getString(
                            R.string.keyguard_indication_trust_unlocked_plugged_in,
                            trustGrantedIndication, powerIndication);
                    mTextView.switchIndication(indication);
                } else {
                    mTextView.switchIndication(trustGrantedIndication);
                }
                mTextView.setTextColor(mInitialTextColorState);
            } else if (!TextUtils.isEmpty(mAlignmentIndication)) {
                mTextView.switchIndication(mAlignmentIndication);
                mTextView.setTextColor(Utils.getColorError(mContext));
            } else if (mPowerPluggedIn) {
                if (DEBUG_CHARGING_SPEED) {
                    powerIndication += ",  " + (mChargingWattage / 1000) + " mW";
                }
                mTextView.setTextColor(mInitialTextColorState);
                if (animate) {
                    animateText(mTextView, powerIndication);
                } else {
                    mTextView.switchIndication(powerIndication);
                }
            } else if (!TextUtils.isEmpty(trustManagedIndication)
                    && mKeyguardUpdateMonitor.getUserTrustIsManaged(userId)
                    && !mKeyguardUpdateMonitor.getUserHasTrust(userId)) {
                mTextView.switchIndication(trustManagedIndication);
                mTextView.setTextColor(mInitialTextColorState);
            } else {
                mTextView.switchIndication(mRestingIndication);
                mTextView.setTextColor(mInitialTextColorState);
            }
            updateChargingIndication();
        }
    }

    public void updateChargingIndicationStyle() {
        switch (mChargingIndication) {
            default:
            case 1: // Flash
                mChargingIndicationView.setFileName("keyguard_charging_indication.json");
                mChargingIndicationView.getLayoutParams().height = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_height);
                mChargingIndicationView.getLayoutParams().width = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_width);
                break;
            case 2: // Battery
                mChargingIndicationView.setFileName("keyguard_charge_battery.json");
                mChargingIndicationView.getLayoutParams().height = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_width);
                mChargingIndicationView.getLayoutParams().width = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_height);
                break;
            case 3: // Drop
                mChargingIndicationView.setFileName("keyguard_charge_drop.json");
                mChargingIndicationView.getLayoutParams().height = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_height);
                mChargingIndicationView.getLayoutParams().width = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_height);
                break;
            case 4: // Explosion
                mChargingIndicationView.setFileName("keyguard_charge_explosion.json");
                mChargingIndicationView.getLayoutParams().height = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_height);
                mChargingIndicationView.getLayoutParams().width = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_height);
                break;
            case 5: // Water
                mChargingIndicationView.setFileName("keyguard_charge_water.json");
                mChargingIndicationView.getLayoutParams().height = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_height);
                mChargingIndicationView.getLayoutParams().width = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_charging_indication_height);
                break;
        }
    }

    private void updateChargingIndication() {
        if (mChargingIndication > 0 && !mDozing && mPowerPluggedIn) {
            if (hasActiveInDisplayFp()) {
                if (mFODPositionY != 0) {
                    // Get screen height
                    WindowManager windowManager = mContext.getSystemService(WindowManager.class);
                    Display defaultDisplay = windowManager.getDefaultDisplay();
                    Point size = new Point();
                    defaultDisplay.getRealSize(size);
                    int screenHeight = size.y;
                    // Correct FOD position if cutout is hidden
                    int statusbarHeight = mContext.getResources().getDimensionPixelSize(
                            com.android.internal.R.dimen.status_bar_height_portrait);
                    boolean cutoutMasked = mContext.getResources().getBoolean(
                            com.android.internal.R.bool.config_maskMainBuiltInDisplayCutout);
                    int fodPositionY = mFODPositionY;
                    if (cutoutMasked) {
                        fodPositionY = mFODPositionY - statusbarHeight;
                    }
                    // Get indication text height
                    int textViewHeight = mTextView.getMeasuredHeight();
                    // Get bottom margin height
                    int marginBottom = mContext.getResources().getDimensionPixelSize(
                            R.dimen.keyguard_indication_margin_bottom_fingerprint_in_display);
                    // Calculate charging indication margin
                    int animationMargin = (screenHeight - fodPositionY) - (textViewHeight + marginBottom) + 10;
                    // Set position of charging indication
                    ViewGroup.MarginLayoutParams params =
                            (ViewGroup.MarginLayoutParams) mChargingIndicationView.getLayoutParams();
                    params.setMargins(0, 0, 0, animationMargin);
                    mChargingIndicationView.setLayoutParams(params);
                }
            }
            mChargingIndicationView.setVisibility(View.VISIBLE);
            mChargingIndicationView.playAnimation();
        } else {
            mChargingIndicationView.setVisibility(View.GONE);
        }
    }

    private boolean hasActiveInDisplayFp() {
        PackageManager packageManager = mContext.getPackageManager();
        boolean hasInDisplayFingerprint = FodUtils.hasFodSupport(mContext);
        int userId = KeyguardUpdateMonitor.getCurrentUser();
        FingerprintManager fpm = (FingerprintManager) mContext.getSystemService(Context.FINGERPRINT_SERVICE);
        return hasInDisplayFingerprint && fpm.getEnrolledFingerprints(userId).size() > 0;
    }

    // animates textView - textView moves up and bounces down
    private void animateText(KeyguardIndicationTextView textView, String indication) {
        int yTranslation = mContext.getResources().getInteger(
                R.integer.wired_charging_keyguard_text_animation_distance);
        int animateUpDuration = mContext.getResources().getInteger(
                R.integer.wired_charging_keyguard_text_animation_duration_up);
        int animateDownDuration = mContext.getResources().getInteger(
                R.integer.wired_charging_keyguard_text_animation_duration_down);
        textView.animate().cancel();
        ViewClippingUtil.setClippingDeactivated(textView, true, mClippingParams);
        textView.animate()
                .translationYBy(yTranslation)
                .setInterpolator(Interpolators.LINEAR)
                .setDuration(animateUpDuration)
                .setListener(new AnimatorListenerAdapter() {
                    private boolean mCancelled;

                    @Override
                    public void onAnimationStart(Animator animation) {
                        textView.switchIndication(indication);
                    }

                    @Override
                    public void onAnimationCancel(Animator animation) {
                        textView.setTranslationY(BOUNCE_ANIMATION_FINAL_Y);
                        mCancelled = true;
                    }

                    @Override
                    public void onAnimationEnd(Animator animation) {
                        if (mCancelled) {
                            ViewClippingUtil.setClippingDeactivated(textView, false,
                                    mClippingParams);
                            return;
                        }
                        textView.animate()
                                .setDuration(animateDownDuration)
                                .setInterpolator(Interpolators.BOUNCE)
                                .translationY(BOUNCE_ANIMATION_FINAL_Y)
                                .setListener(new AnimatorListenerAdapter() {
                                    @Override
                                    public void onAnimationEnd(Animator animation) {
                                        textView.setTranslationY(BOUNCE_ANIMATION_FINAL_Y);
                                        ViewClippingUtil.setClippingDeactivated(textView, false,
                                                mClippingParams);
                                    }
                                });
                    }
                });
    }

    @VisibleForTesting
    String computePowerIndication() {
        if (mPowerCharged) {
            return mContext.getResources().getString(R.string.keyguard_charged);
        }

        // Try fetching charging time from battery stats.
        long chargingTimeRemaining = 0;
        try {
            chargingTimeRemaining = mBatteryInfo.computeChargeTimeRemaining();

        } catch (RemoteException e) {
            Log.e(TAG, "Error calling IBatteryStats: ", e);
        }
        final boolean hasChargingTime = chargingTimeRemaining > 0;

        int chargingId;
        if (mPowerPluggedInWired) {
            switch (mChargingSpeed) {
                case KeyguardUpdateMonitor.BatteryStatus.CHARGING_FAST:
                    chargingId = hasChargingTime
                            ? R.string.keyguard_indication_charging_time_fast
                            : R.string.keyguard_plugged_in_charging_fast;
                    break;
                case KeyguardUpdateMonitor.BatteryStatus.CHARGING_DASH:
                    chargingId = hasChargingTime
                            ? R.string.keyguard_indication_dash_charging_time
                            : R.string.keyguard_plugged_in_dash_charging;
                    break;
                case KeyguardUpdateMonitor.BatteryStatus.CHARGING_WARP:
                    chargingId = hasChargingTime
                            ? R.string.keyguard_indication_warp_charging_time
                            : R.string.keyguard_plugged_in_warp_charging;
                    break;
                case KeyguardUpdateMonitor.BatteryStatus.CHARGING_SLOWLY:
                    chargingId = hasChargingTime
                            ? R.string.keyguard_indication_charging_time_slowly
                            : R.string.keyguard_plugged_in_charging_slowly;
                    break;
                default:
                    chargingId = hasChargingTime
                            ? R.string.keyguard_indication_charging_time
                            : R.string.keyguard_plugged_in;
                    break;
            }
        } else {
            chargingId = hasChargingTime
                    ? R.string.keyguard_indication_charging_time_wireless
                    : R.string.keyguard_plugged_in_wireless;
        }

        String batteryInfo = "";
         if (mShowBatteryInfo) {
            if (mChargingCurrent > 0) {
                batteryInfo = batteryInfo + (mChargingCurrent / 1000) + "mA";
            }
            if (mChargingWattage > 0) {
                batteryInfo = (batteryInfo == "" ? "" : batteryInfo + " · ") +
                        String.format("%.1f" , (mChargingWattage / 1000 / 1000)) + "W";
            }
            if (mChargingVoltage > 0) {
                batteryInfo = (batteryInfo == "" ? "" : batteryInfo + " · ") +
                        String.format("%.1f", (mChargingVoltage / 1000 / 1000)) + "V";
            }
            if (mTemperature > 0) {
                batteryInfo = (batteryInfo == "" ? "" : batteryInfo + " · ") +
                        mTemperature / 10 + "°C";
            }
            if (batteryInfo != "") {
                batteryInfo = "\n" + batteryInfo;
            }
        }

        String percentage = NumberFormat.getPercentInstance()
                .format(mBatteryLevel / 100f);
        if (hasChargingTime) {
            // We now have battery percentage in these strings and it's expected that all
            // locales will also have it in the future. For now, we still have to support the old
            // format until all languages get the new translations.
            String chargingTimeFormatted = Formatter.formatShortElapsedTimeRoundingUpToMinutes(
                    mContext, chargingTimeRemaining);

            try {
                String chargingText = mContext.getResources().getString(chargingId, chargingTimeFormatted,
                        percentage);
                return chargingText + batteryInfo;
            } catch (IllegalFormatConversionException e) {
                String chargingText =  mContext.getResources().getString(chargingId, chargingTimeFormatted);
                return chargingText + batteryInfo;
            }
        } else {
            // Same as above
            try {
                String chargingText =  mContext.getResources().getString(chargingId, percentage);
                return chargingText + batteryInfo;
            } catch (IllegalFormatConversionException e) {
                String chargingText =  mContext.getResources().getString(chargingId);
                return chargingText + batteryInfo;
            }
        }
    }

    public void setStatusBarKeyguardViewManager(
            StatusBarKeyguardViewManager statusBarKeyguardViewManager) {
        mStatusBarKeyguardViewManager = statusBarKeyguardViewManager;
    }

    private final KeyguardUpdateMonitorCallback mTickReceiver =
            new KeyguardUpdateMonitorCallback() {
                @Override
                public void onTimeChanged() {
                    if (mVisible) {
                        updateIndication(false /* animate */);
                    }
                }
            };

    private final Handler mHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            if (msg.what == MSG_HIDE_TRANSIENT) {
                hideTransientIndication();
            } else if (msg.what == MSG_CLEAR_BIOMETRIC_MSG) {
                mLockIcon.setTransientBiometricsError(false);
            } else if (msg.what == MSG_SWIPE_UP_TO_UNLOCK) {
                showSwipeUpToUnlock();
            }
        }
    };

    private void showSwipeUpToUnlock() {
        if (mDozing) {
            return;
        }

        if (mStatusBarKeyguardViewManager.isBouncerShowing()) {
            String message = mContext.getString(R.string.keyguard_retry);
            mStatusBarKeyguardViewManager.showBouncerMessage(message, mInitialTextColorState);
        } else if (mKeyguardUpdateMonitor.isScreenOn()) {
            showTransientIndication(mContext.getString(R.string.keyguard_unlock),
                    mInitialTextColorState, true /* hideOnScreenOff */);
            hideTransientIndicationDelayed(BaseKeyguardCallback.HIDE_DELAY_MS);
        }
    }

    public void setDozing(boolean dozing) {
        if (mDozing == dozing) {
            return;
        }
        mDozing = dozing;
        if (mHideTransientMessageOnScreenOff && mDozing) {
            hideTransientIndication();
        } else {
            updateIndication(false);
        }
        updateDisclosure();
    }

    public void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
        pw.println("KeyguardIndicationController:");
        pw.println("  mTransientTextColorState: " + mTransientTextColorState);
        pw.println("  mInitialTextColorState: " + mInitialTextColorState);
        pw.println("  mPowerPluggedInWired: " + mPowerPluggedInWired);
        pw.println("  mPowerPluggedIn: " + mPowerPluggedIn);
        pw.println("  mPowerCharged: " + mPowerCharged);
        pw.println("  mChargingSpeed: " + mChargingSpeed);
        pw.println("  mChargingWattage: " + mChargingWattage);
        pw.println("  mMessageToShowOnScreenOn: " + mMessageToShowOnScreenOn);
        pw.println("  mDozing: " + mDozing);
        pw.println("  mBatteryLevel: " + mBatteryLevel);
        pw.println("  mTextView.getText(): " + (mTextView == null ? null : mTextView.getText()));
        pw.println("  computePowerIndication(): " + computePowerIndication());
    }

    @Override
    public void onStateChanged(int newState) {
        // don't care
    }

    @Override
    public void onDozingChanged(boolean isDozing) {
        setDozing(isDozing);
    }

    @Override
    public void onUnlockMethodStateChanged() {
        updateIndication(!mDozing);
    }

    protected class BaseKeyguardCallback extends KeyguardUpdateMonitorCallback {
        public static final int HIDE_DELAY_MS = 5000;

        @Override
        public void onRefreshBatteryInfo(KeyguardUpdateMonitor.BatteryStatus status) {
            boolean isChargingOrFull = status.status == BatteryManager.BATTERY_STATUS_CHARGING
                    || status.status == BatteryManager.BATTERY_STATUS_FULL;
            boolean wasPluggedIn = mPowerPluggedIn;
            mPowerPluggedInWired = status.isPluggedInWired() && isChargingOrFull;
            mPowerPluggedIn = status.isPluggedIn() && isChargingOrFull;
            mPowerCharged = status.isCharged();
            mChargingCurrent = status.maxChargingCurrent;
            mChargingVoltage = status.maxChargingVoltage;
            mChargingWattage = status.maxChargingWattage;
            mTemperature = status.temperature;
            mChargingSpeed = status.getChargingSpeed(mSlowThreshold, mFastThreshold);
            mBatteryLevel = status.level;
            updateIndication(!wasPluggedIn && mPowerPluggedInWired);
            if (mDozing) {
                if (!wasPluggedIn && mPowerPluggedIn) {
                    showTransientIndication(computePowerIndication());
                    hideTransientIndicationDelayed(HIDE_DELAY_MS);
                } else if (wasPluggedIn && !mPowerPluggedIn) {
                    hideTransientIndication();
                }
            }
        }

        @Override
        public void onKeyguardVisibilityChanged(boolean showing) {
            if (showing) {
                updateDisclosure();
            }
        }

        @Override
        public void onBiometricHelp(int msgId, String helpString,
                BiometricSourceType biometricSourceType) {
            if (!mKeyguardUpdateMonitor.isUnlockingWithBiometricAllowed()) {
                return;
            }
            boolean showSwipeToUnlock =
                    msgId == KeyguardUpdateMonitor.BIOMETRIC_HELP_FACE_NOT_RECOGNIZED;
            if (mStatusBarKeyguardViewManager.isBouncerShowing()) {
                mStatusBarKeyguardViewManager.showBouncerMessage(helpString,
                        mInitialTextColorState);
            } else if (mKeyguardUpdateMonitor.isScreenOn()) {
                showTransientIndication(helpString, mInitialTextColorState, showSwipeToUnlock);
                if (!showSwipeToUnlock) {
                    hideTransientIndicationDelayed(TRANSIENT_BIOMETRIC_ERROR_TIMEOUT);
                }
            }
            if (showSwipeToUnlock) {
                mHandler.sendMessageDelayed(mHandler.obtainMessage(MSG_SWIPE_UP_TO_UNLOCK),
                        TRANSIENT_BIOMETRIC_ERROR_TIMEOUT);
            }
        }

        @Override
        public void onBiometricError(int msgId, String errString,
                BiometricSourceType biometricSourceType) {
            if (shouldSuppressBiometricError(msgId, biometricSourceType, mKeyguardUpdateMonitor)) {
                return;
            }
            animatePadlockError();
            if (msgId == FaceManager.FACE_ERROR_TIMEOUT) {
                // The face timeout message is not very actionable, let's ask the user to
                // manually retry.
                showSwipeUpToUnlock();
            } else if (mStatusBarKeyguardViewManager.isBouncerShowing()) {
                mStatusBarKeyguardViewManager.showBouncerMessage(errString, mInitialTextColorState);
            } else if (mKeyguardUpdateMonitor.isScreenOn()) {
                showTransientIndication(errString);
                // We want to keep this message around in case the screen was off
                hideTransientIndicationDelayed(HIDE_DELAY_MS);
            } else {
                mMessageToShowOnScreenOn = errString;
            }
        }

        private void animatePadlockError() {
            mLockIcon.setTransientBiometricsError(true);
            mHandler.removeMessages(MSG_CLEAR_BIOMETRIC_MSG);
            mHandler.sendMessageDelayed(mHandler.obtainMessage(MSG_CLEAR_BIOMETRIC_MSG),
                    TRANSIENT_BIOMETRIC_ERROR_TIMEOUT);
        }

        private boolean shouldSuppressBiometricError(int msgId,
                BiometricSourceType biometricSourceType, KeyguardUpdateMonitor updateMonitor) {
            if (biometricSourceType == BiometricSourceType.FINGERPRINT)
                return shouldSuppressFingerprintError(msgId, updateMonitor);
            if (biometricSourceType == BiometricSourceType.FACE)
                return shouldSuppressFaceError(msgId, updateMonitor);
            return false;
        }

        private boolean shouldSuppressFingerprintError(int msgId,
                KeyguardUpdateMonitor updateMonitor) {
            return ((!updateMonitor.isUnlockingWithBiometricAllowed()
                    && msgId != FingerprintManager.FINGERPRINT_ERROR_LOCKOUT_PERMANENT)
                    || msgId == FingerprintManager.FINGERPRINT_ERROR_CANCELED);
        }

        private boolean shouldSuppressFaceError(int msgId, KeyguardUpdateMonitor updateMonitor) {
            return ((!updateMonitor.isUnlockingWithBiometricAllowed()
                    && msgId != FaceManager.FACE_ERROR_LOCKOUT_PERMANENT)
                    || msgId == FaceManager.FACE_ERROR_CANCELED);
        }

        @Override
        public void onTrustAgentErrorMessage(CharSequence message) {
            showTransientIndication(message, Utils.getColorError(mContext),
                    false /* hideOnScreenOff */);
        }

        @Override
        public void onScreenTurnedOn() {
            if (mMessageToShowOnScreenOn != null) {
                showTransientIndication(mMessageToShowOnScreenOn, Utils.getColorError(mContext),
                        false /* hideOnScreenOff */);
                // We want to keep this message around in case the screen was off
                hideTransientIndicationDelayed(HIDE_DELAY_MS);
                mMessageToShowOnScreenOn = null;
            }
        }

        @Override
        public void onBiometricRunningStateChanged(boolean running,
                BiometricSourceType biometricSourceType) {
            if (running) {
                // Let's hide any previous messages when authentication starts, otherwise
                // multiple auth attempts would overlap.
                hideTransientIndication();
                mMessageToShowOnScreenOn = null;
            }
        }

        @Override
        public void onBiometricAuthenticated(int userId, BiometricSourceType biometricSourceType) {
            super.onBiometricAuthenticated(userId, biometricSourceType);
            mHandler.sendEmptyMessage(MSG_HIDE_TRANSIENT);
        }

        @Override
        public void onUserUnlocked() {
            if (mVisible) {
                updateIndication(false);
            }
        }
    }
}
