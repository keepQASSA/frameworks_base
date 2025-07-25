/*
 * Copyright (C) 2013 The Android Open Source Project
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
package com.android.systemui;

import static android.app.StatusBarManager.DISABLE2_SYSTEM_ICONS;
import static android.app.StatusBarManager.DISABLE_NONE;

import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_PORTRAIT;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_IOS;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_MX;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_RLANDSCAPE;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_RLANDSCAPE_A;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_RLANDSCAPE_B;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_A;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_B;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_CAPSULE;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEA;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEB;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEC;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPED;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEE;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEF;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEG;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEH;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEI;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEJ;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEK;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEL;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEM;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEN;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEO;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_IOS15;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_ONEUI7;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_AIROO;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_CIRCLE;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_BIG_CIRCLE;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_DOTTED_CIRCLE;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_BIG_DOTTED_CIRCLE;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_SOLID;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_BIG_SOLID;
import static com.android.settingslib.graph.BatteryMeterDrawableBase.BATTERY_STYLE_HIDDEN;

import static com.android.systemui.util.SysuiLifecycle.viewAttachLifecycle;

import static java.lang.annotation.RetentionPolicy.SOURCE;

import android.animation.LayoutTransition;
import android.animation.ObjectAnimator;
import android.annotation.IntDef;
import android.app.ActivityManager;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.database.ContentObserver;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Handler;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.ArraySet;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.StyleRes;

import com.android.settingslib.Utils;
import com.android.settingslib.graph.BatteryMeterDrawableBase;
import com.android.settingslib.graph.ThemedBatteryDrawable;
import com.android.settingslib.graph.IosBatteryDrawable;
import com.android.settingslib.graph.MxBatteryDrawable;
import com.android.settingslib.graph.RLandscapeBatteryDrawable;
import com.android.settingslib.graph.RLandscapeABatteryDrawable;
import com.android.settingslib.graph.RLandscapeBBatteryDrawable;
import com.android.settingslib.graph.LandscapeBatteryDrawable;
import com.android.settingslib.graph.LandscapeABatteryDrawable;
import com.android.settingslib.graph.LandscapeBBatteryDrawable;
import com.android.settingslib.graph.LandscapeCapsuleBatteryDrawable;
import com.android.settingslib.graph.LandscapeBatteryA;
import com.android.settingslib.graph.LandscapeBatteryB;
import com.android.settingslib.graph.LandscapeBatteryC;
import com.android.settingslib.graph.LandscapeBatteryD;
import com.android.settingslib.graph.LandscapeBatteryE;
import com.android.settingslib.graph.LandscapeBatteryF;
import com.android.settingslib.graph.LandscapeBatteryG;
import com.android.settingslib.graph.LandscapeBatteryH;
import com.android.settingslib.graph.LandscapeBatteryI;
import com.android.settingslib.graph.LandscapeBatteryJ;
import com.android.settingslib.graph.LandscapeBatteryK;
import com.android.settingslib.graph.LandscapeBatteryL;
import com.android.settingslib.graph.LandscapeBatteryM;
import com.android.settingslib.graph.LandscapeBatteryN;
import com.android.settingslib.graph.LandscapeBatteryO;
import com.android.settingslib.graph.LandscapeBatteryDrawableiOS15;
import com.android.settingslib.graph.LandscapeBatteryDrawableOneUI7;
import com.android.settingslib.graph.AirooBatteryDrawable;
import com.android.systemui.plugins.DarkIconDispatcher;
import com.android.systemui.plugins.DarkIconDispatcher.DarkReceiver;
import com.android.systemui.settings.CurrentUserTracker;
import com.android.systemui.statusbar.phone.StatusBarIconController;
import com.android.systemui.statusbar.policy.BatteryController;
import com.android.systemui.statusbar.policy.BatteryController.BatteryStateChangeCallback;
import com.android.systemui.statusbar.policy.ConfigurationController;
import com.android.systemui.statusbar.policy.ConfigurationController.ConfigurationListener;
import com.android.systemui.tuner.TunerService;
import com.android.systemui.tuner.TunerService.Tunable;
import com.android.systemui.util.Utils.DisableStateTracker;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.annotation.Retention;
import java.text.NumberFormat;

public class BatteryMeterView extends LinearLayout implements
        BatteryStateChangeCallback, Tunable, DarkReceiver, ConfigurationListener {

    public static final String STATUS_BAR_BATTERY_STYLE =
            "system:" + Settings.System.STATUS_BAR_BATTERY_STYLE;
    public static final String STATUS_BAR_SHOW_BATTERY_PERCENT =
            "system:" + Settings.System.STATUS_BAR_SHOW_BATTERY_PERCENT;
    public static final String STATUS_BAR_BATTERY_TEXT_CHARGING =
            "system:" + Settings.System.STATUS_BAR_BATTERY_TEXT_CHARGING;
    public static final String SHOW_BATTERY_SYMBOL =
            "system:" + Settings.System.SHOW_BATTERY_SYMBOL;

    @Retention(SOURCE)
    @IntDef({MODE_DEFAULT, MODE_ON, MODE_OFF, MODE_ESTIMATE})
    public @interface BatteryPercentMode {}
    public static final int MODE_DEFAULT = 0;
    public static final int MODE_ON = 1;
    public static final int MODE_OFF = 2;
    public static final int MODE_ESTIMATE = 3; // Not to be used

    private final BatteryMeterDrawableBase mXDrawable;
    private final ThemedBatteryDrawable mDrawable;
    private final String mSlotBattery;
    private final IosBatteryDrawable mIosDrawable;
    private final MxBatteryDrawable mMxDrawable;
    private final RLandscapeBatteryDrawable mRLandscapeDrawable;
    private final RLandscapeABatteryDrawable mRLandscapeADrawable;
    private final RLandscapeBBatteryDrawable mRLandscapeBDrawable;
    private final LandscapeBatteryDrawable mLandscapeDrawable;
    private final LandscapeABatteryDrawable mLandscapeADrawable;
    private final LandscapeBBatteryDrawable mLandscapeBDrawable;
    private final LandscapeCapsuleBatteryDrawable mLandscapeCapsuleDrawable;
    private final LandscapeBatteryA mLandscapeBatteryA;
    private final LandscapeBatteryB mLandscapeBatteryB;
    private final LandscapeBatteryC mLandscapeBatteryC;
    private final LandscapeBatteryD mLandscapeBatteryD;
    private final LandscapeBatteryE mLandscapeBatteryE;
    private final LandscapeBatteryF mLandscapeBatteryF;
    private final LandscapeBatteryG mLandscapeBatteryG;
    private final LandscapeBatteryH mLandscapeBatteryH;
    private final LandscapeBatteryI mLandscapeBatteryI;
    private final LandscapeBatteryJ mLandscapeBatteryJ;
    private final LandscapeBatteryK mLandscapeBatteryK;
    private final LandscapeBatteryL mLandscapeBatteryL;
    private final LandscapeBatteryM mLandscapeBatteryM;
    private final LandscapeBatteryN mLandscapeBatteryN;
    private final LandscapeBatteryO mLandscapeBatteryO;
    private final LandscapeBatteryDrawableiOS15 mLandscapeDrawableiOS15;
    private final LandscapeBatteryDrawableOneUI7 mLandscapeDrawableOneUI7;
    private final AirooBatteryDrawable mAirooDrawable;
    private final ImageView mBatteryIconView;
    private final CurrentUserTracker mUserTracker;
    private TextView mBatteryPercentView;

    private BatteryController mBatteryController;
    private SettingObserver mSettingObserver;
    private final @StyleRes int mPercentageStyleId;
    private int mTextColor;
    private int mLevel;
    private int mShowPercentMode = MODE_DEFAULT;
    // Some places may need to show the battery conditionally, and not obey the tuner
    private boolean mIgnoreTunerUpdates;
    private boolean mIsSubscribedForTunerUpdates;

    private boolean mCharging;
    public int mBatteryStyle = BATTERY_STYLE_PORTRAIT;
    public int mShowBatteryPercent;
    public int mShowBatteryEstimate = 0;
    private boolean mBatteryPercentCharging;

    private DualToneHandler mDualToneHandler;
    private int mUser;
    private boolean mShowSymbol;

    /**
     * Whether we should use colors that adapt based on wallpaper/the scrim behind quick settings.
     */
    private boolean mUseWallpaperTextColors;

    private int mNonAdaptedSingleToneColor;
    private int mNonAdaptedForegroundColor;
    private int mNonAdaptedBackgroundColor;

    public BatteryMeterView(Context context) {
        this(context, null, 0);
    }

    public BatteryMeterView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public BatteryMeterView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);

        setOrientation(LinearLayout.HORIZONTAL);
        setGravity(Gravity.CENTER_VERTICAL | Gravity.START);

        TypedArray atts = context.obtainStyledAttributes(attrs, R.styleable.BatteryMeterView,
                defStyle, 0);
        final int frameColor = atts.getColor(R.styleable.BatteryMeterView_frameColor,
                context.getColor(R.color.meter_background_color));
        mPercentageStyleId = atts.getResourceId(R.styleable.BatteryMeterView_textAppearance, 0);
        mDrawable = new ThemedBatteryDrawable(context, frameColor);
        mXDrawable = new BatteryMeterDrawableBase(context, frameColor);
        mIosDrawable = new IosBatteryDrawable(context, frameColor);
        mMxDrawable = new MxBatteryDrawable(context, frameColor);
        mRLandscapeDrawable = new RLandscapeBatteryDrawable(context, frameColor);
        mRLandscapeADrawable = new RLandscapeABatteryDrawable(context, frameColor);
        mRLandscapeBDrawable = new RLandscapeBBatteryDrawable(context, frameColor);
        mLandscapeDrawable = new LandscapeBatteryDrawable(context, frameColor);
        mLandscapeADrawable = new LandscapeABatteryDrawable(context, frameColor);
        mLandscapeBDrawable = new LandscapeBBatteryDrawable(context, frameColor);
        mLandscapeCapsuleDrawable = new LandscapeCapsuleBatteryDrawable(context, frameColor);
        mLandscapeBatteryA = new LandscapeBatteryA(context, frameColor);
        mLandscapeBatteryB = new LandscapeBatteryB(context, frameColor);
        mLandscapeBatteryC = new LandscapeBatteryC(context, frameColor);
        mLandscapeBatteryD = new LandscapeBatteryD(context, frameColor);
        mLandscapeBatteryE = new LandscapeBatteryE(context, frameColor);
        mLandscapeBatteryF = new LandscapeBatteryF(context, frameColor);
        mLandscapeBatteryG = new LandscapeBatteryG(context, frameColor);
        mLandscapeBatteryH = new LandscapeBatteryH(context, frameColor);
        mLandscapeBatteryI = new LandscapeBatteryI(context, frameColor);
        mLandscapeBatteryJ = new LandscapeBatteryJ(context, frameColor);
        mLandscapeBatteryK = new LandscapeBatteryK(context, frameColor);
        mLandscapeBatteryL = new LandscapeBatteryL(context, frameColor);
        mLandscapeBatteryM = new LandscapeBatteryM(context, frameColor);
        mLandscapeBatteryN = new LandscapeBatteryN(context, frameColor);
        mLandscapeBatteryO = new LandscapeBatteryO(context, frameColor);
        mLandscapeDrawableiOS15 = new LandscapeBatteryDrawableiOS15(context, frameColor);
        mLandscapeDrawableOneUI7 = new LandscapeBatteryDrawableOneUI7(context, frameColor);
        mAirooDrawable = new AirooBatteryDrawable(context, frameColor);
        atts.recycle();

        mSettingObserver = new SettingObserver(new Handler(context.getMainLooper()));

        addOnAttachStateChangeListener(
                new DisableStateTracker(DISABLE_NONE, DISABLE2_SYSTEM_ICONS));

        setupLayoutTransition();

        mSlotBattery = context.getString(
                com.android.internal.R.string.status_bar_battery);
        mBatteryIconView = new ImageView(context);
        mBatteryIconView.setImageDrawable(mDrawable);
        final MarginLayoutParams mlp = new MarginLayoutParams(
                getResources().getDimensionPixelSize(R.dimen.status_bar_battery_icon_width),
                getResources().getDimensionPixelSize(R.dimen.status_bar_battery_icon_height));
        mlp.setMargins(0, 0, 0,
                getResources().getDimensionPixelOffset(R.dimen.battery_margin_bottom));
        addView(mBatteryIconView, mlp);

        updateShowPercent();
        mDualToneHandler = new DualToneHandler(context);
        // Init to not dark at all.
        onDarkChanged(new Rect(), 0, DarkIconDispatcher.DEFAULT_ICON_TINT);

        mUserTracker = new CurrentUserTracker(mContext) {
            @Override
            public void onUserSwitched(int newUserId) {
                mUser = newUserId;
                getContext().getContentResolver().unregisterContentObserver(mSettingObserver);
                updateShowPercent();
            }
        };

        setClipChildren(false);
        setClipToPadding(false);
        Dependency.get(ConfigurationController.class).observe(viewAttachLifecycle(this), this);
    }

    private void setupLayoutTransition() {
        LayoutTransition transition = new LayoutTransition();
        transition.setDuration(200);

        ObjectAnimator appearAnimator = ObjectAnimator.ofFloat(null, "alpha", 0f, 1f);
        transition.setAnimator(LayoutTransition.APPEARING, appearAnimator);
        transition.setInterpolator(LayoutTransition.APPEARING, Interpolators.ALPHA_IN);

        ObjectAnimator disappearAnimator = ObjectAnimator.ofFloat(null, "alpha", 1f, 0f);
        transition.setInterpolator(LayoutTransition.DISAPPEARING, Interpolators.ALPHA_OUT);
        transition.setAnimator(LayoutTransition.DISAPPEARING, disappearAnimator);

        setLayoutTransition(transition);
    }

    public void setForceShowPercent(boolean show) {
        setPercentShowMode(show ? MODE_ON : MODE_DEFAULT);
    }

    /**
     * Force a particular mode of showing percent
     *
     * 0 - No preference
     * 1 - Force on
     * 2 - Force off
     * @param mode desired mode (none, on, off)
     */
    public void setPercentShowMode(@BatteryPercentMode int mode) {
        mShowPercentMode = mode;
        updateShowPercent();
    }

    /**
     * Set {@code true} to turn off BatteryMeterView's subscribing to the tuner for updates, and
     * thus avoid it controlling its own visibility
     *
     * @param ignore whether to ignore the tuner or not
     */
    public void setIgnoreTunerUpdates(boolean ignore) {
        mIgnoreTunerUpdates = ignore;
        updateTunerSubscription();
    }

    private void updateTunerSubscription() {
        if (mIgnoreTunerUpdates) {
            unsubscribeFromTunerUpdates();
        } else {
            subscribeForTunerUpdates();
        }
    }

    private void subscribeForTunerUpdates() {
        if (mIsSubscribedForTunerUpdates || mIgnoreTunerUpdates) {
            return;
        }

        Dependency.get(TunerService.class)
                .addTunable(this, STATUS_BAR_BATTERY_STYLE,
                                  STATUS_BAR_SHOW_BATTERY_PERCENT,
                                  SHOW_BATTERY_SYMBOL,
                                  STATUS_BAR_BATTERY_TEXT_CHARGING);
        mIsSubscribedForTunerUpdates = true;
    }

    private void unsubscribeFromTunerUpdates() {
        if (!mIsSubscribedForTunerUpdates) {
            return;
        }

        Dependency.get(TunerService.class).removeTunable(this);
        mIsSubscribedForTunerUpdates = false;
    }

    /**
     * Sets whether the battery meter view uses the wallpaperTextColor. If we're not using it, we'll
     * revert back to dark-mode-based/tinted colors.
     *
     * @param shouldUseWallpaperTextColor whether we should use wallpaperTextColor for all
     *                                    components
     */
    public void useWallpaperTextColor(boolean shouldUseWallpaperTextColor) {
        if (shouldUseWallpaperTextColor == mUseWallpaperTextColors) {
            return;
        }

        mUseWallpaperTextColors = shouldUseWallpaperTextColor;

        if (mUseWallpaperTextColors) {
            updateColors(
                    Utils.getColorAttrDefaultColor(mContext, R.attr.wallpaperTextColor),
                    Utils.getColorAttrDefaultColor(mContext, R.attr.wallpaperTextColorSecondary),
                    Utils.getColorAttrDefaultColor(mContext, R.attr.wallpaperTextColor));
        } else {
            updateColors(mNonAdaptedForegroundColor, mNonAdaptedBackgroundColor,
                    mNonAdaptedSingleToneColor);
        }
    }

    public void setColorsFromContext(Context context) {
        if (context == null) {
            return;
        }

        mDualToneHandler.setColorsFromContext(context);
    }

    @Override
    public boolean hasOverlappingRendering() {
        return false;
    }

    @Override
    public void onTuningChanged(String key, String newValue) {
        switch (key) {
            case STATUS_BAR_BATTERY_STYLE:
                mBatteryStyle =
                        TunerService.parseInteger(newValue, BATTERY_STYLE_BIG_CIRCLE);
                updateBatteryStyle();
                updatePercentView();
                updateVisibility();
                break;
            case STATUS_BAR_SHOW_BATTERY_PERCENT:
                mShowBatteryPercent =
                        TunerService.parseInteger(newValue, 0);
                updatePercentView();
                break;
            case STATUS_BAR_BATTERY_TEXT_CHARGING:
                mBatteryPercentCharging =
                        TunerService.parseIntegerSwitch(newValue, true);
                updatePercentView();
                break;
            case SHOW_BATTERY_SYMBOL:
                mShowSymbol =
                        TunerService.parseIntegerSwitch(newValue, false);
                updatePercentView();
                break;
            default:
                break;
        }
    }

    @Override
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        mBatteryController = Dependency.get(BatteryController.class);
        mBatteryController.addCallback(this);
        mUser = ActivityManager.getCurrentUser();
        getContext().getContentResolver().registerContentObserver(
                Settings.Global.getUriFor(Settings.Global.BATTERY_ESTIMATES_LAST_UPDATE_TIME),
                false, mSettingObserver);
        updateShowPercent();
        subscribeForTunerUpdates();
        mUserTracker.startTracking();
    }

    @Override
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        mUserTracker.stopTracking();
        mBatteryController.removeCallback(this);
        getContext().getContentResolver().unregisterContentObserver(mSettingObserver);
        unsubscribeFromTunerUpdates();
    }

    @Override
    public void onBatteryLevelChanged(int level, boolean pluggedIn, boolean charging) {
        if (mLevel != level) {
            mLevel = level;
            mDrawable.setBatteryLevel(mLevel);
            mXDrawable.setBatteryLevel(level);
            mIosDrawable.setBatteryLevel(mLevel);
            mMxDrawable.setBatteryLevel(mLevel);
            mRLandscapeDrawable.setBatteryLevel(mLevel);
            mRLandscapeADrawable.setBatteryLevel(mLevel);
            mRLandscapeBDrawable.setBatteryLevel(mLevel);
            mLandscapeDrawable.setBatteryLevel(mLevel);
            mLandscapeADrawable.setBatteryLevel(mLevel);
            mLandscapeBDrawable.setBatteryLevel(mLevel);
            mLandscapeCapsuleDrawable.setBatteryLevel(mLevel);
            mLandscapeBatteryA.setBatteryLevel(level);
            mLandscapeBatteryB.setBatteryLevel(level);
            mLandscapeBatteryC.setBatteryLevel(level);
            mLandscapeBatteryD.setBatteryLevel(level);
            mLandscapeBatteryE.setBatteryLevel(level);
            mLandscapeBatteryF.setBatteryLevel(level);
            mLandscapeBatteryG.setBatteryLevel(level);
            mLandscapeBatteryH.setBatteryLevel(level);
            mLandscapeBatteryI.setBatteryLevel(level);
            mLandscapeBatteryJ.setBatteryLevel(level);
            mLandscapeBatteryK.setBatteryLevel(level);
            mLandscapeBatteryL.setBatteryLevel(level);
            mLandscapeBatteryM.setBatteryLevel(level);
            mLandscapeBatteryN.setBatteryLevel(level);
            mLandscapeBatteryO.setBatteryLevel(level);
            mLandscapeDrawableiOS15.setBatteryLevel(mLevel);
            mLandscapeDrawableOneUI7.setBatteryLevel(mLevel);
            mAirooDrawable.setBatteryLevel(mLevel);
        }
        if (mCharging != pluggedIn) {
            mCharging = pluggedIn;
            mDrawable.setCharging(mCharging);
            mXDrawable.setCharging(mCharging);
            mIosDrawable.setCharging(mCharging);
            mMxDrawable.setCharging(mCharging);
            mRLandscapeDrawable.setCharging(mCharging);
            mRLandscapeADrawable.setCharging(mCharging);
            mRLandscapeBDrawable.setCharging(mCharging);
            mLandscapeDrawable.setCharging(mCharging);
            mLandscapeADrawable.setCharging(mCharging);
            mLandscapeBDrawable.setCharging(mCharging);
            mLandscapeCapsuleDrawable.setCharging(mCharging);
            mLandscapeBatteryA.setCharging(mCharging);
            mLandscapeBatteryB.setCharging(mCharging);
            mLandscapeBatteryC.setCharging(mCharging);
            mLandscapeBatteryD.setCharging(mCharging);
            mLandscapeBatteryE.setCharging(mCharging);
            mLandscapeBatteryF.setCharging(mCharging);
            mLandscapeBatteryG.setCharging(mCharging);
            mLandscapeBatteryH.setCharging(mCharging);
            mLandscapeBatteryI.setCharging(mCharging);
            mLandscapeBatteryJ.setCharging(mCharging);
            mLandscapeBatteryK.setCharging(mCharging);
            mLandscapeBatteryL.setCharging(mCharging);
            mLandscapeBatteryM.setCharging(mCharging);
            mLandscapeBatteryN.setCharging(mCharging);
            mLandscapeBatteryO.setCharging(mCharging);
            mLandscapeDrawableiOS15.setCharging(mCharging);
            mLandscapeDrawableOneUI7.setCharging(mCharging);
            mAirooDrawable.setCharging(mCharging);
            updateShowPercent();
        } else {
            updatePercentText();
        }
    }

    @Override
    public void onPowerSaveChanged(boolean isPowerSave) {
        mDrawable.setPowerSaveEnabled(isPowerSave);
        mXDrawable.setPowerSave(isPowerSave);
        mIosDrawable.setPowerSaveEnabled(isPowerSave);
        mMxDrawable.setPowerSaveEnabled(isPowerSave);
        mRLandscapeDrawable.setPowerSaveEnabled(isPowerSave);
        mRLandscapeADrawable.setPowerSaveEnabled(isPowerSave);
        mRLandscapeBDrawable.setPowerSaveEnabled(isPowerSave);
        mLandscapeDrawable.setPowerSaveEnabled(isPowerSave);
        mLandscapeADrawable.setPowerSaveEnabled(isPowerSave);
        mLandscapeBDrawable.setPowerSaveEnabled(isPowerSave);
        mLandscapeCapsuleDrawable.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryA.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryB.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryC.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryD.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryE.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryF.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryG.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryH.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryI.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryJ.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryK.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryL.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryM.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryN.setPowerSaveEnabled(isPowerSave);
        mLandscapeBatteryO.setPowerSaveEnabled(isPowerSave);
        mLandscapeDrawableiOS15.setPowerSaveEnabled(isPowerSave);
        mLandscapeDrawableOneUI7.setPowerSaveEnabled(isPowerSave);
        mAirooDrawable.setPowerSaveEnabled(isPowerSave);
        updateShowPercent();
    }

    private TextView loadPercentView() {
        return (TextView) LayoutInflater.from(getContext())
                .inflate(R.layout.battery_percentage_view, null);
    }

    /**
     * Updates percent view by removing old one and reinflating if necessary
     */
    public void updatePercentView() {
        removeBatteryPercentView();
        updateShowPercent();
    }

    private void updatePercentText() {
        if (mBatteryController == null) {
            return;
        }

        if (mBatteryPercentView != null) {
            setPercentTextAtCurrentLevel();
        } else {
            setContentDescription(
                    getContext().getString(mCharging ? R.string.accessibility_battery_level_charging
                            : R.string.accessibility_battery_level, mLevel));
        }
    }

    private void setPercentTextAtCurrentLevel() {
        String text = NumberFormat.getPercentInstance().format(mLevel / 100f);

        if (mShowBatteryEstimate != 0 && !mCharging) {
            mBatteryController.getEstimatedTimeRemainingString((String estimate) -> {
                if (estimate != null) {
                    if (mShowPercentMode == MODE_ON || mShowBatteryPercent >= 2) {
                        mBatteryPercentView.setText(text + " · " + estimate);
                    } else {
                        mBatteryPercentView.setText(estimate);
                    }
                } else if (mShowPercentMode == MODE_ON || mShowBatteryPercent >= 2) {
                    mBatteryPercentView.setText(text);
                } else {
                    mBatteryPercentView.setText("");
                }
                setContentDescription(getContext().getString(
                        R.string.accessibility_battery_level_with_estimate,
                        mLevel, estimate));
            });
        } else {
            // Use the high voltage symbol ⚡ (u26A1 unicode) but prevent the system
            // to load its emoji colored variant with the uFE0E flag
            String bolt = "\u26A1";
            CharSequence mChargeIndicator = mCharging && (mBatteryStyle == BATTERY_STYLE_HIDDEN ||
                mBatteryStyle == BATTERY_STYLE_LANDSCAPE_CAPSULE)
                    ? (bolt + " ") : "";
            if (mShowSymbol) {
                mBatteryPercentView.setText(mChargeIndicator + NumberFormat.getPercentInstance().format(mLevel / 100f));
            } else {
                mBatteryPercentView.setText(text);
            }
            setContentDescription(
                    getContext().getString(mCharging ? R.string.accessibility_battery_level_charging
                    : R.string.accessibility_battery_level, mLevel));
        }
    }

    private void removeBatteryPercentView() {
        if (mBatteryPercentView != null) {
            removeView(mBatteryPercentView);
            mBatteryPercentView = null;
        }
    }

    private void updateShowPercent() {
        final boolean showing = mBatteryPercentView != null;
        final boolean drawPercentInside = mShowBatteryPercent == 1
                                    && !mCharging;
        final boolean addPecentView = mShowBatteryPercent >= 2
                                    || (mBatteryPercentCharging && mCharging)
                                    || mShowPercentMode == MODE_ON
                                    || mShowBatteryEstimate != 0;

        mDrawable.setShowPercent(drawPercentInside);
        mXDrawable.setShowPercent(drawPercentInside);
        mIosDrawable.setShowPercent(drawPercentInside);
        mMxDrawable.setShowPercent(drawPercentInside);
        mRLandscapeDrawable.setShowPercent(drawPercentInside);
        mRLandscapeADrawable.setShowPercent(drawPercentInside);
        mRLandscapeBDrawable.setShowPercent(drawPercentInside);
        mLandscapeDrawable.setShowPercent(drawPercentInside);
        mLandscapeADrawable.setShowPercent(drawPercentInside);
        mLandscapeBDrawable.setShowPercent(drawPercentInside);
        mLandscapeCapsuleDrawable.setShowPercent(drawPercentInside);
        mLandscapeBatteryA.setShowPercent(drawPercentInside);
        mLandscapeBatteryB.setShowPercent(drawPercentInside);
        mLandscapeBatteryC.setShowPercent(drawPercentInside);
        mLandscapeBatteryD.setShowPercent(drawPercentInside);
        mLandscapeBatteryE.setShowPercent(drawPercentInside);
        mLandscapeBatteryF.setShowPercent(drawPercentInside);
        mLandscapeBatteryG.setShowPercent(drawPercentInside);
        mLandscapeBatteryH.setShowPercent(drawPercentInside);
        mLandscapeBatteryI.setShowPercent(drawPercentInside);
        mLandscapeBatteryJ.setShowPercent(drawPercentInside);
        mLandscapeBatteryK.setShowPercent(drawPercentInside);
        mLandscapeBatteryL.setShowPercent(drawPercentInside);
        mLandscapeBatteryM.setShowPercent(drawPercentInside);
        mLandscapeBatteryN.setShowPercent(drawPercentInside);
        mLandscapeBatteryO.setShowPercent(drawPercentInside);
        mLandscapeDrawableiOS15.setShowPercent(drawPercentInside);
        mLandscapeDrawableOneUI7.setShowPercent(drawPercentInside);
        mAirooDrawable.setShowPercent(drawPercentInside);

        if (addPecentView) {
            if (!showing) {
                mBatteryPercentView = loadPercentView();
                if (mPercentageStyleId != 0) { // Only set if specified as attribute
                    mBatteryPercentView.setTextAppearance(mPercentageStyleId);
                }
                if (mTextColor != 0) mBatteryPercentView.setTextColor(mTextColor);
                addView(mBatteryPercentView,
                        new ViewGroup.LayoutParams(
                                LayoutParams.WRAP_CONTENT,
                                LayoutParams.MATCH_PARENT));
            }
            updatePercentText();
            if (mBatteryStyle == BATTERY_STYLE_HIDDEN) {
                mBatteryPercentView.setPaddingRelative(0, 0, 0, 0);
            } else {
                Resources res = getContext().getResources();
                mBatteryPercentView.setPaddingRelative(
                        res.getDimensionPixelSize(R.dimen.battery_level_padding_start), 0, 0, 0);
                setLayoutDirection(mShowBatteryPercent > 2 ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
            }
        } else {
            removeBatteryPercentView();
        }
    }

    public void updateVisibility() {
        if (mBatteryStyle == BATTERY_STYLE_HIDDEN) {
            mBatteryIconView.setVisibility(View.GONE);
            mBatteryIconView.setImageDrawable(null);
            //setVisibility(View.GONE);
        } else {
            mBatteryIconView.setVisibility(View.VISIBLE);
            //setVisibility(View.VISIBLE);
            scaleBatteryMeterViews();
        }
    }

    @Override
    public void onDensityOrFontScaleChanged() {
        scaleBatteryMeterViews();
    }

    /**
     * Looks up the scale factor for status bar icons and scales the battery view by that amount.
     */
    private void scaleBatteryMeterViews() {
        if (mBatteryIconView == null) {
            return;
        }
        Resources res = getContext().getResources();
        TypedValue typedValue = new TypedValue();

        res.getValue(R.dimen.status_bar_icon_scale_factor, typedValue, true);
        float iconScaleFactor = typedValue.getFloat();

        int batteryHeight = res.getDimensionPixelSize(
                           isIosMxBattery() ? R.dimen.status_bar_battery_icon_height_ios_mx :
                           isLandscapeBattery() ? R.dimen.status_bar_battery_icon_height_landscape :
                           isLandscapeABBattery() ? R.dimen.status_bar_battery_icon_height_landscape_ab :
                           isLandscapeCapsuleBattery() ? R.dimen.status_bar_battery_icon_height_landscape_capsule :
                           isLandscapeAOBattery () ? R.dimen.status_bar_battery_icon_height_landscape_a_o :
                           isLandscapeiOS15Battery() ? R.dimen.status_bar_battery_icon_height_landscape_ios15 :
                           isLandscapeOneUI7Battery() ? R.dimen.status_bar_battery_icon_height_landscape_oneui7 :
                           isAirooBattery() ? R.dimen.status_bar_battery_icon_height_airoo :
                           isBigCircleBattery() ? R.dimen.status_bar_battery_big_circle_icon_height :
                                                  R.dimen.status_bar_battery_icon_height);
        int batteryWidth = mBatteryStyle == BATTERY_STYLE_CIRCLE ||
                           mBatteryStyle == BATTERY_STYLE_DOTTED_CIRCLE ||
                           mBatteryStyle == BATTERY_STYLE_SOLID ?
                res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_circle_width) :
                res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width);
        int marginBottom = res.getDimensionPixelSize(R.dimen.battery_margin_bottom);

        if (isIosMxBattery()) {
                 batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width_ios_mx);
        }

        if (isLandscapeBattery()) {
                 batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width_landscape);
        }

        if (isLandscapeABBattery()) {
                 batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width_landscape_ab);
        }

        if (isLandscapeCapsuleBattery()) {
                 batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width_landscape_capsule);
        }

        if (isLandscapeAOBattery()) {
                batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width_landscape_a_o);
        }

        if (isLandscapeiOS15Battery()) {
                 batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width_landscape_ios15);
        }

        if (isLandscapeOneUI7Battery()) {
                 batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width_landscape_oneui7);
        }

        if (isAirooBattery()) {
                 batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_icon_width_airoo);
        }

        if (isBigCircleBattery()) {
                 batteryWidth = res.getDimensionPixelSize(R.dimen.status_bar_battery_big_circle_icon_width);
        }

        LinearLayout.LayoutParams scaledLayoutParams = new LinearLayout.LayoutParams(
                (int) (batteryWidth * iconScaleFactor), (int) (batteryHeight * iconScaleFactor));
        scaledLayoutParams.setMargins(0, 0, 0, marginBottom);

        mBatteryIconView.setLayoutParams(scaledLayoutParams);
    }

    public void updateBatteryStyle() {
        if (mBatteryStyle == BATTERY_STYLE_HIDDEN) return;

        if (mBatteryStyle == BATTERY_STYLE_PORTRAIT) {
            mBatteryIconView.setImageDrawable(mDrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_IOS) {
                mBatteryIconView.setImageDrawable(mIosDrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_MX) {
                mBatteryIconView.setImageDrawable(mMxDrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_RLANDSCAPE) {
                mBatteryIconView.setImageDrawable(mRLandscapeDrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_RLANDSCAPE_A) {
                mBatteryIconView.setImageDrawable(mRLandscapeADrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_RLANDSCAPE_B) {
                mBatteryIconView.setImageDrawable(mRLandscapeBDrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPE) {
                mBatteryIconView.setImageDrawable(mLandscapeDrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPE_A) {
                mBatteryIconView.setImageDrawable(mLandscapeADrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPE_B) {
                mBatteryIconView.setImageDrawable(mLandscapeBDrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPE_CAPSULE) {
                mBatteryIconView.setImageDrawable(mLandscapeCapsuleDrawable);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEA) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryA);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEB) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryB);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEC) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryC);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPED) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryD);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEE) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryE);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEF) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryF);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEG) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryG);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEH) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryH);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEI) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryI);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEJ) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryJ);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEK) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryK);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEL) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryL);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEM) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryM);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEN) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryN);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPEO) {
                mBatteryIconView.setImageDrawable(mLandscapeBatteryO);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPE_IOS15) {
                mBatteryIconView.setImageDrawable(mLandscapeDrawableiOS15);
        } else if (mBatteryStyle == BATTERY_STYLE_LANDSCAPE_ONEUI7) {
                mBatteryIconView.setImageDrawable(mLandscapeDrawableOneUI7);
        } else if (mBatteryStyle == BATTERY_STYLE_AIROO) {
                mBatteryIconView.setImageDrawable(mAirooDrawable);
        } else {
            mXDrawable.setMeterStyle(mBatteryStyle);
            mBatteryIconView.setImageDrawable(mXDrawable);
        }
    }

    @Override
    public void onDarkChanged(Rect area, float darkIntensity, int tint) {
        float intensity = DarkIconDispatcher.isInArea(area, this) ? darkIntensity : 0;
        mNonAdaptedSingleToneColor = mDualToneHandler.getSingleColor(intensity);
        mNonAdaptedForegroundColor = mDualToneHandler.getFillColor(intensity);
        mNonAdaptedBackgroundColor = mDualToneHandler.getBackgroundColor(intensity);

        if (!mUseWallpaperTextColors) {
            updateColors(mNonAdaptedForegroundColor, mNonAdaptedBackgroundColor,
                    mNonAdaptedSingleToneColor);
        }
    }

    private boolean isIosMxBattery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_MX ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_IOS;
    }

    private boolean isLandscapeBattery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_RLANDSCAPE ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE;
    }

    private boolean isLandscapeABBattery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_RLANDSCAPE_A  ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_RLANDSCAPE_B ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_A  ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_B;
    }

    private boolean isLandscapeCapsuleBattery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_CAPSULE;
    }

    private boolean isLandscapeAOBattery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEA ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEB ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEC ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPED ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEE ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEF ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEG ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEH ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEI ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEJ ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEK ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEL ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEM ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEN ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPEO;
    }

    private boolean isLandscapeiOS15Battery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_IOS15;
    }

    private boolean isLandscapeOneUI7Battery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_LANDSCAPE_ONEUI7;
    }

    private boolean isAirooBattery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_AIROO;
    }

    private boolean isBigCircleBattery() {
        return mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_BIG_CIRCLE ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_BIG_DOTTED_CIRCLE ||
               mBatteryStyle == BatteryMeterDrawableBase.BATTERY_STYLE_BIG_SOLID;
    }

    private void updateColors(int foregroundColor, int backgroundColor, int singleToneColor) {
        mDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mXDrawable.setColors(foregroundColor, backgroundColor);
        mIosDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mMxDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mRLandscapeDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mRLandscapeADrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mRLandscapeBDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeADrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeCapsuleDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryA.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryB.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryC.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryD.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryE.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryF.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryG.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryH.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryI.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryJ.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryK.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryL.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryM.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryN.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeBatteryO.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeDrawableiOS15.setColors(foregroundColor, backgroundColor, singleToneColor);
        mLandscapeDrawableOneUI7.setColors(foregroundColor, backgroundColor, singleToneColor);
        mAirooDrawable.setColors(foregroundColor, backgroundColor, singleToneColor);
        mTextColor = singleToneColor;
        if (mBatteryPercentView != null) {
            mBatteryPercentView.setTextColor(singleToneColor);
        }
    }

    public void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
        String powerSave = mDrawable == null ? null : mDrawable.getPowerSaveEnabled() + "";
        CharSequence percent = mBatteryPercentView == null ? null : mBatteryPercentView.getText();
        pw.println("  BatteryMeterView:");
        pw.println("    mDrawable.getPowerSave: " + powerSave);
        pw.println("    mBatteryPercentView.getText(): " + percent);
        pw.println("    mTextColor: #" + Integer.toHexString(mTextColor));
        pw.println("    mLevel: " + mLevel);
    }

    private final class SettingObserver extends ContentObserver {
        public SettingObserver(Handler handler) {
            super(handler);
        }

        @Override
        public void onChange(boolean selfChange, Uri uri) {
            super.onChange(selfChange, uri);
            updateShowPercent();
            if (TextUtils.equals(uri.getLastPathSegment(),
                    Settings.Global.BATTERY_ESTIMATES_LAST_UPDATE_TIME)) {
                // update the text for sure if the estimate in the cache was updated
                updatePercentText();
            }
        }
    }
}
