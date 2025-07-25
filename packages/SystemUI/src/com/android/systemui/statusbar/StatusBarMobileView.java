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

package com.android.systemui.statusbar;

import static com.android.systemui.plugins.DarkIconDispatcher.getTint;
import static com.android.systemui.plugins.DarkIconDispatcher.isInArea;
import static com.android.systemui.statusbar.StatusBarIconView.STATE_DOT;
import static com.android.systemui.statusbar.StatusBarIconView.STATE_HIDDEN;
import static com.android.systemui.statusbar.StatusBarIconView.STATE_ICON;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;

import com.android.internal.annotations.VisibleForTesting;
import com.android.settingslib.graph.SignalDrawable;
import com.android.systemui.Dependency;
import com.android.systemui.DualToneHandler;
import com.android.systemui.R;
import com.android.systemui.plugins.DarkIconDispatcher.DarkReceiver;
import com.android.systemui.statusbar.phone.StatusBarSignalPolicy.MobileIconState;
import com.android.systemui.tuner.TunerService;

public class StatusBarMobileView extends FrameLayout implements DarkReceiver,
        StatusIconDisplayable, TunerService.Tunable {
    private static final String TAG = "StatusBarMobileView";

    private static final String EVL_MOBILE_TYPE_LAYOUT_SWITCH = "system:evl_mobile_type_layout_switch";
    private static final String EVL_MOBILE_TYPE_ICON_POSITION = "system:evl_mobile_type_icon_position";
    private static final String EVL_MOBILE_TYPE_PADDING_LEFT = "system:evl_mobile_type_padding_left";
    private static final String EVL_MOBILE_TYPE_PADDING_RIGHT = "system:evl_mobile_type_padding_right";

    private static final String IDC_SIGNAL_HEIGHT =
            "system:" + "IDC_SIGNAL_HEIGHT";
    private static final String IDC_SIGNAL_WIDTH =
            "system:" + "IDC_SIGNAL_WIDTH";
    private static final String IDC_SIGNAL_CUSTOM_DIMENSION =
            "system:" + "IDC_SIGNAL_CUSTOM_DIMENSION";

    private boolean evlCustomEnabled;
    private boolean evlDataPosition;
    private int evlPaddingLeft;
    private int evlPaddingRight;

    private boolean useIdcCustomDimension;
    private int idcSignalHeight;
    private int idcSignalWidth;

    /// Used to show etc dots
    private StatusBarIconView mDotView;
    /// The main icon view
    private LinearLayout mMobileGroup;
    private String mSlot;
    private MobileIconState mState;
    private SignalDrawable mMobileDrawable;
    private View mInoutContainer;
    private ImageView mIn;
    private ImageView mOut;
    private ImageView mMobile, mMobileType, mMobileRoaming;
    private View mMobileRoamingSpace;
    private int mVisibleState = -1;
    private DualToneHandler mDualToneHandler;
    private View mMobileSignalType;
    private boolean mOldStyleType;
    private ImageView mMobileTypeSmall;
    private ImageView mVolte;

    public static StatusBarMobileView fromContext(Context context, String slot) {
        LayoutInflater inflater = LayoutInflater.from(context);
        StatusBarMobileView v = (StatusBarMobileView)
                inflater.inflate(R.layout.status_bar_mobile_signal_group, null);

        v.setSlot(slot);
        v.init();
        v.setVisibleState(STATE_ICON);
        return v;
    }

    public StatusBarMobileView(Context context) {
        super(context);
    }

    public StatusBarMobileView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public StatusBarMobileView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    public StatusBarMobileView(Context context, AttributeSet attrs, int defStyleAttr,
            int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
    }

    @Override
    public void getDrawingRect(Rect outRect) {
        super.getDrawingRect(outRect);
        float translationX = getTranslationX();
        float translationY = getTranslationY();
        outRect.left += translationX;
        outRect.right += translationX;
        outRect.top += translationY;
        outRect.bottom += translationY;
    }

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        updateMobileTypeLayout();
        Dependency.get(TunerService.class)
            .addTunable(this, new String[] {
                            EVL_MOBILE_TYPE_LAYOUT_SWITCH,
                            EVL_MOBILE_TYPE_ICON_POSITION,
                            EVL_MOBILE_TYPE_PADDING_LEFT,
                            EVL_MOBILE_TYPE_PADDING_RIGHT,
                            IDC_SIGNAL_HEIGHT,
                            IDC_SIGNAL_WIDTH,
                            IDC_SIGNAL_CUSTOM_DIMENSION
                        });
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        Dependency.get(TunerService.class).removeTunable(this);
    }

    @Override
    public void onTuningChanged(String key, String newValue) {
        if (EVL_MOBILE_TYPE_LAYOUT_SWITCH.equals(key)) {
            evlCustomEnabled = TunerService.parseIntegerSwitch(newValue, false);
            updateMobileTypeLayout();
        } else if (EVL_MOBILE_TYPE_ICON_POSITION.equals(key)) {
            evlDataPosition = TunerService.parseIntegerSwitch(newValue, false);
            updateMobileTypeLayout();
        } else if (EVL_MOBILE_TYPE_PADDING_LEFT.equals(key)) {
            int L = TunerService.parseInteger(newValue, 2);
            evlPaddingLeft = Math.round(TypedValue.applyDimension(
                                             TypedValue.COMPLEX_UNIT_DIP, L,
                                             getResources().getDisplayMetrics()));
            updateMobileTypeLayout();
        } else if (EVL_MOBILE_TYPE_PADDING_RIGHT.equals(key)) {
            int R = TunerService.parseInteger(newValue, 1);
            evlPaddingRight = Math.round(TypedValue.applyDimension(
                                             TypedValue.COMPLEX_UNIT_DIP, R,
                                             getResources().getDisplayMetrics()));
            updateMobileTypeLayout();
        } else if (IDC_SIGNAL_HEIGHT.equals(key)) {
            int midcSignalHeight = TunerService.parseInteger(newValue, 15);
            idcSignalHeight = Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, midcSignalHeight,
                getResources().getDisplayMetrics()));
            setMobileSignalWidth(true);
        } else if (IDC_SIGNAL_WIDTH.equals(key)) {
            int midcSignalWidth = TunerService.parseInteger(newValue, 15);
            idcSignalWidth = Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, midcSignalWidth,
                getResources().getDisplayMetrics()));
        } else if (IDC_SIGNAL_CUSTOM_DIMENSION.equals(key)) {
            useIdcCustomDimension = TunerService.parseIntegerSwitch(newValue, false);
            setMobileSignalWidth(true);
        }
    }

    private void updateMobileTypeLayout() {
        LinearLayout mobileTypeLayout = findViewById(R.id.evl_mobile_type_layout);
        mobileTypeLayout.setLayoutDirection(evlCustomEnabled && evlDataPosition ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);

        int defaultLeft = Math.round(TypedValue.applyDimension(
                                         TypedValue.COMPLEX_UNIT_DIP, 2.0f,
                                         getResources().getDisplayMetrics()));
        int defaultRight = Math.round(TypedValue.applyDimension(
                                          TypedValue.COMPLEX_UNIT_DIP, 1.0f,
                                          getResources().getDisplayMetrics()));

        if (evlCustomEnabled) {
            mMobileType.setPadding(evlPaddingLeft, mMobileType.getPaddingTop(), evlPaddingRight, mMobileType.getPaddingBottom());
        } else {
            mMobileType.setPadding(defaultLeft, mMobileType.getPaddingTop(), defaultRight, mMobileType.getPaddingBottom());
        }
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        mMobileGroup.measure(widthMeasureSpec, heightMeasureSpec);
        setMeasuredDimension(mMobileGroup.getMeasuredWidth(), mMobileGroup.getMeasuredHeight());
    }

    private void init() {
        mDualToneHandler = new DualToneHandler(getContext());
        mMobileGroup = findViewById(R.id.mobile_group);
        mMobile = findViewById(R.id.mobile_signal);
        mMobileType = findViewById(R.id.mobile_type);
        mMobileRoaming = findViewById(R.id.mobile_roaming);
        mMobileRoamingSpace = findViewById(R.id.mobile_roaming_space);
        mIn = findViewById(R.id.mobile_in);
        mOut = findViewById(R.id.mobile_out);
        mInoutContainer = findViewById(R.id.inout_container);
        mMobileSignalType = findViewById(R.id.mobile_signal_type);
        mMobileTypeSmall = findViewById(R.id.mobile_type_small);
        mVolte = findViewById(R.id.mobile_volte);

        mMobileDrawable = new SignalDrawable(getContext());
        mMobile.setImageDrawable(mMobileDrawable);

        initDotView();
    }

    private void initDotView() {
        mDotView = new StatusBarIconView(mContext, mSlot, null);
        mDotView.setVisibleState(STATE_DOT);

        int width = mContext.getResources().getDimensionPixelSize(R.dimen.status_bar_icon_size);
        LayoutParams lp = new LayoutParams(width, width);
        lp.gravity = Gravity.CENTER_VERTICAL | Gravity.START;
        addView(mDotView, lp);
    }

    public void applyMobileState(MobileIconState state) {
        boolean requestLayout = false;
        if (state == null) {
            requestLayout = getVisibility() != View.GONE;
            setVisibility(View.GONE);
            mState = null;
        } else if (mState == null) {
            requestLayout = true;
            mState = state.copy();
            initViewState();
        } else if (!mState.equals(state)) {
            requestLayout = updateState(state.copy());
        }

        if (requestLayout) {
            requestLayout();
        }
    }

    private void initViewState() {
        setContentDescription(mState.contentDescription);
        if (!mState.visible) {
            mMobileGroup.setVisibility(View.GONE);
        } else {
            mMobileGroup.setVisibility(View.VISIBLE);
        }
        if (mState.strengthId > 0) {
            mMobile.setVisibility(View.VISIBLE);
            mMobileDrawable.setLevel(mState.strengthId);
        } else {
            mMobile.setVisibility(View.GONE);
        }
        boolean showRoamingSpace = false;
        if (mState.typeId > 0) {
            if (mOldStyleType) {
                showOldStyle(mState);
                showRoamingSpace = true;
            } else {
                showNewStyle(mState);
            }
        } else {
            hideIndicators();
        }
        if (mState.roaming) {
            showRoaming();
        }
        mMobileRoaming.setVisibility(mState.roaming ? View.VISIBLE : View.GONE);
        mMobileRoamingSpace.setVisibility(mState.roaming || showRoamingSpace ? View.VISIBLE : View.GONE);
        mIn.setVisibility(mState.activityIn ? View.VISIBLE : View.GONE);
        mOut.setVisibility(mState.activityOut ? View.VISIBLE : View.GONE);
        mInoutContainer.setVisibility((mState.activityIn || mState.activityOut)
                ? View.VISIBLE : View.GONE);
        if (mState.volteId > 0 ) {
            mVolte.setImageResource(mState.volteId);
            mVolte.setVisibility(View.VISIBLE);
        }else {
            mVolte.setVisibility(View.GONE);
        }
    }

    private void setMobileSignalWidth(boolean small) {
        ViewGroup.LayoutParams p = mMobileSignalType.getLayoutParams();
        if (small) {
            if (!useIdcCustomDimension) {
            p.height = mContext.getResources().getDimensionPixelSize(
                        R.dimen.status_bar_mobile_signal_height);
            p.width = mContext.getResources().getDimensionPixelSize(
                        R.dimen.status_bar_mobile_signal_width);
            } else {
            p.height = (int) idcSignalHeight;
            p.width = (int) idcSignalWidth;
            }
        } else {
            if (!useIdcCustomDimension) {
            p.height = mContext.getResources().getDimensionPixelSize(
                    R.dimen.status_bar_mobile_signal_height_type_height);
            p.width = mContext.getResources().getDimensionPixelSize(
                    R.dimen.status_bar_mobile_signal_with_type_width);
            int paddingLimit = mContext.getResources().getDimensionPixelSize(
                    R.dimen.status_bar_mobile_type_padding_limit);
            int padding = mMobileTypeSmall.getWidth() < paddingLimit ?
                    mContext.getResources().getDimensionPixelSize(R.dimen.status_bar_mobile_type_padding) : 0;
            mMobileTypeSmall.setPadding(padding, 0, 0, 0);
            } else {
            p.height = (int) idcSignalHeight;
            p.width = (int) idcSignalWidth;
            int paddingLimit = mContext.getResources().getDimensionPixelSize(
                    R.dimen.status_bar_mobile_type_padding_limit);
            int padding = mMobileTypeSmall.getWidth() < paddingLimit ?
                    mContext.getResources().getDimensionPixelSize(R.dimen.status_bar_mobile_type_padding) : 0;
            mMobileTypeSmall.setPadding(padding, 0, 0, 0);
            }
        }
        mMobileSignalType.setLayoutParams(p);
    }

    private boolean updateState(MobileIconState state) {
        boolean needsLayout = false;

        setContentDescription(state.contentDescription);
        if (mState.visible != state.visible) {
            mMobileGroup.setVisibility(state.visible ? View.VISIBLE : View.GONE);
            needsLayout = true;
        }
        if (state.strengthId > 0) {
            mMobileDrawable.setLevel(state.strengthId);
            mMobile.setVisibility(View.VISIBLE);
        } else {
            mMobile.setVisibility(View.GONE);
        }
        boolean showRoamingSpace = false;
        if (mState.typeId != state.typeId) {
            needsLayout |= state.typeId == 0 || mState.typeId == 0;
            if (state.typeId != 0) {
                if (mOldStyleType) {
                    showOldStyle(state);
                    showRoamingSpace = true;
                } else {
                    showNewStyle(state);
                }
            } else {
                hideIndicators();
            }
        }
        if (state.roaming) {
            showRoaming();
        }
        mMobileRoaming.setVisibility(state.roaming ? View.VISIBLE : View.GONE);
        mMobileRoamingSpace.setVisibility(showRoamingSpace || state.roaming ? View.VISIBLE : View.GONE);
        mIn.setVisibility(state.activityIn ? View.VISIBLE : View.GONE);
        mOut.setVisibility(state.activityOut ? View.VISIBLE : View.GONE);
        mInoutContainer.setVisibility((state.activityIn || state.activityOut)
                ? View.VISIBLE : View.GONE);

        if (mState.volteId != state.volteId) {
            if (state.volteId != 0) {
                mVolte.setImageResource(state.volteId);
                mVolte.setVisibility(View.VISIBLE);
            } else {
                mVolte.setVisibility(View.GONE);
            }
        }

        needsLayout |= state.roaming != mState.roaming
                || state.activityIn != mState.activityIn
                || state.activityOut != mState.activityOut;

        mState = state;
        return needsLayout;
    }

    @Override
    public void onDarkChanged(Rect area, float darkIntensity, int tint) {
        float intensity = isInArea(area, this) ? darkIntensity : 0;
        mMobileDrawable.setTintList(
                ColorStateList.valueOf(mDualToneHandler.getSingleColor(intensity)));
        ColorStateList color = ColorStateList.valueOf(getTint(area, this, tint));
        mIn.setImageTintList(color);
        mOut.setImageTintList(color);
        mMobileType.setImageTintList(color);
        mMobileTypeSmall.setImageTintList(color);
        mMobileRoaming.setImageTintList(color);
        mVolte.setImageTintList(color);
        mDotView.setDecorColor(tint);
        mDotView.setIconColor(tint, false);
    }

    @Override
    public String getSlot() {
        return mSlot;
    }

    public void setSlot(String slot) {
        mSlot = slot;
    }

    @Override
    public void setStaticDrawableColor(int color) {
        ColorStateList list = ColorStateList.valueOf(color);
        float intensity = color == Color.WHITE ? 0 : 1;
        // We want the ability to change the theme from the one set by SignalDrawable in certain
        // surfaces. In this way, we can pass a theme to the view.
        mMobileDrawable.setTintList(
                ColorStateList.valueOf(mDualToneHandler.getSingleColor(intensity)));
        mIn.setImageTintList(list);
        mOut.setImageTintList(list);
        mMobileType.setImageTintList(list);
        mMobileRoaming.setImageTintList(list);
        mMobileTypeSmall.setImageTintList(list);
        mVolte.setImageTintList(list);
        mDotView.setDecorColor(color);
    }

    @Override
    public void setDecorColor(int color) {
        mDotView.setDecorColor(color);
    }

    @Override
    public boolean isIconVisible() {
        return mState.visible;
    }

    @Override
    public void setVisibleState(int state, boolean animate) {
        if (state == mVisibleState) {
            return;
        }

        mVisibleState = state;
        switch (state) {
            case STATE_ICON:
                mMobileGroup.setVisibility(View.VISIBLE);
                mDotView.setVisibility(View.GONE);
                break;
            case STATE_DOT:
                mMobileGroup.setVisibility(View.INVISIBLE);
                mDotView.setVisibility(View.VISIBLE);
                break;
            case STATE_HIDDEN:
            default:
                mMobileGroup.setVisibility(View.INVISIBLE);
                mDotView.setVisibility(View.INVISIBLE);
                break;
        }
    }

    @Override
    public int getVisibleState() {
        return mVisibleState;
    }

    @VisibleForTesting
    public MobileIconState getState() {
        return mState;
    }

    @Override
    public String toString() {
        return "StatusBarMobileView(slot=" + mSlot + " state=" + mState + ")";
    }

    public void updateDisplayType(boolean oldStyleType) {
        boolean needsLayout = false;
        boolean showRoamingSpace = false;

        if (mOldStyleType != oldStyleType) {
            if (mState.typeId != 0) {
                if (oldStyleType) {
                    showOldStyle(mState);
                    showRoamingSpace = true;
               } else {
                    showNewStyle(mState);
                }
            } else {
                hideIndicators();
            }
        }
        if (mState.roaming) {
            showRoaming();
        }
        mMobileRoaming.setVisibility(mState.roaming ? View.VISIBLE : View.GONE);
        mMobileRoamingSpace.setVisibility(showRoamingSpace || mState.roaming ? View.VISIBLE : View.GONE);
        mIn.setVisibility(mState.activityIn ? View.VISIBLE : View.GONE);
        mOut.setVisibility(mState.activityOut ? View.VISIBLE : View.GONE);
        mInoutContainer.setVisibility((mState.activityIn || mState.activityOut)
                ? View.VISIBLE : View.GONE);

        needsLayout = mOldStyleType != oldStyleType;
        mOldStyleType = oldStyleType;

        if (needsLayout) {
            requestLayout();
        }
    }

    private void showOldStyle(MobileIconState state) {
        mMobileType.setVisibility(View.GONE);
        mMobileTypeSmall.setContentDescription(state.typeContentDescription);
        mMobileTypeSmall.setImageResource(state.typeId);
        mMobileTypeSmall.setVisibility(View.VISIBLE);
        setMobileSignalWidth(false);
    }

    private void showNewStyle(MobileIconState state) {
        mMobileType.setVisibility(View.VISIBLE);
        mMobileType.setContentDescription(state.typeContentDescription);
        mMobileType.setImageResource(state.typeId);
        mMobileTypeSmall.setVisibility(View.GONE);
        setMobileSignalWidth(true);
    }

    private void showRoaming() {
        mMobileTypeSmall.setVisibility(View.GONE);
        setMobileSignalWidth(true);
    }

    private void hideIndicators() {
        mMobileType.setVisibility(View.GONE);
        mMobileTypeSmall.setVisibility(View.GONE);
        setMobileSignalWidth(true);
    }
}
