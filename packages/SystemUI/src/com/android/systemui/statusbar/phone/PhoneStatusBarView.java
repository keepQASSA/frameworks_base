/*
 * Copyright (C) 2008 The Android Open Source Project
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

package com.android.systemui.statusbar.phone;

import static android.content.res.Configuration.ORIENTATION_PORTRAIT;

import static com.android.systemui.ScreenDecorations.DisplayCutoutView.boundsFromDirection;
import static com.android.systemui.SysUiServiceProvider.getComponent;

import static java.lang.Float.isNaN;

import android.annotation.Nullable;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Point;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.EventLog;
import android.util.Pair;
import android.view.Display;
import android.view.DisplayCutout;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.accessibility.AccessibilityEvent;
import android.widget.FrameLayout;
import android.widget.LinearLayout;

import com.android.systemui.Dependency;
import com.android.systemui.EventLogTags;
import com.android.systemui.R;
import com.android.systemui.plugins.DarkIconDispatcher;
import com.android.systemui.plugins.DarkIconDispatcher.DarkReceiver;
import com.android.systemui.statusbar.CommandQueue;
import com.android.systemui.statusbar.CommandQueue.Callbacks;
import com.android.systemui.util.leak.RotationUtils;
import android.util.TypedValue;
import com.android.systemui.tuner.TunerService;
import android.provider.Settings;

import java.util.Objects;

public class PhoneStatusBarView extends PanelBar implements Callbacks, TunerService.Tunable {
    private static final String TAG = "PhoneStatusBarView";
    private static final boolean DEBUG = StatusBar.DEBUG;
    private static final boolean DEBUG_GESTURES = false;
    private static final int NO_VALUE = Integer.MIN_VALUE;
    private final CommandQueue mCommandQueue;

    private static final String LEFT_PADDING =
            "system:" + Settings.System.LEFT_PADDING;
    private static final String RIGHT_PADDING =
            "system:" + Settings.System.RIGHT_PADDING;
    private static final String TOP_PADDING =
            "system:" + Settings.System.TOP_PADDING;

    private int mBasePaddingBottom;
    private int mLeftPad;
    private int mRightPad;
    private int mTopPad;

    private ViewGroup mStatusBarContents;

    StatusBar mBar;

    boolean mIsFullyOpenedPanel = false;
    private ScrimController mScrimController;
    private float mMinFraction;
    private Runnable mHideExpandedRunnable = new Runnable() {
        @Override
        public void run() {
            if (mPanelFraction == 0.0f) {
                mBar.makeExpandedInvisible();
            }
        }
    };
    private DarkReceiver mBattery;
    private int mLastOrientation;
    private int mRotationOrientation;
    @Nullable
    private View mCenterIconSpace;
    @Nullable
    private View mCutoutSpace;
    @Nullable
    private DisplayCutout mDisplayCutout;
    /**
     * Draw this many pixels into the left/right side of the cutout to optimally use the space
     */
    private int mCutoutSideNudge = 0;
    private int mStatusBarHeight;
    private boolean mHeadsUpVisible;

    public PhoneStatusBarView(Context context, AttributeSet attrs) {
        super(context, attrs);

        mCommandQueue = getComponent(context, CommandQueue.class);
    }

    public void setBar(StatusBar bar) {
        mBar = bar;
    }

    public void setScrimController(ScrimController scrimController) {
        mScrimController = scrimController;
    }

    public void swiftStatusBarItems(int horizontalShift, int verticalShift) {
        if (mStatusBarContents == null) {
            return;
        }

        mStatusBarContents.setPaddingRelative(mLeftPad + horizontalShift,
                                              mTopPad + verticalShift,
                                              mRightPad + horizontalShift,
                                              mBasePaddingBottom - verticalShift);
        invalidate();
    }

    @Override
    public void onFinishInflate() {
        mBattery = findViewById(R.id.battery);
        mCutoutSpace = findViewById(R.id.cutout_space_view);
        mCenterIconSpace = findViewById(R.id.centered_icon_area);
        mStatusBarContents = (ViewGroup) findViewById(R.id.status_bar_contents);

        mBasePaddingBottom = mStatusBarContents.getPaddingBottom();
		Dependency.get(TunerService.class).addTunable(this,
                LEFT_PADDING, RIGHT_PADDING,
                TOP_PADDING);

        updateResources();
    }

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        // Always have Battery meters in the status bar observe the dark/light modes.
        Dependency.get(DarkIconDispatcher.class).addDarkReceiver(mBattery);
        if (updateOrientationAndCutout(getResources().getConfiguration().orientation)) {
            updateLayoutForCutout();
        }
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        Dependency.get(DarkIconDispatcher.class).removeDarkReceiver(mBattery);
        mDisplayCutout = null;
    }

    @Override
    protected void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        updateResources();

        // May trigger cutout space layout-ing
        if (updateOrientationAndCutout(newConfig.orientation)) {
            updateLayoutForCutout();
            requestLayout();
        }
    }

    @Override
    public WindowInsets onApplyWindowInsets(WindowInsets insets) {
        if (updateOrientationAndCutout(mLastOrientation)) {
            updateLayoutForCutout();
            requestLayout();
        }
        return super.onApplyWindowInsets(insets);
    }

    /**
     *
     * @param newOrientation may pass NO_VALUE for no change
     * @return boolean indicating if we need to update the cutout location / margins
     */
    private boolean updateOrientationAndCutout(int newOrientation) {
        boolean changed = false;
        if (newOrientation != NO_VALUE) {
            if (mLastOrientation != newOrientation) {
                changed = true;
                mLastOrientation = newOrientation;
            }
            mRotationOrientation = RotationUtils.getExactRotation(mContext);
        }

        if (!Objects.equals(getRootWindowInsets().getDisplayCutout(), mDisplayCutout)) {
            changed = true;
            mDisplayCutout = getRootWindowInsets().getDisplayCutout();
        }

        return changed;
    }

    @Override
    public boolean panelEnabled() {
        return mCommandQueue.panelsEnabled();
    }

    @Override
    public boolean onRequestSendAccessibilityEventInternal(View child, AccessibilityEvent event) {
        if (super.onRequestSendAccessibilityEventInternal(child, event)) {
            // The status bar is very small so augment the view that the user is touching
            // with the content of the status bar a whole. This way an accessibility service
            // may announce the current item as well as the entire content if appropriate.
            AccessibilityEvent record = AccessibilityEvent.obtain();
            onInitializeAccessibilityEvent(record);
            dispatchPopulateAccessibilityEvent(record);
            event.appendRecord(record);
            return true;
        }
        return false;
    }

    @Override
    public void onPanelPeeked() {
        super.onPanelPeeked();
        mBar.makeExpandedVisible(false);
    }

    @Override
    public void onPanelCollapsed() {
        super.onPanelCollapsed();
        // Close the status bar in the next frame so we can show the end of the animation.
        post(mHideExpandedRunnable);
        mIsFullyOpenedPanel = false;
    }

    public void removePendingHideExpandedRunnables() {
        removeCallbacks(mHideExpandedRunnable);
    }

    @Override
    public void onPanelFullyOpened() {
        super.onPanelFullyOpened();
        if (!mIsFullyOpenedPanel) {
            mPanel.sendAccessibilityEvent(AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED);
        }
        mIsFullyOpenedPanel = true;
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        boolean barConsumedEvent = mBar.interceptTouchEvent(event);

        if (DEBUG_GESTURES) {
            if (event.getActionMasked() != MotionEvent.ACTION_MOVE) {
                EventLog.writeEvent(EventLogTags.SYSUI_PANELBAR_TOUCH,
                        event.getActionMasked(), (int) event.getX(), (int) event.getY(),
                        barConsumedEvent ? 1 : 0);
            }
        }

        return barConsumedEvent || super.onTouchEvent(event);
    }

    @Override
    public void onTrackingStarted() {
        super.onTrackingStarted();
        mBar.onTrackingStarted();
        mScrimController.onTrackingStarted();
        removePendingHideExpandedRunnables();
    }

    @Override
    public void onClosingFinished() {
        super.onClosingFinished();
        mBar.onClosingFinished();
    }

    @Override
    public void onTrackingStopped(boolean expand) {
        super.onTrackingStopped(expand);
        mBar.onTrackingStopped(expand);
    }

    @Override
    public void onExpandingFinished() {
        super.onExpandingFinished();
        mScrimController.onExpandingFinished();
    }

    @Override
    public boolean onInterceptTouchEvent(MotionEvent event) {
        return mBar.interceptTouchEvent(event) || super.onInterceptTouchEvent(event);
    }

    @Override
    public void panelScrimMinFractionChanged(float minFraction) {
        if (isNaN(minFraction)) {
            throw new IllegalArgumentException("minFraction cannot be NaN");
        }
        if (mMinFraction != minFraction) {
            mMinFraction = minFraction;
            updateScrimFraction();
        }
    }

    @Override
    public void panelExpansionChanged(float frac, boolean expanded) {
        super.panelExpansionChanged(frac, expanded);
        updateScrimFraction();
        if ((frac == 0 || frac == 1) && mBar.getNavigationBarView() != null) {
            mBar.getNavigationBarView().onStatusBarPanelStateChanged();
        }
    }

    private void updateScrimFraction() {
        float scrimFraction = mPanelFraction;
        if (mMinFraction < 1.0f) {
            scrimFraction = Math.max((mPanelFraction - mMinFraction) / (1.0f - mMinFraction),
                    0);
        }
        mScrimController.setPanelExpansion(scrimFraction);
    }

    public void updateResources() {
        mCutoutSideNudge = getResources().getDimensionPixelSize(
                R.dimen.display_cutout_margin_consumption);

        boolean isRtl = getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;

        int statusBarPaddingTop = getResources().getDimensionPixelSize(
                R.dimen.status_bar_padding_top);
        int statusBarPaddingStart = getResources().getDimensionPixelSize(
                R.dimen.status_bar_padding_start);
        int statusBarPaddingEnd = getResources().getDimensionPixelSize(
                R.dimen.status_bar_padding_end);

        ViewGroup.LayoutParams layoutParams = getLayoutParams();
        mStatusBarHeight = getResources().getDimensionPixelSize(R.dimen.status_bar_height);
        layoutParams.height = mStatusBarHeight;

        View sbContents = findViewById(R.id.status_bar_contents);
        sbContents.setPaddingRelative(
                (int) mLeftPad,
                (int) mTopPad,
                (int) mRightPad,
                0);

        findViewById(R.id.notification_lights_out).setPadding(0, (int) mLeftPad, 0, 0);

        setLayoutParams(layoutParams);
    }

    private void updateLayoutForCutout() {
        Pair<Integer, Integer> cornerCutoutMargins = cornerCutoutMargins(mDisplayCutout,
                getDisplay(), mRotationOrientation, mStatusBarHeight);
        updateCutoutLocation(cornerCutoutMargins);
        updateSafeInsets(cornerCutoutMargins);
    }

    private void updateCutoutLocation(Pair<Integer, Integer> cornerCutoutMargins) {
        // Not all layouts have a cutout (e.g., Car)
        if (mCutoutSpace == null) {
            return;
        }

        if (mDisplayCutout == null || mDisplayCutout.isEmpty()
                    || mLastOrientation != ORIENTATION_PORTRAIT || cornerCutoutMargins != null) {
            mCenterIconSpace.setVisibility(View.VISIBLE);
            mCutoutSpace.setVisibility(View.GONE);
            return;
        }

        mCenterIconSpace.setVisibility(View.GONE);
        mCutoutSpace.setVisibility(View.VISIBLE);
        LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) mCutoutSpace.getLayoutParams();

        Rect bounds = new Rect();
        boundsFromDirection(mDisplayCutout, Gravity.TOP, bounds);

        bounds.left = bounds.left + mCutoutSideNudge;
        bounds.right = bounds.right - mCutoutSideNudge;
        lp.width = bounds.width();
        lp.height = bounds.height();
    }

    private void updateSafeInsets(Pair<Integer, Integer> cornerCutoutMargins) {
        // Depending on our rotation, we may have to work around a cutout in the middle of the view,
        // or letterboxing from the right or left sides.

        FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) getLayoutParams();
        if (mDisplayCutout == null || mDisplayCutout.isEmpty() || cornerCutoutMargins == null) {
            lp.leftMargin = 0;
            lp.rightMargin = 0;
            return;
        }
        lp.leftMargin = cornerCutoutMargins.first;
        lp.rightMargin = cornerCutoutMargins.second;

        // If we're already inset enough (e.g. on the status bar side), we can have 0 margin
        WindowInsets insets = getRootWindowInsets();
        int leftInset = insets.getSystemWindowInsetLeft();
        int rightInset = insets.getSystemWindowInsetRight();
        if (lp.leftMargin <= leftInset) {
            lp.leftMargin = 0;
        }
        if (lp.rightMargin <= rightInset) {
            lp.rightMargin = 0;
        }
    }

    /**
     * Returns a Pair of integers where
     *  - Pair.first is the left margin inset
     *  - Pair.second is the right margin inset
     */
    public static Pair<Integer, Integer> cornerCutoutMargins(DisplayCutout cutout,
            Display display) {
        return cornerCutoutMargins(cutout, display, RotationUtils.ROTATION_NONE, -1);
    }

    private static Pair<Integer, Integer> cornerCutoutMargins(DisplayCutout cutout,
            Display display, int rotationOrientation, int statusBarHeight) {
        if (cutout == null) {
            return null;
        }
        Point size = new Point();
        display.getRealSize(size);

        if (rotationOrientation != RotationUtils.ROTATION_NONE) {
            return new Pair<>(cutout.getSafeInsetLeft(), cutout.getSafeInsetRight());
        }

        Rect bounds = new Rect();
        boundsFromDirection(cutout, Gravity.TOP, bounds);

        if (statusBarHeight >= 0 && bounds.top > statusBarHeight) {
            return null;
        }

        if (bounds.left <= 0) {
            return new Pair<>(bounds.right, 0);
        }

        if (bounds.right >= size.x) {
            return new Pair<>(0, size.x - bounds.left);
        }

        return null;
    }

    public void setHeadsUpVisible(boolean headsUpVisible) {
        mHeadsUpVisible = headsUpVisible;
        updateVisibility();
    }

    @Override
    protected boolean shouldPanelBeVisible() {
        return mHeadsUpVisible || super.shouldPanelBeVisible();
    }

    @Override
    public void onTuningChanged(String key, String newValue) {
        if (LEFT_PADDING.equals(key)) {
            int mLPadding = TunerService.parseInteger(newValue, 0);
            mLeftPad = Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, mLPadding,
                getResources().getDisplayMetrics()));
            updateResources();
        } else if (RIGHT_PADDING.equals(key)) {
            int mRPadding = TunerService.parseInteger(newValue, 0);
            mRightPad = Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, mRPadding,
                getResources().getDisplayMetrics()));
            updateResources();
        } else if (TOP_PADDING.equals(key)) {
            int mTPadding = TunerService.parseInteger(newValue, 0);
            mTopPad = Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, mTPadding,
                getResources().getDisplayMetrics()));
            updateResources();
        }
    }
}
