/*
 * Copyright (C) 2012 The Android Open Source Project
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

package com.android.keyguard;

import android.content.Context;
import android.os.AsyncTask;
import android.os.UserHandle;
import android.provider.Settings;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.LinearLayout;

import com.android.keyguard.KeyguardSecurityModel.SecurityMode;
import com.android.internal.widget.LockPatternUtils;
import com.android.internal.widget.LockPatternUtils.RequestThrottledException;
import com.android.keyguard.PasswordTextView.QuickUnlockListener;
import com.android.settingslib.animation.AppearAnimationUtils;
import com.android.settingslib.animation.DisappearAnimationUtils;
import com.android.systemui.R;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Displays a PIN pad for unlocking.
 */
public class KeyguardPINView extends KeyguardPinBasedInputView {

    private final AppearAnimationUtils mAppearAnimationUtils;
    private final DisappearAnimationUtils mDisappearAnimationUtils;
    private final DisappearAnimationUtils mDisappearAnimationUtilsLocked;
    private ViewGroup mContainer;
    private ViewGroup mRow0;
    private ViewGroup mRow1;
    private ViewGroup mRow2;
    private ViewGroup mRow3;
    private View mDivider;
    private int mDisappearYTranslation;
    private View[][] mViews;
    private final KeyguardUpdateMonitor mKeyguardUpdateMonitor;

    private static List<Integer> sNumbers = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);

    private final int userId = KeyguardUpdateMonitor.getCurrentUser();

    public KeyguardPINView(Context context) {
        this(context, null);
    }

    public KeyguardPINView(Context context, AttributeSet attrs) {
        super(context, attrs);
        mAppearAnimationUtils = new AppearAnimationUtils(context);
        mDisappearAnimationUtils = new DisappearAnimationUtils(context,
                125, 0.6f /* translationScale */,
                0.45f /* delayScale */, AnimationUtils.loadInterpolator(
                        mContext, android.R.interpolator.fast_out_linear_in));
        mDisappearAnimationUtilsLocked = new DisappearAnimationUtils(context,
                (long) (125 * KeyguardPatternView.DISAPPEAR_MULTIPLIER_LOCKED),
                0.6f /* translationScale */,
                0.45f /* delayScale */, AnimationUtils.loadInterpolator(
                        mContext, android.R.interpolator.fast_out_linear_in));
        mDisappearYTranslation = getResources().getDimensionPixelSize(
                R.dimen.disappear_y_translation);
        mKeyguardUpdateMonitor = KeyguardUpdateMonitor.getInstance(context);
    }

    @Override
    protected void resetState() {
        super.resetState();
        if (mSecurityMessageDisplay != null) {
            mSecurityMessageDisplay.setMessage("");
        }
    }

    @Override
    protected int getPasswordTextViewId() {
        return R.id.pinEntry;
    }

    @Override
    protected void onFinishInflate() {
        super.onFinishInflate();

        mContainer = findViewById(R.id.container);
        mRow0 = findViewById(R.id.row0);
        mRow1 = findViewById(R.id.row1);
        mRow2 = findViewById(R.id.row2);
        mRow3 = findViewById(R.id.row3);
        mDivider = findViewById(R.id.divider);
        mViews = new View[][]{
                new View[]{
                        mRow0, null, null
                },
                new View[]{
                        findViewById(R.id.key1), findViewById(R.id.key2),
                        findViewById(R.id.key3)
                },
                new View[]{
                        findViewById(R.id.key4), findViewById(R.id.key5),
                        findViewById(R.id.key6)
                },
                new View[]{
                        findViewById(R.id.key7), findViewById(R.id.key8),
                        findViewById(R.id.key9)
                },
                new View[]{
                        findViewById(R.id.delete_button), findViewById(R.id.key0),
                        findViewById(R.id.key_enter)
                },
                new View[]{
                        null, mEcaView, null
                }};

        View cancelBtn = findViewById(R.id.cancel_button);
        if (cancelBtn != null) {
            cancelBtn.setOnClickListener(view -> {
                mCallback.reset();
                mCallback.onCancelClicked();
            });
        }

        boolean scramblePin = (Settings.System.getIntForUser(getContext().getContentResolver(),
                Settings.System.LOCKSCREEN_PIN_SCRAMBLE_LAYOUT, 0, UserHandle.USER_CURRENT) == 1);
        if (scramblePin) {
            Collections.shuffle(sNumbers);
            // get all children who are NumPadKey's
            LinearLayout container = (LinearLayout) findViewById(R.id.container);
            List<NumPadKey> views = new ArrayList<NumPadKey>();
            for (int i = 0; i < container.getChildCount(); i++) {
                if (container.getChildAt(i) instanceof LinearLayout) {
                    LinearLayout nestedLayout = ((LinearLayout) container.getChildAt(i));
                    for (int j = 0; j < nestedLayout.getChildCount(); j++){
                        View view = nestedLayout.getChildAt(j);
                        if (view.getClass() == NumPadKey.class) {
                            views.add((NumPadKey) view);
                        }
                    }
                }
            }
            // reset the digits in the views
            for (int i = 0; i < sNumbers.size(); i++) {
                NumPadKey view = views.get(i);
                view.setDigit(sNumbers.get(i));
            }
        }

        boolean quickUnlock = (Settings.System.getIntForUser(getContext().getContentResolver(),
                Settings.System.LOCKSCREEN_QUICK_UNLOCK_CONTROL, 0, UserHandle.USER_CURRENT) == 1);

        if (quickUnlock) {
            mPasswordEntry.setQuickUnlockListener(new QuickUnlockListener() {
                public void onValidateQuickUnlock(String password) {
                    if (password != null && password.length() == keyguardPinPasswordLength()) {
                        validateQuickUnlock(mLockPatternUtils, password, userId);
                    }
                }
            });
        } else {
            mPasswordEntry.setQuickUnlockListener(null);
        }
    }

    @Override
    public void showUsabilityHint() {
    }

    @Override
    public int getWrongPasswordStringId() {
        return R.string.kg_wrong_pin;
    }

    @Override
    public void startAppearAnimation() {
        enableClipping(false);
        setAlpha(1f);
        setTranslationY(mAppearAnimationUtils.getStartTranslation());
        AppearAnimationUtils.startTranslationYAnimation(this, 0 /* delay */, 500 /* duration */,
                0, mAppearAnimationUtils.getInterpolator());
        mAppearAnimationUtils.startAnimation2d(mViews,
                new Runnable() {
                    @Override
                    public void run() {
                        enableClipping(true);
                    }
                });
    }

    @Override
    public boolean startDisappearAnimation(final Runnable finishRunnable) {
        enableClipping(false);
        setTranslationY(0);
        AppearAnimationUtils.startTranslationYAnimation(this, 0 /* delay */, 280 /* duration */,
                mDisappearYTranslation, mDisappearAnimationUtils.getInterpolator());
        DisappearAnimationUtils disappearAnimationUtils = mKeyguardUpdateMonitor
                .needsSlowUnlockTransition()
                        ? mDisappearAnimationUtilsLocked
                        : mDisappearAnimationUtils;
        disappearAnimationUtils.startAnimation2d(mViews,
                new Runnable() {
                    @Override
                    public void run() {
                        enableClipping(true);
                        if (finishRunnable != null) {
                            finishRunnable.run();
                        }
                    }
                });
        return true;
    }

    private void enableClipping(boolean enable) {
        mContainer.setClipToPadding(enable);
        mContainer.setClipChildren(enable);
        mRow1.setClipToPadding(enable);
        mRow2.setClipToPadding(enable);
        mRow3.setClipToPadding(enable);
        setClipChildren(enable);
    }

    @Override
    public boolean hasOverlappingRendering() {
        return false;
    }

    private AsyncTask<?, ?, ?> validateQuickUnlock(final LockPatternUtils utils,
            final String password,
            final int userId) {
        AsyncTask<Void, Void, Boolean> task = new AsyncTask<Void, Void, Boolean>() {

            @Override
            protected Boolean doInBackground(Void... args) {
                try {
                    return utils.checkPassword(password, userId);
                } catch (RequestThrottledException ex) {
                    return false;
                }
            }

            @Override
            protected void onPostExecute(Boolean result) {
                runQuickUnlock(result);
            }
        };
        task.execute();
        return task;
    }

    private void runQuickUnlock(Boolean matched) {
        if (matched) {
            mPasswordEntry.setEnabled(false);
            mCallback.reportUnlockAttempt(userId, true, 0);
            mCallback.dismiss(true, userId, getSecurityMode());
            resetPasswordText(true, true);
        }
    }

    private int keyguardPinPasswordLength() {
        int pinPasswordLength = -1;
        try {
            pinPasswordLength = (int) mLockPatternUtils.getLockSettings().getLong("lockscreen.pin_password_length", -1, userId);
        } catch (Exception e) {
            // do nothing
        }
        return pinPasswordLength >= 4 ? pinPasswordLength : -1;
    }

    @Override
    public SecurityMode getSecurityMode() {
        return SecurityMode.PIN;
    }
}
