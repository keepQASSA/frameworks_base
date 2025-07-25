/*
 * Copyright (C) 2015 The Android Open Source Project
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

package com.android.systemui.volume;

import static android.app.ActivityManager.LOCK_TASK_MODE_NONE;
import static android.media.AudioManager.RINGER_MODE_NORMAL;
import static android.media.AudioManager.RINGER_MODE_SILENT;
import static android.media.AudioManager.RINGER_MODE_VIBRATE;
import static android.media.AudioManager.STREAM_ACCESSIBILITY;
import static android.media.AudioManager.STREAM_ALARM;
import static android.media.AudioManager.STREAM_MUSIC;
import static android.media.AudioManager.STREAM_NOTIFICATION;
import static android.media.AudioManager.STREAM_RING;
import static android.media.AudioManager.STREAM_VOICE_CALL;
import static android.view.View.ACCESSIBILITY_LIVE_REGION_POLITE;
import static android.view.View.GONE;
import static android.view.View.INVISIBLE;
import static android.view.View.VISIBLE;
import static android.view.ViewGroup.LayoutParams.WRAP_CONTENT;

import static com.android.settingslib.media.MediaOutputSliceConstants.ACTION_MEDIA_OUTPUT;
import static com.android.systemui.volume.Events.DISMISS_REASON_SETTINGS_CLICKED;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.app.Dialog;
import android.app.KeyguardManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothProfile;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.ColorMatrix;
import android.graphics.ColorMatrixColorFilter;
import android.graphics.PixelFormat;
import android.graphics.Region;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.media.AudioManager;
import android.media.AudioSystem;
import android.media.AppTrackData;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.SystemClock;
import android.os.VibrationEffect;
import android.provider.Settings;
import android.provider.Settings.Global;
import android.text.InputFilter;
import android.util.Log;
import android.util.Slog;
import android.util.SparseBooleanArray;
import android.view.ContextThemeWrapper;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.AccessibilityDelegate;
import android.view.ViewGroup;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.ViewPropertyAnimator;
import android.view.ViewStub;
import android.view.ViewTreeObserver;
import android.view.ViewTreeObserver.InternalInsetsInfo;
import android.view.ViewTreeObserver.OnComputeInternalInsetsListener;
import android.view.Window;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.SeekBar;
import android.widget.SeekBar.OnSeekBarChangeListener;
import android.widget.TextView;
import android.widget.Toast;

import com.android.settingslib.Utils;
import com.android.systemui.Dependency;
import com.android.systemui.Prefs;
import com.android.systemui.R;
import com.android.systemui.plugins.ActivityStarter;
import com.android.systemui.plugins.VolumeDialog;
import com.android.systemui.plugins.VolumeDialogController;
import com.android.systemui.plugins.VolumeDialogController.State;
import com.android.systemui.plugins.VolumeDialogController.StreamState;
import com.android.systemui.statusbar.phone.ExpandableIndicator;
import com.android.systemui.statusbar.policy.AccessibilityManagerWrapper;
import com.android.systemui.statusbar.policy.ConfigurationController;
import com.android.systemui.statusbar.policy.DeviceProvisionedController;
import com.android.systemui.tuner.TunerService;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Visual presentation of the volume dialog.
 *
 * A client of VolumeDialogControllerImpl and its state model.
 *
 * Methods ending in "H" must be called on the (ui) handler.
 */
public class VolumeDialogImpl implements VolumeDialog,
        ConfigurationController.ConfigurationListener {
    private static final String TAG = Util.logTag(VolumeDialogImpl.class);

    private static final long USER_ATTEMPT_GRACE_PERIOD = 1000;
    private static final int UPDATE_ANIMATION_DURATION = 80;

    public static final String SHOW_APP_VOLUME =
            "system:" + Settings.System.SHOW_APP_VOLUME;

    static final int DIALOG_TIMEOUT_MILLIS = 3000;
    static final int DIALOG_SAFETYWARNING_TIMEOUT_MILLIS = 5000;
    static final int DIALOG_ODI_CAPTIONS_TOOLTIP_TIMEOUT_MILLIS = 5000;
    static final int DIALOG_HOVERING_TIMEOUT_MILLIS = 16000;
    static final int DIALOG_SHOW_ANIMATION_DURATION = 300;
    static final int DIALOG_HIDE_ANIMATION_DURATION = 250;

    private final Context mContext;
    private WindowManager mWindowManager;
    private WindowManager.LayoutParams mWindowParams;
    private final H mHandler = new H();
    private final VolumeDialogController mController;
    private final DeviceProvisionedController mDeviceProvisionedController;

    private View mDialog;
    private ViewGroup mDialogView;
    private ViewGroup mDialogMainView;
    private ViewGroup mDialogRowsView;
    private ViewGroup mRinger;
    private ImageButton mRingerIcon;
    private FrameLayout mODICaptionsView;
    private CaptionsToggleImageButton mODICaptionsIcon;
    private View mMediaOutputView;
    private ImageButton mMediaOutputIcon;
    private View mExpandRowsView;
    private ExpandableIndicator mExpandRows;
    private FrameLayout mZenIcon;
    private final List<VolumeRow> mRows = new ArrayList<>();
    private final List<VolumeRow> mAppRows = new ArrayList<>();
    private ConfigurableTexts mConfigurableTexts;
    private final SparseBooleanArray mDynamic = new SparseBooleanArray();
    private final KeyguardManager mKeyguard;
    private final ActivityManager mActivityManager;
    private final AccessibilityManagerWrapper mAccessibilityMgr;
    private final Object mSafetyWarningLock = new Object();
    private final Accessibility mAccessibility = new Accessibility();

    private final ColorFilter mAppIconMuteColorFilter;

    private boolean mShowing;
    private boolean mShowA11yStream;

    private int mActiveStream;
    private int mAllyStream;
    private int mPrevActiveStream;
    private boolean mAutomute = VolumePrefs.DEFAULT_ENABLE_AUTOMUTE;
    private boolean mMusicHidden;
    private boolean mSilentMode = VolumePrefs.DEFAULT_ENABLE_SILENT_MODE;
    private State mState;
    private SafetyWarningDialog mSafetyWarning;
    private boolean mHovering = false;
    private boolean mShowActiveStreamOnly;
    private boolean mConfigChanged = false;
    private boolean mHasSeenODICaptionsTooltip;
    private ViewStub mODICaptionsTooltipViewStub;
    private View mODICaptionsTooltipView = null;

    private boolean mShowAppVolume;

    // Volume panel placement left or right
    private boolean mVolumePanelOnLeft;

    private boolean mExpanded;

    private boolean mHasAlertSlider;

    // Variable to track the default row with which the panel is initially shown
    private VolumeRow mDefaultRow = null;

    public VolumeDialogImpl(Context context) {
        mContext =
                new ContextThemeWrapper(context, R.style.qs_theme);
        mController = Dependency.get(VolumeDialogController.class);
        mKeyguard = (KeyguardManager) mContext.getSystemService(Context.KEYGUARD_SERVICE);
        mActivityManager = (ActivityManager) mContext.getSystemService(Context.ACTIVITY_SERVICE);
        mWindowManager = (WindowManager) mContext.getSystemService(Context.WINDOW_SERVICE);
        mAccessibilityMgr = Dependency.get(AccessibilityManagerWrapper.class);
        mDeviceProvisionedController = Dependency.get(DeviceProvisionedController.class);
        mShowActiveStreamOnly = showActiveStreamOnly();
        mHasSeenODICaptionsTooltip =
                Prefs.getBoolean(context, Prefs.Key.HAS_SEEN_ODI_CAPTIONS_TOOLTIP, false);
        mVolumePanelOnLeft = mContext.getResources().getBoolean(R.bool.config_audioPanelOnLeftSide);
        mHasAlertSlider = mContext.getResources().getBoolean(com.android.internal.R.bool.config_hasAlertSlider);
        Dependency.get(TunerService.class).addTunable(mTunable, SHOW_APP_VOLUME);
        ColorMatrix colorMatrix = new ColorMatrix();
        colorMatrix.setSaturation(0);
        mAppIconMuteColorFilter = new ColorMatrixColorFilter(colorMatrix);
    }

    @Override
    public void onUiModeChanged() {
        mContext.getTheme().applyStyle(mContext.getThemeResId(), true);
    }

    public void init(int windowType, Callback callback) {
        initDialog();

        mAccessibility.init();

        mController.addCallback(mControllerCallbackH, mHandler);
        mController.getState();

        Dependency.get(ConfigurationController.class).addCallback(this);
    }

    @Override
    public void destroy() {
        mController.removeCallback(mControllerCallbackH);
        mHandler.removeCallbacksAndMessages(null);
        Dependency.get(ConfigurationController.class).removeCallback(this);
    }

    private void initDialog() {
        int land_margin = (int) mContext.getResources().getDimension(
                R.dimen.volume_dialog_panel_land_margin);

        // Gravitate various views left/right depending on panel placement setting.
        final int panelGravity = mVolumePanelOnLeft ? Gravity.LEFT : Gravity.RIGHT;

        mConfigurableTexts = new ConfigurableTexts(mContext);
        mHovering = false;
        mShowing = false;
        mExpanded = false;
        mWindowParams = new WindowManager.LayoutParams();
        mWindowParams.flags &= ~WindowManager.LayoutParams.FLAG_DIM_BEHIND;
        mWindowParams.flags &= ~WindowManager.LayoutParams.FLAG_LAYOUT_INSET_DECOR;
        mWindowParams.flags |= WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
                | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
                | WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED
                | WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH
                | WindowManager.LayoutParams.FLAG_HARDWARE_ACCELERATED;
        mWindowParams.type = WindowManager.LayoutParams.TYPE_VOLUME_OVERLAY;
        mWindowParams.format = PixelFormat.TRANSLUCENT;
        mWindowParams.windowAnimations = -1;
        mDialog = LayoutInflater.from(mContext).inflate(R.layout.volume_dialog,
                (ViewGroup) null, false);

        mDialog.setOnTouchListener((v, event) -> {
            if (mShowing) {
                switch (event.getAction()) {
                    case MotionEvent.ACTION_OUTSIDE:
                    case MotionEvent.ACTION_DOWN:
                        dismissH(Events.DISMISS_REASON_TOUCH_OUTSIDE);
                        return true;
                }
            }
            return false;
        });

        mDialogView = mDialog.findViewById(R.id.volume_dialog);
        mDialogView.setAlpha(0);
        mDialogView.setLayoutDirection(mVolumePanelOnLeft ?
                View.LAYOUT_DIRECTION_LTR : View.LAYOUT_DIRECTION_RTL);

        mDialogView.setOnHoverListener((v, event) -> {
            int action = event.getActionMasked();
            mHovering = (action == MotionEvent.ACTION_HOVER_ENTER)
                    || (action == MotionEvent.ACTION_HOVER_MOVE);
            rescheduleTimeoutH();
            return true;
        });

        FrameLayout.LayoutParams dialogViewLP =
                (FrameLayout.LayoutParams) mDialogView.getLayoutParams();
        dialogViewLP.gravity = Gravity.CENTER_VERTICAL;
        mDialogView.setLayoutParams(dialogViewLP);

        mDialogMainView = mDialog.findViewById(R.id.main);
        if (mDialogMainView != null) {
            setLayoutGravity(mDialogMainView.getLayoutParams(), panelGravity);
        }

        mDialogRowsView = mDialog.findViewById(R.id.volume_dialog_rows);
        mRinger = mDialog.findViewById(R.id.ringer);
        if (mRinger != null) {
            mRingerIcon = mRinger.findViewById(R.id.ringer_icon);
            mZenIcon = mRinger.findViewById(R.id.dnd_icon);
            if(isLandscape() && mVolumePanelOnLeft){
                MarginLayoutParams ringerLayoutParams = (MarginLayoutParams) mRinger.getLayoutParams();
                ringerLayoutParams.setMargins(0, 0, land_margin, 0);
                mRinger.setLayoutParams(ringerLayoutParams);
            }
            // Apply ringer layout gravity based on panel left/right setting
            // Layout type is different between landscape/portrait.
            setLayoutGravity(mRinger.getLayoutParams(), panelGravity);
        }

        mODICaptionsView = mDialog.findViewById(R.id.odi_captions);
        if (mODICaptionsView != null) {
            mODICaptionsIcon = mODICaptionsView.findViewById(R.id.odi_captions_icon);
            if(isLandscape()){
                setLayoutGravity(mODICaptionsView.getLayoutParams(), panelGravity);
                MarginLayoutParams captionsLayoutParams = (MarginLayoutParams) mODICaptionsView.getLayoutParams();
                if(mVolumePanelOnLeft){
                    captionsLayoutParams.setMargins(land_margin, 0, 0, 0);
                }
                mODICaptionsView.setLayoutParams(captionsLayoutParams);
            }else{
                setLayoutGravity(mODICaptionsView.getLayoutParams(), panelGravity);
            }
        }
        mODICaptionsTooltipViewStub = mDialog.findViewById(mVolumePanelOnLeft ?
                R.id.odi_captions_tooltip_stub_left :
                R.id.odi_captions_tooltip_stub);
        if (mHasSeenODICaptionsTooltip && mODICaptionsTooltipViewStub != null) {
            mDialogView.removeView(mODICaptionsTooltipViewStub);
            mODICaptionsTooltipViewStub = null;
        }

        if(isLandscape() && mVolumePanelOnLeft){
            LinearLayout mainView = mDialog.findViewById(R.id.main);
            MarginLayoutParams mainLayoutParams = (MarginLayoutParams) mainView.getLayoutParams();
            mainLayoutParams.setMargins(0, land_margin, land_margin, 0);
            mainView.setLayoutParams(mainLayoutParams);
        }

        mMediaOutputView = mDialog.findViewById(R.id.media_output_container);
        mMediaOutputIcon = mDialog.findViewById(R.id.media_output);
        if (mMediaOutputIcon != null) {
            setLayoutGravity(mMediaOutputIcon.getLayoutParams(), panelGravity);
        }

        mExpandRowsView = mDialog.findViewById(R.id.expandable_indicator_container);
        mExpandRows = mDialog.findViewById(R.id.expandable_indicator);
        if (mExpandRows != null) {
            setLayoutGravity(mExpandRows.getLayoutParams(), panelGravity);
            mExpandRows.setRotation(mVolumePanelOnLeft ? -90 : 90);
        }

        if (mHasAlertSlider) {
            mRinger.setVisibility(View.GONE);
        }

        if (mRows.isEmpty()) {
            if (!AudioSystem.isSingleVolume(mContext)) {
                addRow(STREAM_ACCESSIBILITY, R.drawable.ic_volume_accessibility,
                        R.drawable.ic_volume_accessibility, true, false);
            }
            addRow(AudioManager.STREAM_MUSIC,
                    R.drawable.ic_volume_media, R.drawable.ic_volume_media_mute, true, true);
            if (!AudioSystem.isSingleVolume(mContext)) {
                if (Util.isVoiceCapable(mContext)) {
                    addRow(AudioManager.STREAM_RING, R.drawable.ic_volume_ringer,
                            R.drawable.ic_volume_ringer_mute, true, false);
                } else {
                    addRow(AudioManager.STREAM_RING, R.drawable.ic_volume_notification,
                            R.drawable.ic_volume_notification_mute, true, false);
                }
                addRow(STREAM_ALARM,
                        R.drawable.ic_volume_alarm, R.drawable.ic_volume_alarm_mute, true, false);
                addRow(AudioManager.STREAM_VOICE_CALL,
                        com.android.internal.R.drawable.ic_phone,
                        com.android.internal.R.drawable.ic_phone, false, false);
                addRow(AudioManager.STREAM_BLUETOOTH_SCO,
                        R.drawable.ic_volume_bt_sco, R.drawable.ic_volume_bt_sco, false, false);
                addRow(AudioManager.STREAM_SYSTEM, R.drawable.ic_volume_system,
                        R.drawable.ic_volume_system_mute, false, false);
            }
        } else {
            addExistingRows();
        }

        updateRowsH(getActiveRow());
        initRingerH();
        initSettingsH();
        initODICaptionsH();

        mAllyStream = -1;
        mMusicHidden = false;
    }

    private final OnComputeInternalInsetsListener mInsetsListener = internalInsetsInfo -> {
        internalInsetsInfo.touchableRegion.setEmpty();
        internalInsetsInfo.setTouchableInsets(InternalInsetsInfo.TOUCHABLE_INSETS_REGION);
        int[] dialogLocation = new int[2];
        mDialogView.getLocationInWindow(dialogLocation);
        internalInsetsInfo.touchableRegion.set(new Region(
                dialogLocation[0],
                dialogLocation[1],
                dialogLocation[0] + mDialogView.getWidth(),
                dialogLocation[1] + mDialogView.getHeight()
        ));
    };

    // Helper to set layout gravity.
    // Particular useful when the ViewGroup in question
    // is different for portait vs landscape.
    private void setLayoutGravity(Object obj, int gravity) {
        if (obj instanceof FrameLayout.LayoutParams) {
            ((FrameLayout.LayoutParams) obj).gravity = gravity;
        } else if (obj instanceof LinearLayout.LayoutParams) {
            ((LinearLayout.LayoutParams) obj).gravity = gravity;
        }
    }

    private float getAnimatorX() {
        final float x = mDialogView.getWidth() / 2.0f;
        return mVolumePanelOnLeft ? -x : x;
    }

    private final TunerService.Tunable mTunable = new TunerService.Tunable() {
        @Override
        public void onTuningChanged(String key, String newValue) {
            if (key.equals(SHOW_APP_VOLUME)) {
                final boolean showAppVolume = TunerService.parseIntegerSwitch(newValue, false);
                if (mShowAppVolume != showAppVolume) {
                    mShowAppVolume = showAppVolume;
                    mHandler.post(() -> {
                        mControllerCallbackH.onConfigurationChanged();
                    });
                }
            }
        }
    };

    protected ViewGroup getDialogView() {
        return mDialogView;
    }

    private int getAlphaAttr(int attr) {
        TypedArray ta = mContext.obtainStyledAttributes(new int[]{attr});
        float alpha = ta.getFloat(0, 0);
        ta.recycle();
        return (int) (alpha * 255);
    }

    private boolean isLandscape() {
        return mContext.getResources().getConfiguration().orientation ==
                Configuration.ORIENTATION_LANDSCAPE;
    }

    public void setStreamImportant(int stream, boolean important) {
        mHandler.obtainMessage(H.SET_STREAM_IMPORTANT, stream, important ? 1 : 0).sendToTarget();
    }

    public void setAutomute(boolean automute) {
        if (mAutomute == automute) return;
        mAutomute = automute;
        mHandler.sendEmptyMessage(H.RECHECK_ALL);
    }

    public void setSilentMode(boolean silentMode) {
        if (mSilentMode == silentMode) return;
        mSilentMode = silentMode;
        mHandler.sendEmptyMessage(H.RECHECK_ALL);
    }

    private void addRow(int stream, int iconRes, int iconMuteRes, boolean important,
            boolean defaultStream) {
        addRow(stream, iconRes, iconMuteRes, important, defaultStream, false);
    }

    private void addRow(int stream, int iconRes, int iconMuteRes, boolean important,
            boolean defaultStream, boolean dynamic) {
        if (D.BUG) Slog.d(TAG, "Adding row for stream " + stream);
        VolumeRow row = new VolumeRow();
        initRow(row, stream, iconRes, iconMuteRes, important, defaultStream);
        mDialogRowsView.addView(row.view);
        mRows.add(row);
    }

    private void addAppRow(AppTrackData data) {
        VolumeRow row = new VolumeRow();
        initAppRow(row, data);
        mDialogRowsView.addView(row.view);
        mAppRows.add(row);
    }

    @SuppressLint("InflateParams")
    private void initAppRow(final VolumeRow row, final AppTrackData data) {
        row.view = LayoutInflater.from(mContext).inflate(R.layout.volume_dialog_row, null);

        row.packageName = data.getPackageName();
        row.isAppVolumeRow = true;

        row.view.setTag(row);
        row.slider = row.view.findViewById(R.id.volume_row_slider);
        row.slider.setOnSeekBarChangeListener(new VolumeSeekBarChangeListener(row));

        row.appMuted = data.isMuted();
        row.slider.setProgress((int) (data.getVolume() * 100));

        row.dndIcon = row.view.findViewById(R.id.dnd_icon);
        row.dndIcon.setVisibility(View.GONE);

        row.icon = row.view.findViewById(R.id.volume_row_app_icon);
        row.icon.setVisibility(View.VISIBLE);
        PackageManager pm = mContext.getPackageManager();
        try {
            row.icon.setImageDrawable(pm.getApplicationIcon(row.packageName));
        } catch (PackageManager.NameNotFoundException e) {
            row.icon.setImageDrawable(pm.getDefaultActivityIcon());
            Log.e(TAG, "Failed to get icon of " + row.packageName, e);
        }

        row.icon.setColorFilter(row.appMuted ? mAppIconMuteColorFilter : null);

        row.icon.setOnClickListener(v -> {
                rescheduleTimeoutH();
                AudioManager audioManager = mController.getAudioManager();
                row.appMuted = !row.appMuted;
                audioManager.setAppMute(row.packageName, row.appMuted);
                row.icon.setColorFilter(row.appMuted ? mAppIconMuteColorFilter : null);
        });
    }

    private void addExistingRows() {
        int N = mRows.size();
        for (int i = 0; i < N; i++) {
            final VolumeRow row = mRows.get(i);
            initRow(row, row.stream, row.iconRes, row.iconMuteRes, row.important,
                    row.defaultStream);
            mDialogRowsView.addView(row.view);
            updateVolumeRowH(row);
        }
    }

    private VolumeRow getActiveRow() {
        for (VolumeRow row : mRows) {
            if (row.stream == mActiveStream) {
                return row;
            }
        }
        for (VolumeRow row : mRows) {
            if (row.stream == STREAM_MUSIC) {
                return row;
            }
        }
        return mRows.get(0);
    }

    private VolumeRow findRow(int stream) {
        for (VolumeRow row : mRows) {
            if (row.stream == stream) return row;
        }
        return null;
    }

    public void dump(PrintWriter writer) {
        writer.println(VolumeDialogImpl.class.getSimpleName() + " state:");
        writer.print("  mShowing: "); writer.println(mShowing);
        writer.print("  mActiveStream: "); writer.println(mActiveStream);
        writer.print("  mDynamic: "); writer.println(mDynamic);
        writer.print("  mAutomute: "); writer.println(mAutomute);
        writer.print("  mSilentMode: "); writer.println(mSilentMode);
    }

    private static int getImpliedLevel(SeekBar seekBar, int progress) {
        final int m = seekBar.getMax();
        final int n = m / 100 - 1;
        final int level = progress == 0 ? 0
                : progress == m ? (m / 100) : (1 + (int)((progress / (float) m) * n));
        return level;
    }

    @SuppressLint("InflateParams")
    private void initRow(final VolumeRow row, final int stream, int iconRes, int iconMuteRes,
            boolean important, boolean defaultStream) {
        row.stream = stream;
        row.iconRes = iconRes;
        row.iconMuteRes = iconMuteRes;
        row.important = important;
        row.defaultStream = defaultStream;
        row.view = LayoutInflater.from(mContext).inflate(R.layout.volume_dialog_row, null);
        row.view.setId(row.stream);
        row.view.setTag(row);
        row.header = row.view.findViewById(R.id.volume_row_header);
        row.header.setId(20 * row.stream);
        if (stream == STREAM_ACCESSIBILITY) {
            row.header.setFilters(new InputFilter[] {new InputFilter.LengthFilter(13)});
        }
        row.dndIcon = row.view.findViewById(R.id.dnd_icon);
        row.slider = row.view.findViewById(R.id.volume_row_slider);
        row.slider.setOnSeekBarChangeListener(new VolumeSeekBarChangeListener(row));

        row.anim = null;

        row.icon = row.view.findViewById(R.id.volume_row_icon);
        row.icon.setImageResource(iconRes);
        row.icon.setVisibility(View.VISIBLE);
        if (row.stream != AudioSystem.STREAM_ACCESSIBILITY) {
            row.icon.setOnClickListener(v -> {
                rescheduleTimeoutH();
                Events.writeEvent(mContext, Events.EVENT_ICON_CLICK, row.stream, row.iconState);
                mController.setActiveStream(row.stream);
                final boolean vmute = row.ss.level == row.ss.levelMin;
                mController.setStreamVolume(stream,
                        vmute ? row.lastAudibleLevel : row.ss.levelMin);
                row.userAttempt = 0;  // reset the grace period, slider updates immediately
            });
        } else {
            row.icon.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        }
    }

    private boolean isNotificationVolumeLinked() {
        ContentResolver cr = mContext.getContentResolver();
        return Settings.System.getInt(cr, Settings.System.VOLUME_LINK_NOTIFICATION, 1) == 1;
    }

    private static boolean isBluetoothA2dpConnected() {
        BluetoothAdapter mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        return mBluetoothAdapter != null && mBluetoothAdapter.isEnabled()
                && mBluetoothAdapter.getProfileConnectionState(BluetoothProfile.A2DP)
                == BluetoothProfile.STATE_CONNECTED;
    }

    private void setVisOrGone(int stream, boolean vis) {
        if (!vis && stream == mAllyStream) {
            return;
        }
        Util.setVisOrGone(findRow(stream).view, vis);
    }

    private void updateExpandedRows(boolean expand) {
        if (!expand) mController.setActiveStream(mAllyStream);
        if (mMusicHidden) {
            setVisOrGone(AudioManager.STREAM_MUSIC, expand);
        }
        setVisOrGone(AudioManager.STREAM_RING, expand);
        setVisOrGone(STREAM_ALARM, expand);
        if (!isNotificationVolumeLinked()) {
            setVisOrGone(AudioManager.STREAM_NOTIFICATION, expand);
        }
        updateAppRows(expand);
    }

    private void updateAppRows(boolean expand) {
        for (int i = mAppRows.size() - 1; i >= 0; i--) {
            final VolumeRow row = mAppRows.get(i);
            removeAppRow(row);
        }
        if (!expand) return;
        if (!mShowAppVolume) return;
        List<AppTrackData> trackDatas = mController.getAudioManager().listAppTrackDatas();
        for (AppTrackData data : trackDatas) {
            if (data.isActive()) {
                addAppRow(data);
            }
        }
    }

    private void animateExpandedRowsChange(boolean expand) {
        final int startWidth = mDialogRowsView.getLayoutParams().width;
        final int targetWidth;

        if (expand) {
            updateExpandedRows(expand);
            mDialogRowsView.measure(WRAP_CONTENT, WRAP_CONTENT);
            targetWidth = mDialogRowsView.getMeasuredWidth();
        } else {
            targetWidth = mContext.getResources().getDimensionPixelSize(
                    R.dimen.volume_dialog_panel_width);
        }

        ValueAnimator animator = ValueAnimator.ofInt(startWidth, targetWidth);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator valueAnimator) {
                mDialogRowsView.getLayoutParams().width =
                        (Integer) valueAnimator.getAnimatedValue();
                mDialogRowsView.requestLayout();
            }
        });
        animator.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                if (!expand) {
                    updateExpandedRows(expand);
                }
            }
        });
        animator.setInterpolator(expand ? new SystemUIInterpolators.LogDecelerateInterpolator()
                : new SystemUIInterpolators.LogAccelerateInterpolator());
        animator.setDuration(UPDATE_ANIMATION_DURATION);
        animator.start();
    }

    public void updateMediaOutputH() {
        if (mMediaOutputView != null) {
            mMediaOutputView.setVisibility(
                    mDeviceProvisionedController.isCurrentUserSetup() &&
                            mActivityManager.getLockTaskModeState() == LOCK_TASK_MODE_NONE &&
                            isBluetoothA2dpConnected() && mExpanded ? VISIBLE : GONE);
        }
        if (mMediaOutputIcon != null) {
            mMediaOutputIcon.setOnClickListener(v -> {
                rescheduleTimeoutH();
                Events.writeEvent(mContext, Events.EVENT_SETTINGS_CLICK);
                Intent intent = new Intent(ACTION_MEDIA_OUTPUT);
                dismissH(DISMISS_REASON_SETTINGS_CLICKED);
                Dependency.get(ActivityStarter.class).startActivity(intent,
                        true /* dismissShade */);
            });
        }
    }

    public void initSettingsH() {
        updateMediaOutputH();
        if (mAllyStream == -1) {
            mAllyStream = mActiveStream;
        }

        if (mExpandRowsView != null) {
            mExpandRowsView.setVisibility(
                    mDeviceProvisionedController.isCurrentUserSetup() &&
                            mActivityManager.getLockTaskModeState() == LOCK_TASK_MODE_NONE ?
                            VISIBLE : GONE);
        }
        if (mExpandRows != null) {
            mExpandRows.setOnClickListener(v -> {
                rescheduleTimeoutH();
                animateExpandedRowsChange(!mExpanded);

                mExpandRows.setExpanded(!mExpanded);
                mExpanded = !mExpanded;

                updateMediaOutputH();
            });
        }
    }

    public void initRingerH() {
        if (mRingerIcon != null) {
            mRingerIcon.setAccessibilityLiveRegion(ACCESSIBILITY_LIVE_REGION_POLITE);
            mRingerIcon.setOnClickListener(v -> {
                rescheduleTimeoutH();
                Prefs.putBoolean(mContext, Prefs.Key.TOUCHED_RINGER_TOGGLE, true);
                final StreamState ss = mState.states.get(AudioManager.STREAM_RING);
                if (ss == null) {
                    return;
                }
                // normal -> vibrate -> silent -> normal (skip vibrate if device doesn't have
                // a vibrator.
                int newRingerMode;
                final boolean hasVibrator = mController.hasVibrator();
                if (mState.ringerModeInternal == AudioManager.RINGER_MODE_NORMAL) {
                    if (hasVibrator) {
                        newRingerMode = AudioManager.RINGER_MODE_VIBRATE;
                    } else {
                        newRingerMode = AudioManager.RINGER_MODE_SILENT;
                    }
                } else if (mState.ringerModeInternal == AudioManager.RINGER_MODE_VIBRATE) {
                    newRingerMode = AudioManager.RINGER_MODE_SILENT;
                } else {
                    newRingerMode = AudioManager.RINGER_MODE_NORMAL;
                    if (ss.level == 0) {
                        mController.setStreamVolume(AudioManager.STREAM_RING, 1);
                    }
                }
                Events.writeEvent(mContext, Events.EVENT_RINGER_TOGGLE, newRingerMode);
                incrementManualToggleCount();
                updateRingerH();
                provideTouchFeedbackH(newRingerMode);
                mController.setRingerMode(newRingerMode, false);
                maybeShowToastH(newRingerMode);
            });
        }
        updateRingerH();
    }

    private void initODICaptionsH() {
        if (mODICaptionsIcon != null) {
            mODICaptionsIcon.setOnConfirmedTapListener(() -> {
                rescheduleTimeoutH();
                onCaptionIconClicked();
                Events.writeEvent(mContext, Events.EVENT_ODI_CAPTIONS_CLICK);
            }, mHandler);
        }

        mController.getCaptionsComponentState(false);
    }

    private void checkODICaptionsTooltip(boolean fromDismiss) {
        if (!mHasSeenODICaptionsTooltip && !fromDismiss && mODICaptionsTooltipViewStub != null) {
            mController.getCaptionsComponentState(true);
        } else {
            if (mHasSeenODICaptionsTooltip && fromDismiss && mODICaptionsTooltipView != null) {
                hideCaptionsTooltip();
            }
        }
    }

    protected void showCaptionsTooltip() {
        if (!mHasSeenODICaptionsTooltip && mODICaptionsTooltipViewStub != null) {
            mODICaptionsTooltipView = mODICaptionsTooltipViewStub.inflate();
            mODICaptionsTooltipView.findViewById(R.id.dismiss).setOnClickListener(v -> {
                rescheduleTimeoutH();
                hideCaptionsTooltip();
                Events.writeEvent(mContext, Events.EVENT_ODI_CAPTIONS_TOOLTIP_CLICK);
            });
            mODICaptionsTooltipViewStub = null;
        }

        if (mODICaptionsTooltipView != null) {
            mODICaptionsTooltipView.setAlpha(0.f);
            mODICaptionsTooltipView.animate()
                .alpha(1.f)
                .setStartDelay(DIALOG_SHOW_ANIMATION_DURATION)
                .withEndAction(() -> {
                    if (D.BUG) Log.d(TAG, "tool:checkODICaptionsTooltip() putBoolean true");
                    Prefs.putBoolean(mContext,
                            Prefs.Key.HAS_SEEN_ODI_CAPTIONS_TOOLTIP, true);
                    mHasSeenODICaptionsTooltip = true;
                    if (mODICaptionsIcon != null) {
                        mODICaptionsIcon
                                .postOnAnimation(getSinglePressFor(mODICaptionsIcon));
                    }
                })
                .start();
        }
    }

    private void hideCaptionsTooltip() {
        if (mODICaptionsTooltipView != null && mODICaptionsTooltipView.getVisibility() == VISIBLE) {
            mODICaptionsTooltipView.animate().cancel();
            mODICaptionsTooltipView.setAlpha(1.f);
            mODICaptionsTooltipView.animate()
                    .alpha(0.f)
                    .setStartDelay(0)
                    .setDuration(DIALOG_HIDE_ANIMATION_DURATION)
                    .withEndAction(() -> mODICaptionsTooltipView.setVisibility(INVISIBLE))
                    .start();
        }
    }

    protected void tryToRemoveCaptionsTooltip() {
        if (mHasSeenODICaptionsTooltip && mODICaptionsTooltipView != null) {
            ViewGroup container = mDialog.findViewById(R.id.volume_dialog_container);
            container.removeView(mODICaptionsTooltipView);
            mODICaptionsTooltipView = null;
        }
    }

    private void updateODICaptionsH(boolean isServiceComponentEnabled, boolean fromTooltip) {
        if (mODICaptionsView != null) {
            mODICaptionsView.setVisibility(isServiceComponentEnabled ? VISIBLE : GONE);
        }

        if (!isServiceComponentEnabled) return;

        updateCaptionsIcon();
        if (fromTooltip) showCaptionsTooltip();
    }

    private void updateCaptionsIcon() {
        boolean captionsEnabled = mController.areCaptionsEnabled();
        if (mODICaptionsIcon.getCaptionsEnabled() != captionsEnabled) {
            mHandler.post(mODICaptionsIcon.setCaptionsEnabled(captionsEnabled));
        }

        boolean isOptedOut = mController.isCaptionStreamOptedOut();
        if (mODICaptionsIcon.getOptedOut() != isOptedOut) {
            mHandler.post(() -> mODICaptionsIcon.setOptedOut(isOptedOut));
        }
    }

    private void onCaptionIconClicked() {
        boolean isEnabled = mController.areCaptionsEnabled();
        mController.setCaptionsEnabled(!isEnabled);
        updateCaptionsIcon();
    }

    private void incrementManualToggleCount() {
        ContentResolver cr = mContext.getContentResolver();
        int ringerCount = Settings.Secure.getInt(cr, Settings.Secure.MANUAL_RINGER_TOGGLE_COUNT, 0);
        Settings.Secure.putInt(cr, Settings.Secure.MANUAL_RINGER_TOGGLE_COUNT, ringerCount + 1);
    }

    private void provideTouchFeedbackH(int newRingerMode) {
        VibrationEffect effect = null;
        switch (newRingerMode) {
            case RINGER_MODE_NORMAL:
                mController.scheduleTouchFeedback();
                break;
            case RINGER_MODE_SILENT:
                effect = VibrationEffect.get(VibrationEffect.EFFECT_CLICK);
                break;
            case RINGER_MODE_VIBRATE:
            default:
                effect = VibrationEffect.get(VibrationEffect.EFFECT_DOUBLE_CLICK);
        }
        if (effect != null) {
            mController.vibrate(effect);
        }
    }

    private void maybeShowToastH(int newRingerMode) {
        int seenToastCount = Prefs.getInt(mContext, Prefs.Key.SEEN_RINGER_GUIDANCE_COUNT, 0);

        if (seenToastCount > VolumePrefs.SHOW_RINGER_TOAST_COUNT) {
            return;
        }
        CharSequence toastText = null;
        switch (newRingerMode) {
            case RINGER_MODE_NORMAL:
                final StreamState ss = mState.states.get(AudioManager.STREAM_RING);
                if (ss != null) {
                    toastText = mContext.getString(
                            R.string.volume_dialog_ringer_guidance_ring,
                            Utils.formatPercentage(ss.level, ss.levelMax));
                }
                break;
            case RINGER_MODE_SILENT:
                toastText = mContext.getString(
                        com.android.internal.R.string.volume_dialog_ringer_guidance_silent);
                break;
            case RINGER_MODE_VIBRATE:
            default:
                toastText = mContext.getString(
                        com.android.internal.R.string.volume_dialog_ringer_guidance_vibrate);
        }

        Toast.makeText(mContext, toastText, Toast.LENGTH_SHORT).show();
        seenToastCount++;
        Prefs.putInt(mContext, Prefs.Key.SEEN_RINGER_GUIDANCE_COUNT, seenToastCount);
    }

    public void show(int reason) {
        mHandler.obtainMessage(H.SHOW, reason, 0).sendToTarget();
    }

    public void dismiss(int reason) {
        mHandler.obtainMessage(H.DISMISS, reason, 0).sendToTarget();
    }

    private void showH(int reason) {
        if (D.BUG) Log.d(TAG, "showH r=" + Events.SHOW_REASONS[reason]);
        mHandler.removeMessages(H.SHOW);
        mHandler.removeMessages(H.DISMISS);
        rescheduleTimeoutH();

        if (mConfigChanged) {
            initDialog(); // resets mShowing to false
            mConfigurableTexts.update();
            mConfigChanged = false;
        }

        if (mDefaultRow == null) {
            mDefaultRow = getActiveRow();
        }

        initSettingsH();
        mDialog.getViewTreeObserver().addOnComputeInternalInsetsListener(mInsetsListener);

        if (!mShowing && !mDialog.isShown()) {
            if (!isLandscape()) {
                mDialogView.setTranslationX(
                        (mVolumePanelOnLeft ? -1 : 1) * mDialogView.getWidth() / 2.0f);
            }
            mDialogView.setAlpha(0);
            mDialogView.animate()
                    .alpha(1)
                    .translationX(0)
                    .setDuration(DIALOG_SHOW_ANIMATION_DURATION)
                    .setInterpolator(new SystemUIInterpolators.LogDecelerateInterpolator())
                    .withStartAction(() -> {
                        if (!mDialog.isShown()) {
                            mWindowManager.addView(mDialog, mWindowParams);
                        }
                    })
                    .withEndAction(() -> {
                        if (!Prefs.getBoolean(mContext, Prefs.Key.TOUCHED_RINGER_TOGGLE, false)) {
                            if (mRingerIcon != null) {
                                mRingerIcon.postOnAnimationDelayed(
                                        getSinglePressFor(mRingerIcon), 1500);
                            }
                        }
                        mShowing = true;
                    })
                    .start();
        }

        Events.writeEvent(mContext, Events.EVENT_SHOW_DIALOG, reason, mKeyguard.isKeyguardLocked());
        mController.notifyVisible(true);
        mController.getCaptionsComponentState(false);
        checkODICaptionsTooltip(false);
    }

    protected void rescheduleTimeoutH() {
        mHandler.removeMessages(H.DISMISS);
        final int timeout = computeTimeoutH();
        mHandler.sendMessageDelayed(mHandler
                .obtainMessage(H.DISMISS, Events.DISMISS_REASON_TIMEOUT, 0), timeout);
        if (D.BUG) Log.d(TAG, "rescheduleTimeout " + timeout + " " + Debug.getCaller());
        mController.userActivity();
    }

    private int computeTimeoutH() {
        if (mHovering) {
            return mAccessibilityMgr.getRecommendedTimeoutMillis(DIALOG_HOVERING_TIMEOUT_MILLIS,
                    AccessibilityManager.FLAG_CONTENT_CONTROLS);
        }
        if (mSafetyWarning != null) {
            return mAccessibilityMgr.getRecommendedTimeoutMillis(
                    DIALOG_SAFETYWARNING_TIMEOUT_MILLIS,
                    AccessibilityManager.FLAG_CONTENT_TEXT
                            | AccessibilityManager.FLAG_CONTENT_CONTROLS);
        }
        if (!mHasSeenODICaptionsTooltip && mODICaptionsTooltipView != null) {
            return mAccessibilityMgr.getRecommendedTimeoutMillis(
                    DIALOG_ODI_CAPTIONS_TOOLTIP_TIMEOUT_MILLIS,
                    AccessibilityManager.FLAG_CONTENT_TEXT
                            | AccessibilityManager.FLAG_CONTENT_CONTROLS);
        }
        return mAccessibilityMgr.getRecommendedTimeoutMillis(DIALOG_TIMEOUT_MILLIS,
                AccessibilityManager.FLAG_CONTENT_CONTROLS);
    }

    protected void dismissH(int reason) {
        if (D.BUG) {
            Log.d(TAG, "mDialog.dismiss() reason: " + Events.DISMISS_REASONS[reason]
                    + " from: " + Debug.getCaller());
        }
        if (!mShowing) {
            // This may happen when dismissing an expanded panel, don't animate again
            return;
        }
        mHandler.removeMessages(H.DISMISS);
        mHandler.removeMessages(H.SHOW);
        mDialogView.animate().cancel();
        if (mShowing) {
            mShowing = false;
            // Only logs when the volume dialog visibility is changed.
            Events.writeEvent(mContext, Events.EVENT_DISMISS_DIALOG, reason);
        }
        mDialogView.setTranslationX(0);
        mDialogView.setAlpha(1);
        ViewPropertyAnimator animator = mDialogView.animate()
                .alpha(0)
                .setDuration(DIALOG_HIDE_ANIMATION_DURATION)
                .setInterpolator(new SystemUIInterpolators.LogAccelerateInterpolator())
                .withEndAction(() -> mHandler.postDelayed(() -> {
                    if (mDialog.isShown()){
                        mWindowManager.removeViewImmediate(mDialog);
                    }
                    mExpanded = false;
                    mDialogRowsView.getLayoutParams().width = mContext.getResources()
                            .getDimensionPixelSize(R.dimen.volume_dialog_panel_width);
                    updateExpandedRows(mExpanded);
                    mExpandRows.setExpanded(mExpanded);
                    mAllyStream = -1;
                    mMusicHidden = false;
                    tryToRemoveCaptionsTooltip();
                    mDefaultRow = null;
                    mDialog.getViewTreeObserver().removeOnComputeInternalInsetsListener(
                            mInsetsListener);
                    mController.notifyVisible(false);
                }, 50));
        animator.translationX(getAnimatorX());
        animator.start();
        checkODICaptionsTooltip(true);
        synchronized (mSafetyWarningLock) {
            if (mSafetyWarning != null) {
                if (D.BUG) Log.d(TAG, "SafetyWarning dismissed");
                mSafetyWarning.dismiss();
            }
        }
    }

    private boolean showActiveStreamOnly() {
        return mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_LEANBACK)
                || mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_TELEVISION);
    }

    private boolean shouldBeVisibleH(VolumeRow row, VolumeRow activeRow) {
        boolean isActive = row.stream == activeRow.stream;

        if (row.stream == AudioSystem.STREAM_MUSIC &&
                activeRow.stream != AudioSystem.STREAM_MUSIC && !mExpanded) {
            mMusicHidden = true;
            return false;
        }

        if (isActive) {
            return true;
        }

        if (!mShowActiveStreamOnly) {
            if (row.stream == AudioSystem.STREAM_ACCESSIBILITY) {
                return mShowA11yStream;
            }

            // if the active row is accessibility, then continue to display previous
            // active row since accessibility is displayed under it
            if (activeRow.stream == AudioSystem.STREAM_ACCESSIBILITY &&
                    row.stream == mPrevActiveStream) {
                return true;
            }

            // if the row is the default stream or the row with which this panel was created,
            // show it additonally to the active row if it is one of the following streams
            if (row.defaultStream || mDefaultRow == row) {
                return activeRow.stream == STREAM_RING
                        || activeRow.stream == STREAM_NOTIFICATION
                        || activeRow.stream == STREAM_ALARM
                        || activeRow.stream == STREAM_VOICE_CALL
                        || activeRow.stream == STREAM_MUSIC
                        || activeRow.stream == STREAM_ACCESSIBILITY
                        || mDynamic.get(activeRow.stream);
            }
        }

        return false;
    }

    private void updateRowsH(final VolumeRow activeRow) {
        if (D.BUG) Log.d(TAG, "updateRowsH");
        if (!mShowing) {
            trimObsoleteH();
        }
        // apply changes to all rows
        for (final VolumeRow row : mRows) {
            final boolean isActive = row == activeRow;
            final boolean shouldBeVisible = shouldBeVisibleH(row, activeRow);
            if (!mExpanded) Util.setVisOrGone(row.view, shouldBeVisible);
            if (row.view.isShown()) {
                updateVolumeRowTintH(row, isActive);
            }
        }
    }

    protected void updateRingerH() {
        if (mState != null) {
            final StreamState ss = mState.states.get(AudioManager.STREAM_RING);
            if (ss == null) {
                return;
            }

            boolean isZenMuted = mState.zenMode == Global.ZEN_MODE_ALARMS
                    || mState.zenMode == Global.ZEN_MODE_NO_INTERRUPTIONS
                    || (mState.zenMode == Global.ZEN_MODE_IMPORTANT_INTERRUPTIONS
                        && mState.disallowRinger);
            enableRingerViewsH(!isZenMuted);
            switch (mState.ringerModeInternal) {
                case AudioManager.RINGER_MODE_VIBRATE:
                    mRingerIcon.setImageResource(R.drawable.ic_volume_ringer_vibrate);
                    addAccessibilityDescription(mRingerIcon, RINGER_MODE_VIBRATE,
                            mContext.getString(R.string.volume_ringer_hint_mute));
                    mRingerIcon.setTag(Events.ICON_STATE_VIBRATE);
                    break;
                case AudioManager.RINGER_MODE_SILENT:
                    mRingerIcon.setImageResource(R.drawable.ic_volume_ringer_mute);
                    mRingerIcon.setTag(Events.ICON_STATE_MUTE);
                    addAccessibilityDescription(mRingerIcon, RINGER_MODE_SILENT,
                            mContext.getString(R.string.volume_ringer_hint_unmute));
                    break;
                case AudioManager.RINGER_MODE_NORMAL:
                default:
                    boolean muted = (mAutomute && ss.level == 0) || ss.muted;
                    if (!isZenMuted && muted) {
                        mRingerIcon.setImageResource(R.drawable.ic_volume_ringer_mute);
                        addAccessibilityDescription(mRingerIcon, RINGER_MODE_NORMAL,
                                mContext.getString(R.string.volume_ringer_hint_unmute));
                        mRingerIcon.setTag(Events.ICON_STATE_MUTE);
                    } else {
                        mRingerIcon.setImageResource(R.drawable.ic_volume_ringer);
                        if (mController.hasVibrator()) {
                            addAccessibilityDescription(mRingerIcon, RINGER_MODE_NORMAL,
                                    mContext.getString(R.string.volume_ringer_hint_vibrate));
                        } else {
                            addAccessibilityDescription(mRingerIcon, RINGER_MODE_NORMAL,
                                    mContext.getString(R.string.volume_ringer_hint_mute));
                        }
                        mRingerIcon.setTag(Events.ICON_STATE_UNMUTE);
                    }
                    break;
            }
        }
    }

    private void addAccessibilityDescription(View view, int currState, String hintLabel) {
        int currStateResId;
        switch (currState) {
            case RINGER_MODE_SILENT:
                currStateResId = R.string.volume_ringer_status_silent;
                break;
            case RINGER_MODE_VIBRATE:
                currStateResId = R.string.volume_ringer_status_vibrate;
                break;
            case RINGER_MODE_NORMAL:
            default:
                currStateResId = R.string.volume_ringer_status_normal;
        }

        view.setContentDescription(mContext.getString(currStateResId));
        view.setAccessibilityDelegate(new AccessibilityDelegate() {
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfo info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                info.addAction(new AccessibilityNodeInfo.AccessibilityAction(
                                AccessibilityNodeInfo.ACTION_CLICK, hintLabel));
            }
        });
    }

    /**
     * Toggles enable state of views in a VolumeRow (not including seekbar or icon)
     * Hides/shows zen icon
     * @param enable whether to enable volume row views and hide dnd icon
     */
    private void enableVolumeRowViewsH(VolumeRow row, boolean enable) {
        boolean showDndIcon = !enable;
        row.dndIcon.setVisibility(showDndIcon ? VISIBLE : GONE);
    }

    /**
     * Toggles enable state of footer/ringer views
     * Hides/shows zen icon
     * @param enable whether to enable ringer views and hide dnd icon
     */
    private void enableRingerViewsH(boolean enable) {
        if (mRingerIcon != null) {
            mRingerIcon.setEnabled(enable);
        }
        if (mZenIcon != null) {
            mZenIcon.setVisibility(enable ? GONE : VISIBLE);
        }
    }

    private void trimObsoleteH() {
        if (D.BUG) Log.d(TAG, "trimObsoleteH");
        for (int i = mRows.size() - 1; i >= 0; i--) {
            final VolumeRow row = mRows.get(i);
            if (row.ss == null || !row.ss.dynamic) continue;
            if (!mDynamic.get(row.stream)) {
                removeRow(row);
            }
        }
    }

    private void removeRow(VolumeRow volumeRow) {
        mRows.remove(volumeRow);
        mDialogRowsView.removeView(volumeRow.view);
    }

    private void removeAppRow(VolumeRow volumeRow) {
        mAppRows.remove(volumeRow);
        mDialogRowsView.removeView(volumeRow.view);
    }

    protected void onStateChangedH(State state) {
        if (D.BUG) Log.d(TAG, "onStateChangedH() state: " + state.toString());
        if (mShowing && mState != null && state != null
                && mState.ringerModeInternal != state.ringerModeInternal
                && state.ringerModeInternal == AudioManager.RINGER_MODE_VIBRATE) {
            mController.vibrate(VibrationEffect.get(VibrationEffect.EFFECT_HEAVY_CLICK));
        }

        mState = state;
        mDynamic.clear();
        // add any new dynamic rows
        for (int i = 0; i < state.states.size(); i++) {
            final int stream = state.states.keyAt(i);
            final StreamState ss = state.states.valueAt(i);
            if (!ss.dynamic) continue;
            mDynamic.put(stream, true);
            if (findRow(stream) == null) {
                addRow(stream, R.drawable.ic_volume_remote, R.drawable.ic_volume_remote_mute, true,
                        false, true);
            }
        }

        if (Util.isVoiceCapable(mContext)) {
            updateNotificationRowH();
        }

        if (mActiveStream != state.activeStream) {
            mPrevActiveStream = mActiveStream;
            mActiveStream = state.activeStream;
            VolumeRow activeRow = getActiveRow();
            updateRowsH(activeRow);
            if (mShowing) rescheduleTimeoutH();
        }
        for (VolumeRow row : mRows) {
            updateVolumeRowH(row);
        }
        updateRingerH();
    }

    CharSequence composeWindowTitle() {
        return mContext.getString(R.string.volume_dialog_title, getStreamLabelH(getActiveRow().ss));
    }

    private void updateNotificationRowH() {
        VolumeRow notificationRow = findRow(AudioManager.STREAM_NOTIFICATION);
        if (notificationRow != null && mState.linkedNotification) {
            removeRow(notificationRow);
        } else if (notificationRow == null && !mState.linkedNotification) {
            addRow(AudioManager.STREAM_NOTIFICATION, R.drawable.ic_volume_notification,
                    R.drawable.ic_volume_notification_mute, true, false);
        }
    }

    private void updateVolumeRowH(VolumeRow row) {
        if (D.BUG) Log.i(TAG, "updateVolumeRowH s=" + row.stream);
        if (mState == null) return;
        final StreamState ss = mState.states.get(row.stream);
        if (ss == null) return;
        row.ss = ss;
        if (ss.level > ss.levelMin) {
            row.lastAudibleLevel = ss.level;
        }
        if (ss.level == row.requestedLevel) {
            row.requestedLevel = -1;
        }
        final boolean isA11yStream = row.stream == STREAM_ACCESSIBILITY;
        final boolean isRingStream = row.stream == AudioManager.STREAM_RING;
        final boolean isSystemStream = row.stream == AudioManager.STREAM_SYSTEM;
        final boolean isAlarmStream = row.stream == STREAM_ALARM;
        final boolean isMusicStream = row.stream == AudioManager.STREAM_MUSIC;
        final boolean isNotificationStream = row.stream == AudioManager.STREAM_NOTIFICATION;
        final boolean isMuted = row.ss.level == row.ss.levelMin;
        final boolean isVibrate = mState.ringerModeInternal == AudioManager.RINGER_MODE_VIBRATE;
        final boolean isRingVibrate = isRingStream && isVibrate;
        final boolean isRingSilent = isRingStream
                && mState.ringerModeInternal == AudioManager.RINGER_MODE_SILENT;
        final boolean isZenPriorityOnly = mState.zenMode == Global.ZEN_MODE_IMPORTANT_INTERRUPTIONS;
        final boolean isZenAlarms = mState.zenMode == Global.ZEN_MODE_ALARMS;
        final boolean isZenNone = mState.zenMode == Global.ZEN_MODE_NO_INTERRUPTIONS;
        final boolean zenMuted =
                isZenAlarms ? (isRingStream || isSystemStream || isNotificationStream)
                : isZenNone ? (isRingStream || isSystemStream || isAlarmStream || isMusicStream || isNotificationStream)
                : isZenPriorityOnly ? ((isAlarmStream && mState.disallowAlarms) ||
                        (isMusicStream && mState.disallowMedia) ||
                        (isRingStream && mState.disallowRinger) ||
                        (isSystemStream && mState.disallowSystem))
                : isVibrate ? isNotificationStream
                : false;

        // update slider max
        final int max = ss.levelMax * 100;
        final boolean maxChanged = max != row.slider.getMax();
        if (maxChanged) {
            row.slider.setMax(max);
        }
        // update slider min
        final int min = ss.levelMin * 100;
        if (min != row.slider.getMin()) {
            row.slider.setMin(min);
        }

        // update header text
        Util.setText(row.header, getStreamLabelH(ss));
        row.slider.setContentDescription(row.header.getText());
        mConfigurableTexts.add(row.header, ss.name);

        // update icon
        final boolean iconEnabled = (mAutomute || ss.muteSupported) && !zenMuted;
        row.icon.setEnabled(iconEnabled);
        row.icon.setAlpha(iconEnabled ? 1 : 0.5f);
        final int iconRes =
                isRingVibrate ? R.drawable.ic_volume_ringer_vibrate
                : isRingSilent || zenMuted ? row.iconMuteRes
                : ss.routedToBluetooth ?
                        (ss.muted ? R.drawable.ic_volume_media_bt_mute
                                : R.drawable.ic_volume_media_bt)
                : mAutomute && ss.level == 0 ? row.iconMuteRes
                : isMuted ? row.iconMuteRes : row.iconRes;
        row.icon.setImageResource(iconRes);
        row.iconState =
                iconRes == R.drawable.ic_volume_ringer_vibrate ? Events.ICON_STATE_VIBRATE
                : (iconRes == R.drawable.ic_volume_media_bt_mute || iconRes == row.iconMuteRes)
                        ? Events.ICON_STATE_MUTE
                : (iconRes == R.drawable.ic_volume_media_bt || iconRes == row.iconRes)
                        ? Events.ICON_STATE_UNMUTE
                : Events.ICON_STATE_UNKNOWN;
        if (iconEnabled) {
            if (isRingStream) {
                if (isRingVibrate) {
                    row.icon.setContentDescription(mContext.getString(
                            R.string.volume_stream_content_description_unmute,
                            getStreamLabelH(ss)));
                } else {
                    if (mController.hasVibrator()) {
                        row.icon.setContentDescription(mContext.getString(
                                mShowA11yStream
                                        ? R.string.volume_stream_content_description_vibrate_a11y
                                        : R.string.volume_stream_content_description_vibrate,
                                getStreamLabelH(ss)));
                    } else {
                        row.icon.setContentDescription(mContext.getString(
                                mShowA11yStream
                                        ? R.string.volume_stream_content_description_mute_a11y
                                        : R.string.volume_stream_content_description_mute,
                                getStreamLabelH(ss)));
                    }
                }
            } else if (isA11yStream) {
                row.icon.setContentDescription(getStreamLabelH(ss));
            } else {
                if (ss.muted || mAutomute && ss.level == 0) {
                   row.icon.setContentDescription(mContext.getString(
                           R.string.volume_stream_content_description_unmute,
                           getStreamLabelH(ss)));
                } else {
                    row.icon.setContentDescription(mContext.getString(
                            mShowA11yStream
                                    ? R.string.volume_stream_content_description_mute_a11y
                                    : R.string.volume_stream_content_description_mute,
                            getStreamLabelH(ss)));
                }
            }
        } else {
            row.icon.setContentDescription(getStreamLabelH(ss));
        }

        // ensure tracking is disabled if zenMuted
        if (zenMuted) {
            row.tracking = false;
        }
        enableVolumeRowViewsH(row, !zenMuted);

        // update slider
        final boolean enableSlider = !zenMuted;
        final int vlevel = row.ss.muted && (!isRingStream && !zenMuted) ? 0
                : row.ss.level;
        updateVolumeRowSliderH(row, enableSlider, vlevel, maxChanged);
    }

    private void updateVolumeRowTintH(VolumeRow row, boolean isActive) {
        if (isActive) {
            row.slider.requestFocus();
        }
        boolean useActiveColoring = isActive && row.slider.isEnabled();
        final ColorStateList tint = useActiveColoring
                ? Utils.getColorAccent(mContext)
                : Utils.getColorAttr(mContext, android.R.attr.colorForeground);
        final int alpha = useActiveColoring
                ? Color.alpha(tint.getDefaultColor())
                : getAlphaAttr(android.R.attr.secondaryContentAlpha);
        if (tint == row.cachedTint && mExpanded) return;
        row.slider.setProgressTintList(tint);
        row.slider.setThumbTintList(tint);
        row.slider.setProgressBackgroundTintList(tint);
        row.slider.setAlpha(((float) alpha) / 255);
        row.icon.setImageTintList(tint);
        row.icon.setImageAlpha(alpha);
        row.cachedTint = tint;
    }

    private void updateVolumeRowSliderH(VolumeRow row, boolean enable, int vlevel, boolean maxChanged) {
        row.slider.setEnabled(enable);
        updateVolumeRowTintH(row, row.stream == mActiveStream);
        if (row.tracking) {
            return;  // don't update if user is sliding
        }
        final int progress = row.slider.getProgress();
        final int level = getImpliedLevel(row.slider, progress);
        final boolean rowVisible = row.view.getVisibility() == VISIBLE;
        final boolean inGracePeriod = (SystemClock.uptimeMillis() - row.userAttempt)
                < USER_ATTEMPT_GRACE_PERIOD;
        mHandler.removeMessages(H.RECHECK, row);
        if (mShowing && rowVisible && inGracePeriod) {
            if (D.BUG) Log.d(TAG, "inGracePeriod");
            mHandler.sendMessageAtTime(mHandler.obtainMessage(H.RECHECK, row),
                    row.userAttempt + USER_ATTEMPT_GRACE_PERIOD);
            return;  // don't update if visible and in grace period
        }
        if (vlevel == level) {
            if (mShowing && rowVisible) {
                return;  // don't clamp if visible
            }
        }
        final int newProgress = vlevel * 100;
        if (progress != newProgress || maxChanged) {
            if (mShowing && rowVisible) {
                // animate!
                if (row.anim != null && row.anim.isRunning()
                        && row.animTargetProgress == newProgress) {
                    return;  // already animating to the target progress
                }
                // start/update animation
                if (row.anim == null) {
                    row.anim = ObjectAnimator.ofInt(row.slider, "progress", progress, newProgress);
                    row.anim.setInterpolator(new DecelerateInterpolator());
                } else {
                    row.anim.cancel();
                    row.anim.setIntValues(progress, newProgress);
                }
                row.animTargetProgress = newProgress;
                row.anim.setDuration(UPDATE_ANIMATION_DURATION);
                row.anim.start();
            } else {
                // update slider directly to clamped value
                if (row.anim != null) {
                    row.anim.cancel();
                }
                row.slider.setProgress(newProgress, true);
            }
        }
    }

    private void recheckH(VolumeRow row) {
        if (row == null) {
            if (D.BUG) Log.d(TAG, "recheckH ALL");
            trimObsoleteH();
            for (VolumeRow r : mRows) {
                updateVolumeRowH(r);
            }
        } else {
            if (D.BUG) Log.d(TAG, "recheckH " + row.stream);
            updateVolumeRowH(row);
        }
    }

    private void setStreamImportantH(int stream, boolean important) {
        for (VolumeRow row : mRows) {
            if (row.stream == stream) {
                row.important = important;
                return;
            }
        }
    }

    private void showSafetyWarningH(int flags) {
        if ((flags & (AudioManager.FLAG_SHOW_UI | AudioManager.FLAG_SHOW_UI_WARNINGS)) != 0
                || mShowing) {
            synchronized (mSafetyWarningLock) {
                if (mSafetyWarning != null) {
                    return;
                }
                mSafetyWarning = new SafetyWarningDialog(mContext, mController.getAudioManager()) {
                    @Override
                    protected void cleanUp() {
                        synchronized (mSafetyWarningLock) {
                            mSafetyWarning = null;
                        }
                        recheckH(null);
                    }
                };
                mSafetyWarning.show();
            }
            recheckH(null);
        }
        rescheduleTimeoutH();
    }

    private String getStreamLabelH(StreamState ss) {
        if (ss == null) {
            return "";
        }
        if (ss.remoteLabel != null) {
            return ss.remoteLabel;
        }
        try {
            return mContext.getResources().getString(ss.name);
        } catch (Resources.NotFoundException e) {
            Slog.e(TAG, "Can't find translation for stream " + ss);
            return "";
        }
    }

    private Runnable getSinglePressFor(ImageButton button) {
        return () -> {
            if (button != null) {
                button.setPressed(true);
                button.postOnAnimationDelayed(getSingleUnpressFor(button), 200);
            }
        };
    }

    private Runnable getSingleUnpressFor(ImageButton button) {
        return () -> {
            if (button != null) {
                button.setPressed(false);
            }
        };
    }

    private final VolumeDialogController.Callbacks mControllerCallbackH
            = new VolumeDialogController.Callbacks() {
        @Override
        public void onShowRequested(int reason) {
            showH(reason);
        }

        @Override
        public void onDismissRequested(int reason) {
            dismissH(reason);
        }

        @Override
        public void onScreenOff() {
            dismissH(Events.DISMISS_REASON_SCREEN_OFF);
        }

        @Override
        public void onStateChanged(State state) {
            onStateChangedH(state);
        }

        @Override
        public void onLayoutDirectionChanged(int layoutDirection) {
            mDialogView.setLayoutDirection(layoutDirection);
        }

        @Override
        public void onConfigurationChanged() {
            if (mDialog.isShown()) mWindowManager.removeViewImmediate(mDialog);
            mConfigChanged = true;
        }

        @Override
        public void onShowVibrateHint() {
            if (mSilentMode) {
                mController.setRingerMode(AudioManager.RINGER_MODE_SILENT, false);
            }
        }

        @Override
        public void onShowSilentHint() {
            if (mSilentMode) {
                mController.setRingerMode(AudioManager.RINGER_MODE_NORMAL, false);
            }
        }

        @Override
        public void onShowSafetyWarning(int flags) {
            showSafetyWarningH(flags);
        }

        @Override
        public void onAccessibilityModeChanged(Boolean showA11yStream) {
            mShowA11yStream = showA11yStream == null ? false : showA11yStream;
            VolumeRow activeRow = getActiveRow();
            if (!mShowA11yStream && STREAM_ACCESSIBILITY == activeRow.stream) {
                dismissH(Events.DISMISS_STREAM_GONE);
            } else {
                updateRowsH(activeRow);
            }

        }

        @Override
        public void onCaptionComponentStateChanged(
                Boolean isComponentEnabled, Boolean fromTooltip) {
            updateODICaptionsH(isComponentEnabled, fromTooltip);
        }
    };

    private final class H extends Handler {
        private static final int SHOW = 1;
        private static final int DISMISS = 2;
        private static final int RECHECK = 3;
        private static final int RECHECK_ALL = 4;
        private static final int SET_STREAM_IMPORTANT = 5;
        private static final int RESCHEDULE_TIMEOUT = 6;
        private static final int STATE_CHANGED = 7;

        public H() {
            super(Looper.getMainLooper());
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case SHOW: showH(msg.arg1); break;
                case DISMISS: dismissH(msg.arg1); break;
                case RECHECK: recheckH((VolumeRow) msg.obj); break;
                case RECHECK_ALL: recheckH(null); break;
                case SET_STREAM_IMPORTANT: setStreamImportantH(msg.arg1, msg.arg2 != 0); break;
                case RESCHEDULE_TIMEOUT: rescheduleTimeoutH(); break;
                case STATE_CHANGED: onStateChangedH(mState); break;
            }
        }
    }

    private final class VolumeSeekBarChangeListener implements OnSeekBarChangeListener {
        private final VolumeRow mRow;

        private VolumeSeekBarChangeListener(VolumeRow row) {
            mRow = row;
        }

        @Override
        public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
            rescheduleTimeoutH();
            if (D.BUG) Log.d(TAG, AudioSystem.streamToString(mRow.stream)
                    + " onProgressChanged " + progress + " fromUser=" + fromUser);
            if (!fromUser) return;
            if (mRow.isAppVolumeRow) {
                mController.getAudioManager().setAppVolume(mRow.packageName, progress * 0.01f);
                return;
            }
            if (mRow.ss == null) return;
            if (mRow.ss.levelMin > 0) {
                final int minProgress = mRow.ss.levelMin * 100;
                if (progress < minProgress) {
                    seekBar.setProgress(minProgress);
                    progress = minProgress;
                }
            }
            final int userLevel = getImpliedLevel(seekBar, progress);
            if (mRow.ss.level != userLevel || mRow.ss.muted && userLevel > 0) {
                mRow.userAttempt = SystemClock.uptimeMillis();
                if (mRow.requestedLevel != userLevel) {
                    mController.setActiveStream(mRow.stream);
                    mController.setStreamVolume(mRow.stream, userLevel);
                    mRow.requestedLevel = userLevel;
                    Events.writeEvent(mContext, Events.EVENT_TOUCH_LEVEL_CHANGED, mRow.stream,
                            userLevel);
                }
            }
        }

        @Override
        public void onStartTrackingTouch(SeekBar seekBar) {
            mRow.tracking = true;
            if (mRow.isAppVolumeRow) return;
            if (D.BUG) Log.d(TAG, "onStartTrackingTouch"+ " " + mRow.stream);
            mController.setActiveStream(mRow.stream);
        }

        @Override
        public void onStopTrackingTouch(SeekBar seekBar) {
            if (D.BUG) Log.d(TAG, "onStopTrackingTouch"+ " " + mRow.stream);
            mRow.tracking = false;
            if (mRow.isAppVolumeRow) return;
            mRow.userAttempt = SystemClock.uptimeMillis();
            final int userLevel = getImpliedLevel(seekBar, seekBar.getProgress());
            Events.writeEvent(mContext, Events.EVENT_TOUCH_LEVEL_DONE, mRow.stream, userLevel);
            if (mRow.ss.level != userLevel) {
                mHandler.sendMessageDelayed(mHandler.obtainMessage(H.RECHECK, mRow),
                        USER_ATTEMPT_GRACE_PERIOD);
            }
        }
    }

    private final class Accessibility extends AccessibilityDelegate {
        public void init() {
            mDialogView.setAccessibilityDelegate(this);
        }

        @Override
        public boolean dispatchPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            // Activities populate their title here. Follow that example.
            event.getText().add(composeWindowTitle());
            return true;
        }

        @Override
        public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child,
                AccessibilityEvent event) {
            rescheduleTimeoutH();
            return super.onRequestSendAccessibilityEvent(host, child, event);
        }
    }

    private static class VolumeRow {
        private View view;
        private TextView header;
        private ImageButton icon;
        private SeekBar slider;
        private int stream;
        private StreamState ss;
        private long userAttempt;  // last user-driven slider change
        private boolean tracking;  // tracking slider touch
        private int requestedLevel = -1;  // pending user-requested level via progress changed
        private int iconRes;
        private int iconMuteRes;
        private boolean important;
        private boolean defaultStream;
        private ColorStateList cachedTint;
        private int iconState;  // from Events
        private ObjectAnimator anim;  // slider progress animation for non-touch-related updates
        private int animTargetProgress;
        private int lastAudibleLevel = 2;
        private FrameLayout dndIcon;
        /* for change app's volume */
        private String packageName;
        private boolean isAppVolumeRow = false;
        private boolean appMuted;
    }
}
