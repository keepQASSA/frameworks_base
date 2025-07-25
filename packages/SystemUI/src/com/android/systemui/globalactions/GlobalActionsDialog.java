/*
 * Copyright (C) 2017 The Android Open Source Project
 * Copyright (C) 2010-2015 CyanogenMod Project
 * Copyright (C) 2017-2018 The LineageOS Project
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

package com.android.systemui.globalactions;

import static android.view.ViewGroup.LayoutParams.MATCH_PARENT;
import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;

import static com.android.internal.widget.LockPatternUtils.StrongAuthTracker.SOME_AUTH_REQUIRED_AFTER_USER_REQUEST;
import static com.android.internal.widget.LockPatternUtils.StrongAuthTracker.STRONG_AUTH_NOT_REQUIRED;
import static com.android.internal.widget.LockPatternUtils.StrongAuthTracker.STRONG_AUTH_REQUIRED_AFTER_USER_LOCKDOWN;

import static com.android.internal.util.custom.PowerMenuConstants.*;

import android.app.ActivityManager;
import android.app.ActivityManagerNative;
import android.app.Dialog;
import android.app.KeyguardManager;
import android.app.PendingIntent;
import android.app.StatusBarManager;
import android.app.WallpaperManager;
import android.app.admin.DevicePolicyManager;
import android.app.trust.TrustManager;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.UserInfo;
import android.content.ServiceConnection;
import android.database.ContentObserver;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.media.AudioManager;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Process;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.UserManager;
import android.os.Vibrator;
import android.provider.Settings;
import android.service.dreams.DreamService;
import android.service.dreams.IDreamManager;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.ArraySet;
import android.util.Log;
import android.view.ContextThemeWrapper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.view.WindowManagerGlobal;
import android.view.accessibility.AccessibilityEvent;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.TextView;

import com.android.internal.R;
import com.android.internal.colorextraction.ColorExtractor;
import com.android.internal.colorextraction.ColorExtractor.GradientColors;
import com.android.internal.colorextraction.drawable.ScrimDrawable;
import com.android.internal.logging.MetricsLogger;
import com.android.internal.logging.nano.MetricsProto.MetricsEvent;
import com.android.internal.statusbar.IStatusBarService;
import com.android.internal.telephony.TelephonyIntents;
import com.android.internal.telephony.TelephonyProperties;
import com.android.internal.util.EmergencyAffordanceManager;
import com.android.internal.util.ScreenRecordHelper;
import com.android.internal.util.ScreenshotHelper;
import com.android.internal.util.UserIcons;
import com.android.internal.view.RotationPolicy;
import com.android.internal.widget.LockPatternUtils;
import com.android.keyguard.KeyguardUpdateMonitor;
import com.android.systemui.Dependency;
import com.android.systemui.Interpolators;
import com.android.systemui.MultiListLayout;
import com.android.systemui.MultiListLayout.MultiListAdapter;
import com.android.systemui.colorextraction.SysuiColorExtractor;
import com.android.systemui.plugins.ActivityStarter;
import com.android.systemui.plugins.GlobalActions.GlobalActionsManager;
import com.android.systemui.plugins.GlobalActionsPanelPlugin;
import com.android.systemui.statusbar.phone.ScrimController;
import com.android.systemui.statusbar.phone.StatusBarWindowController;
import com.android.systemui.statusbar.phone.UnlockMethodCache;
import com.android.systemui.statusbar.policy.ConfigurationController;
import com.android.systemui.statusbar.policy.KeyguardMonitor;
import com.android.systemui.util.EmergencyDialerConstants;
import com.android.systemui.util.leak.RotationUtils;
import com.android.systemui.volume.SystemUIInterpolators.LogAccelerateInterpolator;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

/**
 * Helper to show the global actions dialog.  Each item is an {@link Action} that
 * may show depending on whether the keyguard is showing, and whether the device
 * is provisioned.
 */
public class GlobalActionsDialog implements DialogInterface.OnDismissListener,
        DialogInterface.OnShowListener, ConfigurationController.ConfigurationListener {

    static public final String SYSTEM_DIALOG_REASON_KEY = "reason";
    static public final String SYSTEM_DIALOG_REASON_GLOBAL_ACTIONS = "globalactions";
    static public final String SYSTEM_DIALOG_REASON_DREAM = "dream";

    private static final String TAG = "GlobalActionsDialog";

    private static final boolean SHOW_SILENT_TOGGLE = false;

    private final Context mContext;
    private final GlobalActionsManager mWindowManagerFuncs;
    private final AudioManager mAudioManager;
    private final IDreamManager mDreamManager;
    private final DevicePolicyManager mDevicePolicyManager;
    private final LockPatternUtils mLockPatternUtils;
    private final KeyguardManager mKeyguardManager;
    private final KeyguardMonitor mKeyguardMonitor;

    private ArrayList<Action> mItems;
    private ActionsDialog mDialog;

    private Action mSilentModeAction;
    private ToggleAction mAirplaneModeOn;

    private MyAdapter mAdapter;

    private boolean mKeyguardShowing = false;
    private boolean mDeviceProvisioned = false;
    private ToggleAction.State mAirplaneState = ToggleAction.State.Off;
    private boolean mIsWaitingForEcmExit = false;
    private boolean mHasTelephony;
    private boolean mHasVibrator;
    private boolean mHasLogoutButton;
    private boolean mHasLockdownButton;
    private final boolean mShowSilentToggle;
    private final EmergencyAffordanceManager mEmergencyAffordanceManager;
    private final ScreenshotHelper mScreenshotHelper;
    private final ScreenRecordHelper mScreenRecordHelper;
    private final ActivityStarter mActivityStarter;
    private GlobalActionsPanelPlugin mPanelPlugin;

    // Power menu customizations
    private String[] mDefaultMenuActions;
    private String[] mRootMenuActions;
    private String[] mRestartMenuActions;
    private String[] mCurrentMenuActions;
    private boolean mIsRestartMenu;
    private boolean mPowerMenuSecure;

    private BitSet mAirplaneModeBits;
    private final Hashtable<Integer, PhoneStateListener> mPhoneStateListeners =
            new Hashtable<Integer, PhoneStateListener>();

    /**
     * @param context everything needs a context :(
     */
    public GlobalActionsDialog(Context context, GlobalActionsManager windowManagerFuncs) {
        mContext = new ContextThemeWrapper(context, com.android.systemui.R.style.qs_theme);
        mWindowManagerFuncs = windowManagerFuncs;
        mAudioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
        mDreamManager = IDreamManager.Stub.asInterface(
                ServiceManager.getService(DreamService.DREAM_SERVICE));
        mDevicePolicyManager = (DevicePolicyManager) mContext.getSystemService(
                Context.DEVICE_POLICY_SERVICE);
        mLockPatternUtils = new LockPatternUtils(mContext);
        mKeyguardManager = (KeyguardManager) mContext.getSystemService(Context.KEYGUARD_SERVICE);
        mKeyguardMonitor = Dependency.get(KeyguardMonitor.class);

        // receive broadcasts
        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_CLOSE_SYSTEM_DIALOGS);
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        filter.addAction(Intent.ACTION_UPDATE_POWER_MENU);
        filter.addAction(TelephonyIntents.ACTION_EMERGENCY_CALLBACK_MODE_CHANGED);
        context.registerReceiver(mBroadcastReceiver, filter);

        // get notified of phone state changes
        SubscriptionManager.from(mContext).addOnSubscriptionsChangedListener(
                new SubscriptionManager.OnSubscriptionsChangedListener() {
            @Override
            public void onSubscriptionsChanged() {
                super.onSubscriptionsChanged();
                setupAirplaneModeListeners();
            }
        });
        setupAirplaneModeListeners();
        mContext.getContentResolver().registerContentObserver(
                Settings.Global.getUriFor(Settings.Global.AIRPLANE_MODE_ON), true,
                mAirplaneModeObserver);
        Vibrator vibrator = (Vibrator) mContext.getSystemService(Context.VIBRATOR_SERVICE);
        mHasVibrator = vibrator != null && vibrator.hasVibrator();

        mShowSilentToggle = SHOW_SILENT_TOGGLE && !mContext.getResources().getBoolean(
                R.bool.config_useFixedVolume);

        mEmergencyAffordanceManager = new EmergencyAffordanceManager(context);
        mScreenshotHelper = new ScreenshotHelper(context);
        mScreenRecordHelper = new ScreenRecordHelper(context);

        Dependency.get(ConfigurationController.class).addCallback(this);

        mActivityStarter = Dependency.get(ActivityStarter.class);
        KeyguardUpdateMonitor keyguardUpdateMonitor = KeyguardUpdateMonitor.getInstance(context);
        UnlockMethodCache unlockMethodCache = UnlockMethodCache.getInstance(context);
        unlockMethodCache.addListener(
                () -> {
                    if (mDialog != null && mDialog.mPanelController != null) {
                        boolean locked = !unlockMethodCache.canSkipBouncer()
                                && keyguardUpdateMonitor.isKeyguardVisible();
                        mDialog.mPanelController.onDeviceLockStateChanged(locked);
                    }
                });

        mDefaultMenuActions = mContext.getResources().getStringArray(
                com.android.internal.R.array.config_globalActionsList);
        mRestartMenuActions = mContext.getResources().getStringArray(
                com.android.internal.R.array.config_restartActionsList);

        updatePowerMenuActions();
    }

    /**
     * Since there are two ways of handling airplane mode (with telephony, we depend on the internal
     * device telephony state), and MSIM devices do not report phone state for missing SIMs, we
     * need to dynamically setup listeners based on subscription changes.
     *
     * So if there is _any_ active SIM in the device, we can depend on the phone state,
     * otherwise fall back to {@link Settings.Global#AIRPLANE_MODE_ON}.
     */
    private void setupAirplaneModeListeners() {
        TelephonyManager telephonyManager = mContext.getSystemService(TelephonyManager.class);
        Set<Integer> keys = mPhoneStateListeners.keySet();
        for (int subId : keys) {
            PhoneStateListener listener = (PhoneStateListener) mPhoneStateListeners.get(subId);
            telephonyManager.createForSubscriptionId(subId).listen(listener,
                    PhoneStateListener.LISTEN_NONE);
        }
        mPhoneStateListeners.clear();
        final List<SubscriptionInfo> subInfoList = SubscriptionManager.from(mContext)
                .getActiveSubscriptionInfoList();
        if (subInfoList != null) {
            mHasTelephony = true;
            mAirplaneModeBits = new BitSet(subInfoList.size());
            for (int i = 0; i < subInfoList.size(); i++) {
                // we need the current index inside the listener, so make it final
                final int subIndex = i;
                int subId = subInfoList.get(subIndex).getSubscriptionId();
                PhoneStateListener subListener = new PhoneStateListener() {
                    @Override
                    public void onServiceStateChanged(ServiceState serviceState) {
                        final boolean inAirplaneMode = serviceState.getState()
                                == ServiceState.STATE_POWER_OFF;
                        mAirplaneModeBits.set(subIndex, inAirplaneMode);
                        // we're in airplane mode if _any_ of the subscriptions say we are
                        mAirplaneState = mAirplaneModeBits.cardinality() > 0
                                ? ToggleAction.State.On : ToggleAction.State.Off;
                        mAirplaneModeOn.updateState(mAirplaneState);
                        if (mAdapter != null) {
                            mAdapter.notifyDataSetChanged();
                        }
                    }
                };
                mPhoneStateListeners.put(subId, subListener);
                telephonyManager.createForSubscriptionId(subId).listen(subListener,
                        PhoneStateListener.LISTEN_SERVICE_STATE);
            }
        } else {
            mHasTelephony = false;
        }
        // Set the initial status of airplane mode toggle
        mAirplaneState = getUpdatedAirplaneToggleState();
    }

    /**
     * Show the global actions dialog (creating if necessary)
     *
     * @param keyguardShowing True if keyguard is showing
     */
    public void showDialog(boolean keyguardShowing, boolean isDeviceProvisioned,
            GlobalActionsPanelPlugin panelPlugin) {
        mKeyguardShowing = keyguardShowing;
        mDeviceProvisioned = isDeviceProvisioned;
        mPanelPlugin = panelPlugin;
        mIsRestartMenu = false;
        mCurrentMenuActions = mRootMenuActions;
        if (mDialog != null) {
            mDialog.dismiss();
            mDialog = null;
            // Show delayed, so that the dismiss of the previous dialog completes
            mHandler.sendEmptyMessage(MESSAGE_SHOW);
        } else {
            handleShow();
        }
    }

    /**
     * Dismiss the global actions dialog, if it's currently shown
     */
    public void dismissDialog() {
        mHandler.removeMessages(MESSAGE_DISMISS);
        mHandler.sendEmptyMessage(MESSAGE_DISMISS);
    }

    private void awakenIfNecessary() {
        if (mDreamManager != null) {
            try {
                if (mDreamManager.isDreaming()) {
                    mDreamManager.awaken();
                }
            } catch (RemoteException e) {
                // we tried
            }
        }
    }

    private void handleShow() {
        awakenIfNecessary();
        mDialog = createDialog();
        prepareDialog();

        // If we only have 1 item and it's a simple press action, just do this action.
        if (mAdapter.getCount() == 1
                && mAdapter.getItem(0) instanceof SinglePressAction
                && !(mAdapter.getItem(0) instanceof LongPressAction)) {
            ((SinglePressAction) mAdapter.getItem(0)).onPress();
        } else {
            WindowManager.LayoutParams attrs = mDialog.getWindow().getAttributes();
            attrs.setTitle("ActionsDialog");
            attrs.layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
            mDialog.getWindow().setAttributes(attrs);
            mDialog.show();
            mWindowManagerFuncs.onGlobalActionsShown();
        }
    }

    private List<Action> getCurrentRestartMenuItems() {
        List<Action> items = new ArrayList<Action>();

        String[] restartMenuActions = mContext.getResources().getStringArray(
                    com.android.internal.R.array.config_restartActionsList);
        for (int i = 0; i < restartMenuActions.length; i++) {
            String actionKey = restartMenuActions[i];
            if (GLOBAL_ACTION_KEY_RESTART_RECOVERY.equals(actionKey)) {
                items.add(new RestartRecoveryAction());
            } else if (GLOBAL_ACTION_KEY_RESTART_BOOTLOADER.equals(actionKey)) {
                items.add(new RestartBootloaderAction());
            } else if (GLOBAL_ACTION_KEY_RESTART_DOWNLOAD.equals(actionKey)) {
                items.add(new RestartDownloadAction());
            } else if (GLOBAL_ACTION_KEY_RESTART_FASTBOOT.equals(actionKey)) {
                items.add(new RestartFastbootAction());
            } else if (GLOBAL_ACTION_KEY_RESTART_SYSTEMUI.equals(actionKey)) {
                items.add(new RestartSystemUIAction());
            }
        }
        return items;
    }

    private boolean isInLockTaskMode() {
        try {
            return ActivityManagerNative.getDefault().isInLockTaskMode();
        } catch (RemoteException e) {
            return false;
        }
    }

    private boolean isAdvancedRestartPossible() {
        if (isInLockTaskMode()){
            return false;
        }
        boolean keyguardLocked = mKeyguardManager.inKeyguardRestrictedInputMode() && mKeyguardManager.isKeyguardSecure();
        boolean advancedRestartEnabled = Settings.System.getInt(mContext.getContentResolver(),
                Settings.System.ADVANCED_REBOOT, 1) == 1;
        boolean advancedRestartSecuredEnabled = Settings.System.getInt(mContext.getContentResolver(),
                Settings.System.ADVANCED_REBOOT_SECURED, 1) == 1;
        boolean isPrimaryUser = UserHandle.getCallingUserId() == UserHandle.USER_OWNER;

        return advancedRestartEnabled && (!keyguardLocked || advancedRestartSecuredEnabled) && isPrimaryUser;
    }

    private boolean shouldShowRestartSubmenu() {
        if (!isAdvancedRestartPossible()) {
            return false;
        } else {
            List<Action> restartMenuItems = getCurrentRestartMenuItems();
            return restartMenuItems.size() > 0;
        }
    }

    /**
     * Create the global actions dialog.
     *
     * @return A new dialog.
     */
    private ActionsDialog createDialog() {
        // Simple toggle style if there's no vibrator, otherwise use a tri-state
        if (!mHasVibrator) {
            mSilentModeAction = new SilentModeToggleAction();
        } else {
            mSilentModeAction = new SilentModeTriStateAction(mAudioManager, mHandler);
        }
        mAirplaneModeOn = new ToggleAction(
                com.android.systemui.R.drawable.ic_lock_airplane_mode_enabled,
                com.android.systemui.R.drawable.ic_lock_airplane_mode_disabled,
                R.string.global_actions_toggle_airplane_mode,
                R.string.global_actions_airplane_mode_on_status,
                R.string.global_actions_airplane_mode_off_status) {

            void onToggle(boolean on) {
                if (mHasTelephony && Boolean.parseBoolean(
                        SystemProperties.get(TelephonyProperties.PROPERTY_INECM_MODE))) {
                    mIsWaitingForEcmExit = true;
                    // Launch ECM exit dialog
                    Intent ecmDialogIntent =
                            new Intent(TelephonyIntents.ACTION_SHOW_NOTICE_ECM_BLOCK_OTHERS, null);
                    ecmDialogIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    mContext.startActivity(ecmDialogIntent);
                } else {
                    changeAirplaneModeSystemSetting(on);
                }
            }

            @Override
            protected void changeStateFromPress(boolean buttonOn) {
                if (!mHasTelephony) return;

                // In ECM mode airplane state cannot be changed
                if (!(Boolean.parseBoolean(
                        SystemProperties.get(TelephonyProperties.PROPERTY_INECM_MODE)))) {
                    mState = buttonOn ? State.TurningOn : State.TurningOff;
                    mAirplaneState = mState;
                }
            }

            public boolean showDuringKeyguard() {
                return true;
            }

            public boolean showBeforeProvisioning() {
                return false;
            }
        };
        onAirplaneModeChanged();

        mItems = new ArrayList<Action>();

        // Always add the power off and restart options if we're not in advanced restart submenu
        if (!mIsRestartMenu) {
            mItems.add(new PowerAction());
            mItems.add(new RestartAction());
        }

        ArraySet<String> addedKeys = new ArraySet<String>();
        mHasLogoutButton = false;
        mHasLockdownButton = false;
        for (int i = 0; i < mCurrentMenuActions.length; i++) {
            String actionKey = mCurrentMenuActions[i];
            if (addedKeys.contains(actionKey)) {
                // If we already have added this, don't add it again.
                continue;
            }
            if (GLOBAL_ACTION_KEY_POWER.equals(actionKey)) {
                continue;
            } else if (GLOBAL_ACTION_KEY_AIRPLANE.equals(actionKey) && !isInLockTaskMode()) {
                mItems.add(mAirplaneModeOn);
            } else if (GLOBAL_ACTION_KEY_BUGREPORT.equals(actionKey)) {
                if (Settings.Global.getInt(mContext.getContentResolver(),
                        Settings.Global.BUGREPORT_IN_POWER_MENU, 0) != 0 && isCurrentUserOwner()) {
                    mItems.add(new BugReportAction());
                }
            } else if (GLOBAL_ACTION_KEY_SILENT.equals(actionKey)) {
                if (mShowSilentToggle) {
                    mItems.add(mSilentModeAction);
                }
            } else if (GLOBAL_ACTION_KEY_USERS.equals(actionKey) && !isInLockTaskMode()) {
                List<UserInfo> users = ((UserManager) mContext.getSystemService(
                        Context.USER_SERVICE)).getUsers();
                if (users.size() > 1) {
                    addUsersToMenu(mItems);
                }
            } else if (GLOBAL_ACTION_KEY_SETTINGS.equals(actionKey)) {
                mItems.add(getSettingsAction());
            } else if (GLOBAL_ACTION_KEY_LOCKDOWN.equals(actionKey) && !isInLockTaskMode()) {
                if (Settings.Secure.getIntForUser(mContext.getContentResolver(),
                            Settings.Secure.LOCKDOWN_IN_POWER_MENU, 0, getCurrentUser().id) != 0
                        && shouldDisplayLockdown()) {
                    mItems.add(getLockdownAction());
                    mHasLockdownButton = true;
                }
            } else if (GLOBAL_ACTION_KEY_VOICEASSIST.equals(actionKey)) {
                mItems.add(getVoiceAssistAction());
            } else if (GLOBAL_ACTION_KEY_ASSIST.equals(actionKey)) {
                mItems.add(getAssistAction());
            } else if (GLOBAL_ACTION_KEY_RESTART.equals(actionKey)) {
                if (!mIsRestartMenu) {
                    continue;
                } else {
                    mItems.add(new RestartAction());
                }
            } else if (GLOBAL_ACTION_KEY_RESTART_RECOVERY.equals(actionKey) &&
                    isAdvancedRestartPossible()) {
                mItems.add(new RestartRecoveryAction());
            } else if (GLOBAL_ACTION_KEY_RESTART_BOOTLOADER.equals(actionKey) &&
                    isAdvancedRestartPossible()) {
                mItems.add(new RestartBootloaderAction());
            } else if (GLOBAL_ACTION_KEY_RESTART_DOWNLOAD.equals(actionKey) &&
                    isAdvancedRestartPossible()) {
                mItems.add(new RestartDownloadAction());
            } else if (GLOBAL_ACTION_KEY_RESTART_FASTBOOT.equals(actionKey) &&
                    isAdvancedRestartPossible()) {
                mItems.add(new RestartFastbootAction());
            } else if (GLOBAL_ACTION_KEY_RESTART_SYSTEMUI.equals(actionKey) &&
                    isAdvancedRestartPossible()) {
                mItems.add(new RestartSystemUIAction());
            } else if (GLOBAL_ACTION_KEY_SCREENSHOT.equals(actionKey)) {
                mItems.add(new ScreenshotAction());
            } else if (GLOBAL_ACTION_KEY_SCREENRECORD.equals(actionKey)) {
                mItems.add(new ScreenrecordAction());
            } else if (GLOBAL_ACTION_KEY_LOGOUT.equals(actionKey)) {
                if (mDevicePolicyManager.isLogoutEnabled()
                        && getCurrentUser().id != UserHandle.USER_SYSTEM) {
                    mItems.add(new LogoutAction());
                    mHasLogoutButton = true;
                }
            } else if (GLOBAL_ACTION_KEY_EMERGENCY.equals(actionKey)) {
                if (!mEmergencyAffordanceManager.needsEmergencyAffordance() && !mIsRestartMenu) {
                    mItems.add(new EmergencyDialerAction());
                }
            } else {
                Log.e(TAG, "Invalid global action key " + actionKey);
            }
            // Add here so we don't add more than one.
            addedKeys.add(actionKey);
        }

        if (mEmergencyAffordanceManager.needsEmergencyAffordance() && !mIsRestartMenu) {
            mItems.add(new EmergencyAffordanceAction());
        }

        mAdapter = new MyAdapter();

        GlobalActionsPanelPlugin.PanelViewController panelViewController =
                mPanelPlugin != null
                        ? mPanelPlugin.onPanelShown(
                                new GlobalActionsPanelPlugin.Callbacks() {
                                    @Override
                                    public void dismissGlobalActionsMenu() {
                                        dismissDialog();
                                    }

                                    @Override
                                    public void startPendingIntentDismissingKeyguard(
                                            PendingIntent intent) {
                                        mActivityStarter
                                                .startPendingIntentDismissingKeyguard(intent);
                                    }
                                },
                                mKeyguardManager.isDeviceLocked())
                        : null;

        ActionsDialog dialog = new ActionsDialog(mContext, mAdapter, panelViewController);
        dialog.setCanceledOnTouchOutside(false); // Handled by the custom class.
        dialog.setKeyguardShowing(mKeyguardShowing);

        dialog.setOnDismissListener(this);
        dialog.setOnShowListener(this);

        mPowerMenuSecure = Settings.Global.getInt(
                        mContext.getContentResolver(), Settings.Global.LOCKSCREEN_POWERMENU_SECURE, 0) != 0;
        return dialog;
    }

    private boolean shouldDisplayLockdown() {
        int userId = getCurrentUser().id;
        // Lockdown is meaningless without a place to go.
        if (!mKeyguardManager.isDeviceSecure(userId)) {
            return false;
        }

        // Only show the lockdown button if the device isn't locked down (for whatever reason).
        int state = mLockPatternUtils.getStrongAuthForUser(userId);
        return (state == STRONG_AUTH_NOT_REQUIRED
                || state == SOME_AUTH_REQUIRED_AFTER_USER_REQUEST);
    }

    @Override
    public void onUiModeChanged() {
        mContext.getTheme().applyStyle(mContext.getThemeResId(), true);
        if (mDialog != null && mDialog.isShowing()) {
            mDialog.refreshDialog();
        }
    }

    public void destroy() {
        Dependency.get(ConfigurationController.class).removeCallback(this);
    }

    private boolean rebootAction(boolean safeMode, String reason) {
        if (mPowerMenuSecure && mKeyguardMonitor.isSecure() && mKeyguardMonitor.isShowing()) {
            Dependency.get(ActivityStarter.class).postQSRunnableDismissingKeyguard(() -> {
                mWindowManagerFuncs.reboot(safeMode, reason);
            });
            return true;
        } else {
            mWindowManagerFuncs.reboot(safeMode, reason);
            return true;
        }
    }

    private final class PowerAction extends SinglePressAction implements LongPressAction {
        private PowerAction() {
            super(R.drawable.ic_lock_power_off,
                    R.string.global_action_power_off);
        }

        @Override
        public boolean onLongPress() {
            UserManager um = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
            if (!um.hasUserRestriction(UserManager.DISALLOW_SAFE_BOOT)) {
                return rebootAction(true, null);
            }
            return false;
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return true;
        }

        @Override
        public void onPress() {
            // shutdown by making sure radio and power are handled accordingly.
            if (mPowerMenuSecure && mKeyguardMonitor.isSecure() && mKeyguardMonitor.isShowing()) {
                Dependency.get(ActivityStarter.class).postQSRunnableDismissingKeyguard(() -> {
                    mWindowManagerFuncs.shutdown();
                });
            } else {
                mWindowManagerFuncs.shutdown();
            }
        }
    }

    private abstract class EmergencyAction extends SinglePressAction {
        EmergencyAction(int iconResId, int messageResId) {
            super(iconResId, messageResId);
        }

        @Override
        public boolean shouldBeSeparated() {
            return shouldUseSeparatedView();
        }

        @Override
        public View create(
                Context context, View convertView, ViewGroup parent, LayoutInflater inflater) {
            View v = super.create(context, convertView, parent, inflater);
            int textColor;
            if (shouldBeSeparated()) {
                textColor = v.getResources().getColor(
                        com.android.systemui.R.color.global_actions_alert_text);
            } else {
                textColor = v.getResources().getColor(
                        com.android.systemui.R.color.global_actions_text);
            }
            TextView messageView = v.findViewById(R.id.message);
            messageView.setTextColor(textColor);
            messageView.setSelected(true); // necessary for marquee to work
            ImageView icon = (ImageView) v.findViewById(R.id.icon);
            icon.getDrawable().setTint(textColor);
            return v;
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return true;
        }
    }

    private class EmergencyAffordanceAction extends EmergencyAction {
        EmergencyAffordanceAction() {
            super(R.drawable.emergency_icon,
                    R.string.global_action_emergency);
        }

        @Override
        public void onPress() {
            mEmergencyAffordanceManager.performEmergencyCall();
        }
    }

    private class EmergencyDialerAction extends EmergencyAction {
        private EmergencyDialerAction() {
            super(com.android.systemui.R.drawable.ic_emergency_star,
                    R.string.global_action_emergency);
        }

        @Override
        public void onPress() {
            MetricsLogger.action(mContext, MetricsEvent.ACTION_EMERGENCY_DIALER_FROM_POWER_MENU);
            Intent intent = new Intent(EmergencyDialerConstants.ACTION_DIAL);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                    | Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS
                    | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            intent.putExtra(EmergencyDialerConstants.EXTRA_ENTRY_TYPE,
                    EmergencyDialerConstants.ENTRY_TYPE_POWER_MENU);
            mContext.startActivityAsUser(intent, UserHandle.CURRENT);
        }
    }

    private final class RestartAction extends SinglePressAction implements LongPressAction {
        private RestartAction() {
            super(R.drawable.ic_restart, R.string.global_action_restart);
            if (mIsRestartMenu) {
                mMessageResId = com.android.systemui.R.string.global_action_restart_system;
            } else if (shouldShowRestartSubmenu()) {
                mMessageResId = R.string.global_action_restart;
            }
        }

        @Override
        public boolean onLongPress() {
            UserManager um = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
            if (!um.hasUserRestriction(UserManager.DISALLOW_SAFE_BOOT)) {
                return rebootAction(true, null);
            }
            return false;
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return true;
        }

        @Override
        public void onPress() {
            if (!mIsRestartMenu && shouldShowRestartSubmenu()) {
                mIsRestartMenu = true;
                mCurrentMenuActions = mRestartMenuActions;
                if (mDialog != null) {
                    mDialog.dismiss();
                    mDialog = null;
                    // Show delayed, so that the dismiss of the previous dialog completes
                    mHandler.sendEmptyMessageDelayed(MESSAGE_SHOW, DIALOG_SHOW_DELAY);
                } else {
                    handleShow();
                }
            } else {
                mHandler.sendEmptyMessage(MESSAGE_DISMISS);
                if (mIsRestartMenu || !isAdvancedRestartPossible()) {
                    rebootAction(false, null);
                }
            }
        }
    }

    private final class RestartRecoveryAction extends SinglePressAction {
        private RestartRecoveryAction() {
            super(com.android.systemui.R.drawable.ic_qs_reboot_recovery,
                    com.android.systemui.R.string.global_action_restart_recovery);
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return true;
        }

        @Override
        public void onPress() {
            rebootAction(false, PowerManager.REBOOT_RECOVERY);

        }
    }

    private final class RestartBootloaderAction extends SinglePressAction {
        private RestartBootloaderAction() {
            super(com.android.systemui.R.drawable.ic_lock_restart_bootloader,
                    com.android.systemui.R.string.global_action_restart_bootloader);
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return true;
        }

        @Override
        public void onPress() {
            rebootAction(false, PowerManager.REBOOT_BOOTLOADER);
        }
    }

    private final class RestartDownloadAction extends SinglePressAction {
        private RestartDownloadAction() {
            super(com.android.systemui.R.drawable.ic_lock_restart_bootloader,
                    com.android.systemui.R.string.global_action_restart_download);
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return true;
        }

        @Override
        public void onPress() {
            rebootAction(false, PowerManager.REBOOT_DOWNLOAD);
        }
    }

    private final class RestartFastbootAction extends SinglePressAction {
        private RestartFastbootAction() {
            super(com.android.systemui.R.drawable.ic_lock_restart_fastboot,
                    com.android.systemui.R.string.global_action_restart_fastboot);
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return true;
        }

        @Override
        public void onPress() {
            rebootAction(false, PowerManager.REBOOT_FASTBOOT);
        }
    }

    private final class RestartSystemUIAction extends SinglePressAction {
        private RestartSystemUIAction() {
            super(com.android.systemui.R.drawable.ic_restart_systemui,
                    com.android.systemui.R.string.global_action_restart_systemui);
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return true;
        }

        @Override
        public void onPress() {
            if (mPowerMenuSecure && mKeyguardMonitor.isSecure() && mKeyguardMonitor.isShowing()) {
                Dependency.get(ActivityStarter.class).postQSRunnableDismissingKeyguard(() -> {
                    Process.killProcess(Process.myPid());
                });
            } else {
                restartSystemUI();
            }
        }
    }

    private class ScreenshotAction extends SinglePressAction implements LongPressAction {
        public ScreenshotAction() {
            super(R.drawable.ic_screenshot, R.string.global_action_screenshot);
        }

        @Override
        public void onPress() {
            // Add a little delay before executing, to give the
            // dialog a chance to go away before it takes a
            // screenshot.
            // TODO: instead, omit global action dialog layer
            mHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    try {
                        WindowManagerGlobal.getWindowManagerService().takeAlternativeScreenshot();
                    } catch (RemoteException e) {
                        Log.e("GlobalActionsDialog", "Error while trying to takeAlternativeScreenshot.", e);
                    }
                    MetricsLogger.action(mContext,
                            MetricsEvent.ACTION_SCREENSHOT_POWER_MENU);
                }
            }, 500);
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return false;
        }

        @Override
        public boolean onLongPress() {
            mScreenshotHelper.takeScreenshot(2, true, true, mHandler, null);
            return true;
        }
    }

    private class ScreenrecordAction extends SinglePressAction {
        public ScreenrecordAction() {
            super(com.android.systemui.R.drawable.ic_qs_screenrecord, com.android.systemui.R.string.global_action_screenrecord);
        }

        @Override
        public void onPress() {
            // Add a little delay before executing, to give the
            // dialog a chance to go away before it shows
            // screenrecord prompt.
            // TODO: instead, omit global action dialog layer
            mHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    mScreenRecordHelper.launchRecordPrompt();
                }
            }, 500);
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return false;
        }
    }

    private class BugReportAction extends SinglePressAction implements LongPressAction {

        public BugReportAction() {
            super(R.drawable.ic_lock_bugreport, R.string.bugreport_title);
        }

        @Override
        public void onPress() {
            // don't actually trigger the bugreport if we are running stability
            // tests via monkey
            if (ActivityManager.isUserAMonkey()) {
                return;
            }
            // Add a little delay before executing, to give the
            // dialog a chance to go away before it takes a
            // screenshot.
            mHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Take an "interactive" bugreport.
                        MetricsLogger.action(mContext,
                                MetricsEvent.ACTION_BUGREPORT_FROM_POWER_MENU_INTERACTIVE);
                        ActivityManager.getService().requestBugReport(
                                ActivityManager.BUGREPORT_OPTION_INTERACTIVE);
                    } catch (RemoteException e) {
                    }
                }
            }, 500);
        }

        @Override
        public boolean onLongPress() {
            // don't actually trigger the bugreport if we are running stability
            // tests via monkey
            if (ActivityManager.isUserAMonkey()) {
                return false;
            }
            try {
                // Take a "full" bugreport.
                MetricsLogger.action(mContext, MetricsEvent.ACTION_BUGREPORT_FROM_POWER_MENU_FULL);
                ActivityManager.getService().requestBugReport(
                        ActivityManager.BUGREPORT_OPTION_FULL);
            } catch (RemoteException e) {
            }
            return false;
        }

        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return false;
        }
    }

    private final class LogoutAction extends SinglePressAction {
        private LogoutAction() {
            super(R.drawable.ic_logout, R.string.global_action_logout);
        }

        @Override
        public boolean showDuringKeyguard() {
            return true;
        }

        @Override
        public boolean showBeforeProvisioning() {
            return false;
        }

        @Override
        public void onPress() {
            // Add a little delay before executing, to give the dialog a chance to go away before
            // switching user
            mHandler.postDelayed(() -> {
                try {
                    int currentUserId = getCurrentUser().id;
                    ActivityManager.getService().switchUser(UserHandle.USER_SYSTEM);
                    ActivityManager.getService().stopUser(currentUserId, true /*force*/, null);
                } catch (RemoteException re) {
                    Log.e(TAG, "Couldn't logout user " + re);
                }
            }, 500);
        }
    }

    private Action getSettingsAction() {
        return new SinglePressAction(R.drawable.ic_settings,
                R.string.global_action_settings) {

            @Override
            public void onPress() {
                Intent intent = new Intent(Settings.ACTION_SETTINGS);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                mContext.startActivity(intent);
            }

            @Override
            public boolean showDuringKeyguard() {
                return true;
            }

            @Override
            public boolean showBeforeProvisioning() {
                return true;
            }
        };
    }

    private Action getAssistAction() {
        return new SinglePressAction(R.drawable.ic_action_assist_focused,
                R.string.global_action_assist) {
            @Override
            public void onPress() {
                Intent intent = new Intent(Intent.ACTION_ASSIST);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                mContext.startActivity(intent);
            }

            @Override
            public boolean showDuringKeyguard() {
                return true;
            }

            @Override
            public boolean showBeforeProvisioning() {
                return true;
            }
        };
    }

    private Action getVoiceAssistAction() {
        return new SinglePressAction(R.drawable.ic_voice_search,
                R.string.global_action_voice_assist) {
            @Override
            public void onPress() {
                Intent intent = new Intent(Intent.ACTION_VOICE_ASSIST);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                mContext.startActivity(intent);
            }

            @Override
            public boolean showDuringKeyguard() {
                return true;
            }

            @Override
            public boolean showBeforeProvisioning() {
                return true;
            }
        };
    }

    private Action getLockdownAction() {
        return new SinglePressAction(R.drawable.ic_lock_lockdown,
                R.string.global_action_lockdown) {

            @Override
            public void onPress() {
                new LockPatternUtils(mContext)
                        .requireStrongAuth(STRONG_AUTH_REQUIRED_AFTER_USER_LOCKDOWN,
                                UserHandle.USER_ALL);
                try {
                    WindowManagerGlobal.getWindowManagerService().lockNow(null);
                    // Lock profiles (if any) on the background thread.
                    final Handler bgHandler = new Handler(Dependency.get(Dependency.BG_LOOPER));
                    bgHandler.post(() -> lockProfiles());
                } catch (RemoteException e) {
                    Log.e(TAG, "Error while trying to lock device.", e);
                }
            }

            @Override
            public boolean showDuringKeyguard() {
                return true;
            }

            @Override
            public boolean showBeforeProvisioning() {
                return false;
            }
        };
    }

    private void lockProfiles() {
        final UserManager um = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
        final TrustManager tm = (TrustManager) mContext.getSystemService(Context.TRUST_SERVICE);
        final int currentUserId = getCurrentUser().id;
        final int[] profileIds = um.getEnabledProfileIds(currentUserId);
        for (final int id : profileIds) {
            if (id != currentUserId) {
                tm.setDeviceLockedForUser(id, true);
            }
        }
    }

    private UserInfo getCurrentUser() {
        try {
            return ActivityManager.getService().getCurrentUser();
        } catch (RemoteException re) {
            return null;
        }
    }

    private boolean isCurrentUserOwner() {
        UserInfo currentUser = getCurrentUser();
        return currentUser == null || currentUser.isPrimary();
    }

    private void addUsersToMenu(ArrayList<Action> items) {
        UserManager um = (UserManager) mContext.getSystemService(Context.USER_SERVICE);
        if (um.isUserSwitcherEnabled()) {
            List<UserInfo> users = um.getUsers();
            UserInfo currentUser = getCurrentUser();
            final int avatarSize = mContext.getResources().getDimensionPixelSize(
                    com.android.systemui.R.dimen.global_actions_avatar_size);
            for (final UserInfo user : users) {
                if (user.supportsSwitchToByUser()) {
                    boolean isCurrentUser = currentUser == null
                            ? user.id == 0 : (currentUser.id == user.id);
                    Drawable avatar = null;
                    Bitmap rawAvatar = um.getUserIcon(user.id);
                    if (rawAvatar == null) {
                        rawAvatar = UserIcons.convertToBitmap(UserIcons.getDefaultUserIcon(
                                mContext.getResources(),
                                user.isGuest() ? UserHandle.USER_NULL : user.id, /*light=*/ false));
                    }
                    avatar = new BitmapDrawable(mContext.getResources(),
                            createCircularClip(rawAvatar, avatarSize, avatarSize));

                    SinglePressAction switchToUser = new SinglePressAction(
                            com.android.systemui.R.drawable.ic_lock_user, avatar,
                            (user.name != null ? user.name : "Primary")) {
                        public void onPress() {
                            try {
                                ActivityManager.getService().switchUser(user.id);
                            } catch (RemoteException re) {
                                Log.e(TAG, "Couldn't switch user " + re);
                            }
                        }

                        public boolean showDuringKeyguard() {
                            return true;
                        }

                        public boolean showBeforeProvisioning() {
                            return false;
                        }
                    };
                    if (isCurrentUser) {
                        switchToUser.setStatus(mContext.getString(
                                com.android.systemui.R.string.global_action_current_user));
                    }
                    items.add(switchToUser);
                }
            }
        }
    }

    private void prepareDialog() {
        refreshSilentMode();
        mAirplaneModeOn.updateState(mAirplaneState);
        mAdapter.notifyDataSetChanged();
        if (mShowSilentToggle) {
            IntentFilter filter = new IntentFilter(AudioManager.RINGER_MODE_CHANGED_ACTION);
            mContext.registerReceiver(mRingerModeReceiver, filter);
        }
    }

    private void refreshSilentMode() {
        if (!mHasVibrator) {
            final boolean silentModeOn =
                    mAudioManager.getRingerMode() != AudioManager.RINGER_MODE_NORMAL;
            ((ToggleAction) mSilentModeAction).updateState(
                    silentModeOn ? ToggleAction.State.On : ToggleAction.State.Off);
        }
    }

    /** {@inheritDoc} */
    public void onDismiss(DialogInterface dialog) {
        if (mDialog == dialog) {
            mDialog = null;
        }
        mWindowManagerFuncs.onGlobalActionsHidden();
        if (mShowSilentToggle) {
            try {
                mContext.unregisterReceiver(mRingerModeReceiver);
            } catch (IllegalArgumentException ie) {
                // ignore this
                Log.w(TAG, ie);
            }
        }
    }

    /** {@inheritDoc} */
    public void onShow(DialogInterface dialog) {
        MetricsLogger.visible(mContext, MetricsEvent.POWER_MENU);
    }

    /**
     * The adapter used for the list within the global actions dialog, taking
     * into account whether the keyguard is showing via
     * {@link com.android.systemui.globalactions.GlobalActionsDialog#mKeyguardShowing} and whether
     * the device is provisioned
     * via {@link com.android.systemui.globalactions.GlobalActionsDialog#mDeviceProvisioned}.
     */
    public class MyAdapter extends MultiListAdapter {
        private int countItems(boolean separated) {
            int count = 0;
            for (int i = 0; i < mItems.size(); i++) {
                final Action action = mItems.get(i);

                if (shouldBeShown(action) && action.shouldBeSeparated() == separated) {
                    count++;
                }
            }
            return count;
        }

        private boolean shouldBeShown(Action action) {
            if (mKeyguardShowing && !action.showDuringKeyguard()) {
                return false;
            }
            if (!mDeviceProvisioned && !action.showBeforeProvisioning()) {
                return false;
            }
            return true;
        }

        @Override
        public int countSeparatedItems() {
            return countItems(true);
        }

        @Override
        public int countListItems() {
            return countItems(false);
        }

        @Override
        public int getCount() {
            return countSeparatedItems() + countListItems();
        }

        @Override
        public boolean isEnabled(int position) {
            return getItem(position).isEnabled();
        }

        @Override
        public boolean areAllItemsEnabled() {
            return false;
        }

        @Override
        public Action getItem(int position) {
            int filteredPos = 0;
            for (int i = 0; i < mItems.size(); i++) {
                final Action action = mItems.get(i);
                if (!shouldBeShown(action)) {
                    continue;
                }
                if (filteredPos == position) {
                    return action;
                }
                filteredPos++;
            }

            throw new IllegalArgumentException("position " + position
                    + " out of range of showable actions"
                    + ", filtered count=" + getCount()
                    + ", keyguardshowing=" + mKeyguardShowing
                    + ", provisioned=" + mDeviceProvisioned);
        }


        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            Action action = getItem(position);
            View view = action.create(mContext, convertView, parent, LayoutInflater.from(mContext));
            view.setOnClickListener(v -> onClickItem(position));
            view.setOnLongClickListener(v -> onLongClickItem(position));
            return view;
        }

        @Override
        public boolean onLongClickItem(int position) {
            final Action action = mAdapter.getItem(position);
            if (action instanceof LongPressAction) {
                mDialog.dismiss();
                return ((LongPressAction) action).onLongPress();
            }
            return false;
        }

        @Override
        public void onClickItem(int position) {
            if (mDialog == null) return;
            Action item = mAdapter.getItem(position);
            if (!(item instanceof SilentModeTriStateAction)) {
                mDialog.dismiss();
            }
            item.onPress();
        }

        @Override
        public boolean shouldBeSeparated(int position) {
            return getItem(position).shouldBeSeparated();
        }
    }

    // note: the scheme below made more sense when we were planning on having
    // 8 different things in the global actions dialog.  seems overkill with
    // only 3 items now, but may as well keep this flexible approach so it will
    // be easy should someone decide at the last minute to include something
    // else, such as 'enable wifi', or 'enable bluetooth'

    /**
     * What each item in the global actions dialog must be able to support.
     */
    public interface Action {
        /**
         * @return Text that will be announced when dialog is created.  null
         * for none.
         */
        CharSequence getLabelForAccessibility(Context context);

        View create(Context context, View convertView, ViewGroup parent, LayoutInflater inflater);

        void onPress();

        /**
         * @return whether this action should appear in the dialog when the keygaurd
         * is showing.
         */
        boolean showDuringKeyguard();

        /**
         * @return whether this action should appear in the dialog before the
         * device is provisioned.onlongpress
         *
         */
        boolean showBeforeProvisioning();

        boolean isEnabled();

        default boolean shouldBeSeparated() {
            return false;
        }
    }

    /**
     * An action that also supports long press.
     */
    private interface LongPressAction extends Action {
        boolean onLongPress();
    }

    /**
     * A single press action maintains no state, just responds to a press
     * and takes an action.
     */
    private static abstract class SinglePressAction implements Action {
        private final int mIconResId;
        private final Drawable mIcon;
        protected int mMessageResId;
        private final CharSequence mMessage;
        private CharSequence mStatusMessage;

        protected SinglePressAction(int iconResId, int messageResId) {
            mIconResId = iconResId;
            mMessageResId = messageResId;
            mMessage = null;
            mIcon = null;
        }

        protected SinglePressAction(int iconResId, Drawable icon, CharSequence message) {
            mIconResId = iconResId;
            mMessageResId = 0;
            mMessage = message;
            mIcon = icon;
        }

        public boolean isEnabled() {
            return true;
        }

        public CharSequence getStatus() {
            return mStatusMessage;
        }

        public void setStatus(CharSequence status) {
            mStatusMessage = status;
        }

        abstract public void onPress();

        public CharSequence getLabelForAccessibility(Context context) {
            if (mMessage != null) {
                return mMessage;
            } else {
                return context.getString(mMessageResId);
            }
        }

        protected int getActionLayoutId(Context context) {
            return com.android.systemui.R.layout.global_actions_grid_item;
        }

        public View create(
                Context context, View convertView, ViewGroup parent, LayoutInflater inflater) {
            View v = inflater.inflate(getActionLayoutId(context), parent,
                    false);

            ImageView icon = (ImageView) v.findViewById(R.id.icon);
            TextView messageView = (TextView) v.findViewById(R.id.message);
            messageView.setSelected(true); // necessary for marquee to work

            if (mIcon != null) {
                icon.setImageDrawable(mIcon);
                icon.setScaleType(ScaleType.CENTER);
            } else if (mIconResId != 0) {
                icon.setImageDrawable(context.getDrawable(mIconResId));
            }
            if (mMessage != null) {
                messageView.setText(mMessage);
            } else {
                messageView.setText(mMessageResId);
            }

            return v;
        }
    }

    /**
     * A toggle action knows whether it is on or off, and displays an icon
     * and status message accordingly.
     */
    private static abstract class ToggleAction implements Action {

        enum State {
            Off(false),
            TurningOn(true),
            TurningOff(true),
            On(false);

            private final boolean inTransition;

            State(boolean intermediate) {
                inTransition = intermediate;
            }

            public boolean inTransition() {
                return inTransition;
            }
        }

        protected State mState = State.Off;

        // prefs
        protected int mEnabledIconResId;
        protected int mDisabledIconResid;
        protected int mMessageResId;
        protected int mEnabledStatusMessageResId;
        protected int mDisabledStatusMessageResId;

        /**
         * @param enabledIconResId           The icon for when this action is on.
         * @param disabledIconResid          The icon for when this action is off.
         * @param message                    The general information message, e.g 'Silent Mode'
         * @param enabledStatusMessageResId  The on status message, e.g 'sound disabled'
         * @param disabledStatusMessageResId The off status message, e.g. 'sound enabled'
         */
        public ToggleAction(int enabledIconResId,
                int disabledIconResid,
                int message,
                int enabledStatusMessageResId,
                int disabledStatusMessageResId) {
            mEnabledIconResId = enabledIconResId;
            mDisabledIconResid = disabledIconResid;
            mMessageResId = message;
            mEnabledStatusMessageResId = enabledStatusMessageResId;
            mDisabledStatusMessageResId = disabledStatusMessageResId;
        }

        /**
         * Override to make changes to resource IDs just before creating the
         * View.
         */
        void willCreate() {

        }

        @Override
        public CharSequence getLabelForAccessibility(Context context) {
            return context.getString(mMessageResId);
        }

        public View create(Context context, View convertView, ViewGroup parent,
                LayoutInflater inflater) {
            willCreate();

            View v = inflater.inflate(com.android.systemui.R
                    .layout.global_actions_grid_item, parent, false);

            ImageView icon = (ImageView) v.findViewById(R.id.icon);
            TextView messageView = (TextView) v.findViewById(R.id.message);
            final boolean enabled = isEnabled();
            boolean on = ((mState == State.On) || (mState == State.TurningOn));

            if (messageView != null) {
                messageView.setText(on ? mEnabledStatusMessageResId : mDisabledStatusMessageResId);
                messageView.setEnabled(enabled);
                messageView.setSelected(true); // necessary for marquee to work
            }

            if (icon != null) {
                icon.setImageDrawable(context.getDrawable(
                        (on ? mEnabledIconResId : mDisabledIconResid)));
                icon.setEnabled(enabled);
            }

            v.setEnabled(enabled);

            return v;
        }

        public final void onPress() {
            if (mState.inTransition()) {
                Log.w(TAG, "shouldn't be able to toggle when in transition");
                return;
            }

            final boolean nowOn = !(mState == State.On);
            onToggle(nowOn);
            changeStateFromPress(nowOn);
        }

        public boolean isEnabled() {
            return !mState.inTransition();
        }

        /**
         * Implementations may override this if their state can be in on of the intermediate
         * states until some notification is received (e.g airplane mode is 'turning off' until
         * we know the wireless connections are back online
         *
         * @param buttonOn Whether the button was turned on or off
         */
        protected void changeStateFromPress(boolean buttonOn) {
            mState = buttonOn ? State.On : State.Off;
        }

        abstract void onToggle(boolean on);

        public void updateState(State state) {
            mState = state;
        }
    }

    private class SilentModeToggleAction extends ToggleAction {
        public SilentModeToggleAction() {
            super(R.drawable.ic_audio_vol_mute,
                    R.drawable.ic_audio_vol,
                    R.string.global_action_toggle_silent_mode,
                    R.string.global_action_silent_mode_on_status,
                    R.string.global_action_silent_mode_off_status);
        }

        void onToggle(boolean on) {
            if (on) {
                mAudioManager.setRingerMode(AudioManager.RINGER_MODE_SILENT);
            } else {
                mAudioManager.setRingerMode(AudioManager.RINGER_MODE_NORMAL);
            }
        }

        public boolean showDuringKeyguard() {
            return true;
        }

        public boolean showBeforeProvisioning() {
            return false;
        }
    }

    private static class SilentModeTriStateAction implements Action, View.OnClickListener {

        private final int[] ITEM_IDS = {R.id.option1, R.id.option2, R.id.option3};

        private final AudioManager mAudioManager;
        private final Handler mHandler;

        SilentModeTriStateAction(AudioManager audioManager, Handler handler) {
            mAudioManager = audioManager;
            mHandler = handler;
        }

        private int ringerModeToIndex(int ringerMode) {
            // They just happen to coincide
            return ringerMode;
        }

        private int indexToRingerMode(int index) {
            // They just happen to coincide
            return index;
        }

        @Override
        public CharSequence getLabelForAccessibility(Context context) {
            return null;
        }

        public View create(Context context, View convertView, ViewGroup parent,
                LayoutInflater inflater) {
            View v = inflater.inflate(R.layout.global_actions_silent_mode, parent, false);

            int selectedIndex = ringerModeToIndex(mAudioManager.getRingerMode());
            for (int i = 0; i < 3; i++) {
                View itemView = v.findViewById(ITEM_IDS[i]);
                itemView.setSelected(selectedIndex == i);
                // Set up click handler
                itemView.setTag(i);
                itemView.setOnClickListener(this);
            }
            return v;
        }

        public void onPress() {
        }

        public boolean showDuringKeyguard() {
            return true;
        }

        public boolean showBeforeProvisioning() {
            return false;
        }

        public boolean isEnabled() {
            return true;
        }

        void willCreate() {
        }

        public void onClick(View v) {
            if (!(v.getTag() instanceof Integer)) return;

            int index = (Integer) v.getTag();
            mAudioManager.setRingerMode(indexToRingerMode(index));
            mHandler.sendEmptyMessageDelayed(MESSAGE_DISMISS, DIALOG_DISMISS_DELAY);
        }
    }

    private BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (Intent.ACTION_CLOSE_SYSTEM_DIALOGS.equals(action)
                    || Intent.ACTION_SCREEN_OFF.equals(action)) {
                String reason = intent.getStringExtra(SYSTEM_DIALOG_REASON_KEY);
                if (!SYSTEM_DIALOG_REASON_GLOBAL_ACTIONS.equals(reason)) {
                    mHandler.sendMessage(mHandler.obtainMessage(MESSAGE_DISMISS, reason));
                }
            } else if (TelephonyIntents.ACTION_EMERGENCY_CALLBACK_MODE_CHANGED.equals(action)) {
                // Airplane mode can be changed after ECM exits if airplane toggle button
                // is pressed during ECM mode
                if (!(intent.getBooleanExtra("PHONE_IN_ECM_STATE", false)) &&
                        mIsWaitingForEcmExit) {
                    mIsWaitingForEcmExit = false;
                    changeAirplaneModeSystemSetting(true);
                }
            } else if (Intent.ACTION_UPDATE_POWER_MENU.equals(action)) {
                updatePowerMenuActions();
            }
        }
    };

    protected void updatePowerMenuActions() {
        ContentResolver resolver = mContext.getContentResolver();
        final String powerMenuActions = Settings.System.getStringForUser(resolver,
                Settings.System.POWER_MENU_ACTIONS, UserHandle.USER_CURRENT);

        if (powerMenuActions != null) {
            mRootMenuActions = powerMenuActions.split("\\|");
        } else {
            mRootMenuActions = mDefaultMenuActions;
        }
    };

    private BroadcastReceiver mRingerModeReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent.getAction().equals(AudioManager.RINGER_MODE_CHANGED_ACTION)) {
                mHandler.sendEmptyMessage(MESSAGE_REFRESH);
            }
        }
    };

    private ContentObserver mAirplaneModeObserver = new ContentObserver(new Handler()) {
        @Override
        public void onChange(boolean selfChange) {
            onAirplaneModeChanged();
        }
    };

    private static final int MESSAGE_DISMISS = 0;
    private static final int MESSAGE_REFRESH = 1;
    private static final int MESSAGE_SHOW = 2;
    private static final int DIALOG_DISMISS_DELAY = 300; // ms
    private static final int DIALOG_SHOW_DELAY = 300; // ms

    private Handler mHandler = new Handler() {
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MESSAGE_DISMISS:
                    if (mDialog != null) {
                        if (SYSTEM_DIALOG_REASON_DREAM.equals(msg.obj)) {
                            mDialog.dismissImmediately();
                        } else {
                            mDialog.dismiss();
                        }
                        mDialog = null;
                    }
                    break;
                case MESSAGE_REFRESH:
                    refreshSilentMode();
                    mAdapter.notifyDataSetChanged();
                    break;
                case MESSAGE_SHOW:
                    handleShow();
                    break;
            }
        }
    };

    private ToggleAction.State getUpdatedAirplaneToggleState() {
        return Settings.Global.getInt(mContext.getContentResolver(),
                Settings.Global.AIRPLANE_MODE_ON, 0) == 1
                    ? ToggleAction.State.On
                    : ToggleAction.State.Off;
    }

    private void onAirplaneModeChanged() {
        // Let the service state callbacks handle the state.
        if (mHasTelephony) return;

        mAirplaneState = getUpdatedAirplaneToggleState();
        mAirplaneModeOn.updateState(mAirplaneState);
    }

    /**
     * Change the airplane mode system setting
     */
    private void changeAirplaneModeSystemSetting(boolean on) {
        Settings.Global.putInt(
                mContext.getContentResolver(),
                Settings.Global.AIRPLANE_MODE_ON,
                on ? 1 : 0);
        Intent intent = new Intent(Intent.ACTION_AIRPLANE_MODE_CHANGED);
        intent.addFlags(Intent.FLAG_RECEIVER_REPLACE_PENDING);
        intent.putExtra("state", on);
        mContext.sendBroadcastAsUser(intent, UserHandle.ALL);
        if (!mHasTelephony) {
            mAirplaneState = on ? ToggleAction.State.On : ToggleAction.State.Off;
        }
    }

    /**
     * Generate a new bitmap (width x height pixels, ARGB_8888) with the input bitmap scaled
     * to fit and clipped to an inscribed circle.
     * @param input Bitmap to resize and clip
     * @param width Width of output bitmap (and diameter of circle)
     * @param height Height of output bitmap
     * @return A shiny new bitmap for you to use
     */
    private static Bitmap createCircularClip(Bitmap input, int width, int height) {
        if (input == null) return null;

        final int inWidth = input.getWidth();
        final int inHeight = input.getHeight();
        final Bitmap output = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        final Canvas canvas = new Canvas(output);
        final Paint paint = new Paint();
        paint.setShader(new BitmapShader(input, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP));
        paint.setAntiAlias(true);
        final RectF srcRect = new RectF(0, 0, inWidth, inHeight);
        final RectF dstRect = new RectF(0, 0, width, height);
        final Matrix m = new Matrix();
        m.setRectToRect(srcRect, dstRect, Matrix.ScaleToFit.CENTER);
        canvas.setMatrix(m);
        canvas.drawCircle(inWidth / 2, inHeight / 2, inWidth / 2, paint);
        return output;
    }

    private static final class ActionsDialog extends Dialog implements DialogInterface,
            ColorExtractor.OnColorsChangedListener {

        private final Context mContext;
        private final MyAdapter mAdapter;
        private final IStatusBarService mStatusBarService;
        private final IBinder mToken = new Binder();
        private MultiListLayout mGlobalActionsLayout;
        private Drawable mBackgroundDrawable;
        private final SysuiColorExtractor mColorExtractor;
        private final GlobalActionsPanelPlugin.PanelViewController mPanelController;
        private boolean mKeyguardShowing;
        private boolean mShowing;
        private float mScrimAlpha;
        private ResetOrientationData mResetOrientationData;
        private boolean mHadTopUi;
        private final StatusBarWindowController mStatusBarWindowController;

        ActionsDialog(Context context, MyAdapter adapter,
                GlobalActionsPanelPlugin.PanelViewController plugin) {
            super(context, com.android.systemui.R.style.Theme_SystemUI_Dialog_GlobalActions);
            mContext = context;
            mAdapter = adapter;
            mColorExtractor = Dependency.get(SysuiColorExtractor.class);
            mStatusBarService = Dependency.get(IStatusBarService.class);
            mStatusBarWindowController = Dependency.get(StatusBarWindowController.class);

            // Window initialization
            Window window = getWindow();
            window.requestFeature(Window.FEATURE_NO_TITLE);
            // Inflate the decor view, so the attributes below are not overwritten by the theme.
            window.getDecorView();
            window.getAttributes().systemUiVisibility |= View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    | View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION;
            window.setLayout(MATCH_PARENT, MATCH_PARENT);
            window.clearFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            window.addFlags(
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
                    | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
                    | WindowManager.LayoutParams.FLAG_LAYOUT_INSET_DECOR
                    | WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED
                    | WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH
                    | WindowManager.LayoutParams.FLAG_HARDWARE_ACCELERATED);
            window.setType(WindowManager.LayoutParams.TYPE_VOLUME_OVERLAY);
            setTitle(R.string.global_actions);

            mPanelController = plugin;
            initializeLayout();
        }

        private boolean shouldUsePanel() {
            return mPanelController != null && mPanelController.getPanelContent() != null;
        }

        private void initializePanel() {
            int rotation = RotationUtils.getRotation(mContext);
            boolean rotationLocked = RotationPolicy.isRotationLocked(mContext);
            if (rotation != RotationUtils.ROTATION_NONE) {
                if (rotationLocked) {
                    if (mResetOrientationData == null) {
                        mResetOrientationData = new ResetOrientationData();
                        mResetOrientationData.locked = true;
                        mResetOrientationData.rotation = rotation;
                    }

                    // Unlock rotation, so user can choose to rotate to portrait to see the panel.
                    // This call is posted so that the rotation does not change until post-layout,
                    // otherwise onConfigurationChanged() may not get invoked.
                    mGlobalActionsLayout.post(() ->
                            RotationPolicy.setRotationLockAtAngle(
                                    mContext, false, RotationUtils.ROTATION_NONE));
                }
            } else {
                if (!rotationLocked) {
                    if (mResetOrientationData == null) {
                        mResetOrientationData = new ResetOrientationData();
                        mResetOrientationData.locked = false;
                    }

                    // Lock to portrait, so the user doesn't accidentally hide the panel.
                    // This call is posted so that the rotation does not change until post-layout,
                    // otherwise onConfigurationChanged() may not get invoked.
                    mGlobalActionsLayout.post(() ->
                            RotationPolicy.setRotationLockAtAngle(
                                    mContext, true, RotationUtils.ROTATION_NONE));
                }

                // Disable rotation suggestions, if enabled
                setRotationSuggestionsEnabled(false);

                FrameLayout panelContainer =
                        findViewById(com.android.systemui.R.id.global_actions_panel_container);
                FrameLayout.LayoutParams panelParams =
                        new FrameLayout.LayoutParams(
                                FrameLayout.LayoutParams.MATCH_PARENT,
                                FrameLayout.LayoutParams.MATCH_PARENT);
                panelContainer.addView(mPanelController.getPanelContent(), panelParams);
                mBackgroundDrawable = mPanelController.getBackgroundDrawable();
                mScrimAlpha = 1f;
            }
        }

        private void initializeLayout() {
            setContentView(getGlobalActionsLayoutId(mContext));
            fixNavBarClipping();
            mGlobalActionsLayout = findViewById(com.android.systemui.R.id.global_actions_view);
            mGlobalActionsLayout.setOutsideTouchListener(view -> dismiss());
            ((View) mGlobalActionsLayout.getParent()).setOnClickListener(view -> dismiss());
            mGlobalActionsLayout.setListViewAccessibilityDelegate(new View.AccessibilityDelegate() {
                @Override
                public boolean dispatchPopulateAccessibilityEvent(
                        View host, AccessibilityEvent event) {
                    // Populate the title here, just as Activity does
                    event.getText().add(mContext.getString(R.string.global_actions));
                    return true;
                }
            });
            mGlobalActionsLayout.setRotationListener(this::onRotate);
            mGlobalActionsLayout.setAdapter(mAdapter);

            if (shouldUsePanel()) {
                initializePanel();
            }
            if (mBackgroundDrawable == null) {
                mBackgroundDrawable = new ScrimDrawable();
                mScrimAlpha = ScrimController.GRADIENT_SCRIM_ALPHA;
            }
            getWindow().setBackgroundDrawable(mBackgroundDrawable);
        }

        private void fixNavBarClipping() {
            ViewGroup content = findViewById(android.R.id.content);
            content.setClipChildren(false);
            content.setClipToPadding(false);
            ViewGroup contentParent = (ViewGroup) content.getParent();
            contentParent.setClipChildren(false);
            contentParent.setClipToPadding(false);
        }

        private int getGlobalActionsLayoutId(Context context) {
            int rotation = RotationUtils.getRotation(context);
            boolean useGridLayout = isForceGridEnabled(context)
                    || (shouldUsePanel() && rotation == RotationUtils.ROTATION_NONE);
            if (rotation == RotationUtils.ROTATION_SEASCAPE) {
                if (useGridLayout) {
                    return com.android.systemui.R.layout.global_actions_grid_seascape;
                } else {
                    return com.android.systemui.R.layout.global_actions_column_seascape;
                }
            } else {
                if (useGridLayout) {
                    return com.android.systemui.R.layout.global_actions_grid;
                } else {
                    return com.android.systemui.R.layout.global_actions_column;
                }
            }
        }

        @Override
        protected void onStart() {
            super.setCanceledOnTouchOutside(true);
            super.onStart();
            mGlobalActionsLayout.updateList();

            if (mBackgroundDrawable instanceof ScrimDrawable) {
                mColorExtractor.addOnColorsChangedListener(this);
                GradientColors colors = mColorExtractor.getNeutralColors();
                updateColors(colors, false /* animate */);
            }
        }

        /**
         * Updates background and system bars according to current GradientColors.
         * @param colors Colors and hints to use.
         * @param animate Interpolates gradient if true, just sets otherwise.
         */
        private void updateColors(GradientColors colors, boolean animate) {
            if (!(mBackgroundDrawable instanceof ScrimDrawable)) {
                return;
            }
            ((ScrimDrawable) mBackgroundDrawable).setColor(colors.getMainColor(), animate);
            View decorView = getWindow().getDecorView();
            if (colors.supportsDarkText()) {
                decorView.setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR |
                        View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
            } else {
                decorView.setSystemUiVisibility(0);
            }
        }

        @Override
        protected void onStop() {
            super.onStop();
            mColorExtractor.removeOnColorsChangedListener(this);
        }

        @Override
        public void show() {
            super.show();
            mShowing = true;
            mHadTopUi = mStatusBarWindowController.getForceHasTopUi();
            mStatusBarWindowController.setForceHasTopUi(true);
            mBackgroundDrawable.setAlpha(0);
            mGlobalActionsLayout.setTranslationX(mGlobalActionsLayout.getAnimationOffsetX());
            mGlobalActionsLayout.setTranslationY(mGlobalActionsLayout.getAnimationOffsetY());
            mGlobalActionsLayout.setAlpha(0);
            mGlobalActionsLayout.animate()
                    .alpha(1)
                    .translationX(0)
                    .translationY(0)
                    .setDuration(300)
                    .setInterpolator(Interpolators.FAST_OUT_SLOW_IN)
                    .setUpdateListener(animation -> {
                        int alpha = (int) ((Float) animation.getAnimatedValue()
                                * mScrimAlpha * 255);
                        mBackgroundDrawable.setAlpha(alpha);
                    })
                    .start();
        }

        @Override
        public void dismiss() {
            if (!mShowing) {
                return;
            }
            mShowing = false;
            mGlobalActionsLayout.setTranslationX(0);
            mGlobalActionsLayout.setTranslationY(0);
            mGlobalActionsLayout.setAlpha(1);
            mGlobalActionsLayout.animate()
                    .alpha(0)
                    .translationX(mGlobalActionsLayout.getAnimationOffsetX())
                    .translationY(mGlobalActionsLayout.getAnimationOffsetY())
                    .setDuration(300)
                    .withEndAction(this::completeDismiss)
                    .setInterpolator(new LogAccelerateInterpolator())
                    .setUpdateListener(animation -> {
                        int alpha = (int) ((1f - (Float) animation.getAnimatedValue())
                                * mScrimAlpha * 255);
                        mBackgroundDrawable.setAlpha(alpha);
                    })
                    .start();
            dismissPanel();
            resetOrientation();
        }

        void dismissImmediately() {
            mShowing = false;
            dismissPanel();
            resetOrientation();
            completeDismiss();
        }

        private void completeDismiss() {
            mStatusBarWindowController.setForceHasTopUi(mHadTopUi);
            super.dismiss();
        }

        private void dismissPanel() {
            if (mPanelController != null) {
                mPanelController.onDismissed();
            }
        }

        private void setRotationSuggestionsEnabled(boolean enabled) {
            try {
                final int userId = Binder.getCallingUserHandle().getIdentifier();
                final int what = enabled
                        ? StatusBarManager.DISABLE2_NONE
                        : StatusBarManager.DISABLE2_ROTATE_SUGGESTIONS;
                mStatusBarService.disable2ForUser(what, mToken, mContext.getPackageName(), userId);
            } catch (RemoteException ex) {
                throw ex.rethrowFromSystemServer();
            }
        }

        private void resetOrientation() {
            if (mResetOrientationData != null) {
                RotationPolicy.setRotationLockAtAngle(mContext, mResetOrientationData.locked,
                        mResetOrientationData.rotation);
            }
            setRotationSuggestionsEnabled(true);
        }

        @Override
        public void onColorsChanged(ColorExtractor extractor, int which) {
            if (mKeyguardShowing) {
                if ((WallpaperManager.FLAG_LOCK & which) != 0) {
                    updateColors(extractor.getColors(WallpaperManager.FLAG_LOCK),
                            true /* animate */);
                }
            } else {
                if ((WallpaperManager.FLAG_SYSTEM & which) != 0) {
                    updateColors(extractor.getColors(WallpaperManager.FLAG_SYSTEM),
                            true /* animate */);
                }
            }
        }

        public void setKeyguardShowing(boolean keyguardShowing) {
            mKeyguardShowing = keyguardShowing;
        }

        public void refreshDialog() {
            initializeLayout();
            mGlobalActionsLayout.updateList();
        }

        public void onRotate(int from, int to) {
            if (mShowing) {
                refreshDialog();
            }
        }

        private static class ResetOrientationData {
            public boolean locked;
            public int rotation;
        }
    }

    public static void restartSystemUI() {
        Process.killProcess(Process.myPid());
    }

    /**
     * Determines whether or not debug mode has been activated for the Global Actions Panel.
     */
    private static boolean isPanelDebugModeEnabled(Context context) {
        return Settings.Secure.getInt(context.getContentResolver(),
                Settings.Secure.GLOBAL_ACTIONS_PANEL_DEBUG_ENABLED, 0) == 1;
    }

    /**
     * Determines whether or not the Global Actions menu should be forced to
     * use the newer grid-style layout.
     */
    private static boolean isForceGridEnabled(Context context) {
        return isPanelDebugModeEnabled(context);
    }

    /**
     * Determines whether the Global Actions menu should use a separated view for emergency actions.
     */
    private static boolean shouldUseSeparatedView() {
        return true;
    }
}
