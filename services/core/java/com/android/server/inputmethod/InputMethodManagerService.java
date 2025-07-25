/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.android.server.inputmethod;

import static android.view.Display.DEFAULT_DISPLAY;
import static android.view.Display.INVALID_DISPLAY;
import static android.view.inputmethod.InputMethodSystemProperty.PER_PROFILE_IME_ENABLED;

import static java.lang.annotation.RetentionPolicy.SOURCE;

import android.Manifest;
import android.accessibilityservice.AccessibilityService;
import android.annotation.AnyThread;
import android.annotation.BinderThread;
import android.annotation.ColorInt;
import android.annotation.DrawableRes;
import android.annotation.IntDef;
import android.annotation.MainThread;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.annotation.UserIdInt;
import android.app.ActivityManager;
import android.app.ActivityManagerInternal;
import android.app.ActivityThread;
import android.app.AlertDialog;
import android.app.AppGlobals;
import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.IPackageManager;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.database.ContentObserver;
import android.graphics.Matrix;
import android.graphics.drawable.Drawable;
import android.hardware.display.DisplayManagerInternal;
import android.inputmethodservice.InputMethodService;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Debug;
import android.os.Handler;
import android.os.IBinder;
import android.os.IInterface;
import android.os.LocaleList;
import android.os.Message;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.ResultReceiver;
import android.os.ServiceManager;
import android.os.ShellCallback;
import android.os.ShellCommand;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.UserManager;
import android.os.UserManagerInternal;
import android.provider.Settings;
import android.text.TextUtils;
import android.text.style.SuggestionSpan;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.EventLog;
import android.util.LruCache;
import android.util.Pair;
import android.util.PrintWriterPrinter;
import android.util.Printer;
import android.util.Slog;
import android.util.SparseArray;
import android.util.SparseBooleanArray;
import android.view.ContextThemeWrapper;
import android.view.DisplayInfo;
import android.view.IWindowManager;
import android.view.InputChannel;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager.LayoutParams;
import android.view.WindowManager.LayoutParams.SoftInputModeFlags;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputBinding;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputConnectionInspector;
import android.view.inputmethod.InputConnectionInspector.MissingMethodFlags;
import android.view.inputmethod.InputMethod;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;
import android.view.inputmethod.InputMethodSubtype;
import android.widget.ArrayAdapter;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.RadioButton;
import android.widget.Switch;
import android.widget.TextView;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.content.PackageMonitor;
import com.android.internal.inputmethod.IInputContentUriToken;
import com.android.internal.inputmethod.IInputMethodPrivilegedOperations;
import com.android.internal.inputmethod.InputMethodDebug;
import com.android.internal.inputmethod.StartInputFlags;
import com.android.internal.inputmethod.StartInputReason;
import com.android.internal.inputmethod.UnbindReason;
import com.android.internal.messages.nano.SystemMessageProto.SystemMessage;
import com.android.internal.notification.SystemNotificationChannels;
import com.android.internal.os.HandlerCaller;
import com.android.internal.os.SomeArgs;
import com.android.internal.os.TransferPipe;
import com.android.internal.util.DumpUtils;
import com.android.internal.util.IndentingPrintWriter;
import com.android.internal.view.IInputContext;
import com.android.internal.view.IInputMethod;
import com.android.internal.view.IInputMethodClient;
import com.android.internal.view.IInputMethodManager;
import com.android.internal.view.IInputMethodSession;
import com.android.internal.view.IInputSessionCallback;
import com.android.internal.view.InputBindResult;
import com.android.server.EventLogTags;
import com.android.server.LocalServices;
import com.android.server.SystemService;
import com.android.server.inputmethod.InputMethodSubtypeSwitchingController.ImeSubtypeListItem;
import com.android.server.inputmethod.InputMethodUtils.InputMethodSettings;
import com.android.server.statusbar.StatusBarManagerService;
import com.android.server.wm.WindowManagerInternal;

import com.android.internal.custom.hardware.LineageHardwareManager;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.annotation.Retention;
import java.security.InvalidParameterException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class provides a system service that manages input methods.
 */
public class InputMethodManagerService extends IInputMethodManager.Stub
        implements ServiceConnection, Handler.Callback {
    static final boolean DEBUG = false;
    static final String TAG = "InputMethodManagerService";

    @Retention(SOURCE)
    @IntDef({ShellCommandResult.SUCCESS, ShellCommandResult.FAILURE})
    private @interface ShellCommandResult {
        int SUCCESS = 0;
        int FAILURE = -1;
    }

    static final int MSG_SHOW_IM_SUBTYPE_PICKER = 1;
    static final int MSG_SHOW_IM_SUBTYPE_ENABLER = 2;
    static final int MSG_SHOW_IM_CONFIG = 3;

    static final int MSG_UNBIND_INPUT = 1000;
    static final int MSG_BIND_INPUT = 1010;
    static final int MSG_SHOW_SOFT_INPUT = 1020;
    static final int MSG_HIDE_SOFT_INPUT = 1030;
    static final int MSG_HIDE_CURRENT_INPUT_METHOD = 1035;
    static final int MSG_INITIALIZE_IME = 1040;
    static final int MSG_CREATE_SESSION = 1050;

    static final int MSG_START_INPUT = 2000;

    static final int MSG_UNBIND_CLIENT = 3000;
    static final int MSG_BIND_CLIENT = 3010;
    static final int MSG_SET_ACTIVE = 3020;
    static final int MSG_SET_INTERACTIVE = 3030;
    static final int MSG_REPORT_FULLSCREEN_MODE = 3045;
    static final int MSG_REPORT_PRE_RENDERED = 3060;
    static final int MSG_APPLY_IME_VISIBILITY = 3070;

    static final int MSG_HARD_KEYBOARD_SWITCH_CHANGED = 4000;

    static final int MSG_SYSTEM_UNLOCK_USER = 5000;

    static final long TIME_TO_RECONNECT = 3 * 1000;

    static final int SECURE_SUGGESTION_SPANS_MAX_SIZE = 20;

    private static final int NOT_A_SUBTYPE_ID = InputMethodUtils.NOT_A_SUBTYPE_ID;
    private static final String TAG_TRY_SUPPRESSING_IME_SWITCHER = "TrySuppressingImeSwitcher";

    /**
     * Binding flags for establishing connection to the {@link InputMethodService}.
     */
    private static final int IME_CONNECTION_BIND_FLAGS =
            Context.BIND_AUTO_CREATE
            | Context.BIND_NOT_VISIBLE
            | Context.BIND_NOT_FOREGROUND
            | Context.BIND_IMPORTANT_BACKGROUND;

    /**
     * Binding flags used only while the {@link InputMethodService} is showing window.
     */
    private static final int IME_VISIBLE_BIND_FLAGS =
            Context.BIND_AUTO_CREATE
            | Context.BIND_TREAT_LIKE_ACTIVITY
            | Context.BIND_FOREGROUND_SERVICE
            | Context.BIND_INCLUDE_CAPABILITIES
            | Context.BIND_SHOWING_UI
            | Context.BIND_SCHEDULE_LIKE_TOP_APP;

    @Retention(SOURCE)
    @IntDef({HardKeyboardBehavior.WIRELESS_AFFORDANCE, HardKeyboardBehavior.WIRED_AFFORDANCE})
    private @interface  HardKeyboardBehavior {
        int WIRELESS_AFFORDANCE = 0;
        int WIRED_AFFORDANCE = 1;
    }

    /**
     * A protected broadcast intent action for internal use for {@link PendingIntent} in
     * the notification.
     */
    private static final String ACTION_SHOW_INPUT_METHOD_PICKER =
            "com.android.server.inputmethod.InputMethodManagerService.SHOW_INPUT_METHOD_PICKER";

    /**
     * Debug flag for overriding runtime {@link SystemProperties}.
     */
    @AnyThread
    private static final class DebugFlag {
        private static final Object LOCK = new Object();
        private final String mKey;
        private final boolean mDefaultValue;
        @GuardedBy("LOCK")
        private boolean mValue;

        public DebugFlag(String key, boolean defaultValue) {
            mKey = key;
            mDefaultValue = defaultValue;
            mValue = SystemProperties.getBoolean(key, defaultValue);
        }

        void refresh() {
            synchronized (LOCK) {
                mValue = SystemProperties.getBoolean(mKey, mDefaultValue);
            }
        }

        boolean value() {
            synchronized (LOCK) {
                return mValue;
            }
        }
    }

    /**
     * Debug flags that can be overridden using "adb shell setprop <key>"
     * Note: These flags are cached. To refresh, run "adb shell ime refresh_debug_properties".
     */
    private static final class DebugFlags {
        static final DebugFlag FLAG_OPTIMIZE_START_INPUT =
                new DebugFlag("debug.optimize_startinput", false);
        static final DebugFlag FLAG_PRE_RENDER_IME_VIEWS =
                new DebugFlag("persist.pre_render_ime_views", false);
    }

    @UserIdInt
    private int mLastSwitchUserId;

    final Context mContext;
    final Resources mRes;
    final Handler mHandler;
    final InputMethodSettings mSettings;
    final SettingsObserver mSettingsObserver;
    final IWindowManager mIWindowManager;
    private final SparseBooleanArray mLoggedDeniedGetInputMethodWindowVisibleHeightForUid =
            new SparseBooleanArray(0);
    final WindowManagerInternal mWindowManagerInternal;
    private final DisplayManagerInternal mDisplayManagerInternal;
    final HandlerCaller mCaller;
    final boolean mHasFeature;
    private final ArrayMap<String, List<InputMethodSubtype>> mAdditionalSubtypeMap =
            new ArrayMap<>();
    private final boolean mIsLowRam;
    private final HardKeyboardListener mHardKeyboardListener;
    private final AppOpsManager mAppOpsManager;
    private final UserManager mUserManager;
    private final UserManagerInternal mUserManagerInternal;

    // All known input methods.  mMethodMap also serves as the global
    // lock for this class.
    final ArrayList<InputMethodInfo> mMethodList = new ArrayList<>();
    final ArrayMap<String, InputMethodInfo> mMethodMap = new ArrayMap<>();
    private final LruCache<SuggestionSpan, InputMethodInfo> mSecureSuggestionSpans =
            new LruCache<>(SECURE_SUGGESTION_SPANS_MAX_SIZE);
    private final InputMethodSubtypeSwitchingController mSwitchingController;

    /**
     * Tracks how many times {@link #mMethodMap} was updated.
     */
    @GuardedBy("mMethodMap")
    private int mMethodMapUpdateCount = 0;

    // Used to bring IME service up to visible adjustment while it is being shown.
    final ServiceConnection mVisibleConnection = new ServiceConnection() {
        @Override public void onBindingDied(ComponentName name) {
            synchronized (mMethodMap) {
                if (mVisibleBound) {
                    mContext.unbindService(mVisibleConnection);
                    mVisibleBound = false;
                }
            }
        }

        @Override public void onServiceConnected(ComponentName name, IBinder service) {
        }

        @Override public void onServiceDisconnected(ComponentName name) {
        }
    };
    boolean mVisibleBound = false;

    // Ongoing notification
    private NotificationManager mNotificationManager;
    private KeyguardManager mKeyguardManager;
    private @Nullable StatusBarManagerService mStatusBar;
    private Notification.Builder mImeSwitcherNotification;
    private PendingIntent mImeSwitchPendingIntent;
    private boolean mShowOngoingImeSwitcherForPhones;
    private boolean mNotificationShown;

    private LineageHardwareManager mLineageHardware;

    static class SessionState {
        final ClientState client;
        final IInputMethod method;

        IInputMethodSession session;
        InputChannel channel;

        @Override
        public String toString() {
            return "SessionState{uid " + client.uid + " pid " + client.pid
                    + " method " + Integer.toHexString(
                            System.identityHashCode(method))
                    + " session " + Integer.toHexString(
                            System.identityHashCode(session))
                    + " channel " + channel
                    + "}";
        }

        SessionState(ClientState _client, IInputMethod _method,
                IInputMethodSession _session, InputChannel _channel) {
            client = _client;
            method = _method;
            session = _session;
            channel = _channel;
        }
    }

    private static final class ClientDeathRecipient implements IBinder.DeathRecipient {
        private final InputMethodManagerService mImms;
        private final IInputMethodClient mClient;

        ClientDeathRecipient(InputMethodManagerService imms, IInputMethodClient client) {
            mImms = imms;
            mClient = client;
        }

        @Override
        public void binderDied() {
            mImms.removeClient(mClient);
        }
    }

    static final class ClientState {
        final IInputMethodClient client;
        final IInputContext inputContext;
        final int uid;
        final int pid;
        final int selfReportedDisplayId;
        final InputBinding binding;
        final ClientDeathRecipient clientDeathRecipient;

        boolean sessionRequested;
        // Determines if IMEs should be pre-rendered.
        // DebugFlag can be flipped anytime. This flag is kept per-client to maintain behavior
        // through the life of the current client.
        boolean shouldPreRenderIme;
        SessionState curSession;

        @Override
        public String toString() {
            return "ClientState{" + Integer.toHexString(
                    System.identityHashCode(this)) + " uid=" + uid
                    + " pid=" + pid + " displayId=" + selfReportedDisplayId + "}";
        }

        ClientState(IInputMethodClient _client, IInputContext _inputContext,
                int _uid, int _pid, int _selfReportedDisplayId,
                ClientDeathRecipient _clientDeathRecipient) {
            client = _client;
            inputContext = _inputContext;
            uid = _uid;
            pid = _pid;
            selfReportedDisplayId = _selfReportedDisplayId;
            binding = new InputBinding(null, inputContext.asBinder(), uid, pid);
            clientDeathRecipient = _clientDeathRecipient;
        }
    }

    final ArrayMap<IBinder, ClientState> mClients = new ArrayMap<>();

    private static final class ActivityViewInfo {
        /**
         * {@link ClientState} where {@link android.app.ActivityView} is running.
         */
        private final ClientState mParentClient;
        /**
         * {@link Matrix} to convert screen coordinates in the embedded virtual display to
         * screen coordinates where {@link #mParentClient} exists.
         */
        private final Matrix mMatrix;

        ActivityViewInfo(ClientState parentClient, Matrix matrix) {
            mParentClient = parentClient;
            mMatrix = matrix;
        }
    }

    /**
     * A mapping table from virtual display IDs created for {@link android.app.ActivityView}
     * to its parent IME client where {@link android.app.ActivityView} is running.
     *
     * <p>Note: this can be used only for virtual display IDs created by
     * {@link android.app.ActivityView}.</p>
     */
    private SparseArray<ActivityViewInfo> mActivityViewDisplayIdToParentMap = new SparseArray<>();

    /**
     * Set once the system is ready to run third party code.
     */
    boolean mSystemReady;

    /**
     * Id obtained with {@link InputMethodInfo#getId()} for the currently selected input method.
     * method.  This is to be synchronized with the secure settings keyed with
     * {@link Settings.Secure#DEFAULT_INPUT_METHOD}.
     *
     * <p>This can be transiently {@code null} when the system is re-initializing input method
     * settings, e.g., the system locale is just changed.</p>
     *
     * <p>Note that {@link #mCurId} is used to track which IME is being connected to
     * {@link InputMethodManagerService}.</p>
     *
     * @see #mCurId
     */
    @Nullable
    String mCurMethodId;

    /**
     * The current binding sequence number, incremented every time there is
     * a new bind performed.
     */
    int mCurSeq;

    /**
     * The client that is currently bound to an input method.
     */
    ClientState mCurClient;

    /**
     * The last window token that we confirmed to be focused.  This is always updated upon reports
     * from the input method client.  If the window state is already changed before the report is
     * handled, this field just keeps the last value.
     */
    IBinder mCurFocusedWindow;

    /**
     * The last window token that we confirmed that IME started talking to.  This is always updated
     * upon reports from the input method.  If the window state is already changed before the report
     * is handled, this field just keeps the last value.
     */
    IBinder mLastImeTargetWindow;

    /**
     * {@link LayoutParams#softInputMode} of {@link #mCurFocusedWindow}.
     *
     * @see #mCurFocusedWindow
     */
    @SoftInputModeFlags
    int mCurFocusedWindowSoftInputMode;

    /**
     * The client by which {@link #mCurFocusedWindow} was reported.
     */
    ClientState mCurFocusedWindowClient;

    /**
     * The input context last provided by the current client.
     */
    IInputContext mCurInputContext;

    /**
     * The missing method flags for the input context last provided by the current client.
     *
     * @see android.view.inputmethod.InputConnectionInspector.MissingMethodFlags
     */
    @MissingMethodFlags
    int mCurInputContextMissingMethods;

    /**
     * The attributes last provided by the current client.
     */
    EditorInfo mCurAttribute;

    /**
     * A special {@link Matrix} to convert virtual screen coordinates to the IME target display
     * coordinates.
     *
     * <p>Used only while the IME client is running in a virtual display inside
     * {@link android.app.ActivityView}. {@code null} otherwise.</p>
     */
    @Nullable
    private Matrix mCurActivityViewToScreenMatrix = null;

    /**
     * Id obtained with {@link InputMethodInfo#getId()} for the input method that we are currently
     * connected to or in the process of connecting to.
     *
     * <p>This can be {@code null} when no input method is connected.</p>
     *
     * @see #mCurMethodId
     */
    @Nullable
    String mCurId;

    /**
     * The current subtype of the current input method.
     */
    private InputMethodSubtype mCurrentSubtype;

    // Was the keyguard locked when this client became current?
    private boolean mCurClientInKeyguard;

    /**
     * Set to true if our ServiceConnection is currently actively bound to
     * a service (whether or not we have gotten its IBinder back yet).
     */
    boolean mHaveConnection;

    /**
     * Set if the client has asked for the input method to be shown.
     */
    boolean mShowRequested;

    /**
     * Set if we were explicitly told to show the input method.
     */
    boolean mShowExplicitlyRequested;

    /**
     * Set if we were forced to be shown.
     */
    boolean mShowForced;

    /**
     * Set if we last told the input method to show itself.
     */
    boolean mInputShown;

    /**
     * {@code true} if the current input method is in fullscreen mode.
     */
    boolean mInFullscreenMode;

    /**
     * The Intent used to connect to the current input method.
     */
    Intent mCurIntent;

    /**
     * The token we have made for the currently active input method, to
     * identify it in the future.
     */
    IBinder mCurToken;

    /**
     * The displayId of current active input method.
     */
    int mCurTokenDisplayId = INVALID_DISPLAY;

    /**
     * The display ID of the input method indicates the fallback display which returned by
     * {@link #computeImeDisplayIdForTarget}.
     */
    private static final int FALLBACK_DISPLAY_ID = DEFAULT_DISPLAY;

    final ImeDisplayValidator mImeDisplayValidator;

    /**
     * If non-null, this is the input method service we are currently connected
     * to.
     */
    IInputMethod mCurMethod;

    /**
     * Time that we last initiated a bind to the input method, to determine
     * if we should try to disconnect and reconnect to it.
     */
    long mLastBindTime;

    /**
     * Have we called mCurMethod.bindInput()?
     */
    boolean mBoundToMethod;

    /**
     * Currently enabled session.  Only touched by service thread, not
     * protected by a lock.
     */
    SessionState mEnabledSession;

    /**
     * True if the device is currently interactive with user.  The value is true initially.
     */
    boolean mIsInteractive = true;

    int mBackDisposition = InputMethodService.BACK_DISPOSITION_DEFAULT;

    /**
     * A set of status bits regarding the active IME.
     *
     * <p>This value is a combination of following two bits:</p>
     * <dl>
     * <dt>{@link InputMethodService#IME_ACTIVE}</dt>
     * <dd>
     *   If this bit is ON, connected IME is ready to accept touch/key events.
     * </dd>
     * <dt>{@link InputMethodService#IME_VISIBLE}</dt>
     * <dd>
     *   If this bit is ON, some of IME view, e.g. software input, candidate view, is visible.
     * </dd>
     * dt>{@link InputMethodService#IME_INVISIBLE}</dt>
     * <dd> If this bit is ON, IME is ready with views from last EditorInfo but is
     *    currently invisible.
     * </dd>
     * </dl>
     * <em>Do not update this value outside of {@link #setImeWindowStatus(IBinder, int, int)} and
     * {@link #unbindCurrentMethodLocked()}.</em>
     */
    int mImeWindowVis;

    private AlertDialog.Builder mDialogBuilder;
    private AlertDialog mSwitchingDialog;
    private IBinder mSwitchingDialogToken = new Binder();
    private View mSwitchingDialogTitleView;
    private InputMethodInfo[] mIms;
    private int[] mSubtypeIds;
    private LocaleList mLastSystemLocales;
    private boolean mShowImeWithHardKeyboard;
    private boolean mAccessibilityRequestingNoSoftKeyboard;
    private final MyPackageMonitor mMyPackageMonitor = new MyPackageMonitor();
    private final IPackageManager mIPackageManager;
    private final String mSlotIme;
    @HardKeyboardBehavior
    private final int mHardKeyboardBehavior;

    /**
     * Internal state snapshot when {@link #MSG_START_INPUT} message is about to be posted to the
     * internal message queue. Any subsequent state change inside {@link InputMethodManagerService}
     * will not affect those tasks that are already posted.
     *
     * <p>Posting {@link #MSG_START_INPUT} message basically means that
     * {@link InputMethodService#doStartInput(InputConnection, EditorInfo, boolean)} will be called
     * back in the current IME process shortly, which will also affect what the current IME starts
     * receiving from {@link InputMethodService#getCurrentInputConnection()}. In other words, this
     * snapshot will be taken every time when {@link InputMethodManagerService} is initiating a new
     * logical input session between the client application and the current IME.</p>
     *
     * <p>Be careful to not keep strong references to this object forever, which can prevent
     * {@link StartInputInfo#mImeToken} and {@link StartInputInfo#mTargetWindow} from being GC-ed.
     * </p>
     */
    private static class StartInputInfo {
        private static final AtomicInteger sSequenceNumber = new AtomicInteger(0);

        final int mSequenceNumber;
        final long mTimestamp;
        final long mWallTime;
        @UserIdInt
        final int mImeUserId;
        @NonNull
        final IBinder mImeToken;
        final int mImeDisplayId;
        @NonNull
        final String mImeId;
        @StartInputReason
        final int mStartInputReason;
        final boolean mRestarting;
        @UserIdInt
        final int mTargetUserId;
        final int mTargetDisplayId;
        @Nullable
        final IBinder mTargetWindow;
        @NonNull
        final EditorInfo mEditorInfo;
        @SoftInputModeFlags
        final int mTargetWindowSoftInputMode;
        final int mClientBindSequenceNumber;

        StartInputInfo(@UserIdInt int imeUserId, @NonNull IBinder imeToken, int imeDisplayId,
                @NonNull String imeId, @StartInputReason int startInputReason, boolean restarting,
                @UserIdInt int targetUserId, int targetDisplayId, @Nullable IBinder targetWindow,
                @NonNull EditorInfo editorInfo, @SoftInputModeFlags int targetWindowSoftInputMode,
                int clientBindSequenceNumber) {
            mSequenceNumber = sSequenceNumber.getAndIncrement();
            mTimestamp = SystemClock.uptimeMillis();
            mWallTime = System.currentTimeMillis();
            mImeUserId = imeUserId;
            mImeToken = imeToken;
            mImeDisplayId = imeDisplayId;
            mImeId = imeId;
            mStartInputReason = startInputReason;
            mRestarting = restarting;
            mTargetUserId = targetUserId;
            mTargetDisplayId = targetDisplayId;
            mTargetWindow = targetWindow;
            mEditorInfo = editorInfo;
            mTargetWindowSoftInputMode = targetWindowSoftInputMode;
            mClientBindSequenceNumber = clientBindSequenceNumber;
        }
    }

    @GuardedBy("mMethodMap")
    private final WeakHashMap<IBinder, IBinder> mImeTargetWindowMap = new WeakHashMap<>();

    /**
     * A ring buffer to store the history of {@link StartInputInfo}.
     */
    private static final class StartInputHistory {
        /**
         * Entry size for non low-RAM devices.
         *
         * <p>TODO: Consider to follow what other system services have been doing to manage
         * constants (e.g. {@link android.provider.Settings.Global#ACTIVITY_MANAGER_CONSTANTS}).</p>
         */
        private final static int ENTRY_SIZE_FOR_HIGH_RAM_DEVICE = 16;

        /**
         * Entry size for non low-RAM devices.
         *
         * <p>TODO: Consider to follow what other system services have been doing to manage
         * constants (e.g. {@link android.provider.Settings.Global#ACTIVITY_MANAGER_CONSTANTS}).</p>
         */
        private final static int ENTRY_SIZE_FOR_LOW_RAM_DEVICE = 5;

        private static int getEntrySize() {
            if (ActivityManager.isLowRamDeviceStatic()) {
                return ENTRY_SIZE_FOR_LOW_RAM_DEVICE;
            } else {
                return ENTRY_SIZE_FOR_HIGH_RAM_DEVICE;
            }
        }

        /**
         * Backing store for the ring bugger.
         */
        private final Entry[] mEntries = new Entry[getEntrySize()];

        /**
         * An index of {@link #mEntries}, to which next {@link #addEntry(StartInputInfo)} should
         * write.
         */
        private int mNextIndex = 0;

        /**
         * Recyclable entry to store the information in {@link StartInputInfo}.
         */
        private static final class Entry {
            int mSequenceNumber;
            long mTimestamp;
            long mWallTime;
            @UserIdInt
            int mImeUserId;
            @NonNull
            String mImeTokenString;
            int mImeDisplayId;
            @NonNull
            String mImeId;
            @StartInputReason
            int mStartInputReason;
            boolean mRestarting;
            @UserIdInt
            int mTargetUserId;
            int mTargetDisplayId;
            @NonNull
            String mTargetWindowString;
            @NonNull
            EditorInfo mEditorInfo;
            @SoftInputModeFlags
            int mTargetWindowSoftInputMode;
            int mClientBindSequenceNumber;

            Entry(@NonNull StartInputInfo original) {
                set(original);
            }

            void set(@NonNull StartInputInfo original) {
                mSequenceNumber = original.mSequenceNumber;
                mTimestamp = original.mTimestamp;
                mWallTime = original.mWallTime;
                mImeUserId = original.mImeUserId;
                // Intentionally convert to String so as not to keep a strong reference to a Binder
                // object.
                mImeTokenString = String.valueOf(original.mImeToken);
                mImeDisplayId = original.mImeDisplayId;
                mImeId = original.mImeId;
                mStartInputReason = original.mStartInputReason;
                mRestarting = original.mRestarting;
                mTargetUserId = original.mTargetUserId;
                mTargetDisplayId = original.mTargetDisplayId;
                // Intentionally convert to String so as not to keep a strong reference to a Binder
                // object.
                mTargetWindowString = String.valueOf(original.mTargetWindow);
                mEditorInfo = original.mEditorInfo;
                mTargetWindowSoftInputMode = original.mTargetWindowSoftInputMode;
                mClientBindSequenceNumber = original.mClientBindSequenceNumber;
            }
        }

        /**
         * Add a new entry and discard the oldest entry as needed.
         * @param info {@lin StartInputInfo} to be added.
         */
        void addEntry(@NonNull StartInputInfo info) {
            final int index = mNextIndex;
            if (mEntries[index] == null) {
                mEntries[index] = new Entry(info);
            } else {
                mEntries[index].set(info);
            }
            mNextIndex = (mNextIndex + 1) % mEntries.length;
        }

        void dump(@NonNull PrintWriter pw, @NonNull String prefix) {
            final SimpleDateFormat dataFormat =
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

            for (int i = 0; i < mEntries.length; ++i) {
                final Entry entry = mEntries[(i + mNextIndex) % mEntries.length];
                if (entry == null) {
                    continue;
                }
                pw.print(prefix);
                pw.println("StartInput #" + entry.mSequenceNumber + ":");

                pw.print(prefix);
                pw.println(" time=" + dataFormat.format(new Date(entry.mWallTime))
                        + " (timestamp=" + entry.mTimestamp + ")"
                        + " reason="
                        + InputMethodDebug.startInputReasonToString(entry.mStartInputReason)
                        + " restarting=" + entry.mRestarting);

                pw.print(prefix);
                pw.print(" imeToken=" + entry.mImeTokenString + " [" + entry.mImeId + "]");
                pw.print(" imeUserId=" + entry.mImeUserId);
                pw.println(" imeDisplayId=" + entry.mImeDisplayId);

                pw.print(prefix);
                pw.println(" targetWin=" + entry.mTargetWindowString
                        + " [" + entry.mEditorInfo.packageName + "]"
                        + " targetUserId=" + entry.mTargetUserId
                        + " targetDisplayId=" + entry.mTargetDisplayId
                        + " clientBindSeq=" + entry.mClientBindSequenceNumber);

                pw.print(prefix);
                pw.println(" softInputMode=" + InputMethodDebug.softInputModeToString(
                                entry.mTargetWindowSoftInputMode));

                pw.print(prefix);
                pw.println(" inputType=0x" + Integer.toHexString(entry.mEditorInfo.inputType)
                        + " imeOptions=0x" + Integer.toHexString(entry.mEditorInfo.imeOptions)
                        + " fieldId=0x" + Integer.toHexString(entry.mEditorInfo.fieldId)
                        + " fieldName=" + entry.mEditorInfo.fieldName
                        + " actionId=" + entry.mEditorInfo.actionId
                        + " actionLabel=" + entry.mEditorInfo.actionLabel);
            }
        }
    }

    @GuardedBy("mMethodMap")
    @NonNull
    private final StartInputHistory mStartInputHistory = new StartInputHistory();

    class SettingsObserver extends ContentObserver {
        int mUserId;
        boolean mRegistered = false;
        @NonNull
        String mLastEnabled = "";

        /**
         * <em>This constructor must be called within the lock.</em>
         */
        SettingsObserver(Handler handler) {
            super(handler);
        }

        public void registerContentObserverLocked(@UserIdInt int userId) {
            if (mRegistered && mUserId == userId) {
                return;
            }
            ContentResolver resolver = mContext.getContentResolver();
            if (mRegistered) {
                mContext.getContentResolver().unregisterContentObserver(this);
                mRegistered = false;
            }
            if (mUserId != userId) {
                mLastEnabled = "";
                mUserId = userId;
            }
            resolver.registerContentObserver(Settings.Secure.getUriFor(
                    Settings.Secure.DEFAULT_INPUT_METHOD), false, this, userId);
            resolver.registerContentObserver(Settings.Secure.getUriFor(
                    Settings.Secure.ENABLED_INPUT_METHODS), false, this, userId);
            resolver.registerContentObserver(Settings.Secure.getUriFor(
                    Settings.Secure.SELECTED_INPUT_METHOD_SUBTYPE), false, this, userId);
            resolver.registerContentObserver(Settings.Secure.getUriFor(
                    Settings.Secure.SHOW_IME_WITH_HARD_KEYBOARD), false, this, userId);
            resolver.registerContentObserver(Settings.Secure.getUriFor(
                    Settings.Secure.ACCESSIBILITY_SOFT_KEYBOARD_MODE), false, this, userId);
            if (mLineageHardware.isSupported(
                    LineageHardwareManager.FEATURE_HIGH_TOUCH_POLLING_RATE)) {
                resolver.registerContentObserver(Settings.System.getUriFor(
                        Settings.System.HIGH_TOUCH_POLLING_RATE_ENABLE),
                        false, this, userId);
            }
            if (mLineageHardware.isSupported(
                    LineageHardwareManager.FEATURE_HIGH_TOUCH_SENSITIVITY)) {
                resolver.registerContentObserver(Settings.System.getUriFor(
                        Settings.System.HIGH_TOUCH_SENSITIVITY_ENABLE),
                        false, this, userId);
            }
            if (mLineageHardware.isSupported(LineageHardwareManager.FEATURE_TOUCH_HOVERING)) {
                resolver.registerContentObserver(Settings.System.getUriFor(
                        Settings.System.FEATURE_TOUCH_HOVERING), false, this, userId);
            }
            mRegistered = true;
        }

        @Override public void onChange(boolean selfChange, Uri uri) {
            final Uri showImeUri = Settings.Secure.getUriFor(
                    Settings.Secure.SHOW_IME_WITH_HARD_KEYBOARD);
            final Uri accessibilityRequestingNoImeUri = Settings.Secure.getUriFor(
                    Settings.Secure.ACCESSIBILITY_SOFT_KEYBOARD_MODE);
            final Uri highTouchPollingRateUri = Settings.System.getUriFor(
                    Settings.System.HIGH_TOUCH_POLLING_RATE_ENABLE);
            final Uri touchSensitivityUri = Settings.System.getUriFor(
                    Settings.System.HIGH_TOUCH_SENSITIVITY_ENABLE);
            final Uri touchHoveringUri = Settings.System.getUriFor(
                    Settings.System.FEATURE_TOUCH_HOVERING);
            synchronized (mMethodMap) {
                if (showImeUri.equals(uri)) {
                    updateKeyboardFromSettingsLocked();
                } else if (accessibilityRequestingNoImeUri.equals(uri)) {
                    final int accessibilitySoftKeyboardSetting = Settings.Secure.getIntForUser(
                            mContext.getContentResolver(),
                            Settings.Secure.ACCESSIBILITY_SOFT_KEYBOARD_MODE, 0, mUserId);
                    mAccessibilityRequestingNoSoftKeyboard =
                            (accessibilitySoftKeyboardSetting & AccessibilityService.SHOW_MODE_MASK)
                                    == AccessibilityService.SHOW_MODE_HIDDEN;
                    if (mAccessibilityRequestingNoSoftKeyboard) {
                        final boolean showRequested = mShowRequested;
                        hideCurrentInputLocked(0, null);
                        mShowRequested = showRequested;
                    } else if (mShowRequested) {
                        showCurrentInputLocked(InputMethodManager.SHOW_IMPLICIT, null);
                    }
                } else if (highTouchPollingRateUri.equals(uri)) {
                    updateTouchPollingRate();
                } else if (touchSensitivityUri.equals(uri)) {
                    updateTouchSensitivity();
                } else if (touchHoveringUri.equals(uri)) {
                    updateTouchHovering();
                } else {
                    boolean enabledChanged = false;
                    String newEnabled = mSettings.getEnabledInputMethodsStr();
                    if (!mLastEnabled.equals(newEnabled)) {
                        mLastEnabled = newEnabled;
                        enabledChanged = true;
                    }
                    updateInputMethodsFromSettingsLocked(enabledChanged);
                }
            }
        }

        @Override
        public String toString() {
            return "SettingsObserver{mUserId=" + mUserId + " mRegistered=" + mRegistered
                    + " mLastEnabled=" + mLastEnabled + "}";
        }
    }

    /**
     * {@link BroadcastReceiver} that is intended to listen to broadcasts sent to the system user
     * only.
     */
    private final class ImmsBroadcastReceiverForSystemUser extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            final String action = intent.getAction();
            if (Intent.ACTION_USER_ADDED.equals(action)
                    || Intent.ACTION_USER_REMOVED.equals(action)) {
                updateCurrentProfileIds();
                return;
            } else if (Intent.ACTION_LOCALE_CHANGED.equals(action)) {
                onActionLocaleChanged();
            } else if (ACTION_SHOW_INPUT_METHOD_PICKER.equals(action)) {
                // ACTION_SHOW_INPUT_METHOD_PICKER action is a protected-broadcast and it is
                // guaranteed to be send only from the system, so that there is no need for extra
                // security check such as
                // {@link #canShowInputMethodPickerLocked(IInputMethodClient)}.
                mHandler.obtainMessage(
                        MSG_SHOW_IM_SUBTYPE_PICKER,
                        // TODO(b/120076400): Design and implement IME switcher for heterogeneous
                        // navbar configuration.
                        InputMethodManager.SHOW_IM_PICKER_MODE_INCLUDE_AUXILIARY_SUBTYPES,
                        DEFAULT_DISPLAY).sendToTarget();
            } else {
                Slog.w(TAG, "Unexpected intent " + intent);
            }
        }
    }

    /**
     * {@link BroadcastReceiver} that is intended to listen to broadcasts sent to all the users.
     */
    private final class ImmsBroadcastReceiverForAllUsers extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            final String action = intent.getAction();
            if (Intent.ACTION_CLOSE_SYSTEM_DIALOGS.equals(action)) {
                final PendingResult pendingResult = getPendingResult();
                if (pendingResult == null) {
                    return;
                }
                // sender userId can be a real user ID or USER_ALL.
                final int senderUserId = pendingResult.getSendingUserId();
                if (senderUserId != UserHandle.USER_ALL) {
                    final int resolvedUserId = PER_PROFILE_IME_ENABLED
                            ? senderUserId : mUserManagerInternal.getProfileParentId(senderUserId);
                    if (resolvedUserId != mSettings.getCurrentUserId()) {
                        // A background user is trying to hide the dialog. Ignore.
                        return;
                    }
                }
                hideInputMethodMenu();
            } else {
                Slog.w(TAG, "Unexpected intent " + intent);
            }
        }
    }

    /**
     * Handles {@link Intent#ACTION_LOCALE_CHANGED}.
     *
     * <p>Note: For historical reasons, {@link Intent#ACTION_LOCALE_CHANGED} has been sent to all
     * the users. We should ignore this event if this is about any background user's locale.</p>
     *
     * <p>Caution: This method must not be called when system is not ready.</p>
     */
    void onActionLocaleChanged() {
        synchronized (mMethodMap) {
            final LocaleList possibleNewLocale = mRes.getConfiguration().getLocales();
            if (possibleNewLocale != null && possibleNewLocale.equals(mLastSystemLocales)) {
                return;
            }
            buildInputMethodListLocked(true);
            // If the locale is changed, needs to reset the default ime
            resetDefaultImeLocked(mContext);
            updateFromSettingsLocked(true);
            mLastSystemLocales = possibleNewLocale;
        }
    }

    final class MyPackageMonitor extends PackageMonitor {
        /**
         * Package names that are known to contain {@link InputMethodService}.
         *
         * <p>No need to include packages because of direct-boot unaware IMEs since we always rescan
         * all the packages when the user is unlocked, and direct-boot awareness will not be changed
         * dynamically unless the entire package is updated, which also always triggers package
         * rescanning.</p>
         */
        @GuardedBy("mMethodMap")
        final private ArraySet<String> mKnownImePackageNames = new ArraySet<>();

        /**
         * Packages that are appeared, disappeared, or modified for whatever reason.
         *
         * <p>Note: For now we intentionally use {@link ArrayList} instead of {@link ArraySet}
         * because 1) the number of elements is almost always 1 or so, and 2) we do not care
         * duplicate elements for our use case.</p>
         *
         * <p>This object must be accessed only from callback methods in {@link PackageMonitor},
         * which should be bound to {@link #getRegisteredHandler()}.</p>
         */
        private final ArrayList<String> mChangedPackages = new ArrayList<>();

        /**
         * {@code true} if one or more packages that contain {@link InputMethodService} appeared.
         *
         * <p>This field must be accessed only from callback methods in {@link PackageMonitor},
         * which should be bound to {@link #getRegisteredHandler()}.</p>
         */
        private boolean mImePackageAppeared = false;

        @GuardedBy("mMethodMap")
        void clearKnownImePackageNamesLocked() {
            mKnownImePackageNames.clear();
        }

        @GuardedBy("mMethodMap")
        final void addKnownImePackageNameLocked(@NonNull String packageName) {
            mKnownImePackageNames.add(packageName);
        }

        @GuardedBy("mMethodMap")
        private boolean isChangingPackagesOfCurrentUserLocked() {
            final int userId = getChangingUserId();
            final boolean retval = userId == mSettings.getCurrentUserId();
            if (DEBUG) {
                if (!retval) {
                    Slog.d(TAG, "--- ignore this call back from a background user: " + userId);
                }
            }
            return retval;
        }

        @Override
        public boolean onHandleForceStop(Intent intent, String[] packages, int uid, boolean doit) {
            synchronized (mMethodMap) {
                if (!isChangingPackagesOfCurrentUserLocked()) {
                    return false;
                }
                String curInputMethodId = mSettings.getSelectedInputMethod();
                final int N = mMethodList.size();
                if (curInputMethodId != null) {
                    for (int i=0; i<N; i++) {
                        InputMethodInfo imi = mMethodList.get(i);
                        if (imi.getId().equals(curInputMethodId)) {
                            for (String pkg : packages) {
                                if (imi.getPackageName().equals(pkg)) {
                                    if (!doit) {
                                        return true;
                                    }
                                    resetSelectedInputMethodAndSubtypeLocked("");
                                    chooseNewDefaultIMELocked();
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            return false;
        }

        @Override
        public void onBeginPackageChanges() {
            clearPackageChangeState();
        }

        @Override
        public void onPackageAppeared(String packageName, int reason) {
            if (!mImePackageAppeared) {
                final PackageManager pm = mContext.getPackageManager();
                final List<ResolveInfo> services = pm.queryIntentServicesAsUser(
                        new Intent(InputMethod.SERVICE_INTERFACE).setPackage(packageName),
                        PackageManager.MATCH_DISABLED_COMPONENTS, getChangingUserId());
                // No need to lock this because we access it only on getRegisteredHandler().
                if (!services.isEmpty()) {
                    mImePackageAppeared = true;
                }
            }
            // No need to lock this because we access it only on getRegisteredHandler().
            mChangedPackages.add(packageName);
        }

        @Override
        public void onPackageDisappeared(String packageName, int reason) {
            // No need to lock this because we access it only on getRegisteredHandler().
            mChangedPackages.add(packageName);
        }

        @Override
        public void onPackageModified(String packageName) {
            // No need to lock this because we access it only on getRegisteredHandler().
            mChangedPackages.add(packageName);
        }

        @Override
        public void onPackagesSuspended(String[] packages) {
            // No need to lock this because we access it only on getRegisteredHandler().
            for (String packageName : packages) {
                mChangedPackages.add(packageName);
            }
        }

        @Override
        public void onPackagesUnsuspended(String[] packages) {
            // No need to lock this because we access it only on getRegisteredHandler().
            for (String packageName : packages) {
                mChangedPackages.add(packageName);
            }
        }

        @Override
        public void onFinishPackageChanges() {
            onFinishPackageChangesInternal();
            clearPackageChangeState();
        }

        @Override
        public void onUidRemoved(int uid) {
            synchronized (mMethodMap) {
                mLoggedDeniedGetInputMethodWindowVisibleHeightForUid.delete(uid);
            }
        }

        private void clearPackageChangeState() {
            // No need to lock them because we access these fields only on getRegisteredHandler().
            mChangedPackages.clear();
            mImePackageAppeared = false;
        }

        @GuardedBy("mMethodMap")
        private boolean shouldRebuildInputMethodListLocked() {
            // This method is guaranteed to be called only by getRegisteredHandler().

            // If there is any new package that contains at least one IME, then rebuilt the list
            // of IMEs.
            if (mImePackageAppeared) {
                return true;
            }

            // Otherwise, check if mKnownImePackageNames and mChangedPackages have any intersection.
            // TODO: Consider to create a utility method to do the following test. List.retainAll()
            // is an option, but it may still do some extra operations that we do not need here.
            final int N = mChangedPackages.size();
            for (int i = 0; i < N; ++i) {
                final String packageName = mChangedPackages.get(i);
                if (mKnownImePackageNames.contains(packageName)) {
                    return true;
                }
            }
            return false;
        }

        private void onFinishPackageChangesInternal() {
            synchronized (mMethodMap) {
                if (!isChangingPackagesOfCurrentUserLocked()) {
                    return;
                }
                if (!shouldRebuildInputMethodListLocked()) {
                    return;
                }

                InputMethodInfo curIm = null;
                String curInputMethodId = mSettings.getSelectedInputMethod();
                final int N = mMethodList.size();
                if (curInputMethodId != null) {
                    for (int i=0; i<N; i++) {
                        InputMethodInfo imi = mMethodList.get(i);
                        final String imiId = imi.getId();
                        if (imiId.equals(curInputMethodId)) {
                            curIm = imi;
                        }

                        int change = isPackageDisappearing(imi.getPackageName());
                        if (isPackageModified(imi.getPackageName())) {
                            mAdditionalSubtypeMap.remove(imi.getId());
                            AdditionalSubtypeUtils.save(mAdditionalSubtypeMap, mMethodMap,
                                    mSettings.getCurrentUserId());
                        }
                        if (change == PACKAGE_TEMPORARY_CHANGE
                                || change == PACKAGE_PERMANENT_CHANGE) {
                            Slog.i(TAG, "Input method uninstalled, disabling: "
                                    + imi.getComponent());
                            setInputMethodEnabledLocked(imi.getId(), false);
                        }
                    }
                }

                buildInputMethodListLocked(false /* resetDefaultEnabledIme */);

                boolean changed = false;

                if (curIm != null) {
                    int change = isPackageDisappearing(curIm.getPackageName());
                    if (change == PACKAGE_TEMPORARY_CHANGE
                            || change == PACKAGE_PERMANENT_CHANGE) {
                        ServiceInfo si = null;
                        try {
                            si = mIPackageManager.getServiceInfo(
                                    curIm.getComponent(), 0, mSettings.getCurrentUserId());
                        } catch (RemoteException ex) {
                        }
                        if (si == null) {
                            // Uh oh, current input method is no longer around!
                            // Pick another one...
                            Slog.i(TAG, "Current input method removed: " + curInputMethodId);
                            updateSystemUiLocked(0 /* vis */, mBackDisposition);
                            if (!chooseNewDefaultIMELocked()) {
                                changed = true;
                                curIm = null;
                                Slog.i(TAG, "Unsetting current input method");
                                resetSelectedInputMethodAndSubtypeLocked("");
                            }
                        }
                    }
                }

                if (curIm == null) {
                    // We currently don't have a default input method... is
                    // one now available?
                    changed = chooseNewDefaultIMELocked();
                } else if (!changed && isPackageModified(curIm.getPackageName())) {
                    // Even if the current input method is still available, mCurrentSubtype could
                    // be obsolete when the package is modified in practice.
                    changed = true;
                }

                if (changed) {
                    updateFromSettingsLocked(false);
                }
            }
        }
    }

    private static final class MethodCallback extends IInputSessionCallback.Stub {
        private final InputMethodManagerService mParentIMMS;
        private final IInputMethod mMethod;
        private final InputChannel mChannel;

        MethodCallback(InputMethodManagerService imms, IInputMethod method,
                InputChannel channel) {
            mParentIMMS = imms;
            mMethod = method;
            mChannel = channel;
        }

        @Override
        public void sessionCreated(IInputMethodSession session) {
            long ident = Binder.clearCallingIdentity();
            try {
                mParentIMMS.onSessionCreated(mMethod, session, mChannel);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    private class HardKeyboardListener
            implements WindowManagerInternal.OnHardKeyboardStatusChangeListener {
        @Override
        public void onHardKeyboardStatusChange(boolean available) {
            mHandler.sendMessage(mHandler.obtainMessage(MSG_HARD_KEYBOARD_SWITCH_CHANGED,
                        available ? 1 : 0));
        }

        public void handleHardKeyboardStatusChange(boolean available) {
            if (DEBUG) {
                Slog.w(TAG, "HardKeyboardStatusChanged: available=" + available);
            }
            synchronized(mMethodMap) {
                if (mSwitchingDialog != null && mSwitchingDialogTitleView != null
                        && mSwitchingDialog.isShowing()) {
                    mSwitchingDialogTitleView.findViewById(
                            com.android.internal.R.id.hard_keyboard_section).setVisibility(
                                    available ? View.VISIBLE : View.GONE);
                }
            }
        }
    }

    public static final class Lifecycle extends SystemService {
        private InputMethodManagerService mService;

        public Lifecycle(Context context) {
            super(context);
            mService = new InputMethodManagerService(context);
        }

        @Override
        public void onStart() {
            LocalServices.addService(InputMethodManagerInternal.class,
                    new LocalServiceImpl(mService));
            publishBinderService(Context.INPUT_METHOD_SERVICE, mService);
        }

        @Override
        public void onSwitchUser(@UserIdInt int userHandle) {
            // Called on ActivityManager thread.
            // TODO: Dispatch this to a worker thread as needed.
            mService.onSwitchUser(userHandle);
        }

        @Override
        public void onBootPhase(int phase) {
            // Called on ActivityManager thread.
            // TODO: Dispatch this to a worker thread as needed.
            if (phase == SystemService.PHASE_ACTIVITY_MANAGER_READY) {
                StatusBarManagerService statusBarService = (StatusBarManagerService) ServiceManager
                        .getService(Context.STATUS_BAR_SERVICE);
                mService.systemRunning(statusBarService);
            }
        }

        @Override
        public void onUnlockUser(final @UserIdInt int userHandle) {
            // Called on ActivityManager thread.
            mService.mHandler.sendMessage(mService.mHandler.obtainMessage(MSG_SYSTEM_UNLOCK_USER,
                    userHandle /* arg1 */, 0 /* arg2 */));
        }
    }

    void onUnlockUser(@UserIdInt int userId) {
        synchronized(mMethodMap) {
            final int currentUserId = mSettings.getCurrentUserId();
            if (DEBUG) {
                Slog.d(TAG, "onUnlockUser: userId=" + userId + " curUserId=" + currentUserId);
            }
            if (userId != currentUserId) {
                return;
            }
            mSettings.switchCurrentUser(currentUserId, !mSystemReady);
            if (mSystemReady) {
                // We need to rebuild IMEs.
                buildInputMethodListLocked(false /* resetDefaultEnabledIme */);
                updateInputMethodsFromSettingsLocked(true /* enabledChanged */);
            }
        }
    }

    void onSwitchUser(@UserIdInt int userId) {
        synchronized (mMethodMap) {
            switchUserLocked(userId);
        }
    }

    public InputMethodManagerService(Context context) {
        mIPackageManager = AppGlobals.getPackageManager();
        mContext = context;
        mRes = context.getResources();
        mHandler = new Handler(this);
        // Note: SettingsObserver doesn't register observers in its constructor.
        mSettingsObserver = new SettingsObserver(mHandler);
        mIWindowManager = IWindowManager.Stub.asInterface(
                ServiceManager.getService(Context.WINDOW_SERVICE));
        mWindowManagerInternal = LocalServices.getService(WindowManagerInternal.class);
        mDisplayManagerInternal = LocalServices.getService(DisplayManagerInternal.class);
        mImeDisplayValidator = displayId -> mWindowManagerInternal.shouldShowIme(displayId);
        mCaller = new HandlerCaller(context, null, new HandlerCaller.Callback() {
            @Override
            public void executeMessage(Message msg) {
                handleMessage(msg);
            }
        }, true /*asyncHandler*/);
        mAppOpsManager = mContext.getSystemService(AppOpsManager.class);
        mUserManager = mContext.getSystemService(UserManager.class);
        mUserManagerInternal = LocalServices.getService(UserManagerInternal.class);
        mHardKeyboardListener = new HardKeyboardListener();
        mHasFeature = context.getPackageManager().hasSystemFeature(
                PackageManager.FEATURE_INPUT_METHODS);
        mSlotIme = mContext.getString(com.android.internal.R.string.status_bar_ime);
        mHardKeyboardBehavior = mContext.getResources().getInteger(
                com.android.internal.R.integer.config_externalHardKeyboardBehavior);
        mIsLowRam = ActivityManager.isLowRamDeviceStatic();

        Bundle extras = new Bundle();
        extras.putBoolean(Notification.EXTRA_ALLOW_DURING_SETUP, true);
        @ColorInt final int accentColor = mContext.getColor(
                com.android.internal.R.color.system_notification_accent_color);
        mImeSwitcherNotification =
                new Notification.Builder(mContext, SystemNotificationChannels.VIRTUAL_KEYBOARD)
                        .setSmallIcon(com.android.internal.R.drawable.ic_notification_ime_default)
                        .setWhen(0)
                        .setOngoing(true)
                        .addExtras(extras)
                        .setCategory(Notification.CATEGORY_SYSTEM)
                        .setColor(accentColor);

        Intent intent = new Intent(ACTION_SHOW_INPUT_METHOD_PICKER)
                .setPackage(mContext.getPackageName());
        mImeSwitchPendingIntent = PendingIntent.getBroadcast(mContext, 0, intent,
                PendingIntent.FLAG_IMMUTABLE);

        mShowOngoingImeSwitcherForPhones = false;

        mNotificationShown = false;
        int userId = 0;
        try {
            userId = ActivityManager.getService().getCurrentUser().id;
        } catch (RemoteException e) {
            Slog.w(TAG, "Couldn't get current user ID; guessing it's 0", e);
        }

        mLastSwitchUserId = userId;

        // mSettings should be created before buildInputMethodListLocked
        mSettings = new InputMethodSettings(
                mRes, context.getContentResolver(), mMethodMap, userId, !mSystemReady);

        updateCurrentProfileIds();
        AdditionalSubtypeUtils.load(mAdditionalSubtypeMap, userId);
        mSwitchingController = InputMethodSubtypeSwitchingController.createInstanceLocked(
                mSettings, context);
    }

    private void resetDefaultImeLocked(Context context) {
        // Do not reset the default (current) IME when it is a 3rd-party IME
        if (mCurMethodId != null && !mMethodMap.get(mCurMethodId).isSystem()) {
            return;
        }
        final List<InputMethodInfo> suitableImes = InputMethodUtils.getDefaultEnabledImes(
                context, mSettings.getEnabledInputMethodListLocked());
        if (suitableImes.isEmpty()) {
            Slog.i(TAG, "No default found");
            return;
        }
        final InputMethodInfo defIm = suitableImes.get(0);
        if (DEBUG) {
            Slog.i(TAG, "Default found, using " + defIm.getId());
        }
        setSelectedInputMethodAndSubtypeLocked(defIm, NOT_A_SUBTYPE_ID, false);
    }

    @GuardedBy("mMethodMap")
    private void switchUserLocked(int newUserId) {
        if (DEBUG) Slog.d(TAG, "Switching user stage 1/3. newUserId=" + newUserId
                + " currentUserId=" + mSettings.getCurrentUserId());

        // ContentObserver should be registered again when the user is changed
        mSettingsObserver.registerContentObserverLocked(newUserId);

        // If the system is not ready or the device is not yed unlocked by the user, then we use
        // copy-on-write settings.
        final boolean useCopyOnWriteSettings =
                !mSystemReady || !mUserManagerInternal.isUserUnlockingOrUnlocked(newUserId);
        mSettings.switchCurrentUser(newUserId, useCopyOnWriteSettings);
        updateCurrentProfileIds();
        // Additional subtypes should be reset when the user is changed
        AdditionalSubtypeUtils.load(mAdditionalSubtypeMap, newUserId);
        final String defaultImiId = mSettings.getSelectedInputMethod();

        if (DEBUG) Slog.d(TAG, "Switching user stage 2/3. newUserId=" + newUserId
                + " defaultImiId=" + defaultImiId);

        // For secondary users, the list of enabled IMEs may not have been updated since the
        // callbacks to PackageMonitor are ignored for the secondary user. Here, defaultImiId may
        // not be empty even if the IME has been uninstalled by the primary user.
        // Even in such cases, IMMS works fine because it will find the most applicable
        // IME for that user.
        final boolean initialUserSwitch = TextUtils.isEmpty(defaultImiId);
        mLastSystemLocales = mRes.getConfiguration().getLocales();

        // TODO: Is it really possible that switchUserLocked() happens before system ready?
        if (mSystemReady) {
            hideCurrentInputLocked(0, null);
            resetCurrentMethodAndClient(UnbindReason.SWITCH_USER);
            buildInputMethodListLocked(initialUserSwitch);
            if (TextUtils.isEmpty(mSettings.getSelectedInputMethod())) {
                // This is the first time of the user switch and
                // set the current ime to the proper one.
                resetDefaultImeLocked(mContext);
            }
            updateFromSettingsLocked(true);
        }

        if (initialUserSwitch) {
            InputMethodUtils.setNonSelectedSystemImesDisabledUntilUsed(mIPackageManager,
                    mSettings.getEnabledInputMethodListLocked(), newUserId,
                    mContext.getBasePackageName());
        }

        updateTouchHovering();
        updateTouchPollingRate();
        updateTouchSensitivity();

        if (DEBUG) Slog.d(TAG, "Switching user stage 3/3. newUserId=" + newUserId
                + " selectedIme=" + mSettings.getSelectedInputMethod());

        mLastSwitchUserId = newUserId;
    }

    void updateCurrentProfileIds() {
        mSettings.setCurrentProfileIds(
                mUserManager.getProfileIdsWithDisabled(mSettings.getCurrentUserId()));
    }

    @Override
    public boolean onTransact(int code, Parcel data, Parcel reply, int flags)
            throws RemoteException {
        try {
            return super.onTransact(code, data, reply, flags);
        } catch (RuntimeException e) {
            // The input method manager only throws security exceptions, so let's
            // log all others.
            if (!(e instanceof SecurityException)) {
                Slog.wtf(TAG, "Input Method Manager Crash", e);
            }
            throw e;
        }
    }

    public void systemRunning(StatusBarManagerService statusBar) {
        synchronized (mMethodMap) {
            if (DEBUG) {
                Slog.d(TAG, "--- systemReady");
            }
            if (!mSystemReady) {
                mSystemReady = true;
                mLastSystemLocales = mRes.getConfiguration().getLocales();
                final int currentUserId = mSettings.getCurrentUserId();
                mSettings.switchCurrentUser(currentUserId,
                        !mUserManagerInternal.isUserUnlockingOrUnlocked(currentUserId));

                // Must happen before registerContentObserverLocked
                mLineageHardware = LineageHardwareManager.getInstance(mContext);

                updateTouchHovering();
                updateTouchPollingRate();
                updateTouchSensitivity();

                mKeyguardManager = mContext.getSystemService(KeyguardManager.class);
                mNotificationManager = mContext.getSystemService(NotificationManager.class);
                mStatusBar = statusBar;
                if (mStatusBar != null) {
                    mStatusBar.setIconVisibility(mSlotIme, false);
                }
                updateSystemUiLocked(mImeWindowVis, mBackDisposition);
                mShowOngoingImeSwitcherForPhones = mRes.getBoolean(
                        com.android.internal.R.bool.show_ongoing_ime_switcher);
                if (mShowOngoingImeSwitcherForPhones) {
                    mWindowManagerInternal.setOnHardKeyboardStatusChangeListener(
                            mHardKeyboardListener);
                }

                mMyPackageMonitor.register(mContext, null, UserHandle.ALL, true);
                mSettingsObserver.registerContentObserverLocked(currentUserId);

                final IntentFilter broadcastFilterForSystemUser = new IntentFilter();
                broadcastFilterForSystemUser.addAction(Intent.ACTION_USER_ADDED);
                broadcastFilterForSystemUser.addAction(Intent.ACTION_USER_REMOVED);
                broadcastFilterForSystemUser.addAction(Intent.ACTION_LOCALE_CHANGED);
                broadcastFilterForSystemUser.addAction(ACTION_SHOW_INPUT_METHOD_PICKER);
                mContext.registerReceiver(new ImmsBroadcastReceiverForSystemUser(),
                        broadcastFilterForSystemUser);

                final IntentFilter broadcastFilterForAllUsers = new IntentFilter();
                broadcastFilterForAllUsers.addAction(Intent.ACTION_CLOSE_SYSTEM_DIALOGS);
                mContext.registerReceiverAsUser(new ImmsBroadcastReceiverForAllUsers(),
                        UserHandle.ALL, broadcastFilterForAllUsers, null, null);

                final String defaultImiId = mSettings.getSelectedInputMethod();
                final boolean imeSelectedOnBoot = !TextUtils.isEmpty(defaultImiId);
                buildInputMethodListLocked(!imeSelectedOnBoot /* resetDefaultEnabledIme */);
                updateFromSettingsLocked(true);
                InputMethodUtils.setNonSelectedSystemImesDisabledUntilUsed(mIPackageManager,
                        mSettings.getEnabledInputMethodListLocked(), currentUserId,
                        mContext.getBasePackageName());
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Check whether or not this is a valid IPC. Assumes an IPC is valid when either
    // 1) it comes from the system process
    // 2) the calling process' user id is identical to the current user id IMMS thinks.
    @GuardedBy("mMethodMap")
    private boolean calledFromValidUserLocked() {
        final int uid = Binder.getCallingUid();
        final int userId = UserHandle.getUserId(uid);
        if (DEBUG) {
            Slog.d(TAG, "--- calledFromForegroundUserOrSystemProcess ? "
                    + "calling uid = " + uid + " system uid = " + Process.SYSTEM_UID
                    + " calling userId = " + userId + ", foreground user id = "
                    + mSettings.getCurrentUserId() + ", calling pid = " + Binder.getCallingPid()
                    + InputMethodUtils.getApiCallStack());
        }
        if (uid == Process.SYSTEM_UID) {
            return true;
        }
        if (userId == mSettings.getCurrentUserId()) {
            return true;
        }
        if (!PER_PROFILE_IME_ENABLED && mSettings.isCurrentProfile(userId)) {
            return true;
        }

        // Caveat: A process which has INTERACT_ACROSS_USERS_FULL gets results for the
        // foreground user, not for the user of that process. Accordingly InputMethodManagerService
        // must not manage background users' states in any functions.
        // Note that privacy-sensitive IPCs, such as setInputMethod, are still securely guarded
        // by a token.
        if (mContext.checkCallingOrSelfPermission(
                android.Manifest.permission.INTERACT_ACROSS_USERS_FULL)
                        == PackageManager.PERMISSION_GRANTED) {
            if (DEBUG) {
                Slog.d(TAG, "--- Access granted because the calling process has "
                        + "the INTERACT_ACROSS_USERS_FULL permission");
            }
            return true;
        }
        // TODO(b/34886274): The semantics of this verification is actually not well-defined.
        Slog.w(TAG, "--- IPC called from background users. Ignore. callers="
                + Debug.getCallers(10));
        return false;
    }


    /**
     * Returns true iff the caller is identified to be the current input method with the token.
     * @param token The window token given to the input method when it was started.
     * @return true if and only if non-null valid token is specified.
     */
    @GuardedBy("mMethodMap")
    private boolean calledWithValidTokenLocked(@NonNull IBinder token) {
        if (token == null) {
            throw new InvalidParameterException("token must not be null.");
        }
        if (token != mCurToken) {
            Slog.e(TAG, "Ignoring " + Debug.getCaller() + " due to an invalid token."
                    + " uid:" + Binder.getCallingUid() + " token:" + token);
            return false;
        }
        return true;
    }

    @GuardedBy("mMethodMap")
    private boolean bindCurrentInputMethodServiceLocked(
            Intent service, ServiceConnection conn, int flags) {
        if (service == null || conn == null) {
            Slog.e(TAG, "--- bind failed: service = " + service + ", conn = " + conn);
            return false;
        }
        return mContext.bindServiceAsUser(service, conn, flags,
                new UserHandle(mSettings.getCurrentUserId()));
    }

    @Override
    public List<InputMethodInfo> getInputMethodList(@UserIdInt int userId) {
        if (UserHandle.getCallingUserId() != userId) {
            mContext.enforceCallingPermission(Manifest.permission.INTERACT_ACROSS_USERS_FULL, null);
        }
        synchronized (mMethodMap) {
            final int[] resolvedUserIds = InputMethodUtils.resolveUserId(userId,
                    mSettings.getCurrentUserId(), null);
            if (resolvedUserIds.length != 1) {
                return Collections.emptyList();
            }
            final long ident = Binder.clearCallingIdentity();
            try {
                return getInputMethodListLocked(resolvedUserIds[0]);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    @Override
    public List<InputMethodInfo> getEnabledInputMethodList(@UserIdInt int userId) {
        if (UserHandle.getCallingUserId() != userId) {
            mContext.enforceCallingPermission(Manifest.permission.INTERACT_ACROSS_USERS_FULL, null);
        }
        synchronized (mMethodMap) {
            final int[] resolvedUserIds = InputMethodUtils.resolveUserId(userId,
                    mSettings.getCurrentUserId(), null);
            if (resolvedUserIds.length != 1) {
                return Collections.emptyList();
            }
            final long ident = Binder.clearCallingIdentity();
            try {
                return getEnabledInputMethodListLocked(resolvedUserIds[0]);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    @GuardedBy("mMethodMap")
    private List<InputMethodInfo> getInputMethodListLocked(@UserIdInt int userId) {
        final ArrayList<InputMethodInfo> methodList;
        if (userId == mSettings.getCurrentUserId()) {
            // Create a copy.
            methodList = new ArrayList<>(mMethodList);
        } else {
            final ArrayMap<String, InputMethodInfo> methodMap = new ArrayMap<>();
            methodList = new ArrayList<>();
            final ArrayMap<String, List<InputMethodSubtype>> additionalSubtypeMap =
                    new ArrayMap<>();
            AdditionalSubtypeUtils.load(additionalSubtypeMap, userId);
            queryInputMethodServicesInternal(mContext, userId, additionalSubtypeMap, methodMap,
                    methodList);
        }
        return methodList;
    }

    @GuardedBy("mMethodMap")
    private List<InputMethodInfo> getEnabledInputMethodListLocked(@UserIdInt int userId) {
        if (userId == mSettings.getCurrentUserId()) {
            return mSettings.getEnabledInputMethodListLocked();
        }
        final ArrayMap<String, InputMethodInfo> methodMap = new ArrayMap<>();
        final ArrayList<InputMethodInfo> methodList = new ArrayList<>();
        final ArrayMap<String, List<InputMethodSubtype>> additionalSubtypeMap =
                new ArrayMap<>();
        AdditionalSubtypeUtils.load(additionalSubtypeMap, userId);
        queryInputMethodServicesInternal(mContext, userId, additionalSubtypeMap, methodMap,
                methodList);
        final InputMethodSettings settings = new InputMethodSettings(mContext.getResources(),
                mContext.getContentResolver(), methodMap, userId, true);
        return settings.getEnabledInputMethodListLocked();
    }

    /**
     * @param imiId if null, returns enabled subtypes for the current imi
     * @return enabled subtypes of the specified imi
     */
    @Override
    public List<InputMethodSubtype> getEnabledInputMethodSubtypeList(String imiId,
            boolean allowsImplicitlySelectedSubtypes) {
        final int callingUserId = UserHandle.getCallingUserId();
        synchronized (mMethodMap) {
            final int[] resolvedUserIds = InputMethodUtils.resolveUserId(callingUserId,
                    mSettings.getCurrentUserId(), null);
            if (resolvedUserIds.length != 1) {
                return Collections.emptyList();
            }
            final long ident = Binder.clearCallingIdentity();
            try {
                return getEnabledInputMethodSubtypeListLocked(imiId,
                        allowsImplicitlySelectedSubtypes, resolvedUserIds[0]);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    @GuardedBy("mMethodMap")
    private List<InputMethodSubtype> getEnabledInputMethodSubtypeListLocked(String imiId,
            boolean allowsImplicitlySelectedSubtypes, @UserIdInt int userId) {
        if (userId == mSettings.getCurrentUserId()) {
            final InputMethodInfo imi;
            if (imiId == null && mCurMethodId != null) {
                imi = mMethodMap.get(mCurMethodId);
            } else {
                imi = mMethodMap.get(imiId);
            }
            if (imi == null) {
                return Collections.emptyList();
            }
            return mSettings.getEnabledInputMethodSubtypeListLocked(
                    mContext, imi, allowsImplicitlySelectedSubtypes);
        }
        final ArrayMap<String, InputMethodInfo> methodMap = new ArrayMap<>();
        final ArrayList<InputMethodInfo> methodList = new ArrayList<>();
        final ArrayMap<String, List<InputMethodSubtype>> additionalSubtypeMap =
                new ArrayMap<>();
        AdditionalSubtypeUtils.load(additionalSubtypeMap, userId);
        queryInputMethodServicesInternal(mContext, userId, additionalSubtypeMap, methodMap,
                methodList);
        final InputMethodInfo imi = methodMap.get(imiId);
        if (imi == null) {
            return Collections.emptyList();
        }
        final InputMethodSettings settings = new InputMethodSettings(mContext.getResources(),
                mContext.getContentResolver(), methodMap, userId, true);
        return settings.getEnabledInputMethodSubtypeListLocked(
                mContext, imi, allowsImplicitlySelectedSubtypes);
    }

    /**
     * Called by each application process as a preparation to start interacting with
     * {@link InputMethodManagerService}.
     *
     * <p>As a general principle, IPCs from the application process that take
     * {@link IInputMethodClient} will be rejected without this step.</p>
     *
     * @param client {@link android.os.Binder} proxy that is associated with the singleton instance
     *               of {@link android.view.inputmethod.InputMethodManager} that runs on the client
     *               process
     * @param inputContext communication channel for the dummy
     *                     {@link android.view.inputmethod.InputConnection}
     * @param selfReportedDisplayId self-reported display ID to which the client is associated.
     *                              Whether the client is still allowed to access to this display
     *                              or not needs to be evaluated every time the client interacts
     *                              with the display
     */
    @Override
    public void addClient(IInputMethodClient client, IInputContext inputContext,
            int selfReportedDisplayId) {
        // Here there are two scenarios where this method is called:
        // A. IMM is being instantiated in a different process and this is an IPC from that process
        // B. IMM is being instantiated in the same process but Binder.clearCallingIdentity() is
        //    called in the caller side if necessary.
        // In either case the following UID/PID should be the ones where InputMethodManager is
        // actually running.
        final int callerUid = Binder.getCallingUid();
        final int callerPid = Binder.getCallingPid();
        synchronized (mMethodMap) {
            // TODO: Optimize this linear search.
            final int numClients = mClients.size();
            for (int i = 0; i < numClients; ++i) {
                final ClientState state = mClients.valueAt(i);
                if (state.uid == callerUid && state.pid == callerPid
                        && state.selfReportedDisplayId == selfReportedDisplayId) {
                    throw new SecurityException("uid=" + callerUid + "/pid=" + callerPid
                            + "/displayId=" + selfReportedDisplayId + " is already registered.");
                }
            }
            final ClientDeathRecipient deathRecipient = new ClientDeathRecipient(this, client);
            try {
                client.asBinder().linkToDeath(deathRecipient, 0);
            } catch (RemoteException e) {
                throw new IllegalStateException(e);
            }
            // We cannot fully avoid race conditions where the client UID already lost the access to
            // the given self-reported display ID, even if the client is not maliciously reporting
            // a fake display ID. Unconditionally returning SecurityException just because the
            // client doesn't pass display ID verification can cause many test failures hence not an
            // option right now.  At the same time
            //    context.getSystemService(InputMethodManager.class)
            // is expected to return a valid non-null instance at any time if we do not choose to
            // have the client crash.  Thus we do not verify the display ID at all here.  Instead we
            // later check the display ID every time the client needs to interact with the specified
            // display.
            mClients.put(client.asBinder(), new ClientState(client, inputContext, callerUid,
                    callerPid, selfReportedDisplayId, deathRecipient));
        }
    }

    void removeClient(IInputMethodClient client) {
        synchronized (mMethodMap) {
            ClientState cs = mClients.remove(client.asBinder());
            if (cs != null) {
                client.asBinder().unlinkToDeath(cs.clientDeathRecipient, 0);
                clearClientSessionLocked(cs);

                final int numItems = mActivityViewDisplayIdToParentMap.size();
                for (int i = numItems - 1; i >= 0; --i) {
                    final ActivityViewInfo info = mActivityViewDisplayIdToParentMap.valueAt(i);
                    if (info.mParentClient == cs) {
                        mActivityViewDisplayIdToParentMap.removeAt(i);
                    }
                }

                if (mCurClient == cs) {
                    if (mBoundToMethod) {
                        mBoundToMethod = false;
                        if (mCurMethod != null) {
                            executeOrSendMessage(mCurMethod, mCaller.obtainMessageO(
                                    MSG_UNBIND_INPUT, mCurMethod));
                        }
                    }
                    mCurClient = null;
                    mCurActivityViewToScreenMatrix = null;
                }
                if (mCurFocusedWindowClient == cs) {
                    mCurFocusedWindowClient = null;
                }
            }
        }
    }

    void executeOrSendMessage(IInterface target, Message msg) {
         if (target.asBinder() instanceof Binder) {
             mCaller.sendMessage(msg);
         } else {
             handleMessage(msg);
             msg.recycle();
         }
    }

    void unbindCurrentClientLocked(@UnbindReason int unbindClientReason) {
        if (mCurClient != null) {
            if (DEBUG) Slog.v(TAG, "unbindCurrentInputLocked: client="
                    + mCurClient.client.asBinder());
            if (mBoundToMethod) {
                mBoundToMethod = false;
                if (mCurMethod != null) {
                    executeOrSendMessage(mCurMethod, mCaller.obtainMessageO(
                            MSG_UNBIND_INPUT, mCurMethod));
                }
            }

            executeOrSendMessage(mCurClient.client, mCaller.obtainMessageIIO(
                    MSG_SET_ACTIVE, 0, 0, mCurClient));
            executeOrSendMessage(mCurClient.client, mCaller.obtainMessageIIO(
                    MSG_UNBIND_CLIENT, mCurSeq, unbindClientReason, mCurClient.client));
            mCurClient.sessionRequested = false;
            mCurClient = null;
            mCurActivityViewToScreenMatrix = null;

            hideInputMethodMenuLocked();
        }
    }

    private int getImeShowFlags() {
        int flags = 0;
        if (mShowForced) {
            flags |= InputMethod.SHOW_FORCED
                    | InputMethod.SHOW_EXPLICIT;
        } else if (mShowExplicitlyRequested) {
            flags |= InputMethod.SHOW_EXPLICIT;
        }
        return flags;
    }

    private int getAppShowFlags() {
        int flags = 0;
        if (mShowForced) {
            flags |= InputMethodManager.SHOW_FORCED;
        } else if (!mShowExplicitlyRequested) {
            flags |= InputMethodManager.SHOW_IMPLICIT;
        }
        return flags;
    }

    @GuardedBy("mMethodMap")
    @NonNull
    InputBindResult attachNewInputLocked(@StartInputReason int startInputReason, boolean initial) {
        if (!mBoundToMethod) {
            executeOrSendMessage(mCurMethod, mCaller.obtainMessageOO(
                    MSG_BIND_INPUT, mCurMethod, mCurClient.binding));
            mBoundToMethod = true;
        }

        final Binder startInputToken = new Binder();
        final StartInputInfo info = new StartInputInfo(mSettings.getCurrentUserId(), mCurToken,
                mCurTokenDisplayId, mCurId, startInputReason, !initial,
                UserHandle.getUserId(mCurClient.uid), mCurClient.selfReportedDisplayId,
                mCurFocusedWindow, mCurAttribute, mCurFocusedWindowSoftInputMode, mCurSeq);
        mImeTargetWindowMap.put(startInputToken, mCurFocusedWindow);
        mStartInputHistory.addEntry(info);

        final SessionState session = mCurClient.curSession;
        executeOrSendMessage(session.method, mCaller.obtainMessageIIOOOO(
                MSG_START_INPUT, mCurInputContextMissingMethods, initial ? 0 : 1 /* restarting */,
                startInputToken, session, mCurInputContext, mCurAttribute));
        if (mShowRequested) {
            if (DEBUG) Slog.v(TAG, "Attach new input asks to show input");
            showCurrentInputLocked(getAppShowFlags(), null);
        }
        return new InputBindResult(InputBindResult.ResultCode.SUCCESS_WITH_IME_SESSION,
                session.session, (session.channel != null ? session.channel.dup() : null),
                mCurId, mCurSeq, mCurActivityViewToScreenMatrix);
    }

    @Nullable
    private Matrix getActivityViewToScreenMatrixLocked(int clientDisplayId, int imeDisplayId) {
        if (clientDisplayId == imeDisplayId) {
            return null;
        }
        int displayId = clientDisplayId;
        Matrix matrix = null;
        while (true) {
            final ActivityViewInfo info = mActivityViewDisplayIdToParentMap.get(displayId);
            if (info == null) {
                return null;
            }
            if (matrix == null) {
                matrix = new Matrix(info.mMatrix);
            } else {
                matrix.postConcat(info.mMatrix);
            }
            if (info.mParentClient.selfReportedDisplayId == imeDisplayId) {
                return matrix;
            }
            displayId = info.mParentClient.selfReportedDisplayId;
        }
    }

    @GuardedBy("mMethodMap")
    @NonNull
    InputBindResult startInputUncheckedLocked(@NonNull ClientState cs, IInputContext inputContext,
            @MissingMethodFlags int missingMethods, @NonNull EditorInfo attribute,
            @StartInputFlags int startInputFlags, @StartInputReason int startInputReason) {
        // If no method is currently selected, do nothing.
        if (mCurMethodId == null) {
            return InputBindResult.NO_IME;
        }

        if (!mSystemReady) {
            // If the system is not yet ready, we shouldn't be running third
            // party code.
            return new InputBindResult(
                    InputBindResult.ResultCode.ERROR_SYSTEM_NOT_READY,
                    null, null, mCurMethodId, mCurSeq, null);
        }

        if (!InputMethodUtils.checkIfPackageBelongsToUid(mAppOpsManager, cs.uid,
                attribute.packageName)) {
            Slog.e(TAG, "Rejecting this client as it reported an invalid package name."
                    + " uid=" + cs.uid + " package=" + attribute.packageName);
            return InputBindResult.INVALID_PACKAGE_NAME;
        }

        if (!mWindowManagerInternal.isUidAllowedOnDisplay(cs.selfReportedDisplayId, cs.uid)) {
            // Wait, the client no longer has access to the display.
            return InputBindResult.INVALID_DISPLAY_ID;
        }
        // Compute the final shown display ID with validated cs.selfReportedDisplayId for this
        // session & other conditions.
        final int displayIdToShowIme = computeImeDisplayIdForTarget(cs.selfReportedDisplayId,
                mImeDisplayValidator);

        if (mCurClient != cs) {
            // Was the keyguard locked when switching over to the new client?
            mCurClientInKeyguard = isKeyguardLocked();
            // If the client is changing, we need to switch over to the new
            // one.
            unbindCurrentClientLocked(UnbindReason.SWITCH_CLIENT);
            if (DEBUG) Slog.v(TAG, "switching to client: client="
                    + cs.client.asBinder() + " keyguard=" + mCurClientInKeyguard);

            // If the screen is on, inform the new client it is active
            if (mIsInteractive) {
                executeOrSendMessage(cs.client, mCaller.obtainMessageIO(MSG_SET_ACTIVE, 1, cs));
            }
        }

        // Bump up the sequence for this client and attach it.
        mCurSeq++;
        if (mCurSeq <= 0) mCurSeq = 1;
        mCurClient = cs;
        mCurInputContext = inputContext;
        mCurActivityViewToScreenMatrix =
                getActivityViewToScreenMatrixLocked(cs.selfReportedDisplayId, displayIdToShowIme);
        if (cs.selfReportedDisplayId != displayIdToShowIme
                && mCurActivityViewToScreenMatrix == null) {
            // CursorAnchorInfo API does not work as-is for cross-display scenario.  Pretend that
            // InputConnection#requestCursorUpdates() is not implemented in the application so that
            // IMEs will always receive false from this API.
            missingMethods |= MissingMethodFlags.REQUEST_CURSOR_UPDATES;
        }
        mCurInputContextMissingMethods = missingMethods;
        mCurAttribute = attribute;

        // Check if the input method is changing.
        // We expect the caller has already verified that the client is allowed to access this
        // display ID.
        if (mCurId != null && mCurId.equals(mCurMethodId)
                && displayIdToShowIme == mCurTokenDisplayId) {
            if (cs.curSession != null) {
                // Fast case: if we are already connected to the input method,
                // then just return it.
                return attachNewInputLocked(startInputReason,
                        (startInputFlags & StartInputFlags.INITIAL_CONNECTION) != 0);
            }
            if (mHaveConnection) {
                if (mCurMethod != null) {
                    // Return to client, and we will get back with it when
                    // we have had a session made for it.
                    requestClientSessionLocked(cs);
                    return new InputBindResult(
                            InputBindResult.ResultCode.SUCCESS_WAITING_IME_SESSION,
                            null, null, mCurId, mCurSeq, null);
                } else if (SystemClock.uptimeMillis()
                        < (mLastBindTime+TIME_TO_RECONNECT)) {
                    // In this case we have connected to the service, but
                    // don't yet have its interface.  If it hasn't been too
                    // long since we did the connection, we'll return to
                    // the client and wait to get the service interface so
                    // we can report back.  If it has been too long, we want
                    // to fall through so we can try a disconnect/reconnect
                    // to see if we can get back in touch with the service.
                    return new InputBindResult(
                            InputBindResult.ResultCode.SUCCESS_WAITING_IME_BINDING,
                            null, null, mCurId, mCurSeq, null);
                } else {
                    EventLog.writeEvent(EventLogTags.IMF_FORCE_RECONNECT_IME,
                            mCurMethodId, SystemClock.uptimeMillis()-mLastBindTime, 0);
                }
            }
        }

        InputMethodInfo info = mMethodMap.get(mCurMethodId);
        if (info == null) {
            throw new IllegalArgumentException("Unknown id: " + mCurMethodId);
        }

        unbindCurrentMethodLocked();

        mCurIntent = new Intent(InputMethod.SERVICE_INTERFACE);
        mCurIntent.setComponent(info.getComponent());
        mCurIntent.putExtra(Intent.EXTRA_CLIENT_LABEL,
                com.android.internal.R.string.input_method_binding_label);
        mCurIntent.putExtra(Intent.EXTRA_CLIENT_INTENT, PendingIntent.getActivity(
                mContext, 0, new Intent(Settings.ACTION_INPUT_METHOD_SETTINGS),
                PendingIntent.FLAG_IMMUTABLE));

        if (bindCurrentInputMethodServiceLocked(mCurIntent, this, IME_CONNECTION_BIND_FLAGS)) {
            mLastBindTime = SystemClock.uptimeMillis();
            mHaveConnection = true;
            mCurId = info.getId();
            mCurToken = new Binder();
            mCurTokenDisplayId = displayIdToShowIme;
            try {
                if (DEBUG) {
                    Slog.v(TAG, "Adding window token: " + mCurToken + " for display: "
                            + mCurTokenDisplayId);
                }
                mIWindowManager.addWindowToken(mCurToken, LayoutParams.TYPE_INPUT_METHOD,
                        mCurTokenDisplayId);
            } catch (RemoteException e) {
            }
            return new InputBindResult(
                    InputBindResult.ResultCode.SUCCESS_WAITING_IME_BINDING,
                    null, null, mCurId, mCurSeq, null);
        }
        mCurIntent = null;
        Slog.w(TAG, "Failure connecting to input method service: " + mCurIntent);
        return InputBindResult.IME_NOT_CONNECTED;
    }

    @FunctionalInterface
    interface ImeDisplayValidator {
        boolean displayCanShowIme(int displayId);
    }

    /**
     * Find the display where the IME should be shown.
     *
     * @param displayId the ID of the display where the IME client target is.
     * @param checker instance of {@link ImeDisplayValidator} which is used for
     *                checking display config to adjust the final target display.
     * @return The ID of the display where the IME should be shown.
     */
    static int computeImeDisplayIdForTarget(int displayId, @NonNull ImeDisplayValidator checker) {
        if (displayId == DEFAULT_DISPLAY || displayId == INVALID_DISPLAY) {
            return FALLBACK_DISPLAY_ID;
        }

        // Show IME window on fallback display when the display doesn't support system decorations
        // or the display is virtual and isn't owned by system for security concern.
        return checker.displayCanShowIme(displayId) ? displayId : FALLBACK_DISPLAY_ID;
    }

    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        synchronized (mMethodMap) {
            if (mCurIntent != null && name.equals(mCurIntent.getComponent())) {
                mCurMethod = IInputMethod.Stub.asInterface(service);
                if (mCurToken == null) {
                    Slog.w(TAG, "Service connected without a token!");
                    unbindCurrentMethodLocked();
                    return;
                }
                if (DEBUG) Slog.v(TAG, "Initiating attach with token: " + mCurToken);
                // Dispatch display id for InputMethodService to update context display.
                executeOrSendMessage(mCurMethod, mCaller.obtainMessageIOO(
                        MSG_INITIALIZE_IME, mCurTokenDisplayId, mCurMethod, mCurToken));
                if (mCurClient != null) {
                    clearClientSessionLocked(mCurClient);
                    requestClientSessionLocked(mCurClient);
                }
            }
        }
    }

    void onSessionCreated(IInputMethod method, IInputMethodSession session,
            InputChannel channel) {
        synchronized (mMethodMap) {
            if (mCurMethod != null && method != null
                    && mCurMethod.asBinder() == method.asBinder()) {
                if (mCurClient != null) {
                    clearClientSessionLocked(mCurClient);
                    mCurClient.curSession = new SessionState(mCurClient,
                            method, session, channel);
                    InputBindResult res = attachNewInputLocked(
                            StartInputReason.SESSION_CREATED_BY_IME, true);
                    if (res.method != null) {
                        executeOrSendMessage(mCurClient.client, mCaller.obtainMessageOO(
                                MSG_BIND_CLIENT, mCurClient.client, res));
                    }
                    return;
                }
            }
        }

        // Session abandoned.  Close its associated input channel.
        channel.dispose();
    }

    void unbindCurrentMethodLocked() {
        if (mVisibleBound) {
            mContext.unbindService(mVisibleConnection);
            mVisibleBound = false;
        }

        if (mHaveConnection) {
            mContext.unbindService(this);
            mHaveConnection = false;
        }

        if (mCurToken != null) {
            try {
                if (DEBUG) {
                    Slog.v(TAG, "Removing window token: " + mCurToken + " for display: "
                            + mCurTokenDisplayId);
                }
                mIWindowManager.removeWindowToken(mCurToken, mCurTokenDisplayId);
            } catch (RemoteException e) {
            }
            // Set IME window status as invisible when unbind current method.
            mImeWindowVis = 0;
            mBackDisposition = InputMethodService.BACK_DISPOSITION_DEFAULT;
            updateSystemUiLocked(mImeWindowVis, mBackDisposition);
            mCurToken = null;
            mCurTokenDisplayId = INVALID_DISPLAY;
        }

        mCurId = null;
        clearCurMethodLocked();
    }

    void resetCurrentMethodAndClient(@UnbindReason int unbindClientReason) {
        mCurMethodId = null;
        unbindCurrentMethodLocked();
        unbindCurrentClientLocked(unbindClientReason);
    }

    void requestClientSessionLocked(ClientState cs) {
        if (!cs.sessionRequested) {
            if (DEBUG) Slog.v(TAG, "Creating new session for client " + cs);
            InputChannel[] channels = InputChannel.openInputChannelPair(cs.toString());
            cs.sessionRequested = true;
            executeOrSendMessage(mCurMethod, mCaller.obtainMessageOOO(
                    MSG_CREATE_SESSION, mCurMethod, channels[1],
                    new MethodCallback(this, mCurMethod, channels[0])));
        }
    }

    void clearClientSessionLocked(ClientState cs) {
        finishSessionLocked(cs.curSession);
        cs.curSession = null;
        cs.sessionRequested = false;
    }

    private void finishSessionLocked(SessionState sessionState) {
        if (sessionState != null) {
            if (sessionState.session != null) {
                try {
                    sessionState.session.finishSession();
                } catch (RemoteException e) {
                    Slog.w(TAG, "Session failed to close due to remote exception", e);
                    updateSystemUiLocked(0 /* vis */, mBackDisposition);
                }
                sessionState.session = null;
            }
            if (sessionState.channel != null) {
                sessionState.channel.dispose();
                sessionState.channel = null;
            }
        }
    }

    void clearCurMethodLocked() {
        if (mCurMethod != null) {
            final int numClients = mClients.size();
            for (int i = 0; i < numClients; ++i) {
                clearClientSessionLocked(mClients.valueAt(i));
            }

            finishSessionLocked(mEnabledSession);
            mEnabledSession = null;
            mCurMethod = null;
        }
        if (mStatusBar != null) {
            mStatusBar.setIconVisibility(mSlotIme, false);
        }
        mInFullscreenMode = false;
    }

    @Override
    public void onServiceDisconnected(ComponentName name) {
        // Note that mContext.unbindService(this) does not trigger this.  Hence if we are here the
        // disconnection is not intended by IMMS (e.g. triggered because the current IMS crashed),
        // which is irregular but can eventually happen for everyone just by continuing using the
        // device.  Thus it is important to make sure that all the internal states are properly
        // refreshed when this method is called back.  Running
        //    adb install -r <APK that implements the current IME>
        // would be a good way to trigger such a situation.
        synchronized (mMethodMap) {
            if (DEBUG) Slog.v(TAG, "Service disconnected: " + name
                    + " mCurIntent=" + mCurIntent);
            if (mCurMethod != null && mCurIntent != null
                    && name.equals(mCurIntent.getComponent())) {
                clearCurMethodLocked();
                // We consider this to be a new bind attempt, since the system
                // should now try to restart the service for us.
                mLastBindTime = SystemClock.uptimeMillis();
                mShowRequested = mInputShown;
                mInputShown = false;
                unbindCurrentClientLocked(UnbindReason.DISCONNECT_IME);
            }
        }
    }

    @BinderThread
    private void updateStatusIcon(@NonNull IBinder token, String packageName,
            @DrawableRes int iconId) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            final long ident = Binder.clearCallingIdentity();
            try {
                if (iconId == 0) {
                    if (DEBUG) Slog.d(TAG, "hide the small icon for the input method");
                    if (mStatusBar != null) {
                        mStatusBar.setIconVisibility(mSlotIme, false);
                    }
                } else if (packageName != null) {
                    if (DEBUG) Slog.d(TAG, "show a small icon for the input method");
                    CharSequence contentDescription = null;
                    try {
                        // Use PackageManager to load label
                        final PackageManager packageManager = mContext.getPackageManager();
                        contentDescription = packageManager.getApplicationLabel(
                                mIPackageManager.getApplicationInfo(packageName, 0,
                                        mSettings.getCurrentUserId()));
                    } catch (RemoteException e) {
                        /* ignore */
                    }
                    if (mStatusBar != null) {
                        mStatusBar.setIcon(mSlotIme, packageName, iconId, 0,
                                contentDescription  != null
                                        ? contentDescription.toString() : null);
                        mStatusBar.setIconVisibility(mSlotIme, true);
                    }
                }
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    private boolean shouldShowImeSwitcherLocked(int visibility) {
        if (!mShowOngoingImeSwitcherForPhones) return false;
        if (mSwitchingDialog != null) return false;
        if (mWindowManagerInternal.isKeyguardShowingAndNotOccluded()
                && mKeyguardManager != null && mKeyguardManager.isKeyguardSecure()) return false;
        if ((visibility & InputMethodService.IME_ACTIVE) == 0
                || (visibility & InputMethodService.IME_INVISIBLE) != 0) {
            return false;
        }
        if (mWindowManagerInternal.isHardKeyboardAvailable()) {
            if (mHardKeyboardBehavior == HardKeyboardBehavior.WIRELESS_AFFORDANCE) {
                // When physical keyboard is attached, we show the ime switcher (or notification if
                // NavBar is not available) because SHOW_IME_WITH_HARD_KEYBOARD settings currently
                // exists in the IME switcher dialog.  Might be OK to remove this condition once
                // SHOW_IME_WITH_HARD_KEYBOARD settings finds a good place to live.
                return true;
            }
        } else if ((visibility & InputMethodService.IME_VISIBLE) == 0) {
            return false;
        }

        List<InputMethodInfo> imis = mSettings.getEnabledInputMethodListLocked();
        final int N = imis.size();
        if (N > 2) return true;
        if (N < 1) return false;
        int nonAuxCount = 0;
        int auxCount = 0;
        InputMethodSubtype nonAuxSubtype = null;
        InputMethodSubtype auxSubtype = null;
        for(int i = 0; i < N; ++i) {
            final InputMethodInfo imi = imis.get(i);
            final List<InputMethodSubtype> subtypes =
                    mSettings.getEnabledInputMethodSubtypeListLocked(mContext, imi, true);
            final int subtypeCount = subtypes.size();
            if (subtypeCount == 0) {
                ++nonAuxCount;
            } else {
                for (int j = 0; j < subtypeCount; ++j) {
                    final InputMethodSubtype subtype = subtypes.get(j);
                    if (!subtype.isAuxiliary()) {
                        ++nonAuxCount;
                        nonAuxSubtype = subtype;
                    } else {
                        ++auxCount;
                        auxSubtype = subtype;
                    }
                }
            }
        }
        if (nonAuxCount > 1 || auxCount > 1) {
            return true;
        } else if (nonAuxCount == 1 && auxCount == 1) {
            if (nonAuxSubtype != null && auxSubtype != null
                    && (nonAuxSubtype.getLocale().equals(auxSubtype.getLocale())
                            || auxSubtype.overridesImplicitlyEnabledSubtype()
                            || nonAuxSubtype.overridesImplicitlyEnabledSubtype())
                    && nonAuxSubtype.containsExtraValueKey(TAG_TRY_SUPPRESSING_IME_SWITCHER)) {
                return false;
            }
            return true;
        }
        return false;
    }

    private boolean isKeyguardLocked() {
        return mKeyguardManager != null && mKeyguardManager.isKeyguardLocked();
    }

    @BinderThread
    @SuppressWarnings("deprecation")
    private void setImeWindowStatus(@NonNull IBinder token, int vis, int backDisposition) {
        final int topFocusedDisplayId = mWindowManagerInternal.getTopFocusedDisplayId();

        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            // Skip update IME status when current token display is not same as focused display.
            // Note that we still need to update IME status when focusing external display
            // that does not support system decoration and fallback to show IME on default
            // display since it is intentional behavior.
            if (mCurTokenDisplayId != topFocusedDisplayId
                    && mCurTokenDisplayId != FALLBACK_DISPLAY_ID) {
                return;
            }
            mImeWindowVis = vis;
            mBackDisposition = backDisposition;
            updateSystemUiLocked(vis, backDisposition);
        }

        final boolean dismissImeOnBackKeyPressed;
        switch (backDisposition) {
            case InputMethodService.BACK_DISPOSITION_WILL_DISMISS:
                dismissImeOnBackKeyPressed = true;
                break;
            case InputMethodService.BACK_DISPOSITION_WILL_NOT_DISMISS:
                dismissImeOnBackKeyPressed = false;
                break;
            default:
            case InputMethodService.BACK_DISPOSITION_DEFAULT:
                dismissImeOnBackKeyPressed = ((vis & InputMethodService.IME_VISIBLE) != 0);
                break;
        }
        mWindowManagerInternal.updateInputMethodWindowStatus(token,
                (vis & InputMethodService.IME_VISIBLE) != 0, dismissImeOnBackKeyPressed);
    }

    @BinderThread
    private void reportStartInput(@NonNull IBinder token, IBinder startInputToken) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            final IBinder targetWindow = mImeTargetWindowMap.get(startInputToken);
            if (targetWindow != null && mLastImeTargetWindow != targetWindow) {
                mWindowManagerInternal.updateInputMethodTargetWindow(token, targetWindow);
            }
            mLastImeTargetWindow = targetWindow;
        }
    }

    // Caution! This method is called in this class. Handle multi-user carefully
    private void updateSystemUiLocked(int vis, int backDisposition) {
        if (mCurToken == null) {
            return;
        }
        if (DEBUG) {
            Slog.d(TAG, "IME window vis: " + vis
                    + " active: " + (vis & InputMethodService.IME_ACTIVE)
                    + " inv: " + (vis & InputMethodService.IME_INVISIBLE)
                    + " displayId: " + mCurTokenDisplayId);
        }

        // TODO: Move this clearing calling identity block to setImeWindowStatus after making sure
        // all updateSystemUi happens on system previlege.
        final long ident = Binder.clearCallingIdentity();
        try {
            // apply policy for binder calls
            if (vis != 0 && isKeyguardLocked() && !mCurClientInKeyguard) {
                vis = 0;
            }
            // mImeWindowVis should be updated before calling shouldShowImeSwitcherLocked().
            final boolean needsToShowImeSwitcher = shouldShowImeSwitcherLocked(vis);
            if (mStatusBar != null) {
                mStatusBar.setImeWindowStatus(mCurTokenDisplayId, mCurToken, vis, backDisposition,
                        needsToShowImeSwitcher);
            }
            final InputMethodInfo imi = mMethodMap.get(mCurMethodId);
            if (imi != null && needsToShowImeSwitcher) {
                // Used to load label
                final CharSequence title = mRes.getText(
                        com.android.internal.R.string.select_input_method);
                final CharSequence summary = InputMethodUtils.getImeAndSubtypeDisplayName(
                        mContext, imi, mCurrentSubtype);
                mImeSwitcherNotification.setContentTitle(title)
                        .setContentText(summary)
                        .setContentIntent(mImeSwitchPendingIntent);
                try {
                    // TODO(b/120076400): Figure out what is the best behavior
                    if ((mNotificationManager != null)
                            && !mIWindowManager.hasNavigationBar(DEFAULT_DISPLAY)) {
                        if (DEBUG) {
                            Slog.d(TAG, "--- show notification: label =  " + summary);
                        }
                        mNotificationManager.notifyAsUser(null,
                                SystemMessage.NOTE_SELECT_INPUT_METHOD,
                                mImeSwitcherNotification.build(), UserHandle.ALL);
                        mNotificationShown = true;
                    }
                } catch (RemoteException e) {
                }
            } else {
                if (mNotificationShown && mNotificationManager != null) {
                    if (DEBUG) {
                        Slog.d(TAG, "--- hide notification");
                    }
                    mNotificationManager.cancelAsUser(null,
                            SystemMessage.NOTE_SELECT_INPUT_METHOD, UserHandle.ALL);
                    mNotificationShown = false;
                }
            }
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    void updateFromSettingsLocked(boolean enabledMayChange) {
        updateInputMethodsFromSettingsLocked(enabledMayChange);
        updateKeyboardFromSettingsLocked();
    }

    void updateInputMethodsFromSettingsLocked(boolean enabledMayChange) {
        if (enabledMayChange) {
            List<InputMethodInfo> enabled = mSettings.getEnabledInputMethodListLocked();
            for (int i=0; i<enabled.size(); i++) {
                // We allow the user to select "disabled until used" apps, so if they
                // are enabling one of those here we now need to make it enabled.
                InputMethodInfo imm = enabled.get(i);
                try {
                    ApplicationInfo ai = mIPackageManager.getApplicationInfo(imm.getPackageName(),
                            PackageManager.GET_DISABLED_UNTIL_USED_COMPONENTS,
                            mSettings.getCurrentUserId());
                    if (ai != null && ai.enabledSetting
                            == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED) {
                        if (DEBUG) {
                            Slog.d(TAG, "Update state(" + imm.getId()
                                    + "): DISABLED_UNTIL_USED -> DEFAULT");
                        }
                        mIPackageManager.setApplicationEnabledSetting(imm.getPackageName(),
                                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
                                PackageManager.DONT_KILL_APP, mSettings.getCurrentUserId(),
                                mContext.getBasePackageName());
                    }
                } catch (RemoteException e) {
                }
            }
        }
        // We are assuming that whoever is changing DEFAULT_INPUT_METHOD and
        // ENABLED_INPUT_METHODS is taking care of keeping them correctly in
        // sync, so we will never have a DEFAULT_INPUT_METHOD that is not
        // enabled.
        String id = mSettings.getSelectedInputMethod();
        // There is no input method selected, try to choose new applicable input method.
        if (TextUtils.isEmpty(id) && chooseNewDefaultIMELocked()) {
            id = mSettings.getSelectedInputMethod();
        }
        if (!TextUtils.isEmpty(id)) {
            try {
                setInputMethodLocked(id, mSettings.getSelectedInputMethodSubtypeId(id));
            } catch (IllegalArgumentException e) {
                Slog.w(TAG, "Unknown input method from prefs: " + id, e);
                resetCurrentMethodAndClient(UnbindReason.SWITCH_IME_FAILED);
            }
        } else {
            // There is no longer an input method set, so stop any current one.
            resetCurrentMethodAndClient(UnbindReason.NO_IME);
        }
        // Here is not the perfect place to reset the switching controller. Ideally
        // mSwitchingController and mSettings should be able to share the same state.
        // TODO: Make sure that mSwitchingController and mSettings are sharing the
        // the same enabled IMEs list.
        mSwitchingController.resetCircularListLocked(mContext);

    }

    private void updateTouchPollingRate() {
        if (!mLineageHardware.isSupported(LineageHardwareManager.FEATURE_HIGH_TOUCH_POLLING_RATE)) {
            return;
        }
        final boolean enabled = Settings.System.getInt(mContext.getContentResolver(),
                Settings.System.HIGH_TOUCH_POLLING_RATE_ENABLE, 0) == 1;
        mLineageHardware.set(LineageHardwareManager.FEATURE_HIGH_TOUCH_POLLING_RATE, enabled);
    }

    private void updateTouchSensitivity() {
        if (!mLineageHardware.isSupported(LineageHardwareManager.FEATURE_HIGH_TOUCH_SENSITIVITY)) {
            return;
        }
        final boolean enabled = Settings.System.getInt(mContext.getContentResolver(),
                Settings.System.HIGH_TOUCH_SENSITIVITY_ENABLE, 0) == 1;
        mLineageHardware.set(LineageHardwareManager.FEATURE_HIGH_TOUCH_SENSITIVITY, enabled);
    }

    private void updateTouchHovering() {
        if (!mLineageHardware.isSupported(LineageHardwareManager.FEATURE_TOUCH_HOVERING)) {
            return;
        }
        final boolean enabled = Settings.System.getInt(mContext.getContentResolver(),
                Settings.System.FEATURE_TOUCH_HOVERING, 0) == 1;
        mLineageHardware.set(LineageHardwareManager.FEATURE_TOUCH_HOVERING, enabled);
    }

    public void updateKeyboardFromSettingsLocked() {
        mShowImeWithHardKeyboard = mSettings.isShowImeWithHardKeyboardEnabled();
        if (mSwitchingDialog != null
                && mSwitchingDialogTitleView != null
                && mSwitchingDialog.isShowing()) {
            final Switch hardKeySwitch = (Switch)mSwitchingDialogTitleView.findViewById(
                    com.android.internal.R.id.hard_keyboard_switch);
            hardKeySwitch.setChecked(mShowImeWithHardKeyboard);
        }
    }

    /* package */ void setInputMethodLocked(String id, int subtypeId) {
        InputMethodInfo info = mMethodMap.get(id);
        if (info == null) {
            throw new IllegalArgumentException("Unknown id: " + id);
        }

        // See if we need to notify a subtype change within the same IME.
        if (id.equals(mCurMethodId)) {
            final int subtypeCount = info.getSubtypeCount();
            if (subtypeCount <= 0) {
                return;
            }
            final InputMethodSubtype oldSubtype = mCurrentSubtype;
            final InputMethodSubtype newSubtype;
            if (subtypeId >= 0 && subtypeId < subtypeCount) {
                newSubtype = info.getSubtypeAt(subtypeId);
            } else {
                // If subtype is null, try to find the most applicable one from
                // getCurrentInputMethodSubtype.
                newSubtype = getCurrentInputMethodSubtypeLocked();
            }
            if (newSubtype == null || oldSubtype == null) {
                Slog.w(TAG, "Illegal subtype state: old subtype = " + oldSubtype
                        + ", new subtype = " + newSubtype);
                return;
            }
            if (newSubtype != oldSubtype) {
                setSelectedInputMethodAndSubtypeLocked(info, subtypeId, true);
                if (mCurMethod != null) {
                    try {
                        updateSystemUiLocked(mImeWindowVis, mBackDisposition);
                        mCurMethod.changeInputMethodSubtype(newSubtype);
                    } catch (RemoteException e) {
                        Slog.w(TAG, "Failed to call changeInputMethodSubtype");
                    }
                }
            }
            return;
        }

        // Changing to a different IME.
        final long ident = Binder.clearCallingIdentity();
        try {
            // Set a subtype to this input method.
            // subtypeId the name of a subtype which will be set.
            setSelectedInputMethodAndSubtypeLocked(info, subtypeId, false);
            // mCurMethodId should be updated after setSelectedInputMethodAndSubtypeLocked()
            // because mCurMethodId is stored as a history in
            // setSelectedInputMethodAndSubtypeLocked().
            mCurMethodId = id;

            if (LocalServices.getService(ActivityManagerInternal.class).isSystemReady()) {
                Intent intent = new Intent(Intent.ACTION_INPUT_METHOD_CHANGED);
                intent.addFlags(Intent.FLAG_RECEIVER_REPLACE_PENDING);
                intent.putExtra("input_method_id", id);
                mContext.sendBroadcastAsUser(intent, UserHandle.CURRENT);
            }
            unbindCurrentClientLocked(UnbindReason.SWITCH_IME);
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    @Override
    public boolean showSoftInput(IInputMethodClient client, int flags,
            ResultReceiver resultReceiver) {
        int uid = Binder.getCallingUid();
        synchronized (mMethodMap) {
            if (!calledFromValidUserLocked()) {
                return false;
            }
            final long ident = Binder.clearCallingIdentity();
            try {
                if (!canInteractWithImeLocked(uid, client, "showSoftInput")) {
                    return false;
                }
                if (DEBUG) Slog.v(TAG, "Client requesting input be shown");
                return showCurrentInputLocked(flags, resultReceiver);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    @GuardedBy("mMethodMap")
    boolean showCurrentInputLocked(int flags, ResultReceiver resultReceiver) {
        mShowRequested = true;
        if (mAccessibilityRequestingNoSoftKeyboard) {
            return false;
        }

        if ((flags&InputMethodManager.SHOW_FORCED) != 0) {
            mShowExplicitlyRequested = true;
            mShowForced = true;
        } else if ((flags&InputMethodManager.SHOW_IMPLICIT) == 0) {
            mShowExplicitlyRequested = true;
        }

        if (!mSystemReady) {
            return false;
        }

        boolean res = false;
        if (mCurMethod != null) {
            if (DEBUG) Slog.d(TAG, "showCurrentInputLocked: mCurToken=" + mCurToken);
            executeOrSendMessage(mCurMethod, mCaller.obtainMessageIOO(
                    MSG_SHOW_SOFT_INPUT, getImeShowFlags(), mCurMethod,
                    resultReceiver));
            mInputShown = true;
            if (mHaveConnection && !mVisibleBound) {
                bindCurrentInputMethodServiceLocked(
                        mCurIntent, mVisibleConnection, IME_VISIBLE_BIND_FLAGS);
                mVisibleBound = true;
            }
            res = true;
        } else if (mHaveConnection && SystemClock.uptimeMillis()
                >= (mLastBindTime+TIME_TO_RECONNECT)) {
            // The client has asked to have the input method shown, but
            // we have been sitting here too long with a connection to the
            // service and no interface received, so let's disconnect/connect
            // to try to prod things along.
            EventLog.writeEvent(EventLogTags.IMF_FORCE_RECONNECT_IME, mCurMethodId,
                    SystemClock.uptimeMillis()-mLastBindTime,1);
            Slog.w(TAG, "Force disconnect/connect to the IME in showCurrentInputLocked()");
            mContext.unbindService(this);
            bindCurrentInputMethodServiceLocked(mCurIntent, this, IME_CONNECTION_BIND_FLAGS);
        } else {
            if (DEBUG) {
                Slog.d(TAG, "Can't show input: connection = " + mHaveConnection + ", time = "
                        + ((mLastBindTime+TIME_TO_RECONNECT) - SystemClock.uptimeMillis()));
            }
        }

        return res;
    }

    @Override
    public boolean hideSoftInput(IInputMethodClient client, int flags,
            ResultReceiver resultReceiver) {
        int uid = Binder.getCallingUid();
        synchronized (mMethodMap) {
            if (!calledFromValidUserLocked()) {
                return false;
            }
            final long ident = Binder.clearCallingIdentity();
            try {
                if (mCurClient == null || client == null
                        || mCurClient.client.asBinder() != client.asBinder()) {
                    // We need to check if this is the current client with
                    // focus in the window manager, to allow this call to
                    // be made before input is started in it.
                    final ClientState cs = mClients.get(client.asBinder());
                    if (cs == null) {
                        throw new IllegalArgumentException("unknown client " + client.asBinder());
                    }
                    if (!mWindowManagerInternal.isInputMethodClientFocus(cs.uid, cs.pid,
                            cs.selfReportedDisplayId)) {
                        if (DEBUG) {
                            Slog.w(TAG, "Ignoring hideSoftInput of uid " + uid + ": " + client);
                        }
                        return false;
                    }
                }

                if (DEBUG) Slog.v(TAG, "Client requesting input be hidden");
                return hideCurrentInputLocked(flags, resultReceiver);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    boolean hideCurrentInputLocked(int flags, ResultReceiver resultReceiver) {
        if ((flags&InputMethodManager.HIDE_IMPLICIT_ONLY) != 0
                && (mShowExplicitlyRequested || mShowForced)) {
            if (DEBUG) Slog.v(TAG, "Not hiding: explicit show not cancelled by non-explicit hide");
            return false;
        }
        if (mShowForced && (flags&InputMethodManager.HIDE_NOT_ALWAYS) != 0) {
            if (DEBUG) Slog.v(TAG, "Not hiding: forced show not cancelled by not-always hide");
            return false;
        }

        // There is a chance that IMM#hideSoftInput() is called in a transient state where
        // IMMS#InputShown is already updated to be true whereas IMMS#mImeWindowVis is still waiting
        // to be updated with the new value sent from IME process.  Even in such a transient state
        // historically we have accepted an incoming call of IMM#hideSoftInput() from the
        // application process as a valid request, and have even promised such a behavior with CTS
        // since Android Eclair.  That's why we need to accept IMM#hideSoftInput() even when only
        // IMMS#InputShown indicates that the software keyboard is shown.
        // TODO: Clean up, IMMS#mInputShown, IMMS#mImeWindowVis and mShowRequested.
        final boolean shouldHideSoftInput = (mCurMethod != null) && (mInputShown ||
                (mImeWindowVis & InputMethodService.IME_ACTIVE) != 0);
        boolean res;
        if (shouldHideSoftInput) {
            // The IME will report its visible state again after the following message finally
            // delivered to the IME process as an IPC.  Hence the inconsistency between
            // IMMS#mInputShown and IMMS#mImeWindowVis should be resolved spontaneously in
            // the final state.
            executeOrSendMessage(mCurMethod, mCaller.obtainMessageOO(
                    MSG_HIDE_SOFT_INPUT, mCurMethod, resultReceiver));
            res = true;
        } else {
            res = false;
        }
        if (mHaveConnection && mVisibleBound) {
            mContext.unbindService(mVisibleConnection);
            mVisibleBound = false;
        }
        mInputShown = false;
        mShowRequested = false;
        mShowExplicitlyRequested = false;
        mShowForced = false;
        return res;
    }

    @NonNull
    @Override
    public InputBindResult startInputOrWindowGainedFocus(
            @StartInputReason int startInputReason, IInputMethodClient client, IBinder windowToken,
            @StartInputFlags int startInputFlags, @SoftInputModeFlags int softInputMode,
            int windowFlags, @Nullable EditorInfo attribute, IInputContext inputContext,
            @MissingMethodFlags int missingMethods, int unverifiedTargetSdkVersion) {
        if (windowToken == null) {
            Slog.e(TAG, "windowToken cannot be null.");
            return InputBindResult.NULL;
        }
        final int callingUserId = UserHandle.getCallingUserId();
        final int userId;
        if (attribute != null && attribute.targetInputMethodUser != null
                && attribute.targetInputMethodUser.getIdentifier() != callingUserId) {
            mContext.enforceCallingPermission(Manifest.permission.INTERACT_ACROSS_USERS_FULL,
                    "Using EditorInfo.targetInputMethodUser requires INTERACT_ACROSS_USERS_FULL.");
            userId = attribute.targetInputMethodUser.getIdentifier();
            if (!mUserManagerInternal.isUserRunning(userId)) {
                // There is a chance that we hit here because of race condition.  Let's just return
                // an error code instead of crashing the caller process, which at least has
                // INTERACT_ACROSS_USERS_FULL permission thus is likely to be an important process.
                Slog.e(TAG, "User #" + userId + " is not running.");
                return InputBindResult.INVALID_USER;
            }
        } else {
            userId = callingUserId;
        }
        final InputBindResult result;
        synchronized (mMethodMap) {
            final long ident = Binder.clearCallingIdentity();
            try {
                result = startInputOrWindowGainedFocusInternalLocked(startInputReason, client,
                        windowToken, startInputFlags, softInputMode, windowFlags, attribute,
                        inputContext, missingMethods, unverifiedTargetSdkVersion, userId);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
        if (result == null) {
            // This must never happen, but just in case.
            Slog.wtf(TAG, "InputBindResult is @NonNull. startInputReason="
                    + InputMethodDebug.startInputReasonToString(startInputReason)
                    + " windowFlags=#" + Integer.toHexString(windowFlags)
                    + " editorInfo=" + attribute);
            return InputBindResult.NULL;
        }
        return result;
    }

    @NonNull
    private InputBindResult startInputOrWindowGainedFocusInternalLocked(
            @StartInputReason int startInputReason, IInputMethodClient client,
            @NonNull IBinder windowToken, @StartInputFlags int startInputFlags,
            @SoftInputModeFlags int softInputMode, int windowFlags, EditorInfo attribute,
            IInputContext inputContext, @MissingMethodFlags int missingMethods,
            int unverifiedTargetSdkVersion, @UserIdInt int userId) {
        if (DEBUG) {
            Slog.v(TAG, "startInputOrWindowGainedFocusInternalLocked: reason="
                    + InputMethodDebug.startInputReasonToString(startInputReason)
                    + " client=" + client.asBinder()
                    + " inputContext=" + inputContext
                    + " missingMethods="
                    + InputConnectionInspector.getMissingMethodFlagsAsString(missingMethods)
                    + " attribute=" + attribute
                    + " startInputFlags="
                    + InputMethodDebug.startInputFlagsToString(startInputFlags)
                    + " softInputMode=" + InputMethodDebug.softInputModeToString(softInputMode)
                    + " windowFlags=#" + Integer.toHexString(windowFlags)
                    + " unverifiedTargetSdkVersion=" + unverifiedTargetSdkVersion);
        }

        final int windowDisplayId = mWindowManagerInternal.getDisplayIdForWindow(windowToken);

        final ClientState cs = mClients.get(client.asBinder());
        if (cs == null) {
            throw new IllegalArgumentException("unknown client " + client.asBinder());
        }
        if (cs.selfReportedDisplayId != windowDisplayId) {
            Slog.e(TAG, "startInputOrWindowGainedFocusInternal: display ID mismatch."
                    + " from client:" + cs.selfReportedDisplayId
                    + " from window:" + windowDisplayId);
            return InputBindResult.DISPLAY_ID_MISMATCH;
        }

        if (!mWindowManagerInternal.isInputMethodClientFocus(cs.uid, cs.pid,
                cs.selfReportedDisplayId)) {
            // Check with the window manager to make sure this client actually
            // has a window with focus.  If not, reject.  This is thread safe
            // because if the focus changes some time before or after, the
            // next client receiving focus that has any interest in input will
            // be calling through here after that change happens.
            if (DEBUG) {
                Slog.w(TAG, "Focus gain on non-focused client " + cs.client
                        + " (uid=" + cs.uid + " pid=" + cs.pid + ")");
            }
            return InputBindResult.NOT_IME_TARGET_WINDOW;
        }

        // cross-profile access is always allowed here to allow profile-switching.
        if (!mSettings.isCurrentProfile(userId)) {
            Slog.w(TAG, "A background user is requesting window. Hiding IME.");
            Slog.w(TAG, "If you need to impersonate a foreground user/profile from"
                    + " a background user, use EditorInfo.targetInputMethodUser with"
                    + " INTERACT_ACROSS_USERS_FULL permission.");
            hideCurrentInputLocked(0, null);
            return InputBindResult.INVALID_USER;
        }

        if (PER_PROFILE_IME_ENABLED && userId != mSettings.getCurrentUserId()) {
            switchUserLocked(userId);
        }
        // Master feature flag that overrides other conditions and forces IME preRendering.
        if (DEBUG) {
            Slog.v(TAG, "IME PreRendering MASTER flag: "
                    + DebugFlags.FLAG_PRE_RENDER_IME_VIEWS.value() + ", LowRam: " + mIsLowRam);
        }
        // pre-rendering not supported on low-ram devices.
        cs.shouldPreRenderIme = DebugFlags.FLAG_PRE_RENDER_IME_VIEWS.value() && !mIsLowRam;

        if (mCurFocusedWindow == windowToken) {
            if (DEBUG) {
                Slog.w(TAG, "Window already focused, ignoring focus gain of: " + client
                        + " attribute=" + attribute + ", token = " + windowToken);
            }
            if (attribute != null) {
                return startInputUncheckedLocked(cs, inputContext, missingMethods,
                        attribute, startInputFlags, startInputReason);
            }
            return new InputBindResult(
                    InputBindResult.ResultCode.SUCCESS_REPORT_WINDOW_FOCUS_ONLY,
                    null, null, null, -1, null);
        }
        mCurFocusedWindow = windowToken;
        mCurFocusedWindowSoftInputMode = softInputMode;
        mCurFocusedWindowClient = cs;

        // Should we auto-show the IME even if the caller has not
        // specified what should be done with it?
        // We only do this automatically if the window can resize
        // to accommodate the IME (so what the user sees will give
        // them good context without input information being obscured
        // by the IME) or if running on a large screen where there
        // is more room for the target window + IME.
        final boolean doAutoShow =
                (softInputMode & LayoutParams.SOFT_INPUT_MASK_ADJUST)
                        == LayoutParams.SOFT_INPUT_ADJUST_RESIZE
                || mRes.getConfiguration().isLayoutSizeAtLeast(
                        Configuration.SCREENLAYOUT_SIZE_LARGE);
        final boolean isTextEditor = (startInputFlags & StartInputFlags.IS_TEXT_EDITOR) != 0;

        // We want to start input before showing the IME, but after closing
        // it.  We want to do this after closing it to help the IME disappear
        // more quickly (not get stuck behind it initializing itself for the
        // new focused input, even if its window wants to hide the IME).
        boolean didStart = false;

        InputBindResult res = null;
        switch (softInputMode & LayoutParams.SOFT_INPUT_MASK_STATE) {
            case LayoutParams.SOFT_INPUT_STATE_UNSPECIFIED:
                if (!isTextEditor || !doAutoShow) {
                    if (LayoutParams.mayUseInputMethod(windowFlags)) {
                        // There is no focus view, and this window will
                        // be behind any soft input window, so hide the
                        // soft input window if it is shown.
                        if (DEBUG) Slog.v(TAG, "Unspecified window will hide input");
                        hideCurrentInputLocked(InputMethodManager.HIDE_NOT_ALWAYS, null);

                        // If focused display changed, we should unbind current method
                        // to make app window in previous display relayout after Ime
                        // window token removed.
                        // Note that we can trust client's display ID as long as it matches
                        // to the display ID obtained from the window.
                        if (cs.selfReportedDisplayId != mCurTokenDisplayId) {
                            unbindCurrentMethodLocked();
                        }
                    }
                } else if (isTextEditor && doAutoShow
                        && (softInputMode & LayoutParams.SOFT_INPUT_IS_FORWARD_NAVIGATION) != 0) {
                    // There is a focus view, and we are navigating forward
                    // into the window, so show the input window for the user.
                    // We only do this automatically if the window can resize
                    // to accommodate the IME (so what the user sees will give
                    // them good context without input information being obscured
                    // by the IME) or if running on a large screen where there
                    // is more room for the target window + IME.
                    if (DEBUG) Slog.v(TAG, "Unspecified window will show input");
                    if (attribute != null) {
                        res = startInputUncheckedLocked(cs, inputContext, missingMethods,
                                attribute, startInputFlags, startInputReason);
                        didStart = true;
                    }
                    showCurrentInputLocked(InputMethodManager.SHOW_IMPLICIT, null);
                }
                break;
            case LayoutParams.SOFT_INPUT_STATE_UNCHANGED:
                // Do nothing.
                break;
            case LayoutParams.SOFT_INPUT_STATE_HIDDEN:
                if ((softInputMode & LayoutParams.SOFT_INPUT_IS_FORWARD_NAVIGATION) != 0) {
                    if (DEBUG) Slog.v(TAG, "Window asks to hide input going forward");
                    hideCurrentInputLocked(0, null);
                }
                break;
            case LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN:
                if (DEBUG) Slog.v(TAG, "Window asks to hide input");
                hideCurrentInputLocked(0, null);
                break;
            case LayoutParams.SOFT_INPUT_STATE_VISIBLE:
                if ((softInputMode & LayoutParams.SOFT_INPUT_IS_FORWARD_NAVIGATION) != 0) {
                    if (DEBUG) Slog.v(TAG, "Window asks to show input going forward");
                    if (InputMethodUtils.isSoftInputModeStateVisibleAllowed(
                            unverifiedTargetSdkVersion, startInputFlags)) {
                        if (attribute != null) {
                            res = startInputUncheckedLocked(cs, inputContext, missingMethods,
                                    attribute, startInputFlags, startInputReason);
                            didStart = true;
                        }
                        showCurrentInputLocked(InputMethodManager.SHOW_IMPLICIT, null);
                    } else {
                        Slog.e(TAG, "SOFT_INPUT_STATE_VISIBLE is ignored because"
                                + " there is no focused view that also returns true from"
                                + " View#onCheckIsTextEditor()");
                    }
                }
                break;
            case LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE:
                if (DEBUG) Slog.v(TAG, "Window asks to always show input");
                if (InputMethodUtils.isSoftInputModeStateVisibleAllowed(
                        unverifiedTargetSdkVersion, startInputFlags)) {
                    if (attribute != null) {
                        res = startInputUncheckedLocked(cs, inputContext, missingMethods,
                                attribute, startInputFlags, startInputReason);
                        didStart = true;
                    }
                    showCurrentInputLocked(InputMethodManager.SHOW_IMPLICIT, null);
                } else {
                    Slog.e(TAG, "SOFT_INPUT_STATE_ALWAYS_VISIBLE is ignored because"
                            + " there is no focused view that also returns true from"
                            + " View#onCheckIsTextEditor()");
                }
                break;
        }

        if (!didStart) {
            if (attribute != null) {
                if (!DebugFlags.FLAG_OPTIMIZE_START_INPUT.value()
                        || (startInputFlags & StartInputFlags.IS_TEXT_EDITOR) != 0) {
                    res = startInputUncheckedLocked(cs, inputContext, missingMethods, attribute,
                            startInputFlags, startInputReason);
                } else {
                    res = InputBindResult.NO_EDITOR;
                }
            } else {
                res = InputBindResult.NULL_EDITOR_INFO;
            }
        }
        return res;
    }

    private boolean canShowInputMethodPickerLocked(IInputMethodClient client) {
        // TODO(yukawa): multi-display support.
        final int uid = Binder.getCallingUid();
        if (mCurFocusedWindowClient != null && client != null
                && mCurFocusedWindowClient.client.asBinder() == client.asBinder()) {
            return true;
        } else if (mCurIntent != null && InputMethodUtils.checkIfPackageBelongsToUid(
                mAppOpsManager,
                uid,
                mCurIntent.getComponent().getPackageName())) {
            return true;
        }
        return false;
    }

    @Override
    public void showInputMethodPickerFromClient(
            IInputMethodClient client, int auxiliarySubtypeMode) {
        synchronized (mMethodMap) {
            if (!calledFromValidUserLocked()) {
                return;
            }
            if(!canShowInputMethodPickerLocked(client)) {
                Slog.w(TAG, "Ignoring showInputMethodPickerFromClient of uid "
                        + Binder.getCallingUid() + ": " + client);
                return;
            }

            // Always call subtype picker, because subtype picker is a superset of input method
            // picker.
            mHandler.sendMessage(mCaller.obtainMessageII(
                    MSG_SHOW_IM_SUBTYPE_PICKER, auxiliarySubtypeMode,
                    (mCurClient != null) ? mCurClient.selfReportedDisplayId : DEFAULT_DISPLAY));
        }
    }

    @Override
    public void showInputMethodPickerFromSystem(IInputMethodClient client, int auxiliarySubtypeMode,
            int displayId) {
        if (mContext.checkCallingPermission(android.Manifest.permission.WRITE_SECURE_SETTINGS)
                != PackageManager.PERMISSION_GRANTED) {
            throw new SecurityException(
                    "showInputMethodPickerFromSystem requires WRITE_SECURE_SETTINGS permission");
        }
        // Always call subtype picker, because subtype picker is a superset of input method
        // picker.
        mHandler.sendMessage(mCaller.obtainMessageII(
                MSG_SHOW_IM_SUBTYPE_PICKER, auxiliarySubtypeMode, displayId));
    }

    public boolean isInputMethodPickerShownForTest() {
        synchronized(mMethodMap) {
            if (mSwitchingDialog == null) {
                return false;
            }
            return mSwitchingDialog.isShowing();
        }
    }

    @BinderThread
    private void setInputMethod(@NonNull IBinder token, String id) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            setInputMethodWithSubtypeIdLocked(token, id, NOT_A_SUBTYPE_ID);
        }
    }

    @BinderThread
    private void setInputMethodAndSubtype(@NonNull IBinder token, String id,
            InputMethodSubtype subtype) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            if (subtype != null) {
                setInputMethodWithSubtypeIdLocked(token, id,
                        InputMethodUtils.getSubtypeIdFromHashCode(mMethodMap.get(id),
                                subtype.hashCode()));
            } else {
                setInputMethod(token, id);
            }
        }
    }

    @Override
    public void showInputMethodAndSubtypeEnablerFromClient(
            IInputMethodClient client, String inputMethodId) {
        synchronized (mMethodMap) {
            // TODO(yukawa): Should we verify the display ID?
            if (!calledFromValidUserLocked()) {
                return;
            }
            executeOrSendMessage(mCurMethod, mCaller.obtainMessageO(
                    MSG_SHOW_IM_SUBTYPE_ENABLER, inputMethodId));
        }
    }

    @BinderThread
    private boolean switchToPreviousInputMethod(@NonNull IBinder token) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return false;
            }
            final Pair<String, String> lastIme = mSettings.getLastInputMethodAndSubtypeLocked();
            final InputMethodInfo lastImi;
            if (lastIme != null) {
                lastImi = mMethodMap.get(lastIme.first);
            } else {
                lastImi = null;
            }
            String targetLastImiId = null;
            int subtypeId = NOT_A_SUBTYPE_ID;
            if (lastIme != null && lastImi != null) {
                final boolean imiIdIsSame = lastImi.getId().equals(mCurMethodId);
                final int lastSubtypeHash = Integer.parseInt(lastIme.second);
                final int currentSubtypeHash = mCurrentSubtype == null ? NOT_A_SUBTYPE_ID
                        : mCurrentSubtype.hashCode();
                // If the last IME is the same as the current IME and the last subtype is not
                // defined, there is no need to switch to the last IME.
                if (!imiIdIsSame || lastSubtypeHash != currentSubtypeHash) {
                    targetLastImiId = lastIme.first;
                    subtypeId = InputMethodUtils.getSubtypeIdFromHashCode(lastImi, lastSubtypeHash);
                }
            }

            if (TextUtils.isEmpty(targetLastImiId)
                    && !InputMethodUtils.canAddToLastInputMethod(mCurrentSubtype)) {
                // This is a safety net. If the currentSubtype can't be added to the history
                // and the framework couldn't find the last ime, we will make the last ime be
                // the most applicable enabled keyboard subtype of the system imes.
                final List<InputMethodInfo> enabled = mSettings.getEnabledInputMethodListLocked();
                if (enabled != null) {
                    final int N = enabled.size();
                    final String locale = mCurrentSubtype == null
                            ? mRes.getConfiguration().locale.toString()
                            : mCurrentSubtype.getLocale();
                    for (int i = 0; i < N; ++i) {
                        final InputMethodInfo imi = enabled.get(i);
                        if (imi.getSubtypeCount() > 0 && imi.isSystem()) {
                            InputMethodSubtype keyboardSubtype =
                                    InputMethodUtils.findLastResortApplicableSubtypeLocked(mRes,
                                            InputMethodUtils.getSubtypes(imi),
                                            InputMethodUtils.SUBTYPE_MODE_KEYBOARD, locale, true);
                            if (keyboardSubtype != null) {
                                targetLastImiId = imi.getId();
                                subtypeId = InputMethodUtils.getSubtypeIdFromHashCode(
                                        imi, keyboardSubtype.hashCode());
                                if(keyboardSubtype.getLocale().equals(locale)) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (!TextUtils.isEmpty(targetLastImiId)) {
                if (DEBUG) {
                    Slog.d(TAG, "Switch to: " + lastImi.getId() + ", " + lastIme.second
                            + ", from: " + mCurMethodId + ", " + subtypeId);
                }
                setInputMethodWithSubtypeIdLocked(token, targetLastImiId, subtypeId);
                return true;
            } else {
                return false;
            }
        }
    }

    @BinderThread
    private boolean switchToNextInputMethod(@NonNull IBinder token, boolean onlyCurrentIme) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return false;
            }
            final ImeSubtypeListItem nextSubtype = mSwitchingController.getNextInputMethodLocked(
                    onlyCurrentIme, mMethodMap.get(mCurMethodId), mCurrentSubtype);
            if (nextSubtype == null) {
                return false;
            }
            setInputMethodWithSubtypeIdLocked(token, nextSubtype.mImi.getId(),
                    nextSubtype.mSubtypeId);
            return true;
        }
    }

    @BinderThread
    private boolean shouldOfferSwitchingToNextInputMethod(@NonNull IBinder token) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return false;
            }
            final ImeSubtypeListItem nextSubtype = mSwitchingController.getNextInputMethodLocked(
                    false /* onlyCurrentIme */, mMethodMap.get(mCurMethodId), mCurrentSubtype);
            if (nextSubtype == null) {
                return false;
            }
            return true;
        }
    }

    @Override
    public InputMethodSubtype getLastInputMethodSubtype() {
        synchronized (mMethodMap) {
            if (!calledFromValidUserLocked()) {
                return null;
            }
            final Pair<String, String> lastIme = mSettings.getLastInputMethodAndSubtypeLocked();
            // TODO: Handle the case of the last IME with no subtypes
            if (lastIme == null || TextUtils.isEmpty(lastIme.first)
                    || TextUtils.isEmpty(lastIme.second)) return null;
            final InputMethodInfo lastImi = mMethodMap.get(lastIme.first);
            if (lastImi == null) return null;
            try {
                final int lastSubtypeHash = Integer.parseInt(lastIme.second);
                final int lastSubtypeId =
                        InputMethodUtils.getSubtypeIdFromHashCode(lastImi, lastSubtypeHash);
                if (lastSubtypeId < 0 || lastSubtypeId >= lastImi.getSubtypeCount()) {
                    return null;
                }
                return lastImi.getSubtypeAt(lastSubtypeId);
            } catch (NumberFormatException e) {
                return null;
            }
        }
    }

    @Override
    public void setAdditionalInputMethodSubtypes(String imiId, InputMethodSubtype[] subtypes) {
        // By this IPC call, only a process which shares the same uid with the IME can add
        // additional input method subtypes to the IME.
        if (TextUtils.isEmpty(imiId) || subtypes == null) return;
        final ArrayList<InputMethodSubtype> toBeAdded = new ArrayList<>();
        for (InputMethodSubtype subtype : subtypes) {
            if (!toBeAdded.contains(subtype)) {
                toBeAdded.add(subtype);
            } else {
                Slog.w(TAG, "Duplicated subtype definition found: "
                        + subtype.getLocale() + ", " + subtype.getMode());
            }
        }
        synchronized (mMethodMap) {
            if (!calledFromValidUserLocked()) {
                return;
            }
            if (!mSystemReady) {
                return;
            }
            final InputMethodInfo imi = mMethodMap.get(imiId);
            if (imi == null) return;
            final String[] packageInfos;
            try {
                packageInfos = mIPackageManager.getPackagesForUid(Binder.getCallingUid());
            } catch (RemoteException e) {
                Slog.e(TAG, "Failed to get package infos");
                return;
            }
            if (packageInfos != null) {
                final int packageNum = packageInfos.length;
                for (int i = 0; i < packageNum; ++i) {
                    if (packageInfos[i].equals(imi.getPackageName())) {
                        if (subtypes.length > 0) {
                            mAdditionalSubtypeMap.put(imi.getId(), toBeAdded);
                        } else {
                            mAdditionalSubtypeMap.remove(imi.getId());
                        }
                        AdditionalSubtypeUtils.save(mAdditionalSubtypeMap, mMethodMap,
                                mSettings.getCurrentUserId());
                        final long ident = Binder.clearCallingIdentity();
                        try {
                            buildInputMethodListLocked(false /* resetDefaultEnabledIme */);
                        } finally {
                            Binder.restoreCallingIdentity(ident);
                        }
                        return;
                    }
                }
            }
        }
        return;
    }

    /**
     * This is kept due to {@link android.annotation.UnsupportedAppUsage} in
     * {@link InputMethodManager#getInputMethodWindowVisibleHeight()} and a dependency in
     * {@link InputMethodService#onCreate()}.
     *
     * <p>TODO(Bug 113914148): Check if we can remove this.</p>
     * @return {@link WindowManagerInternal#getInputMethodWindowVisibleHeight()}
     */
    @Override
    @Deprecated
    public int getInputMethodWindowVisibleHeight(@NonNull IInputMethodClient client) {
        int callingUid = Binder.getCallingUid();
        return Binder.withCleanCallingIdentity(() -> {
            final int curTokenDisplayId;
            synchronized (mMethodMap) {
                if (!canInteractWithImeLocked(callingUid, client,
                        "getInputMethodWindowVisibleHeight")) {
                    if (!mLoggedDeniedGetInputMethodWindowVisibleHeightForUid.get(callingUid)) {
                        EventLog.writeEvent(0x534e4554, "204906124", callingUid, "");
                        mLoggedDeniedGetInputMethodWindowVisibleHeightForUid.put(callingUid, true);
                    }
                    return 0;
                }
                // This should probably use the caller's display id, but because this is unsupported
                // and maintained only for compatibility, there's no point in fixing it.
                curTokenDisplayId = mCurTokenDisplayId;
            }
            return mWindowManagerInternal.getInputMethodWindowVisibleHeight(curTokenDisplayId);
        });
    }

    private boolean canInteractWithImeLocked(int callingUid, IInputMethodClient client,
            String method) {
        if (mCurClient == null || client == null
                || mCurClient.client.asBinder() != client.asBinder()) {
            // We need to check if this is the current client with
            // focus in the window manager, to allow this call to
            // be made before input is started in it.
            final ClientState cs = mClients.get(client.asBinder());
            if (cs == null) {
                throw new IllegalArgumentException("unknown client " + client.asBinder());
            }
            if (!mWindowManagerInternal.isInputMethodClientFocus(cs.uid, cs.pid,
                    cs.selfReportedDisplayId)) {
                Slog.w(TAG, "Ignoring " + method + " of uid " + callingUid + ": " + client);
                return false;
            }
        }
        return true;
    }

    @Override
    public void reportActivityView(IInputMethodClient parentClient, int childDisplayId,
            float[] matrixValues) {
        final DisplayInfo displayInfo = mDisplayManagerInternal.getDisplayInfo(childDisplayId);
        if (displayInfo == null) {
            throw new IllegalArgumentException(
                    "Cannot find display for non-existent displayId: " + childDisplayId);
        }
        final int callingUid = Binder.getCallingUid();
        if (callingUid != displayInfo.ownerUid) {
            throw new SecurityException("The caller doesn't own the display.");
        }

        synchronized (mMethodMap) {
            final ClientState cs = mClients.get(parentClient.asBinder());
            if (cs == null) {
                return;
            }

            // null matrixValues means that the entry needs to be removed.
            if (matrixValues == null) {
                final ActivityViewInfo info = mActivityViewDisplayIdToParentMap.get(childDisplayId);
                if (info == null) {
                    return;
                }
                if (info.mParentClient != cs) {
                    throw new SecurityException("Only the owner client can clear"
                            + " ActivityViewGeometry for display #" + childDisplayId);
                }
                mActivityViewDisplayIdToParentMap.remove(childDisplayId);
                return;
            }

            ActivityViewInfo info = mActivityViewDisplayIdToParentMap.get(childDisplayId);
            if (info != null && info.mParentClient != cs) {
                throw new InvalidParameterException("Display #" + childDisplayId
                        + " is already registered by " + info.mParentClient);
            }
            if (info == null) {
                if (!mWindowManagerInternal.isUidAllowedOnDisplay(childDisplayId, cs.uid)) {
                    throw new SecurityException(cs + " cannot access to display #"
                            + childDisplayId);
                }
                info = new ActivityViewInfo(cs, new Matrix());
                mActivityViewDisplayIdToParentMap.put(childDisplayId, info);
            }
            info.mMatrix.setValues(matrixValues);

            if (mCurClient == null || mCurClient.curSession == null) {
                return;
            }

            Matrix matrix = null;
            int displayId = mCurClient.selfReportedDisplayId;
            boolean needToNotify = false;
            while (true) {
                needToNotify |= (displayId == childDisplayId);
                final ActivityViewInfo next = mActivityViewDisplayIdToParentMap.get(displayId);
                if (next == null) {
                    break;
                }
                if (matrix == null) {
                    matrix = new Matrix(next.mMatrix);
                } else {
                    matrix.postConcat(next.mMatrix);
                }
                if (next.mParentClient.selfReportedDisplayId == mCurTokenDisplayId) {
                    if (needToNotify) {
                        final float[] values = new float[9];
                        matrix.getValues(values);
                        try {
                            mCurClient.client.updateActivityViewToScreenMatrix(mCurSeq, values);
                        } catch (RemoteException e) {
                        }
                    }
                    break;
                }
                displayId = info.mParentClient.selfReportedDisplayId;
            }
        }
    }

    @BinderThread
    private void notifyUserAction(@NonNull IBinder token) {
        if (DEBUG) {
            Slog.d(TAG, "Got the notification of a user action.");
        }
        synchronized (mMethodMap) {
            if (mCurToken != token) {
                if (DEBUG) {
                    Slog.d(TAG, "Ignoring the user action notification from IMEs that are no longer"
                            + " active.");
                }
                return;
            }
            final InputMethodInfo imi = mMethodMap.get(mCurMethodId);
            if (imi != null) {
                mSwitchingController.onUserActionLocked(imi, mCurrentSubtype);
            }
        }
    }

    @BinderThread
    private void reportPreRendered(IBinder token, EditorInfo info) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            if (mCurClient != null && mCurClient.client != null) {
                executeOrSendMessage(mCurClient.client, mCaller.obtainMessageOO(
                        MSG_REPORT_PRE_RENDERED, info, mCurClient));
            }
        }
    }

    @BinderThread
    private void applyImeVisibility(IBinder token, boolean setVisible) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            if (mCurClient != null && mCurClient.client != null) {
                executeOrSendMessage(mCurClient.client, mCaller.obtainMessageIO(
                        MSG_APPLY_IME_VISIBILITY, setVisible ? 1 : 0, mCurClient));
            }
        }
    }

    private void setInputMethodWithSubtypeIdLocked(IBinder token, String id, int subtypeId) {
        if (token == null) {
            if (mContext.checkCallingOrSelfPermission(
                    android.Manifest.permission.WRITE_SECURE_SETTINGS)
                    != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException(
                        "Using null token requires permission "
                        + android.Manifest.permission.WRITE_SECURE_SETTINGS);
            }
        } else if (mCurToken != token) {
            Slog.w(TAG, "Ignoring setInputMethod of uid " + Binder.getCallingUid()
                    + " token: " + token);
            return;
        }

        final long ident = Binder.clearCallingIdentity();
        try {
            setInputMethodLocked(id, subtypeId);
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    @BinderThread
    private void hideMySoftInput(@NonNull IBinder token, int flags) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            long ident = Binder.clearCallingIdentity();
            try {
                hideCurrentInputLocked(flags, null);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    @BinderThread
    private void showMySoftInput(@NonNull IBinder token, int flags) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            long ident = Binder.clearCallingIdentity();
            try {
                showCurrentInputLocked(flags, null);
            } finally {
                Binder.restoreCallingIdentity(ident);
            }
        }
    }

    void setEnabledSessionInMainThread(SessionState session) {
        if (mEnabledSession != session) {
            if (mEnabledSession != null && mEnabledSession.session != null) {
                try {
                    if (DEBUG) Slog.v(TAG, "Disabling: " + mEnabledSession);
                    mEnabledSession.method.setSessionEnabled(mEnabledSession.session, false);
                } catch (RemoteException e) {
                }
            }
            mEnabledSession = session;
            if (mEnabledSession != null && mEnabledSession.session != null) {
                try {
                    if (DEBUG) Slog.v(TAG, "Enabling: " + mEnabledSession);
                    mEnabledSession.method.setSessionEnabled(mEnabledSession.session, true);
                } catch (RemoteException e) {
                }
            }
        }
    }

    @MainThread
    @Override
    public boolean handleMessage(Message msg) {
        SomeArgs args;
        switch (msg.what) {
            case MSG_SHOW_IM_SUBTYPE_PICKER:
                final boolean showAuxSubtypes;
                final int displayId = msg.arg2;
                switch (msg.arg1) {
                    case InputMethodManager.SHOW_IM_PICKER_MODE_AUTO:
                        // This is undocumented so far, but IMM#showInputMethodPicker() has been
                        // implemented so that auxiliary subtypes will be excluded when the soft
                        // keyboard is invisible.
                        showAuxSubtypes = mInputShown;
                        break;
                    case InputMethodManager.SHOW_IM_PICKER_MODE_INCLUDE_AUXILIARY_SUBTYPES:
                        showAuxSubtypes = true;
                        break;
                    case InputMethodManager.SHOW_IM_PICKER_MODE_EXCLUDE_AUXILIARY_SUBTYPES:
                        showAuxSubtypes = false;
                        break;
                    default:
                        Slog.e(TAG, "Unknown subtype picker mode = " + msg.arg1);
                        return false;
                }
                showInputMethodMenu(showAuxSubtypes, displayId);
                return true;

            case MSG_SHOW_IM_SUBTYPE_ENABLER:
                showInputMethodAndSubtypeEnabler((String)msg.obj);
                return true;

            case MSG_SHOW_IM_CONFIG:
                showConfigureInputMethods();
                return true;

            // ---------------------------------------------------------

            case MSG_UNBIND_INPUT:
                try {
                    ((IInputMethod)msg.obj).unbindInput();
                } catch (RemoteException e) {
                    // There is nothing interesting about the method dying.
                }
                return true;
            case MSG_BIND_INPUT:
                args = (SomeArgs)msg.obj;
                try {
                    ((IInputMethod)args.arg1).bindInput((InputBinding)args.arg2);
                } catch (RemoteException e) {
                }
                args.recycle();
                return true;
            case MSG_SHOW_SOFT_INPUT:
                args = (SomeArgs)msg.obj;
                try {
                    if (DEBUG) Slog.v(TAG, "Calling " + args.arg1 + ".showSoftInput("
                            + msg.arg1 + ", " + args.arg2 + ")");
                    ((IInputMethod)args.arg1).showSoftInput(msg.arg1, (ResultReceiver)args.arg2);
                } catch (RemoteException e) {
                }
                args.recycle();
                return true;
            case MSG_HIDE_SOFT_INPUT:
                args = (SomeArgs)msg.obj;
                try {
                    if (DEBUG) Slog.v(TAG, "Calling " + args.arg1 + ".hideSoftInput(0, "
                            + args.arg2 + ")");
                    ((IInputMethod)args.arg1).hideSoftInput(0, (ResultReceiver)args.arg2);
                } catch (RemoteException e) {
                }
                args.recycle();
                return true;
            case MSG_HIDE_CURRENT_INPUT_METHOD:
                synchronized (mMethodMap) {
                    hideCurrentInputLocked(0, null);
                }
                return true;
            case MSG_INITIALIZE_IME:
                args = (SomeArgs)msg.obj;
                try {
                    if (DEBUG) {
                        Slog.v(TAG, "Sending attach of token: " + args.arg2 + " for display: "
                                + msg.arg1);
                    }
                    final IBinder token = (IBinder) args.arg2;
                    ((IInputMethod) args.arg1).initializeInternal(token, msg.arg1,
                            new InputMethodPrivilegedOperationsImpl(this, token));
                } catch (RemoteException e) {
                }
                args.recycle();
                return true;
            case MSG_CREATE_SESSION: {
                args = (SomeArgs)msg.obj;
                IInputMethod method = (IInputMethod)args.arg1;
                InputChannel channel = (InputChannel)args.arg2;
                try {
                    method.createSession(channel, (IInputSessionCallback)args.arg3);
                } catch (RemoteException e) {
                } finally {
                    // Dispose the channel if the input method is not local to this process
                    // because the remote proxy will get its own copy when unparceled.
                    if (channel != null && Binder.isProxy(method)) {
                        channel.dispose();
                    }
                }
                args.recycle();
                return true;
            }
            // ---------------------------------------------------------

            case MSG_START_INPUT: {
                final int missingMethods = msg.arg1;
                final boolean restarting = msg.arg2 != 0;
                args = (SomeArgs) msg.obj;
                final IBinder startInputToken = (IBinder) args.arg1;
                final SessionState session = (SessionState) args.arg2;
                final IInputContext inputContext = (IInputContext) args.arg3;
                final EditorInfo editorInfo = (EditorInfo) args.arg4;
                try {
                    setEnabledSessionInMainThread(session);
                    session.method.startInput(startInputToken, inputContext, missingMethods,
                            editorInfo, restarting, session.client.shouldPreRenderIme);
                } catch (RemoteException e) {
                }
                args.recycle();
                return true;
            }

            // ---------------------------------------------------------

            case MSG_UNBIND_CLIENT:
                try {
                    ((IInputMethodClient)msg.obj).onUnbindMethod(msg.arg1, msg.arg2);
                } catch (RemoteException e) {
                    // There is nothing interesting about the last client dying.
                }
                return true;
            case MSG_BIND_CLIENT: {
                args = (SomeArgs)msg.obj;
                IInputMethodClient client = (IInputMethodClient)args.arg1;
                InputBindResult res = (InputBindResult)args.arg2;
                try {
                    client.onBindMethod(res);
                } catch (RemoteException e) {
                    Slog.w(TAG, "Client died receiving input method " + args.arg2);
                } finally {
                    // Dispose the channel if the input method is not local to this process
                    // because the remote proxy will get its own copy when unparceled.
                    if (res.channel != null && Binder.isProxy(client)) {
                        res.channel.dispose();
                    }
                }
                args.recycle();
                return true;
            }
            case MSG_SET_ACTIVE:
                try {
                    ((ClientState)msg.obj).client.setActive(msg.arg1 != 0, msg.arg2 != 0);
                } catch (RemoteException e) {
                    Slog.w(TAG, "Got RemoteException sending setActive(false) notification to pid "
                            + ((ClientState)msg.obj).pid + " uid "
                            + ((ClientState)msg.obj).uid);
                }
                return true;
            case MSG_SET_INTERACTIVE:
                handleSetInteractive(msg.arg1 != 0);
                return true;
            case MSG_REPORT_FULLSCREEN_MODE: {
                final boolean fullscreen = msg.arg1 != 0;
                final ClientState clientState = (ClientState)msg.obj;
                try {
                    clientState.client.reportFullscreenMode(fullscreen);
                } catch (RemoteException e) {
                    Slog.w(TAG, "Got RemoteException sending "
                            + "reportFullscreen(" + fullscreen + ") notification to pid="
                            + clientState.pid + " uid=" + clientState.uid);
                }
                return true;
            }
            case MSG_REPORT_PRE_RENDERED: {
                args = (SomeArgs) msg.obj;
                final EditorInfo info = (EditorInfo) args.arg1;
                final ClientState clientState = (ClientState) args.arg2;
                try {
                    clientState.client.reportPreRendered(info);
                } catch (RemoteException e) {
                    Slog.w(TAG, "Got RemoteException sending "
                            + "reportPreRendered(" + info + ") notification to pid="
                            + clientState.pid + " uid=" + clientState.uid);
                }
                args.recycle();
                return true;
            }
            case MSG_APPLY_IME_VISIBILITY: {
                final boolean setVisible = msg.arg1 != 0;
                final ClientState clientState = (ClientState) msg.obj;
                try {
                    clientState.client.applyImeVisibility(setVisible);
                } catch (RemoteException e) {
                    Slog.w(TAG, "Got RemoteException sending "
                            + "applyImeVisibility(" + setVisible + ") notification to pid="
                            + clientState.pid + " uid=" + clientState.uid);
                }
                return true;
            }

            // --------------------------------------------------------------
            case MSG_HARD_KEYBOARD_SWITCH_CHANGED:
                mHardKeyboardListener.handleHardKeyboardStatusChange(msg.arg1 == 1);
                return true;
            case MSG_SYSTEM_UNLOCK_USER:
                final int userId = msg.arg1;
                onUnlockUser(userId);
                return true;
        }
        return false;
    }

    private void handleSetInteractive(final boolean interactive) {
        synchronized (mMethodMap) {
            mIsInteractive = interactive;
            updateSystemUiLocked(interactive ? mImeWindowVis : 0, mBackDisposition);

            // Inform the current client of the change in active status
            if (mCurClient != null && mCurClient.client != null) {
                executeOrSendMessage(mCurClient.client, mCaller.obtainMessageIIO(
                        MSG_SET_ACTIVE, mIsInteractive ? 1 : 0, mInFullscreenMode ? 1 : 0,
                        mCurClient));
            }
        }
    }

    private boolean chooseNewDefaultIMELocked() {
        final InputMethodInfo imi = InputMethodUtils.getMostApplicableDefaultIME(
                mSettings.getEnabledInputMethodListLocked());
        if (imi != null) {
            if (DEBUG) {
                Slog.d(TAG, "New default IME was selected: " + imi.getId());
            }
            resetSelectedInputMethodAndSubtypeLocked(imi.getId());
            return true;
        }

        return false;
    }

    static void queryInputMethodServicesInternal(Context context,
            @UserIdInt int userId, ArrayMap<String, List<InputMethodSubtype>> additionalSubtypeMap,
            ArrayMap<String, InputMethodInfo> methodMap, ArrayList<InputMethodInfo> methodList) {
        methodList.clear();
        methodMap.clear();

        // Note: We do not specify PackageManager.MATCH_ENCRYPTION_* flags here because the default
        // behavior of PackageManager is exactly what we want.  It by default picks up appropriate
        // services depending on the unlock state for the specified user.
        final List<ResolveInfo> services = context.getPackageManager().queryIntentServicesAsUser(
                new Intent(InputMethod.SERVICE_INTERFACE),
                PackageManager.GET_META_DATA | PackageManager.MATCH_DISABLED_UNTIL_USED_COMPONENTS,
                userId);

        methodList.ensureCapacity(services.size());
        methodMap.ensureCapacity(services.size());

        for (int i = 0; i < services.size(); ++i) {
            ResolveInfo ri = services.get(i);
            ServiceInfo si = ri.serviceInfo;
            final String imeId = InputMethodInfo.computeId(ri);
            if (!android.Manifest.permission.BIND_INPUT_METHOD.equals(si.permission)) {
                Slog.w(TAG, "Skipping input method " + imeId
                        + ": it does not require the permission "
                        + android.Manifest.permission.BIND_INPUT_METHOD);
                continue;
            }

            if (DEBUG) Slog.d(TAG, "Checking " + imeId);

            try {
                final InputMethodInfo imi = new InputMethodInfo(context, ri,
                        additionalSubtypeMap.get(imeId));
                if (imi.isVrOnly()) {
                    continue;  // Skip VR-only IME, which isn't supported for now.
                }
                methodList.add(imi);
                methodMap.put(imi.getId(), imi);
                if (DEBUG) {
                    Slog.d(TAG, "Found an input method " + imi);
                }
            } catch (Exception e) {
                Slog.wtf(TAG, "Unable to load input method " + imeId, e);
            }
        }
    }

    @GuardedBy("mMethodMap")
    void buildInputMethodListLocked(boolean resetDefaultEnabledIme) {
        if (DEBUG) {
            Slog.d(TAG, "--- re-buildInputMethodList reset = " + resetDefaultEnabledIme
                    + " \n ------ caller=" + Debug.getCallers(10));
        }
        if (!mSystemReady) {
            Slog.e(TAG, "buildInputMethodListLocked is not allowed until system is ready");
            return;
        }
        mMethodMapUpdateCount++;
        mMyPackageMonitor.clearKnownImePackageNamesLocked();

        queryInputMethodServicesInternal(mContext, mSettings.getCurrentUserId(),
                mAdditionalSubtypeMap, mMethodMap, mMethodList);

        // Construct the set of possible IME packages for onPackageChanged() to avoid false
        // negatives when the package state remains to be the same but only the component state is
        // changed.
        {
            // Here we intentionally use PackageManager.MATCH_DISABLED_COMPONENTS since the purpose
            // of this query is to avoid false negatives.  PackageManager.MATCH_ALL could be more
            // conservative, but it seems we cannot use it for now (Issue 35176630).
            final List<ResolveInfo> allInputMethodServices =
                    mContext.getPackageManager().queryIntentServicesAsUser(
                            new Intent(InputMethod.SERVICE_INTERFACE),
                            PackageManager.MATCH_DISABLED_COMPONENTS, mSettings.getCurrentUserId());
            final int N = allInputMethodServices.size();
            for (int i = 0; i < N; ++i) {
                final ServiceInfo si = allInputMethodServices.get(i).serviceInfo;
                if (android.Manifest.permission.BIND_INPUT_METHOD.equals(si.permission)) {
                    mMyPackageMonitor.addKnownImePackageNameLocked(si.packageName);
                }
            }
        }

        boolean reenableMinimumNonAuxSystemImes = false;
        // TODO: The following code should find better place to live.
        if (!resetDefaultEnabledIme) {
            boolean enabledImeFound = false;
            boolean enabledNonAuxImeFound = false;
            final List<InputMethodInfo> enabledImes = mSettings.getEnabledInputMethodListLocked();
            final int N = enabledImes.size();
            for (int i = 0; i < N; ++i) {
                final InputMethodInfo imi = enabledImes.get(i);
                if (mMethodList.contains(imi)) {
                    enabledImeFound = true;
                    if (!imi.isAuxiliaryIme()) {
                        enabledNonAuxImeFound = true;
                        break;
                    }
                }
            }
            if (!enabledImeFound) {
                if (DEBUG) {
                    Slog.i(TAG, "All the enabled IMEs are gone. Reset default enabled IMEs.");
                }
                resetDefaultEnabledIme = true;
                resetSelectedInputMethodAndSubtypeLocked("");
            } else if (!enabledNonAuxImeFound) {
                if (DEBUG) {
                    Slog.i(TAG, "All the enabled non-Aux IMEs are gone. Do partial reset.");
                }
                reenableMinimumNonAuxSystemImes = true;
            }
        }

        if (resetDefaultEnabledIme || reenableMinimumNonAuxSystemImes) {
            final ArrayList<InputMethodInfo> defaultEnabledIme =
                    InputMethodUtils.getDefaultEnabledImes(mContext, mMethodList,
                            reenableMinimumNonAuxSystemImes);
            final int N = defaultEnabledIme.size();
            for (int i = 0; i < N; ++i) {
                final InputMethodInfo imi =  defaultEnabledIme.get(i);
                if (DEBUG) {
                    Slog.d(TAG, "--- enable ime = " + imi);
                }
                setInputMethodEnabledLocked(imi.getId(), true);
            }
        }

        final String defaultImiId = mSettings.getSelectedInputMethod();
        if (!TextUtils.isEmpty(defaultImiId)) {
            if (!mMethodMap.containsKey(defaultImiId)) {
                Slog.w(TAG, "Default IME is uninstalled. Choose new default IME.");
                if (chooseNewDefaultIMELocked()) {
                    updateInputMethodsFromSettingsLocked(true);
                }
            } else {
                // Double check that the default IME is certainly enabled.
                setInputMethodEnabledLocked(defaultImiId, true);
            }
        }
        // Here is not the perfect place to reset the switching controller. Ideally
        // mSwitchingController and mSettings should be able to share the same state.
        // TODO: Make sure that mSwitchingController and mSettings are sharing the
        // the same enabled IMEs list.
        mSwitchingController.resetCircularListLocked(mContext);
    }

    // ----------------------------------------------------------------------

    private void showInputMethodAndSubtypeEnabler(String inputMethodId) {
        Intent intent = new Intent(Settings.ACTION_INPUT_METHOD_SUBTYPE_SETTINGS);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                | Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
                | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        if (!TextUtils.isEmpty(inputMethodId)) {
            intent.putExtra(Settings.EXTRA_INPUT_METHOD_ID, inputMethodId);
        }
        final int userId;
        synchronized (mMethodMap) {
            userId = mSettings.getCurrentUserId();
        }
        mContext.startActivityAsUser(intent, null, UserHandle.of(userId));
    }

    private void showConfigureInputMethods() {
        Intent intent = new Intent(Settings.ACTION_INPUT_METHOD_SETTINGS);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                | Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
                | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        mContext.startActivityAsUser(intent, null, UserHandle.CURRENT);
    }

    private boolean isScreenLocked() {
        return mKeyguardManager != null
                && mKeyguardManager.isKeyguardLocked() && mKeyguardManager.isKeyguardSecure();
    }

    private void showInputMethodMenu(boolean showAuxSubtypes, int displayId) {
        if (DEBUG) Slog.v(TAG, "Show switching menu. showAuxSubtypes=" + showAuxSubtypes);

        final boolean isScreenLocked = isScreenLocked();

        final String lastInputMethodId = mSettings.getSelectedInputMethod();
        int lastInputMethodSubtypeId = mSettings.getSelectedInputMethodSubtypeId(lastInputMethodId);
        if (DEBUG) Slog.v(TAG, "Current IME: " + lastInputMethodId);

        synchronized (mMethodMap) {
            final List<ImeSubtypeListItem> imList =
                    mSwitchingController.getSortedInputMethodAndSubtypeListLocked(
                            showAuxSubtypes, isScreenLocked);
            if (imList.isEmpty()) {
                return;
            }

            hideInputMethodMenuLocked();

            if (lastInputMethodSubtypeId == NOT_A_SUBTYPE_ID) {
                final InputMethodSubtype currentSubtype = getCurrentInputMethodSubtypeLocked();
                if (currentSubtype != null) {
                    final InputMethodInfo currentImi = mMethodMap.get(mCurMethodId);
                    lastInputMethodSubtypeId = InputMethodUtils.getSubtypeIdFromHashCode(
                            currentImi, currentSubtype.hashCode());
                }
            }

            final int N = imList.size();
            mIms = new InputMethodInfo[N];
            mSubtypeIds = new int[N];
            int checkedItem = 0;
            for (int i = 0; i < N; ++i) {
                final ImeSubtypeListItem item = imList.get(i);
                mIms[i] = item.mImi;
                mSubtypeIds[i] = item.mSubtypeId;
                if (mIms[i].getId().equals(lastInputMethodId)) {
                    int subtypeId = mSubtypeIds[i];
                    if ((subtypeId == NOT_A_SUBTYPE_ID)
                            || (lastInputMethodSubtypeId == NOT_A_SUBTYPE_ID && subtypeId == 0)
                            || (subtypeId == lastInputMethodSubtypeId)) {
                        checkedItem = i;
                    }
                }
            }

            final ActivityThread currentThread = ActivityThread.currentActivityThread();
            final Context settingsContext = new ContextThemeWrapper(
                    displayId == DEFAULT_DISPLAY ? currentThread.getSystemUiContext()
                            : currentThread.createSystemUiContext(displayId),
                    com.android.internal.R.style.Theme_DeviceDefault_Settings);

            mDialogBuilder = new AlertDialog.Builder(settingsContext);
            mDialogBuilder.setOnCancelListener(new OnCancelListener() {
                @Override
                public void onCancel(DialogInterface dialog) {
                    hideInputMethodMenu();
                }
            });

            final Context dialogContext = mDialogBuilder.getContext();
            final TypedArray a = dialogContext.obtainStyledAttributes(null,
                    com.android.internal.R.styleable.DialogPreference,
                    com.android.internal.R.attr.alertDialogStyle, 0);
            final Drawable dialogIcon = a.getDrawable(
                    com.android.internal.R.styleable.DialogPreference_dialogIcon);
            a.recycle();

            mDialogBuilder.setIcon(dialogIcon);

            final LayoutInflater inflater = dialogContext.getSystemService(LayoutInflater.class);
            final View tv = inflater.inflate(
                    com.android.internal.R.layout.input_method_switch_dialog_title, null);
            mDialogBuilder.setCustomTitle(tv);

            // Setup layout for a toggle switch of the hardware keyboard
            mSwitchingDialogTitleView = tv;
            mSwitchingDialogTitleView
                    .findViewById(com.android.internal.R.id.hard_keyboard_section)
                    .setVisibility(mWindowManagerInternal.isHardKeyboardAvailable()
                            ? View.VISIBLE : View.GONE);
            final Switch hardKeySwitch = (Switch) mSwitchingDialogTitleView.findViewById(
                    com.android.internal.R.id.hard_keyboard_switch);
            hardKeySwitch.setChecked(mShowImeWithHardKeyboard);
            hardKeySwitch.setOnCheckedChangeListener(new OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    mSettings.setShowImeWithHardKeyboard(isChecked);
                    // Ensure that the input method dialog is dismissed when changing
                    // the hardware keyboard state.
                    hideInputMethodMenu();
                }
            });

            final ImeSubtypeListAdapter adapter = new ImeSubtypeListAdapter(dialogContext,
                    com.android.internal.R.layout.input_method_switch_item, imList, checkedItem);
            final OnClickListener choiceListener = new OnClickListener() {
                @Override
                public void onClick(final DialogInterface dialog, final int which) {
                    synchronized (mMethodMap) {
                        if (mIms == null || mIms.length <= which || mSubtypeIds == null
                                || mSubtypeIds.length <= which) {
                            return;
                        }
                        final InputMethodInfo im = mIms[which];
                        int subtypeId = mSubtypeIds[which];
                        adapter.mCheckedItem = which;
                        adapter.notifyDataSetChanged();
                        hideInputMethodMenu();
                        if (im != null) {
                            if (subtypeId < 0 || subtypeId >= im.getSubtypeCount()) {
                                subtypeId = NOT_A_SUBTYPE_ID;
                            }
                            setInputMethodLocked(im.getId(), subtypeId);
                        }
                    }
                }
            };
            mDialogBuilder.setSingleChoiceItems(adapter, checkedItem, choiceListener);

            mSwitchingDialog = mDialogBuilder.create();
            mSwitchingDialog.setCanceledOnTouchOutside(true);
            final Window w = mSwitchingDialog.getWindow();
            final LayoutParams attrs = w.getAttributes();
            w.setType(LayoutParams.TYPE_INPUT_METHOD_DIALOG);
            // Use an alternate token for the dialog for that window manager can group the token
            // with other IME windows based on type vs. grouping based on whichever token happens
            // to get selected by the system later on.
            attrs.token = mSwitchingDialogToken;
            attrs.privateFlags |= LayoutParams.PRIVATE_FLAG_SHOW_FOR_ALL_USERS;
            attrs.setTitle("Select input method");
            w.setAttributes(attrs);
            updateSystemUiLocked(mImeWindowVis, mBackDisposition);
            mSwitchingDialog.show();
        }
    }

    private static class ImeSubtypeListAdapter extends ArrayAdapter<ImeSubtypeListItem> {
        private final LayoutInflater mInflater;
        private final int mTextViewResourceId;
        private final List<ImeSubtypeListItem> mItemsList;
        public int mCheckedItem;
        public ImeSubtypeListAdapter(Context context, int textViewResourceId,
                List<ImeSubtypeListItem> itemsList, int checkedItem) {
            super(context, textViewResourceId, itemsList);

            mTextViewResourceId = textViewResourceId;
            mItemsList = itemsList;
            mCheckedItem = checkedItem;
            mInflater = context.getSystemService(LayoutInflater.class);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            final View view = convertView != null ? convertView
                    : mInflater.inflate(mTextViewResourceId, null);
            if (position < 0 || position >= mItemsList.size()) return view;
            final ImeSubtypeListItem item = mItemsList.get(position);
            final CharSequence imeName = item.mImeName;
            final CharSequence subtypeName = item.mSubtypeName;
            final TextView firstTextView = (TextView)view.findViewById(android.R.id.text1);
            final TextView secondTextView = (TextView)view.findViewById(android.R.id.text2);
            if (TextUtils.isEmpty(subtypeName)) {
                firstTextView.setText(imeName);
                secondTextView.setVisibility(View.GONE);
            } else {
                firstTextView.setText(subtypeName);
                secondTextView.setText(imeName);
                secondTextView.setVisibility(View.VISIBLE);
            }
            final RadioButton radioButton =
                    (RadioButton)view.findViewById(com.android.internal.R.id.radio);
            radioButton.setChecked(position == mCheckedItem);
            return view;
        }
    }

    void hideInputMethodMenu() {
        synchronized (mMethodMap) {
            hideInputMethodMenuLocked();
        }
    }

    void hideInputMethodMenuLocked() {
        if (DEBUG) Slog.v(TAG, "Hide switching menu");

        if (mSwitchingDialog != null) {
            mSwitchingDialog.dismiss();
            mSwitchingDialog = null;
            mSwitchingDialogTitleView = null;
        }

        updateSystemUiLocked(mImeWindowVis, mBackDisposition);
        mDialogBuilder = null;
        mIms = null;
    }

    // ----------------------------------------------------------------------

    /**
     * Enable or disable the given IME by updating {@link Settings.Secure#ENABLED_INPUT_METHODS}.
     *
     * @param id ID of the IME is to be manipulated. It is OK to pass IME ID that is currently not
     *           recognized by the system.
     * @param enabled {@code true} if {@code id} needs to be enabled.
     * @return {@code true} if the IME was previously enabled. {@code false} otherwise.
     */
    private boolean setInputMethodEnabledLocked(String id, boolean enabled) {
        List<Pair<String, ArrayList<String>>> enabledInputMethodsList = mSettings
                .getEnabledInputMethodsAndSubtypeListLocked();

        if (enabled) {
            for (Pair<String, ArrayList<String>> pair: enabledInputMethodsList) {
                if (pair.first.equals(id)) {
                    // We are enabling this input method, but it is already enabled.
                    // Nothing to do. The previous state was enabled.
                    return true;
                }
            }
            mSettings.appendAndPutEnabledInputMethodLocked(id, false);
            // Previous state was disabled.
            return false;
        } else {
            StringBuilder builder = new StringBuilder();
            if (mSettings.buildAndPutEnabledInputMethodsStrRemovingIdLocked(
                    builder, enabledInputMethodsList, id)) {
                // Disabled input method is currently selected, switch to another one.
                final String selId = mSettings.getSelectedInputMethod();
                if (id.equals(selId) && !chooseNewDefaultIMELocked()) {
                    Slog.i(TAG, "Can't find new IME, unsetting the current input method.");
                    resetSelectedInputMethodAndSubtypeLocked("");
                }
                // Previous state was enabled.
                return true;
            } else {
                // We are disabling the input method but it is already disabled.
                // Nothing to do.  The previous state was disabled.
                return false;
            }
        }
    }

    private void setSelectedInputMethodAndSubtypeLocked(InputMethodInfo imi, int subtypeId,
            boolean setSubtypeOnly) {
        mSettings.saveCurrentInputMethodAndSubtypeToHistory(mCurMethodId, mCurrentSubtype);

        // Set Subtype here
        if (imi == null || subtypeId < 0) {
            mSettings.putSelectedSubtype(NOT_A_SUBTYPE_ID);
            mCurrentSubtype = null;
        } else {
            if (subtypeId < imi.getSubtypeCount()) {
                InputMethodSubtype subtype = imi.getSubtypeAt(subtypeId);
                mSettings.putSelectedSubtype(subtype.hashCode());
                mCurrentSubtype = subtype;
            } else {
                mSettings.putSelectedSubtype(NOT_A_SUBTYPE_ID);
                // If the subtype is not specified, choose the most applicable one
                mCurrentSubtype = getCurrentInputMethodSubtypeLocked();
            }
        }

        if (!setSubtypeOnly) {
            // Set InputMethod here
            mSettings.putSelectedInputMethod(imi != null ? imi.getId() : "");
        }
    }

    private void resetSelectedInputMethodAndSubtypeLocked(String newDefaultIme) {
        InputMethodInfo imi = mMethodMap.get(newDefaultIme);
        int lastSubtypeId = NOT_A_SUBTYPE_ID;
        // newDefaultIme is empty when there is no candidate for the selected IME.
        if (imi != null && !TextUtils.isEmpty(newDefaultIme)) {
            String subtypeHashCode = mSettings.getLastSubtypeForInputMethodLocked(newDefaultIme);
            if (subtypeHashCode != null) {
                try {
                    lastSubtypeId = InputMethodUtils.getSubtypeIdFromHashCode(
                            imi, Integer.parseInt(subtypeHashCode));
                } catch (NumberFormatException e) {
                    Slog.w(TAG, "HashCode for subtype looks broken: " + subtypeHashCode, e);
                }
            }
        }
        setSelectedInputMethodAndSubtypeLocked(imi, lastSubtypeId, false);
    }

    /**
     * @return Return the current subtype of this input method.
     */
    @Override
    public InputMethodSubtype getCurrentInputMethodSubtype() {
        synchronized (mMethodMap) {
            // TODO: Make this work even for non-current users?
            if (!calledFromValidUserLocked()) {
                return null;
            }
            return getCurrentInputMethodSubtypeLocked();
        }
    }

    private InputMethodSubtype getCurrentInputMethodSubtypeLocked() {
        if (mCurMethodId == null) {
            return null;
        }
        final boolean subtypeIsSelected = mSettings.isSubtypeSelected();
        final InputMethodInfo imi = mMethodMap.get(mCurMethodId);
        if (imi == null || imi.getSubtypeCount() == 0) {
            return null;
        }
        if (!subtypeIsSelected || mCurrentSubtype == null
                || !InputMethodUtils.isValidSubtypeId(imi, mCurrentSubtype.hashCode())) {
            int subtypeId = mSettings.getSelectedInputMethodSubtypeId(mCurMethodId);
            if (subtypeId == NOT_A_SUBTYPE_ID) {
                // If there are no selected subtypes, the framework will try to find
                // the most applicable subtype from explicitly or implicitly enabled
                // subtypes.
                List<InputMethodSubtype> explicitlyOrImplicitlyEnabledSubtypes =
                        mSettings.getEnabledInputMethodSubtypeListLocked(mContext, imi, true);
                // If there is only one explicitly or implicitly enabled subtype,
                // just returns it.
                if (explicitlyOrImplicitlyEnabledSubtypes.size() == 1) {
                    mCurrentSubtype = explicitlyOrImplicitlyEnabledSubtypes.get(0);
                } else if (explicitlyOrImplicitlyEnabledSubtypes.size() > 1) {
                    mCurrentSubtype = InputMethodUtils.findLastResortApplicableSubtypeLocked(
                            mRes, explicitlyOrImplicitlyEnabledSubtypes,
                            InputMethodUtils.SUBTYPE_MODE_KEYBOARD, null, true);
                    if (mCurrentSubtype == null) {
                        mCurrentSubtype = InputMethodUtils.findLastResortApplicableSubtypeLocked(
                                mRes, explicitlyOrImplicitlyEnabledSubtypes, null, null,
                                true);
                    }
                }
            } else {
                mCurrentSubtype = InputMethodUtils.getSubtypes(imi).get(subtypeId);
            }
        }
        return mCurrentSubtype;
    }

    private List<InputMethodInfo> getInputMethodListAsUser(@UserIdInt int userId) {
        synchronized (mMethodMap) {
            return getInputMethodListLocked(userId);
        }
    }

    private List<InputMethodInfo> getEnabledInputMethodListAsUser(@UserIdInt int userId) {
        synchronized (mMethodMap) {
            return getEnabledInputMethodListLocked(userId);
        }
    }

    private static final class LocalServiceImpl extends InputMethodManagerInternal {
        @NonNull
        private final InputMethodManagerService mService;

        LocalServiceImpl(@NonNull InputMethodManagerService service) {
            mService = service;
        }

        @Override
        public void setInteractive(boolean interactive) {
            // Do everything in handler so as not to block the caller.
            mService.mHandler.obtainMessage(MSG_SET_INTERACTIVE, interactive ? 1 : 0, 0)
                    .sendToTarget();
        }

        @Override
        public void hideCurrentInputMethod() {
            mService.mHandler.removeMessages(MSG_HIDE_CURRENT_INPUT_METHOD);
            mService.mHandler.sendEmptyMessage(MSG_HIDE_CURRENT_INPUT_METHOD);
        }

        @Override
        public List<InputMethodInfo> getInputMethodListAsUser(int userId) {
            return mService.getInputMethodListAsUser(userId);
        }

        @Override
        public List<InputMethodInfo> getEnabledInputMethodListAsUser(int userId) {
            return mService.getEnabledInputMethodListAsUser(userId);
        }
    }

    @BinderThread
    private IInputContentUriToken createInputContentUriToken(@Nullable IBinder token,
            @Nullable Uri contentUri, @Nullable String packageName) {
        if (token == null) {
            throw new NullPointerException("token");
        }
        if (packageName == null) {
            throw new NullPointerException("packageName");
        }
        if (contentUri == null) {
            throw new NullPointerException("contentUri");
        }
        final String contentUriScheme = contentUri.getScheme();
        if (!"content".equals(contentUriScheme)) {
            throw new InvalidParameterException("contentUri must have content scheme");
        }

        synchronized (mMethodMap) {
            final int uid = Binder.getCallingUid();
            if (mCurMethodId == null) {
                return null;
            }
            if (mCurToken != token) {
                Slog.e(TAG, "Ignoring createInputContentUriToken mCurToken=" + mCurToken
                        + " token=" + token);
                return null;
            }
            // We cannot simply distinguish a bad IME that reports an arbitrary package name from
            // an unfortunate IME whose internal state is already obsolete due to the asynchronous
            // nature of our system.  Let's compare it with our internal record.
            if (!TextUtils.equals(mCurAttribute.packageName, packageName)) {
                Slog.e(TAG, "Ignoring createInputContentUriToken mCurAttribute.packageName="
                    + mCurAttribute.packageName + " packageName=" + packageName);
                return null;
            }
            // This user ID can never bee spoofed.
            final int imeUserId = UserHandle.getUserId(uid);
            // This user ID can never bee spoofed.
            final int appUserId = UserHandle.getUserId(mCurClient.uid);
            // This user ID may be invalid if "contentUri" embedded an invalid user ID.
            final int contentUriOwnerUserId = ContentProvider.getUserIdFromUri(contentUri,
                    imeUserId);
            final Uri contentUriWithoutUserId = ContentProvider.getUriWithoutUserId(contentUri);
            // Note: InputContentUriTokenHandler.take() checks whether the IME (specified by "uid")
            // actually has the right to grant a read permission for "contentUriWithoutUserId" that
            // is claimed to belong to "contentUriOwnerUserId".  For example, specifying random
            // content URI and/or contentUriOwnerUserId just results in a SecurityException thrown
            // from InputContentUriTokenHandler.take() and can never be allowed beyond what is
            // actually allowed to "uid", which is guaranteed to be the IME's one.
            return new InputContentUriTokenHandler(contentUriWithoutUserId, uid,
                    packageName, contentUriOwnerUserId, appUserId);
        }
    }

    @BinderThread
    private void reportFullscreenMode(@NonNull IBinder token, boolean fullscreen) {
        synchronized (mMethodMap) {
            if (!calledWithValidTokenLocked(token)) {
                return;
            }
            if (mCurClient != null && mCurClient.client != null) {
                mInFullscreenMode = fullscreen;
                executeOrSendMessage(mCurClient.client, mCaller.obtainMessageIO(
                        MSG_REPORT_FULLSCREEN_MODE, fullscreen ? 1 : 0, mCurClient));
            }
        }
    }

    @Override
    protected void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
        if (!DumpUtils.checkDumpPermission(mContext, TAG, pw)) return;

        IInputMethod method;
        ClientState client;
        ClientState focusedWindowClient;

        final Printer p = new PrintWriterPrinter(pw);

        synchronized (mMethodMap) {
            p.println("Current Input Method Manager state:");
            int N = mMethodList.size();
            p.println("  Input Methods: mMethodMapUpdateCount=" + mMethodMapUpdateCount);
            for (int i=0; i<N; i++) {
                InputMethodInfo info = mMethodList.get(i);
                p.println("  InputMethod #" + i + ":");
                info.dump(p, "    ");
            }
            p.println("  Clients:");
            final int numClients = mClients.size();
            for (int i = 0; i < numClients; ++i) {
                final ClientState ci = mClients.valueAt(i);
                p.println("  Client " + ci + ":");
                p.println("    client=" + ci.client);
                p.println("    inputContext=" + ci.inputContext);
                p.println("    sessionRequested=" + ci.sessionRequested);
                p.println("    curSession=" + ci.curSession);
            }
            p.println("  mCurMethodId=" + mCurMethodId);
            client = mCurClient;
            p.println("  mCurClient=" + client + " mCurSeq=" + mCurSeq);
            p.println("  mCurFocusedWindow=" + mCurFocusedWindow
                    + " softInputMode=" +
                    InputMethodDebug.softInputModeToString(mCurFocusedWindowSoftInputMode)
                    + " client=" + mCurFocusedWindowClient);
            focusedWindowClient = mCurFocusedWindowClient;
            p.println("  mCurId=" + mCurId + " mHaveConnection=" + mHaveConnection
                    + " mBoundToMethod=" + mBoundToMethod + " mVisibleBound=" + mVisibleBound);
            p.println("  mCurToken=" + mCurToken);
            p.println("  mCurTokenDisplayId=" + mCurTokenDisplayId);
            p.println("  mCurIntent=" + mCurIntent);
            method = mCurMethod;
            p.println("  mCurMethod=" + mCurMethod);
            p.println("  mEnabledSession=" + mEnabledSession);
            p.println("  mShowRequested=" + mShowRequested
                    + " mShowExplicitlyRequested=" + mShowExplicitlyRequested
                    + " mShowForced=" + mShowForced
                    + " mInputShown=" + mInputShown);
            p.println("  mInFullscreenMode=" + mInFullscreenMode);
            p.println("  mSystemReady=" + mSystemReady + " mInteractive=" + mIsInteractive);
            p.println("  mSettingsObserver=" + mSettingsObserver);
            p.println("  mSwitchingController:");
            mSwitchingController.dump(p);
            p.println("  mSettings:");
            mSettings.dumpLocked(p, "    ");

            p.println("  mStartInputHistory:");
            mStartInputHistory.dump(pw, "   ");
        }

        p.println(" ");
        if (client != null) {
            pw.flush();
            try {
                TransferPipe.dumpAsync(client.client.asBinder(), fd, args);
            } catch (IOException | RemoteException e) {
                p.println("Failed to dump input method client: " + e);
            }
        } else {
            p.println("No input method client.");
        }

        if (focusedWindowClient != null && client != focusedWindowClient) {
            p.println(" ");
            p.println("Warning: Current input method client doesn't match the last focused. "
                    + "window.");
            p.println("Dumping input method client in the last focused window just in case.");
            p.println(" ");
            pw.flush();
            try {
                TransferPipe.dumpAsync(focusedWindowClient.client.asBinder(), fd, args);
            } catch (IOException | RemoteException e) {
                p.println("Failed to dump input method client in focused window: " + e);
            }
        }

        p.println(" ");
        if (method != null) {
            pw.flush();
            try {
                TransferPipe.dumpAsync(method.asBinder(), fd, args);
            } catch (IOException | RemoteException e) {
                p.println("Failed to dump input method service: " + e);
            }
        } else {
            p.println("No input method service.");
        }
    }

    @BinderThread
    @Override
    public void onShellCommand(@Nullable FileDescriptor in, @Nullable FileDescriptor out,
            @Nullable FileDescriptor err,
            @NonNull String[] args, @Nullable ShellCallback callback,
            @NonNull ResultReceiver resultReceiver) throws RemoteException {
        final int callingUid = Binder.getCallingUid();
        // Reject any incoming calls from non-shell users, including ones from the system user.
        if (callingUid != Process.ROOT_UID && callingUid != Process.SHELL_UID) {
            // Note that Binder#onTransact() will automatically close "in", "out", and "err" when
            // returned from this method, hence there is no need to close those FDs.
            // "resultReceiver" is the only thing that needs to be taken care of here.
            if (resultReceiver != null) {
                resultReceiver.send(ShellCommandResult.FAILURE, null);
            }
            final String errorMsg = "InputMethodManagerService does not support shell commands from"
                    + " non-shell users. callingUid=" + callingUid
                    + " args=" + Arrays.toString(args);
            if (Process.isCoreUid(callingUid)) {
                // Let's not crash the calling process if the caller is one of core components.
                Slog.e(TAG, errorMsg);
                return;
            }
            throw new SecurityException(errorMsg);
        }
        new ShellCommandImpl(this).exec(
                this, in, out, err, args, callback, resultReceiver);
    }

    private static final class ShellCommandImpl extends ShellCommand {
        @NonNull
        final InputMethodManagerService mService;

        ShellCommandImpl(InputMethodManagerService service) {
            mService = service;
        }

        @RequiresPermission(allOf = {
                Manifest.permission.DUMP,
                Manifest.permission.INTERACT_ACROSS_USERS_FULL,
                Manifest.permission.WRITE_SECURE_SETTINGS,
        })
        @BinderThread
        @ShellCommandResult
        @Override
        public int onCommand(@Nullable String cmd) {
            // For shell command, require all the permissions here in favor of code simplicity.
            Arrays.asList(
                    Manifest.permission.DUMP,
                    Manifest.permission.INTERACT_ACROSS_USERS_FULL,
                    Manifest.permission.WRITE_SECURE_SETTINGS
            ).forEach(permission -> mService.mContext.enforceCallingPermission(permission, null));

            final long identity = Binder.clearCallingIdentity();
            try {
                return onCommandWithSystemIdentity(cmd);
            } finally {
                Binder.restoreCallingIdentity(identity);
            }
        }

        @BinderThread
        @ShellCommandResult
        private int onCommandWithSystemIdentity(@Nullable String cmd) {
            if ("refresh_debug_properties".equals(cmd)) {
                return refreshDebugProperties();
            }

            if ("get-last-switch-user-id".equals(cmd)) {
                return mService.getLastSwitchUserId(this);
            }

            // For existing "adb shell ime <command>".
            if ("ime".equals(cmd)) {
                final String imeCommand = getNextArg();
                if (imeCommand == null || "help".equals(imeCommand) || "-h".equals(imeCommand)) {
                    onImeCommandHelp();
                    return ShellCommandResult.SUCCESS;
                }
                switch (imeCommand) {
                    case "list":
                        return mService.handleShellCommandListInputMethods(this);
                    case "enable":
                        return mService.handleShellCommandEnableDisableInputMethod(this, true);
                    case "disable":
                        return mService.handleShellCommandEnableDisableInputMethod(this, false);
                    case "set":
                        return mService.handleShellCommandSetInputMethod(this);
                    case "reset":
                        return mService.handleShellCommandResetInputMethod(this);
                    default:
                        getOutPrintWriter().println("Unknown command: " + imeCommand);
                        return ShellCommandResult.FAILURE;
                }
            }

            return handleDefaultCommands(cmd);
        }

        @BinderThread
        @ShellCommandResult
        private int refreshDebugProperties() {
            DebugFlags.FLAG_OPTIMIZE_START_INPUT.refresh();
            DebugFlags.FLAG_PRE_RENDER_IME_VIEWS.refresh();
            return ShellCommandResult.SUCCESS;
        }

        @BinderThread
        @Override
        public void onHelp() {
            try (PrintWriter pw = getOutPrintWriter()) {
                pw.println("InputMethodManagerService commands:");
                pw.println("  help");
                pw.println("    Prints this help text.");
                pw.println("  dump [options]");
                pw.println("    Synonym of dumpsys.");
                pw.println("  ime <command> [options]");
                pw.println("    Manipulate IMEs.  Run \"ime help\" for details.");
            }
        }

        private void onImeCommandHelp() {
            try (IndentingPrintWriter pw =
                         new IndentingPrintWriter(getOutPrintWriter(), "  ", 100)) {
                pw.println("ime <command>:");
                pw.increaseIndent();

                pw.println("list [-a] [-s]");
                pw.increaseIndent();
                pw.println("prints all enabled input methods.");
                pw.increaseIndent();
                pw.println("-a: see all input methods");
                pw.println("-s: only a single summary line of each");
                pw.decreaseIndent();
                pw.decreaseIndent();

                pw.println("enable [--user <USER_ID>] <ID>");
                pw.increaseIndent();
                pw.println("allows the given input method ID to be used.");
                pw.increaseIndent();
                pw.print("--user <USER_ID>: Specify which user to enable.");
                pw.println(" Assumes the current user if not specified.");
                pw.decreaseIndent();
                pw.decreaseIndent();

                pw.println("disable [--user <USER_ID>] <ID>");
                pw.increaseIndent();
                pw.println("disallows the given input method ID to be used.");
                pw.increaseIndent();
                pw.print("--user <USER_ID>: Specify which user to disable.");
                pw.println(" Assumes the current user if not specified.");
                pw.decreaseIndent();
                pw.decreaseIndent();

                pw.println("set [--user <USER_ID>] <ID>");
                pw.increaseIndent();
                pw.println("switches to the given input method ID.");
                pw.increaseIndent();
                pw.print("--user <USER_ID>: Specify which user to enable.");
                pw.println(" Assumes the current user if not specified.");
                pw.decreaseIndent();
                pw.decreaseIndent();

                pw.println("reset [--user <USER_ID>]");
                pw.increaseIndent();
                pw.println("reset currently selected/enabled IMEs to the default ones as if "
                        + "the device is initially booted with the current locale.");
                pw.increaseIndent();
                pw.print("--user <USER_ID>: Specify which user to reset.");
                pw.println(" Assumes the current user if not specified.");
                pw.decreaseIndent();

                pw.decreaseIndent();

                pw.decreaseIndent();
            }
        }
    }

    // ----------------------------------------------------------------------
    // Shell command handlers:

    @BinderThread
    @ShellCommandResult
    private int getLastSwitchUserId(@NonNull ShellCommand shellCommand) {
        synchronized (mMethodMap) {
            shellCommand.getOutPrintWriter().println(mLastSwitchUserId);
            return ShellCommandResult.SUCCESS;
        }
    }

    /**
     * Handles {@code adb shell ime list}.
     * @param shellCommand {@link ShellCommand} object that is handling this command.
     * @return Exit code of the command.
     */
    @BinderThread
    @ShellCommandResult
    private int handleShellCommandListInputMethods(@NonNull ShellCommand shellCommand) {
        boolean all = false;
        boolean brief = false;
        int userIdToBeResolved = UserHandle.USER_CURRENT;
        while (true) {
            final String nextOption = shellCommand.getNextOption();
            if (nextOption == null) {
                break;
            }
            switch (nextOption) {
                case "-a":
                    all = true;
                    break;
                case "-s":
                    brief = true;
                    break;
                case "-u":
                case "--user":
                    userIdToBeResolved = UserHandle.parseUserArg(shellCommand.getNextArgRequired());
                    break;
            }
        }
        synchronized (mMethodMap) {
            final PrintWriter pr = shellCommand.getOutPrintWriter();
            final int[] userIds = InputMethodUtils.resolveUserId(userIdToBeResolved,
                    mSettings.getCurrentUserId(), shellCommand.getErrPrintWriter());
            for (int userId : userIds) {
                final List<InputMethodInfo> methods = all
                        ? getInputMethodListLocked(userId)
                        : getEnabledInputMethodListLocked(userId);
                if (userIds.length > 1) {
                    pr.print("User #");
                    pr.print(userId);
                    pr.println(":");
                }
                for (InputMethodInfo info : methods) {
                    if (brief) {
                        pr.println(info.getId());
                    } else {
                        pr.print(info.getId());
                        pr.println(":");
                        info.dump(pr::println, "  ");
                    }
                }
            }
        }
        return ShellCommandResult.SUCCESS;
    }

    /**
     * Handles {@code adb shell ime enable} and {@code adb shell ime disable}.
     * @param shellCommand {@link ShellCommand} object that is handling this command.
     * @param enabled {@code true} if the command was {@code adb shell ime enable}.
     * @return Exit code of the command.
     */
    @BinderThread
    @ShellCommandResult
    private int handleShellCommandEnableDisableInputMethod(
            @NonNull ShellCommand shellCommand, boolean enabled) {
        final int userIdToBeResolved = handleOptionsForCommandsThatOnlyHaveUserOption(shellCommand);
        final String imeId = shellCommand.getNextArgRequired();
        final PrintWriter out = shellCommand.getOutPrintWriter();
        final PrintWriter error = shellCommand.getErrPrintWriter();
        synchronized (mMethodMap) {
            final int[] userIds = InputMethodUtils.resolveUserId(userIdToBeResolved,
                    mSettings.getCurrentUserId(), shellCommand.getErrPrintWriter());
            for (int userId : userIds) {
                if (!userHasDebugPriv(userId, shellCommand)) {
                    continue;
                }
                handleShellCommandEnableDisableInputMethodInternalLocked(userId, imeId, enabled,
                        out, error);
            }
        }
        return ShellCommandResult.SUCCESS;
    }

    /**
     * A special helper method for commands that only have {@code -u} and {@code --user} options.
     *
     * <p>You cannot use this helper method if the command has other options.</p>
     *
     * <p>CAVEAT: This method must be called only once before any other
     * {@link ShellCommand#getNextArg()} and {@link ShellCommand#getNextArgRequired()} for the
     * main arguments.</p>
     *
     * @param shellCommand {@link ShellCommand} from which options should be obtained.
     * @return User ID to be resolved. {@link UserHandle#CURRENT} if not specified.
     */
    @BinderThread
    @UserIdInt
    private static int handleOptionsForCommandsThatOnlyHaveUserOption(ShellCommand shellCommand) {
        while (true) {
            final String nextOption = shellCommand.getNextOption();
            if (nextOption == null) {
                break;
            }
            switch (nextOption) {
                case "-u":
                case "--user":
                    return UserHandle.parseUserArg(shellCommand.getNextArgRequired());
            }
        }
        return UserHandle.USER_CURRENT;
    }

    @BinderThread
    private void handleShellCommandEnableDisableInputMethodInternalLocked(
            @UserIdInt int userId, String imeId, boolean enabled, PrintWriter out,
            PrintWriter error) {
        boolean failedToEnableUnknownIme = false;
        boolean previouslyEnabled = false;
        if (userId == mSettings.getCurrentUserId()) {
            if (enabled && !mMethodMap.containsKey(imeId)) {
                failedToEnableUnknownIme = true;
            } else {
                previouslyEnabled = setInputMethodEnabledLocked(imeId, enabled);
            }
        } else {
            final ArrayMap<String, InputMethodInfo> methodMap = new ArrayMap<>();
            final ArrayList<InputMethodInfo> methodList = new ArrayList<>();
            final ArrayMap<String, List<InputMethodSubtype>> additionalSubtypeMap =
                    new ArrayMap<>();
            AdditionalSubtypeUtils.load(additionalSubtypeMap, userId);
            queryInputMethodServicesInternal(mContext, userId, additionalSubtypeMap,
                    methodMap, methodList);
            final InputMethodSettings settings = new InputMethodSettings(mContext.getResources(),
                    mContext.getContentResolver(), methodMap, userId, false);
            if (enabled) {
                if (!methodMap.containsKey(imeId)) {
                    failedToEnableUnknownIme = true;
                } else {
                    for (InputMethodInfo imi : settings.getEnabledInputMethodListLocked()) {
                        if (TextUtils.equals(imi.getId(), imeId)) {
                            previouslyEnabled = true;
                            break;
                        }
                    }
                    if (!previouslyEnabled) {
                        settings.appendAndPutEnabledInputMethodLocked(imeId, false);
                    }
                }
            } else {
                previouslyEnabled =
                        settings.buildAndPutEnabledInputMethodsStrRemovingIdLocked(
                                new StringBuilder(),
                                settings.getEnabledInputMethodsAndSubtypeListLocked(), imeId);
            }
        }
        if (failedToEnableUnknownIme) {
            error.print("Unknown input method ");
            error.print(imeId);
            error.println(" cannot be enabled for user #" + userId);
        } else {
            out.print("Input method ");
            out.print(imeId);
            out.print(": ");
            out.print((enabled == previouslyEnabled) ? "already " : "now ");
            out.print(enabled ? "enabled" : "disabled");
            out.print(" for user #");
            out.println(userId);
        }
    }

    /**
     * Handles {@code adb shell ime set}.
     * @param shellCommand {@link ShellCommand} object that is handling this command.
     * @return Exit code of the command.
     */
    @BinderThread
    @ShellCommandResult
    private int handleShellCommandSetInputMethod(@NonNull ShellCommand shellCommand) {
        final int userIdToBeResolved = handleOptionsForCommandsThatOnlyHaveUserOption(shellCommand);
        final String imeId = shellCommand.getNextArgRequired();
        final PrintWriter out = shellCommand.getOutPrintWriter();
        final PrintWriter error = shellCommand.getErrPrintWriter();
        synchronized (mMethodMap) {
            final int[] userIds = InputMethodUtils.resolveUserId(userIdToBeResolved,
                    mSettings.getCurrentUserId(), shellCommand.getErrPrintWriter());
            for (int userId : userIds) {
                if (!userHasDebugPriv(userId, shellCommand)) {
                    continue;
                }
                boolean failedToSelectUnknownIme = false;
                if (userId == mSettings.getCurrentUserId()) {
                    if (mMethodMap.containsKey(imeId)) {
                        setInputMethodLocked(imeId, NOT_A_SUBTYPE_ID);
                    } else {
                        failedToSelectUnknownIme = true;
                    }
                } else {
                    final ArrayMap<String, InputMethodInfo> methodMap = new ArrayMap<>();
                    final ArrayList<InputMethodInfo> methodList = new ArrayList<>();
                    final ArrayMap<String, List<InputMethodSubtype>> additionalSubtypeMap =
                            new ArrayMap<>();
                    AdditionalSubtypeUtils.load(additionalSubtypeMap, userId);
                    queryInputMethodServicesInternal(mContext, userId, additionalSubtypeMap,
                            methodMap, methodList);
                    final InputMethodSettings settings = new InputMethodSettings(
                            mContext.getResources(), mContext.getContentResolver(), methodMap,
                            userId, false);
                    if (methodMap.containsKey(imeId)) {
                        settings.putSelectedInputMethod(imeId);
                        settings.putSelectedSubtype(NOT_A_SUBTYPE_ID);
                    } else {
                        failedToSelectUnknownIme = true;
                    }
                }
                if (failedToSelectUnknownIme) {
                    error.print("Unknown input method ");
                    error.print(imeId);
                    error.print(" cannot be selected for user #");
                    error.println(userId);
                } else {
                    out.print("Input method ");
                    out.print(imeId);
                    out.print(" selected for user #");
                    out.println(userId);
                }
            }
        }
        return ShellCommandResult.SUCCESS;
    }

    /**
     * Handles {@code adb shell ime reset-ime}.
     * @param shellCommand {@link ShellCommand} object that is handling this command.
     * @return Exit code of the command.
     */
    @BinderThread
    @ShellCommandResult
    private int handleShellCommandResetInputMethod(@NonNull ShellCommand shellCommand) {
        final PrintWriter out = shellCommand.getOutPrintWriter();
        final int userIdToBeResolved = handleOptionsForCommandsThatOnlyHaveUserOption(shellCommand);
        synchronized (mMethodMap) {
            final int[] userIds = InputMethodUtils.resolveUserId(userIdToBeResolved,
                    mSettings.getCurrentUserId(), shellCommand.getErrPrintWriter());
            for (int userId : userIds) {
                if (!userHasDebugPriv(userId, shellCommand)) {
                    continue;
                }
                final String nextIme;
                final List<InputMethodInfo> nextEnabledImes;
                if (userId == mSettings.getCurrentUserId()) {
                    hideCurrentInputLocked(0, null);
                    unbindCurrentMethodLocked();
                    // Reset the current IME
                    resetSelectedInputMethodAndSubtypeLocked(null);
                    // Also reset the settings of the current IME
                    mSettings.putSelectedInputMethod(null);
                    // Disable all enabled IMEs.
                    mSettings.getEnabledInputMethodListLocked().forEach(
                            imi -> setInputMethodEnabledLocked(imi.getId(), false));
                    // Re-enable with default enabled IMEs.
                    InputMethodUtils.getDefaultEnabledImes(mContext, mMethodList).forEach(
                            imi -> setInputMethodEnabledLocked(imi.getId(), true));
                    updateInputMethodsFromSettingsLocked(true /* enabledMayChange */);
                    InputMethodUtils.setNonSelectedSystemImesDisabledUntilUsed(mIPackageManager,
                            mSettings.getEnabledInputMethodListLocked(),
                            mSettings.getCurrentUserId(),
                            mContext.getBasePackageName());
                    nextIme = mSettings.getSelectedInputMethod();
                    nextEnabledImes = mSettings.getEnabledInputMethodListLocked();
                } else {
                    final ArrayMap<String, InputMethodInfo> methodMap = new ArrayMap<>();
                    final ArrayList<InputMethodInfo> methodList = new ArrayList<>();
                    final ArrayMap<String, List<InputMethodSubtype>> additionalSubtypeMap =
                            new ArrayMap<>();
                    AdditionalSubtypeUtils.load(additionalSubtypeMap, userId);
                    queryInputMethodServicesInternal(mContext, userId, additionalSubtypeMap,
                            methodMap, methodList);
                    final InputMethodSettings settings = new InputMethodSettings(
                            mContext.getResources(), mContext.getContentResolver(), methodMap,
                            userId, false);

                    nextEnabledImes = InputMethodUtils.getDefaultEnabledImes(mContext, methodList);
                    nextIme = InputMethodUtils.getMostApplicableDefaultIME(nextEnabledImes).getId();

                    // Reset enabled IMEs.
                    settings.putEnabledInputMethodsStr("");
                    nextEnabledImes.forEach(imi -> settings.appendAndPutEnabledInputMethodLocked(
                            imi.getId(), false));

                    // Reset selected IME.
                    settings.putSelectedInputMethod(nextIme);
                    settings.putSelectedSubtype(NOT_A_SUBTYPE_ID);
                }
                out.println("Reset current and enabled IMEs for user #" + userId);
                out.println("  Selected: " + nextIme);
                nextEnabledImes.forEach(ime -> out.println("   Enabled: " + ime.getId()));
            }
        }
        return ShellCommandResult.SUCCESS;
    }

    /**
     * @param userId the actual user handle obtained by {@link UserHandle#getIdentifier()}
     * and *not* pseudo ids like {@link UserHandle#USER_ALL etc}.
     * @return {@code true} if userId has debugging privileges.
     * i.e. {@link UserManager#DISALLOW_DEBUGGING_FEATURES} is {@code false}.
     */
    private boolean userHasDebugPriv(int userId, final ShellCommand shellCommand) {
        if (mUserManager.hasUserRestriction(
                UserManager.DISALLOW_DEBUGGING_FEATURES, UserHandle.of(userId))) {
            shellCommand.getErrPrintWriter().println("User #" + userId
                    + " is restricted with DISALLOW_DEBUGGING_FEATURES.");
            return false;
        }
        return true;
    }

    private static final class InputMethodPrivilegedOperationsImpl
            extends IInputMethodPrivilegedOperations.Stub {
        private final InputMethodManagerService mImms;
        @NonNull
        private final IBinder mToken;
        InputMethodPrivilegedOperationsImpl(InputMethodManagerService imms,
                @NonNull IBinder token) {
            mImms = imms;
            mToken = token;
        }

        @BinderThread
        @Override
        public void setImeWindowStatus(int vis, int backDisposition) {
            mImms.setImeWindowStatus(mToken, vis, backDisposition);
        }

        @BinderThread
        @Override
        public void reportStartInput(IBinder startInputToken) {
            mImms.reportStartInput(mToken, startInputToken);
        }

        @BinderThread
        @Override
        public IInputContentUriToken createInputContentUriToken(Uri contentUri,
                String packageName) {
            return mImms.createInputContentUriToken(mToken, contentUri, packageName);
        }

        @BinderThread
        @Override
        public void reportFullscreenMode(boolean fullscreen) {
            mImms.reportFullscreenMode(mToken, fullscreen);
        }

        @BinderThread
        @Override
        public void setInputMethod(String id) {
            mImms.setInputMethod(mToken, id);
        }

        @BinderThread
        @Override
        public void setInputMethodAndSubtype(String id, InputMethodSubtype subtype) {
            mImms.setInputMethodAndSubtype(mToken, id, subtype);
        }

        @BinderThread
        @Override
        public void hideMySoftInput(int flags) {
            mImms.hideMySoftInput(mToken, flags);
        }

        @BinderThread
        @Override
        public void showMySoftInput(int flags) {
            mImms.showMySoftInput(mToken, flags);
        }

        @BinderThread
        @Override
        public void updateStatusIcon(String packageName, @DrawableRes int iconId) {
            mImms.updateStatusIcon(mToken, packageName, iconId);
        }

        @BinderThread
        @Override
        public boolean switchToPreviousInputMethod() {
            return mImms.switchToPreviousInputMethod(mToken);
        }

        @BinderThread
        @Override
        public boolean switchToNextInputMethod(boolean onlyCurrentIme) {
            return mImms.switchToNextInputMethod(mToken, onlyCurrentIme);
        }

        @BinderThread
        @Override
        public boolean shouldOfferSwitchingToNextInputMethod() {
            return mImms.shouldOfferSwitchingToNextInputMethod(mToken);
        }

        @BinderThread
        @Override
        public void notifyUserAction() {
            mImms.notifyUserAction(mToken);
        }

        @BinderThread
        @Override
        public void reportPreRendered(EditorInfo info) {
            mImms.reportPreRendered(mToken, info);
        }

        @BinderThread
        @Override
        public void applyImeVisibility(boolean setVisible) {
            mImms.applyImeVisibility(mToken, setVisible);
        }
    }
}
