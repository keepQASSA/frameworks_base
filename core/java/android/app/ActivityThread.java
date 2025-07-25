/*
 * Copyright (C) 2006 The Android Open Source Project
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

package android.app;

import static android.app.ActivityManager.PROCESS_STATE_UNKNOWN;
import static android.app.servertransaction.ActivityLifecycleItem.ON_CREATE;
import static android.app.servertransaction.ActivityLifecycleItem.ON_DESTROY;
import static android.app.servertransaction.ActivityLifecycleItem.ON_PAUSE;
import static android.app.servertransaction.ActivityLifecycleItem.ON_RESUME;
import static android.app.servertransaction.ActivityLifecycleItem.ON_START;
import static android.app.servertransaction.ActivityLifecycleItem.ON_STOP;
import static android.app.servertransaction.ActivityLifecycleItem.PRE_ON_CREATE;
import static android.content.ContentResolver.DEPRECATE_DATA_COLUMNS;
import static android.content.ContentResolver.DEPRECATE_DATA_PREFIX;
import static android.view.Display.INVALID_DISPLAY;

import static com.android.internal.annotations.VisibleForTesting.Visibility.PACKAGE;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.UnsupportedAppUsage;
import android.app.assist.AssistContent;
import android.app.assist.AssistStructure;
import android.app.backup.BackupAgent;
import android.app.servertransaction.ActivityLifecycleItem;
import android.app.servertransaction.ActivityLifecycleItem.LifecycleState;
import android.app.servertransaction.ActivityRelaunchItem;
import android.app.servertransaction.ActivityResultItem;
import android.app.servertransaction.ClientTransaction;
import android.app.servertransaction.ClientTransactionItem;
import android.app.servertransaction.PendingTransactionActions;
import android.app.servertransaction.PendingTransactionActions.StopInfo;
import android.app.servertransaction.TransactionExecutor;
import android.app.servertransaction.TransactionExecutorHelper;
import android.content.AutofillOptions;
import android.content.BroadcastReceiver;
import android.content.ComponentCallbacks2;
import android.content.ComponentName;
import android.content.ContentCaptureOptions;
import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.Context;
import android.content.IContentProvider;
import android.content.IIntentReceiver;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.IPackageManager;
import android.content.pm.InstrumentationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ParceledListSlice;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.content.res.AssetManager;
import android.content.res.CompatibilityInfo;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDebug;
import android.database.sqlite.SQLiteDebug.DbStats;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.HardwareRenderer;
import android.graphics.ImageDecoder;
import android.hardware.display.DisplayManagerGlobal;
import android.net.ConnectivityManager;
import android.net.IConnectivityManager;
import android.net.Proxy;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Debug;
import android.os.Environment;
import android.os.FileUtils;
import android.os.GraphicsEnvironment;
import android.os.Handler;
import android.os.HandlerExecutor;
import android.os.IBinder;
import android.os.ICancellationSignal;
import android.os.LocaleList;
import android.os.Looper;
import android.os.Message;
import android.os.MessageQueue;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.PersistableBundle;
import android.os.Process;
import android.os.RemoteCallback;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.StrictMode;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.Trace;
import android.os.UserHandle;
import android.provider.BlockedNumberContract;
import android.provider.CalendarContract;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.Downloads;
import android.provider.FontsContract;
import android.provider.Settings;
import android.renderscript.RenderScriptCacheDir;
import android.security.NetworkSecurityPolicy;
import android.security.net.config.NetworkSecurityConfigProvider;
import android.system.ErrnoException;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.AndroidRuntimeException;
import android.util.ArrayMap;
import android.util.DisplayMetrics;
import android.util.EventLog;
import android.util.Log;
import android.util.LogPrinter;
import android.util.MergedConfiguration;
import android.util.Pair;
import android.util.PrintWriterPrinter;
import android.util.Slog;
import android.util.SparseArray;
import android.util.SparseIntArray;
import android.util.SuperNotCalledException;
import android.util.UtilConfig;
import android.util.proto.ProtoOutputStream;
import android.view.Choreographer;
import android.view.ContextThemeWrapper;
import android.view.Display;
import android.view.ThreadedRenderer;
import android.view.View;
import android.view.ViewDebug;
import android.view.ViewManager;
import android.view.ViewRootImpl;
import android.view.Window;
import android.view.WindowManager;
import android.view.WindowManagerGlobal;
import android.webkit.WebView;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.app.IVoiceInteractor;
import com.android.internal.content.ReferrerIntent;
import com.android.internal.os.BinderInternal;
import com.android.internal.os.RuntimeInit;
import com.android.internal.os.SomeArgs;
import com.android.internal.util.ArrayUtils;
import com.android.internal.util.FastPrintWriter;
import com.android.internal.util.Preconditions;
import com.android.internal.util.function.pooled.PooledLambda;
import com.android.org.conscrypt.OpenSSLSocketImpl;
import com.android.org.conscrypt.TrustedCertificateStore;
import com.android.server.am.MemInfoDumpProto;

import dalvik.system.CloseGuard;
import dalvik.system.VMDebug;
import dalvik.system.VMRuntime;

import libcore.io.ForwardingOs;
import libcore.io.IoUtils;
import libcore.io.Os;
import libcore.net.event.NetworkEventDispatcher;

import org.apache.harmony.dalvik.ddmc.DdmVmInternal;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.nio.file.Files;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TimeZone;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

final class RemoteServiceException extends AndroidRuntimeException {
    public RemoteServiceException(String msg) {
        super(msg);
    }
}

/**
 * This manages the execution of the main thread in an
 * application process, scheduling and executing activities,
 * broadcasts, and other operations on it as the activity
 * manager requests.
 *
 * {@hide}
 */
public final class ActivityThread extends ClientTransactionHandler {
    /** @hide */
    public static final String TAG = "ActivityThread";
    private static final android.graphics.Bitmap.Config THUMBNAIL_FORMAT = Bitmap.Config.RGB_565;
    static final boolean localLOGV = false;
    static final boolean DEBUG_MESSAGES = false;
    /** @hide */
    public static final boolean DEBUG_BROADCAST = false;
    private static final boolean DEBUG_RESULTS = false;
    private static final boolean DEBUG_BACKUP = false;
    public static final boolean DEBUG_CONFIGURATION = false;
    private static final boolean DEBUG_SERVICE = false;
    public static final boolean DEBUG_MEMORY_TRIM = false;
    private static final boolean DEBUG_PROVIDER = false;
    public static final boolean DEBUG_ORDER = false;
    private static final long MIN_TIME_BETWEEN_GCS = 5*1000;
    /**
     * If the activity doesn't become idle in time, the timeout will ensure to apply the pending top
     * process state.
     */
    private static final long PENDING_TOP_PROCESS_STATE_TIMEOUT = 1000;
    /**
     * The delay to release the provider when it has no more references. It reduces the number of
     * transactions for acquiring and releasing provider if the client accesses the provider
     * frequently in a short time.
     */
    private static final long CONTENT_PROVIDER_RETAIN_TIME = 1000;
    private static final int SQLITE_MEM_RELEASED_EVENT_LOG_TAG = 75003;

    /** Type for IActivityManager.serviceDoneExecuting: anonymous operation */
    public static final int SERVICE_DONE_EXECUTING_ANON = 0;
    /** Type for IActivityManager.serviceDoneExecuting: done with an onStart call */
    public static final int SERVICE_DONE_EXECUTING_START = 1;
    /** Type for IActivityManager.serviceDoneExecuting: done stopping (destroying) service */
    public static final int SERVICE_DONE_EXECUTING_STOP = 2;

    // Whether to invoke an activity callback after delivering new configuration.
    private static final boolean REPORT_TO_ACTIVITY = true;

    /** Use foreground GC policy (less pause time) and higher JIT weight. */
    private static final int VM_PROCESS_STATE_JANK_PERCEPTIBLE = 0;
    /** Use background GC policy and default JIT threshold. */
    private static final int VM_PROCESS_STATE_JANK_IMPERCEPTIBLE = 1;

    /**
     * Denotes an invalid sequence number corresponding to a process state change.
     */
    public static final long INVALID_PROC_STATE_SEQ = -1;

    /**
     * Identifier for the sequence no. associated with this process start. It will be provided
     * as one of the arguments when the process starts.
     */
    public static final String PROC_START_SEQ_IDENT = "seq=";

    private final Object mNetworkPolicyLock = new Object();

    /**
     * Denotes the sequence number of the process state change for which the main thread needs
     * to block until the network rules are updated for it.
     *
     * Value of {@link #INVALID_PROC_STATE_SEQ} indicates there is no need for blocking.
     */
    @GuardedBy("mNetworkPolicyLock")
    private long mNetworkBlockSeq = INVALID_PROC_STATE_SEQ;

    @UnsupportedAppUsage
    private ContextImpl mSystemContext;
    private ContextImpl mSystemUiContext;

    @UnsupportedAppUsage
    static volatile IPackageManager sPackageManager;

    @UnsupportedAppUsage
    final ApplicationThread mAppThread = new ApplicationThread();
    @UnsupportedAppUsage
    final Looper mLooper = Looper.myLooper();
    @UnsupportedAppUsage
    final H mH = new H();
    final Executor mExecutor = new HandlerExecutor(mH);
    /**
     * Maps from activity token to local record of running activities in this process.
     *
     * This variable is readable if the code is running in activity thread or holding {@link
     * #mResourcesManager}. It's only writable if the code is running in activity thread and holding
     * {@link #mResourcesManager}.
     */
    @UnsupportedAppUsage
    final ArrayMap<IBinder, ActivityClientRecord> mActivities = new ArrayMap<>();
    /** The activities to be truly destroyed (not include relaunch). */
    final Map<IBinder, ClientTransactionItem> mActivitiesToBeDestroyed =
            Collections.synchronizedMap(new ArrayMap<IBinder, ClientTransactionItem>());
    // List of new activities (via ActivityRecord.nextIdle) that should
    // be reported when next we idle.
    ActivityClientRecord mNewActivities = null;
    // Number of activities that are currently visible on-screen.
    @UnsupportedAppUsage
    int mNumVisibleActivities = 0;
    private final AtomicInteger mNumLaunchingActivities = new AtomicInteger();
    @GuardedBy("mAppThread")
    private int mLastProcessState = PROCESS_STATE_UNKNOWN;
    @GuardedBy("mAppThread")
    private int mPendingProcessState = PROCESS_STATE_UNKNOWN;
    ArrayList<WeakReference<AssistStructure>> mLastAssistStructures = new ArrayList<>();
    private int mLastSessionId;
    @UnsupportedAppUsage
    final ArrayMap<IBinder, Service> mServices = new ArrayMap<>();
    @UnsupportedAppUsage
    AppBindData mBoundApplication;
    Profiler mProfiler;
    @UnsupportedAppUsage
    int mCurDefaultDisplayDpi;
    @UnsupportedAppUsage
    boolean mDensityCompatMode;
    @UnsupportedAppUsage
    Configuration mConfiguration;
    Configuration mCompatConfiguration;
    @UnsupportedAppUsage
    Application mInitialApplication;
    @UnsupportedAppUsage
    final ArrayList<Application> mAllApplications
            = new ArrayList<Application>();
    /**
     * Bookkeeping of instantiated backup agents indexed first by user id, then by package name.
     * Indexing by user id supports parallel backups across users on system packages as they run in
     * the same process with the same package name. Indexing by package name supports multiple
     * distinct applications running in the same process.
     */
    private final SparseArray<ArrayMap<String, BackupAgent>> mBackupAgentsByUser =
            new SparseArray<>();
    /** Reference to singleton {@link ActivityThread} */
    @UnsupportedAppUsage
    private static volatile ActivityThread sCurrentActivityThread;
    @UnsupportedAppUsage
    Instrumentation mInstrumentation;
    String mInstrumentationPackageName = null;
    @UnsupportedAppUsage
    String mInstrumentationAppDir = null;
    String[] mInstrumentationSplitAppDirs = null;
    String mInstrumentationLibDir = null;
    @UnsupportedAppUsage
    String mInstrumentedAppDir = null;
    String[] mInstrumentedSplitAppDirs = null;
    String mInstrumentedLibDir = null;
    boolean mSystemThread = false;
    boolean mSomeActivitiesChanged = false;
    boolean mUpdatingSystemConfig = false;
    /* package */ boolean mHiddenApiWarningShown = false;

    // These can be accessed by multiple threads; mResourcesManager is the lock.
    // XXX For now we keep around information about all packages we have
    // seen, not removing entries from this map.
    // NOTE: The activity and window managers need to call in to
    // ActivityThread to do things like update resource configurations,
    // which means this lock gets held while the activity and window managers
    // holds their own lock.  Thus you MUST NEVER call back into the activity manager
    // or window manager or anything that depends on them while holding this lock.
    // These LoadedApk are only valid for the userId that we're running as.
    @GuardedBy("mResourcesManager")
    @UnsupportedAppUsage
    final ArrayMap<String, WeakReference<LoadedApk>> mPackages = new ArrayMap<>();
    @GuardedBy("mResourcesManager")
    @UnsupportedAppUsage
    final ArrayMap<String, WeakReference<LoadedApk>> mResourcePackages = new ArrayMap<>();
    @GuardedBy("mResourcesManager")
    final ArrayList<ActivityClientRecord> mRelaunchingActivities = new ArrayList<>();
    @GuardedBy("mResourcesManager")
    @UnsupportedAppUsage
    Configuration mPendingConfiguration = null;
    // An executor that performs multi-step transactions.
    private final TransactionExecutor mTransactionExecutor = new TransactionExecutor(this);

    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    private final ResourcesManager mResourcesManager;

    // Registry of remote cancellation transports pending a reply with reply handles.
    @GuardedBy("this")
    private @Nullable Map<SafeCancellationTransport, CancellationSignal> mRemoteCancellations;

    private static final class ProviderKey {
        final String authority;
        final int userId;

        public ProviderKey(String authority, int userId) {
            this.authority = authority;
            this.userId = userId;
        }

        @Override
        public boolean equals(Object o) {
            if (o instanceof ProviderKey) {
                final ProviderKey other = (ProviderKey) o;
                return Objects.equals(authority, other.authority) && userId == other.userId;
            }
            return false;
        }

        @Override
        public int hashCode() {
            return ((authority != null) ? authority.hashCode() : 0) ^ userId;
        }
    }

    // The lock of mProviderMap protects the following variables.
    @UnsupportedAppUsage
    final ArrayMap<ProviderKey, ProviderClientRecord> mProviderMap
        = new ArrayMap<ProviderKey, ProviderClientRecord>();
    @UnsupportedAppUsage
    final ArrayMap<IBinder, ProviderRefCount> mProviderRefCountMap
        = new ArrayMap<IBinder, ProviderRefCount>();
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    final ArrayMap<IBinder, ProviderClientRecord> mLocalProviders
        = new ArrayMap<IBinder, ProviderClientRecord>();
    @UnsupportedAppUsage
    final ArrayMap<ComponentName, ProviderClientRecord> mLocalProvidersByName
            = new ArrayMap<ComponentName, ProviderClientRecord>();

    // Mitigation for b/74523247: Used to serialize calls to AM.getContentProvider().
    // Note we never removes items from this map but that's okay because there are only so many
    // users and so many authorities.
    // TODO Remove it once we move CPR.wait() from AMS to the client side.
    @GuardedBy("mGetProviderLocks")
    final ArrayMap<ProviderKey, Object> mGetProviderLocks = new ArrayMap<>();

    final ArrayMap<Activity, ArrayList<OnActivityPausedListener>> mOnPauseListeners
        = new ArrayMap<Activity, ArrayList<OnActivityPausedListener>>();

    final GcIdler mGcIdler = new GcIdler();
    final PurgeIdler mPurgeIdler = new PurgeIdler();

    boolean mPurgeIdlerScheduled = false;
    boolean mGcIdlerScheduled = false;

    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    static volatile Handler sMainThreadHandler;  // set once in main()

    Bundle mCoreSettings = null;

    /** Activity client record, used for bookkeeping for the real {@link Activity} instance. */
    public static final class ActivityClientRecord {
        @UnsupportedAppUsage
        public IBinder token;
        public IBinder assistToken;
        int ident;
        @UnsupportedAppUsage
        Intent intent;
        String referrer;
        IVoiceInteractor voiceInteractor;
        Bundle state;
        PersistableBundle persistentState;
        @UnsupportedAppUsage
        Activity activity;
        Window window;
        Activity parent;
        String embeddedID;
        Activity.NonConfigurationInstances lastNonConfigurationInstances;
        // TODO(lifecycler): Use mLifecycleState instead.
        @UnsupportedAppUsage
        boolean paused;
        @UnsupportedAppUsage
        boolean stopped;
        boolean hideForNow;
        Configuration newConfig;
        Configuration createdConfig;
        Configuration overrideConfig;
        // Used to save the last reported configuration from server side so that activity
        // configuration transactions can always use the latest configuration.
        @GuardedBy("this")
        private Configuration mPendingOverrideConfig;
        // Used for consolidating configs before sending on to Activity.
        private Configuration tmpConfig = new Configuration();
        // Callback used for updating activity override config.
        ViewRootImpl.ActivityConfigCallback configCallback;
        ActivityClientRecord nextIdle;

        // Indicates whether this activity is currently the topmost resumed one in the system.
        // This holds the last reported value from server.
        boolean isTopResumedActivity;
        // This holds the value last sent to the activity. This is needed, because an update from
        // server may come at random time, but we always need to report changes between ON_RESUME
        // and ON_PAUSE to the app.
        boolean lastReportedTopResumedState;

        ProfilerInfo profilerInfo;

        @UnsupportedAppUsage
        ActivityInfo activityInfo;
        @UnsupportedAppUsage
        CompatibilityInfo compatInfo;
        @UnsupportedAppUsage
        public LoadedApk packageInfo;

        List<ResultInfo> pendingResults;
        List<ReferrerIntent> pendingIntents;

        boolean startsNotResumed;
        public final boolean isForward;
        int pendingConfigChanges;

        Window mPendingRemoveWindow;
        WindowManager mPendingRemoveWindowManager;
        @UnsupportedAppUsage
        boolean mPreserveWindow;

        @LifecycleState
        private int mLifecycleState = PRE_ON_CREATE;

        @VisibleForTesting
        @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
        public ActivityClientRecord() {
            this.isForward = false;
            init();
        }

        public ActivityClientRecord(IBinder token, Intent intent, int ident,
                ActivityInfo info, Configuration overrideConfig, CompatibilityInfo compatInfo,
                String referrer, IVoiceInteractor voiceInteractor, Bundle state,
                PersistableBundle persistentState, List<ResultInfo> pendingResults,
                List<ReferrerIntent> pendingNewIntents, boolean isForward,
                ProfilerInfo profilerInfo, ClientTransactionHandler client,
                IBinder assistToken) {
            this.token = token;
            this.assistToken = assistToken;
            this.ident = ident;
            this.intent = intent;
            this.referrer = referrer;
            this.voiceInteractor = voiceInteractor;
            this.activityInfo = info;
            this.compatInfo = compatInfo;
            this.state = state;
            this.persistentState = persistentState;
            this.pendingResults = pendingResults;
            this.pendingIntents = pendingNewIntents;
            this.isForward = isForward;
            this.profilerInfo = profilerInfo;
            this.overrideConfig = overrideConfig;
            this.packageInfo = client.getPackageInfoNoCheck(activityInfo.applicationInfo,
                    compatInfo);
            init();
        }

        /** Common initializer for all constructors. */
        private void init() {
            parent = null;
            embeddedID = null;
            paused = false;
            stopped = false;
            hideForNow = false;
            nextIdle = null;
            configCallback = (Configuration overrideConfig, int newDisplayId) -> {
                if (activity == null) {
                    throw new IllegalStateException(
                            "Received config update for non-existing activity");
                }
                activity.mMainThread.handleActivityConfigurationChanged(token, overrideConfig,
                        newDisplayId);
            };
        }

        /** Get the current lifecycle state. */
        public int getLifecycleState() {
            return mLifecycleState;
        }

        /** Update the current lifecycle state for internal bookkeeping. */
        public void setState(@LifecycleState int newLifecycleState) {
            mLifecycleState = newLifecycleState;
            switch (mLifecycleState) {
                case ON_CREATE:
                    paused = true;
                    stopped = true;
                    break;
                case ON_START:
                    paused = true;
                    stopped = false;
                    break;
                case ON_RESUME:
                    paused = false;
                    stopped = false;
                    break;
                case ON_PAUSE:
                    paused = true;
                    stopped = false;
                    break;
                case ON_STOP:
                    paused = true;
                    stopped = true;
                    break;
            }
        }

        private boolean isPreHoneycomb() {
            return activity != null && activity.getApplicationInfo().targetSdkVersion
                    < android.os.Build.VERSION_CODES.HONEYCOMB;
        }

        private boolean isPreP() {
            return activity != null && activity.getApplicationInfo().targetSdkVersion
                    < android.os.Build.VERSION_CODES.P;
        }

        public boolean isPersistable() {
            return activityInfo.persistableMode == ActivityInfo.PERSIST_ACROSS_REBOOTS;
        }

        public boolean isVisibleFromServer() {
            return activity != null && activity.mVisibleFromServer;
        }

        public String toString() {
            ComponentName componentName = intent != null ? intent.getComponent() : null;
            return "ActivityRecord{"
                + Integer.toHexString(System.identityHashCode(this))
                + " token=" + token + " " + (componentName == null
                        ? "no component name" : componentName.toShortString())
                + "}";
        }

        public String getStateString() {
            StringBuilder sb = new StringBuilder();
            sb.append("ActivityClientRecord{");
            sb.append("paused=").append(paused);
            sb.append(", stopped=").append(stopped);
            sb.append(", hideForNow=").append(hideForNow);
            sb.append(", startsNotResumed=").append(startsNotResumed);
            sb.append(", isForward=").append(isForward);
            sb.append(", pendingConfigChanges=").append(pendingConfigChanges);
            sb.append(", preserveWindow=").append(mPreserveWindow);
            if (activity != null) {
                sb.append(", Activity{");
                sb.append("resumed=").append(activity.mResumed);
                sb.append(", stopped=").append(activity.mStopped);
                sb.append(", finished=").append(activity.isFinishing());
                sb.append(", destroyed=").append(activity.isDestroyed());
                sb.append(", startedActivity=").append(activity.mStartedActivity);
                sb.append(", changingConfigurations=").append(activity.mChangingConfigurations);
                sb.append("}");
            }
            sb.append("}");
            return sb.toString();
        }
    }

    final class ProviderClientRecord {
        final String[] mNames;
        @UnsupportedAppUsage
        final IContentProvider mProvider;
        @UnsupportedAppUsage
        final ContentProvider mLocalProvider;
        @UnsupportedAppUsage
        final ContentProviderHolder mHolder;

        ProviderClientRecord(String[] names, IContentProvider provider,
                ContentProvider localProvider, ContentProviderHolder holder) {
            mNames = names;
            mProvider = provider;
            mLocalProvider = localProvider;
            mHolder = holder;
        }
    }

    static final class ReceiverData extends BroadcastReceiver.PendingResult {
        public ReceiverData(Intent intent, int resultCode, String resultData, Bundle resultExtras,
                boolean ordered, boolean sticky, IBinder token, int sendingUser) {
            super(resultCode, resultData, resultExtras, TYPE_COMPONENT, ordered, sticky,
                    token, sendingUser, intent.getFlags());
            this.intent = intent;
        }

        @UnsupportedAppUsage
        Intent intent;
        @UnsupportedAppUsage
        ActivityInfo info;
        @UnsupportedAppUsage
        CompatibilityInfo compatInfo;
        public String toString() {
            return "ReceiverData{intent=" + intent + " packageName=" +
                    info.packageName + " resultCode=" + getResultCode()
                    + " resultData=" + getResultData() + " resultExtras="
                    + getResultExtras(false) + "}";
        }
    }

    static final class CreateBackupAgentData {
        ApplicationInfo appInfo;
        CompatibilityInfo compatInfo;
        int backupMode;
        int userId;
        public String toString() {
            return "CreateBackupAgentData{appInfo=" + appInfo
                    + " backupAgent=" + appInfo.backupAgentName
                    + " mode=" + backupMode + " userId=" + userId + "}";
        }
    }

    static final class CreateServiceData {
        @UnsupportedAppUsage
        IBinder token;
        @UnsupportedAppUsage
        ServiceInfo info;
        @UnsupportedAppUsage
        CompatibilityInfo compatInfo;
        @UnsupportedAppUsage
        Intent intent;
        public String toString() {
            return "CreateServiceData{token=" + token + " className="
            + info.name + " packageName=" + info.packageName
            + " intent=" + intent + "}";
        }
    }

    static final class BindServiceData {
        @UnsupportedAppUsage
        IBinder token;
        @UnsupportedAppUsage
        Intent intent;
        boolean rebind;
        public String toString() {
            return "BindServiceData{token=" + token + " intent=" + intent + "}";
        }
    }

    static final class ServiceArgsData {
        @UnsupportedAppUsage
        IBinder token;
        boolean taskRemoved;
        int startId;
        int flags;
        @UnsupportedAppUsage
        Intent args;
        public String toString() {
            return "ServiceArgsData{token=" + token + " startId=" + startId
            + " args=" + args + "}";
        }
    }

    static final class AppBindData {
        @UnsupportedAppUsage
        LoadedApk info;
        @UnsupportedAppUsage
        String processName;
        @UnsupportedAppUsage
        ApplicationInfo appInfo;
        @UnsupportedAppUsage
        List<ProviderInfo> providers;
        ComponentName instrumentationName;
        @UnsupportedAppUsage
        Bundle instrumentationArgs;
        IInstrumentationWatcher instrumentationWatcher;
        IUiAutomationConnection instrumentationUiAutomationConnection;
        int debugMode;
        boolean enableBinderTracking;
        boolean trackAllocation;
        @UnsupportedAppUsage
        boolean restrictedBackupMode;
        @UnsupportedAppUsage
        boolean persistent;
        Configuration config;
        @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
        CompatibilityInfo compatInfo;
        String buildSerial;

        /** Initial values for {@link Profiler}. */
        ProfilerInfo initProfilerInfo;

        AutofillOptions autofillOptions;

        /**
         * Content capture options for the application - when null, it means ContentCapture is not
         * enabled for the package.
         */
        @Nullable
        ContentCaptureOptions contentCaptureOptions;

        @Override
        public String toString() {
            return "AppBindData{appInfo=" + appInfo + "}";
        }
    }

    static final class Profiler {
        String profileFile;
        ParcelFileDescriptor profileFd;
        int samplingInterval;
        boolean autoStopProfiler;
        boolean streamingOutput;
        boolean profiling;
        boolean handlingProfiling;
        public void setProfiler(ProfilerInfo profilerInfo) {
            ParcelFileDescriptor fd = profilerInfo.profileFd;
            if (profiling) {
                if (fd != null) {
                    try {
                        fd.close();
                    } catch (IOException e) {
                        // Ignore
                    }
                }
                return;
            }
            if (profileFd != null) {
                try {
                    profileFd.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
            profileFile = profilerInfo.profileFile;
            profileFd = fd;
            samplingInterval = profilerInfo.samplingInterval;
            autoStopProfiler = profilerInfo.autoStopProfiler;
            streamingOutput = profilerInfo.streamingOutput;
        }
        public void startProfiling() {
            if (profileFd == null || profiling) {
                return;
            }
            try {
                int bufferSize = SystemProperties.getInt("debug.traceview-buffer-size-mb", 8);
                VMDebug.startMethodTracing(profileFile, profileFd.getFileDescriptor(),
                        bufferSize * 1024 * 1024, 0, samplingInterval != 0, samplingInterval,
                        streamingOutput);
                profiling = true;
            } catch (RuntimeException e) {
                Slog.w(TAG, "Profiling failed on path " + profileFile, e);
                try {
                    profileFd.close();
                    profileFd = null;
                } catch (IOException e2) {
                    Slog.w(TAG, "Failure closing profile fd", e2);
                }
            }
        }
        public void stopProfiling() {
            if (profiling) {
                profiling = false;
                Debug.stopMethodTracing();
                if (profileFd != null) {
                    try {
                        profileFd.close();
                    } catch (IOException e) {
                    }
                }
                profileFd = null;
                profileFile = null;
            }
        }
    }

    static final class DumpComponentInfo {
        ParcelFileDescriptor fd;
        IBinder token;
        String prefix;
        String[] args;
    }

    static final class ContextCleanupInfo {
        ContextImpl context;
        String what;
        String who;
    }

    static final class DumpHeapData {
        // Whether to dump the native or managed heap.
        public boolean managed;
        public boolean mallocInfo;
        public boolean runGc;
        String path;
        ParcelFileDescriptor fd;
        RemoteCallback finishCallback;
    }

    static final class UpdateCompatibilityData {
        String pkg;
        CompatibilityInfo info;
    }

    static final class RequestAssistContextExtras {
        IBinder activityToken;
        IBinder requestToken;
        int requestType;
        int sessionId;
        int flags;
    }

    private class ApplicationThread extends IApplicationThread.Stub {
        private static final String DB_INFO_FORMAT = "  %8s %8s %14s %14s  %s";

        public final void scheduleSleeping(IBinder token, boolean sleeping) {
            sendMessage(H.SLEEPING, token, sleeping ? 1 : 0);
        }

        public final void scheduleReceiver(Intent intent, ActivityInfo info,
                CompatibilityInfo compatInfo, int resultCode, String data, Bundle extras,
                boolean sync, int sendingUser, int processState) {
            updateProcessState(processState, false);
            ReceiverData r = new ReceiverData(intent, resultCode, data, extras,
                    sync, false, mAppThread.asBinder(), sendingUser);
            r.info = info;
            r.compatInfo = compatInfo;
            sendMessage(H.RECEIVER, r);
        }

        public final void scheduleCreateBackupAgent(ApplicationInfo app,
                CompatibilityInfo compatInfo, int backupMode, int userId) {
            CreateBackupAgentData d = new CreateBackupAgentData();
            d.appInfo = app;
            d.compatInfo = compatInfo;
            d.backupMode = backupMode;
            d.userId = userId;

            sendMessage(H.CREATE_BACKUP_AGENT, d);
        }

        public final void scheduleDestroyBackupAgent(ApplicationInfo app,
                CompatibilityInfo compatInfo, int userId) {
            CreateBackupAgentData d = new CreateBackupAgentData();
            d.appInfo = app;
            d.compatInfo = compatInfo;
            d.userId = userId;

            sendMessage(H.DESTROY_BACKUP_AGENT, d);
        }

        public final void scheduleCreateService(IBinder token,
                ServiceInfo info, CompatibilityInfo compatInfo, int processState) {
            updateProcessState(processState, false);
            CreateServiceData s = new CreateServiceData();
            s.token = token;
            s.info = info;
            s.compatInfo = compatInfo;

            sendMessage(H.CREATE_SERVICE, s);
        }

        public final void scheduleBindService(IBinder token, Intent intent,
                boolean rebind, int processState) {
            updateProcessState(processState, false);
            BindServiceData s = new BindServiceData();
            s.token = token;
            s.intent = intent;
            s.rebind = rebind;

            if (DEBUG_SERVICE)
                Slog.v(TAG, "scheduleBindService token=" + token + " intent=" + intent + " uid="
                        + Binder.getCallingUid() + " pid=" + Binder.getCallingPid());
            sendMessage(H.BIND_SERVICE, s);
        }

        public final void scheduleUnbindService(IBinder token, Intent intent) {
            BindServiceData s = new BindServiceData();
            s.token = token;
            s.intent = intent;

            sendMessage(H.UNBIND_SERVICE, s);
        }

        public final void scheduleServiceArgs(IBinder token, ParceledListSlice args) {
            List<ServiceStartArgs> list = args.getList();

            for (int i = 0; i < list.size(); i++) {
                ServiceStartArgs ssa = list.get(i);
                ServiceArgsData s = new ServiceArgsData();
                s.token = token;
                s.taskRemoved = ssa.taskRemoved;
                s.startId = ssa.startId;
                s.flags = ssa.flags;
                s.args = ssa.args;

                sendMessage(H.SERVICE_ARGS, s);
            }
        }

        public final void scheduleStopService(IBinder token) {
            sendMessage(H.STOP_SERVICE, token);
        }

        public final void bindApplication(String processName, ApplicationInfo appInfo,
                List<ProviderInfo> providers, ComponentName instrumentationName,
                ProfilerInfo profilerInfo, Bundle instrumentationArgs,
                IInstrumentationWatcher instrumentationWatcher,
                IUiAutomationConnection instrumentationUiConnection, int debugMode,
                boolean enableBinderTracking, boolean trackAllocation,
                boolean isRestrictedBackupMode, boolean persistent, Configuration config,
                CompatibilityInfo compatInfo, Map services, Bundle coreSettings,
                String buildSerial, AutofillOptions autofillOptions,
                ContentCaptureOptions contentCaptureOptions) {
            if (services != null) {
                if (false) {
                    // Test code to make sure the app could see the passed-in services.
                    for (Object oname : services.keySet()) {
                        if (services.get(oname) == null) {
                            continue; // AM just passed in a null service.
                        }
                        String name = (String) oname;

                        // See b/79378449 about the following exemption.
                        switch (name) {
                            case "package":
                            case Context.WINDOW_SERVICE:
                                continue;
                        }

                        if (ServiceManager.getService(name) == null) {
                            Log.wtf(TAG, "Service " + name + " should be accessible by this app");
                        }
                    }
                }

                // Setup the service cache in the ServiceManager
                ServiceManager.initServiceCache(services);
            }

            setCoreSettings(coreSettings);

            AppBindData data = new AppBindData();
            data.processName = processName;
            data.appInfo = appInfo;
            data.providers = providers;
            data.instrumentationName = instrumentationName;
            data.instrumentationArgs = instrumentationArgs;
            data.instrumentationWatcher = instrumentationWatcher;
            data.instrumentationUiAutomationConnection = instrumentationUiConnection;
            data.debugMode = debugMode;
            data.enableBinderTracking = enableBinderTracking;
            data.trackAllocation = trackAllocation;
            data.restrictedBackupMode = isRestrictedBackupMode;
            data.persistent = persistent;
            data.config = config;
            data.compatInfo = compatInfo;
            data.initProfilerInfo = profilerInfo;
            data.buildSerial = buildSerial;
            data.autofillOptions = autofillOptions;
            data.contentCaptureOptions = contentCaptureOptions;
            sendMessage(H.BIND_APPLICATION, data);
        }

        public final void runIsolatedEntryPoint(String entryPoint, String[] entryPointArgs) {
            SomeArgs args = SomeArgs.obtain();
            args.arg1 = entryPoint;
            args.arg2 = entryPointArgs;
            sendMessage(H.RUN_ISOLATED_ENTRY_POINT, args);
        }

        public final void scheduleExit() {
            sendMessage(H.EXIT_APPLICATION, null);
        }

        public final void scheduleSuicide() {
            sendMessage(H.SUICIDE, null);
        }

        public void scheduleApplicationInfoChanged(ApplicationInfo ai) {
            mH.removeMessages(H.APPLICATION_INFO_CHANGED, ai);
            sendMessage(H.APPLICATION_INFO_CHANGED, ai);
        }

        public void updateTimeZone() {
            TimeZone.setDefault(null);
        }

        public void clearDnsCache() {
            // a non-standard API to get this to libcore
            InetAddress.clearDnsCache();
            // Allow libcore to perform the necessary actions as it sees fit upon a network
            // configuration change.
            NetworkEventDispatcher.getInstance().onNetworkConfigurationChanged();
        }

        public void updateHttpProxy() {
            ActivityThread.updateHttpProxy(
                    getApplication() != null ? getApplication() : getSystemContext());
        }

        public void processInBackground() {
            mH.removeMessages(H.GC_WHEN_IDLE);
            mH.sendMessage(mH.obtainMessage(H.GC_WHEN_IDLE));
        }

        public void dumpService(ParcelFileDescriptor pfd, IBinder servicetoken, String[] args) {
            DumpComponentInfo data = new DumpComponentInfo();
            try {
                data.fd = pfd.dup();
                data.token = servicetoken;
                data.args = args;
                sendMessage(H.DUMP_SERVICE, data, 0, 0, true /*async*/);
            } catch (IOException e) {
                Slog.w(TAG, "dumpService failed", e);
            } finally {
                IoUtils.closeQuietly(pfd);
            }
        }

        // This function exists to make sure all receiver dispatching is
        // correctly ordered, since these are one-way calls and the binder driver
        // applies transaction ordering per object for such calls.
        public void scheduleRegisteredReceiver(IIntentReceiver receiver, Intent intent,
                int resultCode, String dataStr, Bundle extras, boolean ordered,
                boolean sticky, int sendingUser, int processState) throws RemoteException {
            updateProcessState(processState, false);
            receiver.performReceive(intent, resultCode, dataStr, extras, ordered,
                    sticky, sendingUser);
        }

        @Override
        public void scheduleLowMemory() {
            sendMessage(H.LOW_MEMORY, null);
        }

        @Override
        public void profilerControl(boolean start, ProfilerInfo profilerInfo, int profileType) {
            sendMessage(H.PROFILER_CONTROL, profilerInfo, start ? 1 : 0, profileType);
        }

        @Override
        public void dumpHeap(boolean managed, boolean mallocInfo, boolean runGc, String path,
                ParcelFileDescriptor fd, RemoteCallback finishCallback) {
            DumpHeapData dhd = new DumpHeapData();
            dhd.managed = managed;
            dhd.mallocInfo = mallocInfo;
            dhd.runGc = runGc;
            dhd.path = path;
            try {
                // Since we're going to dump the heap asynchronously, dup the file descriptor before
                // it's closed on returning from the IPC call.
                dhd.fd = fd.dup();
            } catch (IOException e) {
                Slog.e(TAG, "Failed to duplicate heap dump file descriptor", e);
                return;
            }
            dhd.finishCallback = finishCallback;
            sendMessage(H.DUMP_HEAP, dhd, 0, 0, true /*async*/);
        }

        public void attachAgent(String agent) {
            sendMessage(H.ATTACH_AGENT, agent);
        }

        public void setSchedulingGroup(int group) {
            // Note: do this immediately, since going into the foreground
            // should happen regardless of what pending work we have to do
            // and the activity manager will wait for us to report back that
            // we are done before sending us to the background.
            try {
                Process.setProcessGroup(Process.myPid(), group);
            } catch (Exception e) {
                Slog.w(TAG, "Failed setting process group to " + group, e);
            }
        }

        public void dispatchPackageBroadcast(int cmd, String[] packages) {
            sendMessage(H.DISPATCH_PACKAGE_BROADCAST, packages, cmd);
        }

        public void scheduleCrash(String msg) {
            sendMessage(H.SCHEDULE_CRASH, msg);
        }

        public void dumpActivity(ParcelFileDescriptor pfd, IBinder activitytoken,
                String prefix, String[] args) {
            DumpComponentInfo data = new DumpComponentInfo();
            try {
                data.fd = pfd.dup();
                data.token = activitytoken;
                data.prefix = prefix;
                data.args = args;
                sendMessage(H.DUMP_ACTIVITY, data, 0, 0, true /*async*/);
            } catch (IOException e) {
                Slog.w(TAG, "dumpActivity failed", e);
            } finally {
                IoUtils.closeQuietly(pfd);
            }
        }

        public void dumpProvider(ParcelFileDescriptor pfd, IBinder providertoken,
                String[] args) {
            DumpComponentInfo data = new DumpComponentInfo();
            try {
                data.fd = pfd.dup();
                data.token = providertoken;
                data.args = args;
                sendMessage(H.DUMP_PROVIDER, data, 0, 0, true /*async*/);
            } catch (IOException e) {
                Slog.w(TAG, "dumpProvider failed", e);
            } finally {
                IoUtils.closeQuietly(pfd);
            }
        }

        @Override
        public void dumpMemInfo(ParcelFileDescriptor pfd, Debug.MemoryInfo mem, boolean checkin,
                boolean dumpFullInfo, boolean dumpDalvik, boolean dumpSummaryOnly,
                boolean dumpUnreachable, String[] args) {
            FileOutputStream fout = new FileOutputStream(pfd.getFileDescriptor());
            PrintWriter pw = new FastPrintWriter(fout);
            try {
                dumpMemInfo(pw, mem, checkin, dumpFullInfo, dumpDalvik, dumpSummaryOnly, dumpUnreachable);
            } finally {
                pw.flush();
                IoUtils.closeQuietly(pfd);
            }
        }

        private void dumpMemInfo(PrintWriter pw, Debug.MemoryInfo memInfo, boolean checkin,
                boolean dumpFullInfo, boolean dumpDalvik, boolean dumpSummaryOnly, boolean dumpUnreachable) {
            long nativeMax = Debug.getNativeHeapSize() / 1024;
            long nativeAllocated = Debug.getNativeHeapAllocatedSize() / 1024;
            long nativeFree = Debug.getNativeHeapFreeSize() / 1024;

            Runtime runtime = Runtime.getRuntime();
            runtime.gc();  // Do GC since countInstancesOfClass counts unreachable objects.
            long dalvikMax = runtime.totalMemory() / 1024;
            long dalvikFree = runtime.freeMemory() / 1024;
            long dalvikAllocated = dalvikMax - dalvikFree;

            Class[] classesToCount = new Class[] {
                    ContextImpl.class,
                    Activity.class,
                    WebView.class,
                    OpenSSLSocketImpl.class
            };
            long[] instanceCounts = VMDebug.countInstancesOfClasses(classesToCount, true);
            long appContextInstanceCount = instanceCounts[0];
            long activityInstanceCount = instanceCounts[1];
            long webviewInstanceCount = instanceCounts[2];
            long openSslSocketCount = instanceCounts[3];

            long viewInstanceCount = ViewDebug.getViewInstanceCount();
            long viewRootInstanceCount = ViewDebug.getViewRootImplCount();
            int globalAssetCount = AssetManager.getGlobalAssetCount();
            int globalAssetManagerCount = AssetManager.getGlobalAssetManagerCount();
            int binderLocalObjectCount = Debug.getBinderLocalObjectCount();
            int binderProxyObjectCount = Debug.getBinderProxyObjectCount();
            int binderDeathObjectCount = Debug.getBinderDeathObjectCount();
            long parcelSize = Parcel.getGlobalAllocSize();
            long parcelCount = Parcel.getGlobalAllocCount();
            SQLiteDebug.PagerStats stats = SQLiteDebug.getDatabaseInfo();

            dumpMemInfoTable(pw, memInfo, checkin, dumpFullInfo, dumpDalvik, dumpSummaryOnly,
                    Process.myPid(),
                    (mBoundApplication != null) ? mBoundApplication.processName : "unknown",
                    nativeMax, nativeAllocated, nativeFree,
                    dalvikMax, dalvikAllocated, dalvikFree);

            if (checkin) {
                // NOTE: if you change anything significant below, also consider changing
                // ACTIVITY_THREAD_CHECKIN_VERSION.

                // Object counts
                pw.print(viewInstanceCount); pw.print(',');
                pw.print(viewRootInstanceCount); pw.print(',');
                pw.print(appContextInstanceCount); pw.print(',');
                pw.print(activityInstanceCount); pw.print(',');

                pw.print(globalAssetCount); pw.print(',');
                pw.print(globalAssetManagerCount); pw.print(',');
                pw.print(binderLocalObjectCount); pw.print(',');
                pw.print(binderProxyObjectCount); pw.print(',');

                pw.print(binderDeathObjectCount); pw.print(',');
                pw.print(openSslSocketCount); pw.print(',');

                // SQL
                pw.print(stats.memoryUsed / 1024); pw.print(',');
                pw.print(stats.memoryUsed / 1024); pw.print(',');
                pw.print(stats.pageCacheOverflow / 1024); pw.print(',');
                pw.print(stats.largestMemAlloc / 1024);
                for (int i = 0; i < stats.dbStats.size(); i++) {
                    DbStats dbStats = stats.dbStats.get(i);
                    pw.print(','); pw.print(dbStats.dbName);
                    pw.print(','); pw.print(dbStats.pageSize);
                    pw.print(','); pw.print(dbStats.dbSize);
                    pw.print(','); pw.print(dbStats.lookaside);
                    pw.print(','); pw.print(dbStats.cache);
                    pw.print(','); pw.print(dbStats.cache);
                }
                pw.println();

                return;
            }

            pw.println(" ");
            pw.println(" Objects");
            printRow(pw, TWO_COUNT_COLUMNS, "Views:", viewInstanceCount, "ViewRootImpl:",
                    viewRootInstanceCount);

            printRow(pw, TWO_COUNT_COLUMNS, "AppContexts:", appContextInstanceCount,
                    "Activities:", activityInstanceCount);

            printRow(pw, TWO_COUNT_COLUMNS, "Assets:", globalAssetCount,
                    "AssetManagers:", globalAssetManagerCount);

            printRow(pw, TWO_COUNT_COLUMNS, "Local Binders:", binderLocalObjectCount,
                    "Proxy Binders:", binderProxyObjectCount);
            printRow(pw, TWO_COUNT_COLUMNS, "Parcel memory:", parcelSize/1024,
                    "Parcel count:", parcelCount);
            printRow(pw, TWO_COUNT_COLUMNS, "Death Recipients:", binderDeathObjectCount,
                    "OpenSSL Sockets:", openSslSocketCount);
            printRow(pw, ONE_COUNT_COLUMN, "WebViews:", webviewInstanceCount);

            // SQLite mem info
            pw.println(" ");
            pw.println(" SQL");
            printRow(pw, ONE_COUNT_COLUMN, "MEMORY_USED:", stats.memoryUsed / 1024);
            printRow(pw, TWO_COUNT_COLUMNS, "PAGECACHE_OVERFLOW:",
                    stats.pageCacheOverflow / 1024, "MALLOC_SIZE:", stats.largestMemAlloc / 1024);
            pw.println(" ");
            int N = stats.dbStats.size();
            if (N > 0) {
                pw.println(" DATABASES");
                printRow(pw, DB_INFO_FORMAT, "pgsz", "dbsz", "Lookaside(b)", "cache",
                        "Dbname");
                for (int i = 0; i < N; i++) {
                    DbStats dbStats = stats.dbStats.get(i);
                    printRow(pw, DB_INFO_FORMAT,
                            (dbStats.pageSize > 0) ? String.valueOf(dbStats.pageSize) : " ",
                            (dbStats.dbSize > 0) ? String.valueOf(dbStats.dbSize) : " ",
                            (dbStats.lookaside > 0) ? String.valueOf(dbStats.lookaside) : " ",
                            dbStats.cache, dbStats.dbName);
                }
            }

            // Asset details.
            String assetAlloc = AssetManager.getAssetAllocations();
            if (assetAlloc != null) {
                pw.println(" ");
                pw.println(" Asset Allocations");
                pw.print(assetAlloc);
            }

            // Unreachable native memory
            if (dumpUnreachable) {
                boolean showContents = ((mBoundApplication != null)
                    && ((mBoundApplication.appInfo.flags&ApplicationInfo.FLAG_DEBUGGABLE) != 0))
                    || android.os.Build.IS_ENG;
                pw.println(" ");
                pw.println(" Unreachable memory");
                pw.print(Debug.getUnreachableMemory(100, showContents));
            }
        }

        @Override
        public void dumpMemInfoProto(ParcelFileDescriptor pfd, Debug.MemoryInfo mem,
                boolean dumpFullInfo, boolean dumpDalvik, boolean dumpSummaryOnly,
                boolean dumpUnreachable, String[] args) {
            ProtoOutputStream proto = new ProtoOutputStream(pfd.getFileDescriptor());
            try {
                dumpMemInfo(proto, mem, dumpFullInfo, dumpDalvik, dumpSummaryOnly, dumpUnreachable);
            } finally {
                proto.flush();
                IoUtils.closeQuietly(pfd);
            }
        }

        private void dumpMemInfo(ProtoOutputStream proto, Debug.MemoryInfo memInfo,
                boolean dumpFullInfo, boolean dumpDalvik,
                boolean dumpSummaryOnly, boolean dumpUnreachable) {
            long nativeMax = Debug.getNativeHeapSize() / 1024;
            long nativeAllocated = Debug.getNativeHeapAllocatedSize() / 1024;
            long nativeFree = Debug.getNativeHeapFreeSize() / 1024;

            Runtime runtime = Runtime.getRuntime();
            runtime.gc();  // Do GC since countInstancesOfClass counts unreachable objects.
            long dalvikMax = runtime.totalMemory() / 1024;
            long dalvikFree = runtime.freeMemory() / 1024;
            long dalvikAllocated = dalvikMax - dalvikFree;

            Class[] classesToCount = new Class[] {
                    ContextImpl.class,
                    Activity.class,
                    WebView.class,
                    OpenSSLSocketImpl.class
            };
            long[] instanceCounts = VMDebug.countInstancesOfClasses(classesToCount, true);
            long appContextInstanceCount = instanceCounts[0];
            long activityInstanceCount = instanceCounts[1];
            long webviewInstanceCount = instanceCounts[2];
            long openSslSocketCount = instanceCounts[3];

            long viewInstanceCount = ViewDebug.getViewInstanceCount();
            long viewRootInstanceCount = ViewDebug.getViewRootImplCount();
            int globalAssetCount = AssetManager.getGlobalAssetCount();
            int globalAssetManagerCount = AssetManager.getGlobalAssetManagerCount();
            int binderLocalObjectCount = Debug.getBinderLocalObjectCount();
            int binderProxyObjectCount = Debug.getBinderProxyObjectCount();
            int binderDeathObjectCount = Debug.getBinderDeathObjectCount();
            long parcelSize = Parcel.getGlobalAllocSize();
            long parcelCount = Parcel.getGlobalAllocCount();
            SQLiteDebug.PagerStats stats = SQLiteDebug.getDatabaseInfo();

            final long mToken = proto.start(MemInfoDumpProto.AppData.PROCESS_MEMORY);
            proto.write(MemInfoDumpProto.ProcessMemory.PID, Process.myPid());
            proto.write(MemInfoDumpProto.ProcessMemory.PROCESS_NAME,
                    (mBoundApplication != null) ? mBoundApplication.processName : "unknown");
            dumpMemInfoTable(proto, memInfo, dumpDalvik, dumpSummaryOnly,
                    nativeMax, nativeAllocated, nativeFree,
                    dalvikMax, dalvikAllocated, dalvikFree);
            proto.end(mToken);

            final long oToken = proto.start(MemInfoDumpProto.AppData.OBJECTS);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.VIEW_INSTANCE_COUNT,
                    viewInstanceCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.VIEW_ROOT_INSTANCE_COUNT,
                    viewRootInstanceCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.APP_CONTEXT_INSTANCE_COUNT,
                    appContextInstanceCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.ACTIVITY_INSTANCE_COUNT,
                    activityInstanceCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.GLOBAL_ASSET_COUNT,
                    globalAssetCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.GLOBAL_ASSET_MANAGER_COUNT,
                    globalAssetManagerCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.LOCAL_BINDER_OBJECT_COUNT,
                    binderLocalObjectCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.PROXY_BINDER_OBJECT_COUNT,
                    binderProxyObjectCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.PARCEL_MEMORY_KB,
                    parcelSize / 1024);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.PARCEL_COUNT, parcelCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.BINDER_OBJECT_DEATH_COUNT,
                    binderDeathObjectCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.OPEN_SSL_SOCKET_COUNT,
                    openSslSocketCount);
            proto.write(MemInfoDumpProto.AppData.ObjectStats.WEBVIEW_INSTANCE_COUNT,
                    webviewInstanceCount);
            proto.end(oToken);

            // SQLite mem info
            final long sToken = proto.start(MemInfoDumpProto.AppData.SQL);
            proto.write(MemInfoDumpProto.AppData.SqlStats.MEMORY_USED_KB,
                    stats.memoryUsed / 1024);
            proto.write(MemInfoDumpProto.AppData.SqlStats.PAGECACHE_OVERFLOW_KB,
                    stats.pageCacheOverflow / 1024);
            proto.write(MemInfoDumpProto.AppData.SqlStats.MALLOC_SIZE_KB,
                    stats.largestMemAlloc / 1024);
            int n = stats.dbStats.size();
            for (int i = 0; i < n; i++) {
                DbStats dbStats = stats.dbStats.get(i);

                final long dToken = proto.start(MemInfoDumpProto.AppData.SqlStats.DATABASES);
                proto.write(MemInfoDumpProto.AppData.SqlStats.Database.NAME, dbStats.dbName);
                proto.write(MemInfoDumpProto.AppData.SqlStats.Database.PAGE_SIZE, dbStats.pageSize);
                proto.write(MemInfoDumpProto.AppData.SqlStats.Database.DB_SIZE, dbStats.dbSize);
                proto.write(MemInfoDumpProto.AppData.SqlStats.Database.LOOKASIDE_B,
                        dbStats.lookaside);
                proto.write(MemInfoDumpProto.AppData.SqlStats.Database.CACHE, dbStats.cache);
                proto.end(dToken);
            }
            proto.end(sToken);

            // Asset details.
            String assetAlloc = AssetManager.getAssetAllocations();
            if (assetAlloc != null) {
                proto.write(MemInfoDumpProto.AppData.ASSET_ALLOCATIONS, assetAlloc);
            }

            // Unreachable native memory
            if (dumpUnreachable) {
                int flags = mBoundApplication == null ? 0 : mBoundApplication.appInfo.flags;
                boolean showContents = (flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0
                        || android.os.Build.IS_ENG;
                proto.write(MemInfoDumpProto.AppData.UNREACHABLE_MEMORY,
                        Debug.getUnreachableMemory(100, showContents));
            }
        }

        @Override
        public void dumpGfxInfo(ParcelFileDescriptor pfd, String[] args) {
            nDumpGraphicsInfo(pfd.getFileDescriptor());
            WindowManagerGlobal.getInstance().dumpGfxInfo(pfd.getFileDescriptor(), args);
            IoUtils.closeQuietly(pfd);
        }

        private File getDatabasesDir(Context context) {
            // There's no simple way to get the databases/ path, so do it this way.
            return context.getDatabasePath("a").getParentFile();
        }

        private void dumpDatabaseInfo(ParcelFileDescriptor pfd, String[] args, boolean isSystem) {
            PrintWriter pw = new FastPrintWriter(
                    new FileOutputStream(pfd.getFileDescriptor()));
            PrintWriterPrinter printer = new PrintWriterPrinter(pw);
            SQLiteDebug.dump(printer, args, isSystem);
            pw.flush();
        }

        @Override
        public void dumpDbInfo(final ParcelFileDescriptor pfd, final String[] args) {
            if (mSystemThread) {
                // Ensure this invocation is asynchronous to prevent writer waiting if buffer cannot
                // be consumed. But it must duplicate the file descriptor first, since caller might
                // be closing it.
                final ParcelFileDescriptor dup;
                try {
                    dup = pfd.dup();
                } catch (IOException e) {
                    Log.w(TAG, "Could not dup FD " + pfd.getFileDescriptor().getInt$());
                    return;
                } finally {
                    IoUtils.closeQuietly(pfd);
                }

                AsyncTask.THREAD_POOL_EXECUTOR.execute(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            dumpDatabaseInfo(dup, args, true);
                        } finally {
                            IoUtils.closeQuietly(dup);
                        }
                    }
                });
            } else {
                dumpDatabaseInfo(pfd, args, false);
                IoUtils.closeQuietly(pfd);
            }
        }

        @Override
        public void unstableProviderDied(IBinder provider) {
            sendMessage(H.UNSTABLE_PROVIDER_DIED, provider);
        }

        @Override
        public void requestAssistContextExtras(IBinder activityToken, IBinder requestToken,
                int requestType, int sessionId, int flags) {
            RequestAssistContextExtras cmd = new RequestAssistContextExtras();
            cmd.activityToken = activityToken;
            cmd.requestToken = requestToken;
            cmd.requestType = requestType;
            cmd.sessionId = sessionId;
            cmd.flags = flags;
            sendMessage(H.REQUEST_ASSIST_CONTEXT_EXTRAS, cmd);
        }

        public void setCoreSettings(Bundle coreSettings) {
            sendMessage(H.SET_CORE_SETTINGS, coreSettings);
        }

        public void updatePackageCompatibilityInfo(String pkg, CompatibilityInfo info) {
            UpdateCompatibilityData ucd = new UpdateCompatibilityData();
            ucd.pkg = pkg;
            ucd.info = info;
            sendMessage(H.UPDATE_PACKAGE_COMPATIBILITY_INFO, ucd);
        }

        public void scheduleTrimMemory(int level) {
            final Runnable r = PooledLambda.obtainRunnable(ActivityThread::handleTrimMemory,
                    ActivityThread.this, level).recycleOnUse();
            // Schedule trimming memory after drawing the frame to minimize jank-risk.
            Choreographer choreographer = Choreographer.getMainThreadInstance();
            if (choreographer != null) {
                choreographer.postCallback(Choreographer.CALLBACK_COMMIT, r, null);
            } else {
                mH.post(r);
            }
        }

        public void scheduleTranslucentConversionComplete(IBinder token, boolean drawComplete) {
            sendMessage(H.TRANSLUCENT_CONVERSION_COMPLETE, token, drawComplete ? 1 : 0);
        }

        public void scheduleOnNewActivityOptions(IBinder token, Bundle options) {
            sendMessage(H.ON_NEW_ACTIVITY_OPTIONS,
                    new Pair<IBinder, ActivityOptions>(token, ActivityOptions.fromBundle(options)));
        }

        public void setProcessState(int state) {
            updateProcessState(state, true);
        }

        /**
         * Updates {@link #mNetworkBlockSeq}. This is used by ActivityManagerService to inform
         * the main thread that it needs to wait for the network rules to get updated before
         * launching an activity.
         */
        @Override
        public void setNetworkBlockSeq(long procStateSeq) {
            synchronized (mNetworkPolicyLock) {
                mNetworkBlockSeq = procStateSeq;
            }
        }

        @Override
        public void scheduleInstallProvider(ProviderInfo provider) {
            sendMessage(H.INSTALL_PROVIDER, provider);
        }

        @Override
        public final void updateTimePrefs(int timeFormatPreference) {
            final Boolean timeFormatPreferenceBool;
            // For convenience we are using the Intent extra values.
            if (timeFormatPreference == Intent.EXTRA_TIME_PREF_VALUE_USE_12_HOUR) {
                timeFormatPreferenceBool = Boolean.FALSE;
            } else if (timeFormatPreference == Intent.EXTRA_TIME_PREF_VALUE_USE_24_HOUR) {
                timeFormatPreferenceBool = Boolean.TRUE;
            } else {
                // timeFormatPreference == Intent.EXTRA_TIME_PREF_VALUE_USE_LOCALE_DEFAULT
                // (or unknown).
                timeFormatPreferenceBool = null;
            }
            DateFormat.set24HourTimePref(timeFormatPreferenceBool);
        }

        @Override
        public void scheduleEnterAnimationComplete(IBinder token) {
            sendMessage(H.ENTER_ANIMATION_COMPLETE, token);
        }

        @Override
        public void notifyCleartextNetwork(byte[] firstPacket) {
            if (StrictMode.vmCleartextNetworkEnabled()) {
                StrictMode.onCleartextNetworkDetected(firstPacket);
            }
        }

        @Override
        public void startBinderTracking() {
            sendMessage(H.START_BINDER_TRACKING, null);
        }

        @Override
        public void stopBinderTrackingAndDump(ParcelFileDescriptor pfd) {
            try {
                sendMessage(H.STOP_BINDER_TRACKING_AND_DUMP, pfd.dup());
            } catch (IOException e) {
            } finally {
                IoUtils.closeQuietly(pfd);
            }
        }

        @Override
        public void scheduleLocalVoiceInteractionStarted(IBinder token,
                IVoiceInteractor voiceInteractor) throws RemoteException {
            SomeArgs args = SomeArgs.obtain();
            args.arg1 = token;
            args.arg2 = voiceInteractor;
            sendMessage(H.LOCAL_VOICE_INTERACTION_STARTED, args);
        }

        @Override
        public void handleTrustStorageUpdate() {
            NetworkSecurityPolicy.getInstance().handleTrustStorageUpdate();
        }

        @Override
        public void scheduleTransaction(ClientTransaction transaction) throws RemoteException {
            ActivityThread.this.scheduleTransaction(transaction);
        }

        @Override
        public void requestDirectActions(@NonNull IBinder activityToken,
                @NonNull IVoiceInteractor interactor, @Nullable RemoteCallback cancellationCallback,
                @NonNull RemoteCallback callback) {
            final CancellationSignal cancellationSignal = new CancellationSignal();
            if (cancellationCallback != null) {
                final ICancellationSignal transport = createSafeCancellationTransport(
                        cancellationSignal);
                final Bundle cancellationResult = new Bundle();
                cancellationResult.putBinder(VoiceInteractor.KEY_CANCELLATION_SIGNAL,
                        transport.asBinder());
                cancellationCallback.sendResult(cancellationResult);
            }
            mH.sendMessage(PooledLambda.obtainMessage(ActivityThread::handleRequestDirectActions,
                    ActivityThread.this, activityToken, interactor, cancellationSignal, callback));
        }

        @Override
        public void performDirectAction(@NonNull IBinder activityToken, @NonNull String actionId,
                @Nullable Bundle arguments, @Nullable RemoteCallback cancellationCallback,
                @NonNull RemoteCallback resultCallback) {
            final CancellationSignal cancellationSignal = new CancellationSignal();
            if (cancellationCallback != null) {
                final ICancellationSignal transport = createSafeCancellationTransport(
                        cancellationSignal);
                final Bundle cancellationResult = new Bundle();
                cancellationResult.putBinder(VoiceInteractor.KEY_CANCELLATION_SIGNAL,
                        transport.asBinder());
                cancellationCallback.sendResult(cancellationResult);
            }
            mH.sendMessage(PooledLambda.obtainMessage(ActivityThread::handlePerformDirectAction,
                    ActivityThread.this, activityToken, actionId, arguments,
                    cancellationSignal, resultCallback));
        }
    }

    private @NonNull SafeCancellationTransport createSafeCancellationTransport(
            @NonNull CancellationSignal cancellationSignal) {
        synchronized (ActivityThread.this) {
            if (mRemoteCancellations == null) {
                mRemoteCancellations = new ArrayMap<>();
            }
            final SafeCancellationTransport transport = new SafeCancellationTransport(
                    this, cancellationSignal);
            mRemoteCancellations.put(transport, cancellationSignal);
            return transport;
        }
    }

    private @NonNull CancellationSignal removeSafeCancellationTransport(
            @NonNull SafeCancellationTransport transport) {
        synchronized (ActivityThread.this) {
            final CancellationSignal cancellation = mRemoteCancellations.remove(transport);
            if (mRemoteCancellations.isEmpty()) {
                mRemoteCancellations = null;
            }
            return cancellation;
        }
    }

    private static final class SafeCancellationTransport extends ICancellationSignal.Stub {
        private final @NonNull WeakReference<ActivityThread> mWeakActivityThread;

        SafeCancellationTransport(@NonNull ActivityThread activityThread,
                @NonNull CancellationSignal cancellation) {
            mWeakActivityThread = new WeakReference<>(activityThread);
        }

        @Override
        public void cancel() {
            final ActivityThread activityThread = mWeakActivityThread.get();
            if (activityThread != null) {
                final CancellationSignal cancellation = activityThread
                        .removeSafeCancellationTransport(this);
                if (cancellation != null) {
                    cancellation.cancel();
                }
            }
        }
    }

    class H extends Handler {
        public static final int BIND_APPLICATION        = 110;
        @UnsupportedAppUsage
        public static final int EXIT_APPLICATION        = 111;
        @UnsupportedAppUsage
        public static final int RECEIVER                = 113;
        @UnsupportedAppUsage
        public static final int CREATE_SERVICE          = 114;
        @UnsupportedAppUsage
        public static final int SERVICE_ARGS            = 115;
        @UnsupportedAppUsage
        public static final int STOP_SERVICE            = 116;

        public static final int CONFIGURATION_CHANGED   = 118;
        public static final int CLEAN_UP_CONTEXT        = 119;
        @UnsupportedAppUsage
        public static final int GC_WHEN_IDLE            = 120;
        @UnsupportedAppUsage
        public static final int BIND_SERVICE            = 121;
        @UnsupportedAppUsage
        public static final int UNBIND_SERVICE          = 122;
        public static final int DUMP_SERVICE            = 123;
        public static final int LOW_MEMORY              = 124;
        public static final int PROFILER_CONTROL        = 127;
        public static final int CREATE_BACKUP_AGENT     = 128;
        public static final int DESTROY_BACKUP_AGENT    = 129;
        public static final int SUICIDE                 = 130;
        @UnsupportedAppUsage
        public static final int REMOVE_PROVIDER         = 131;
        public static final int DISPATCH_PACKAGE_BROADCAST = 133;
        @UnsupportedAppUsage
        public static final int SCHEDULE_CRASH          = 134;
        public static final int DUMP_HEAP               = 135;
        public static final int DUMP_ACTIVITY           = 136;
        public static final int SLEEPING                = 137;
        public static final int SET_CORE_SETTINGS       = 138;
        public static final int UPDATE_PACKAGE_COMPATIBILITY_INFO = 139;
        @UnsupportedAppUsage
        public static final int DUMP_PROVIDER           = 141;
        public static final int UNSTABLE_PROVIDER_DIED  = 142;
        public static final int REQUEST_ASSIST_CONTEXT_EXTRAS = 143;
        public static final int TRANSLUCENT_CONVERSION_COMPLETE = 144;
        @UnsupportedAppUsage
        public static final int INSTALL_PROVIDER        = 145;
        public static final int ON_NEW_ACTIVITY_OPTIONS = 146;
        @UnsupportedAppUsage
        public static final int ENTER_ANIMATION_COMPLETE = 149;
        public static final int START_BINDER_TRACKING = 150;
        public static final int STOP_BINDER_TRACKING_AND_DUMP = 151;
        public static final int LOCAL_VOICE_INTERACTION_STARTED = 154;
        public static final int ATTACH_AGENT = 155;
        public static final int APPLICATION_INFO_CHANGED = 156;
        public static final int RUN_ISOLATED_ENTRY_POINT = 158;
        public static final int EXECUTE_TRANSACTION = 159;
        public static final int RELAUNCH_ACTIVITY = 160;
        public static final int PURGE_RESOURCES = 161;

        String codeToString(int code) {
            if (DEBUG_MESSAGES) {
                switch (code) {
                    case BIND_APPLICATION: return "BIND_APPLICATION";
                    case EXIT_APPLICATION: return "EXIT_APPLICATION";
                    case RECEIVER: return "RECEIVER";
                    case CREATE_SERVICE: return "CREATE_SERVICE";
                    case SERVICE_ARGS: return "SERVICE_ARGS";
                    case STOP_SERVICE: return "STOP_SERVICE";
                    case CONFIGURATION_CHANGED: return "CONFIGURATION_CHANGED";
                    case CLEAN_UP_CONTEXT: return "CLEAN_UP_CONTEXT";
                    case GC_WHEN_IDLE: return "GC_WHEN_IDLE";
                    case BIND_SERVICE: return "BIND_SERVICE";
                    case UNBIND_SERVICE: return "UNBIND_SERVICE";
                    case DUMP_SERVICE: return "DUMP_SERVICE";
                    case LOW_MEMORY: return "LOW_MEMORY";
                    case PROFILER_CONTROL: return "PROFILER_CONTROL";
                    case CREATE_BACKUP_AGENT: return "CREATE_BACKUP_AGENT";
                    case DESTROY_BACKUP_AGENT: return "DESTROY_BACKUP_AGENT";
                    case SUICIDE: return "SUICIDE";
                    case REMOVE_PROVIDER: return "REMOVE_PROVIDER";
                    case DISPATCH_PACKAGE_BROADCAST: return "DISPATCH_PACKAGE_BROADCAST";
                    case SCHEDULE_CRASH: return "SCHEDULE_CRASH";
                    case DUMP_HEAP: return "DUMP_HEAP";
                    case DUMP_ACTIVITY: return "DUMP_ACTIVITY";
                    case SLEEPING: return "SLEEPING";
                    case SET_CORE_SETTINGS: return "SET_CORE_SETTINGS";
                    case UPDATE_PACKAGE_COMPATIBILITY_INFO: return "UPDATE_PACKAGE_COMPATIBILITY_INFO";
                    case DUMP_PROVIDER: return "DUMP_PROVIDER";
                    case UNSTABLE_PROVIDER_DIED: return "UNSTABLE_PROVIDER_DIED";
                    case REQUEST_ASSIST_CONTEXT_EXTRAS: return "REQUEST_ASSIST_CONTEXT_EXTRAS";
                    case TRANSLUCENT_CONVERSION_COMPLETE: return "TRANSLUCENT_CONVERSION_COMPLETE";
                    case INSTALL_PROVIDER: return "INSTALL_PROVIDER";
                    case ON_NEW_ACTIVITY_OPTIONS: return "ON_NEW_ACTIVITY_OPTIONS";
                    case ENTER_ANIMATION_COMPLETE: return "ENTER_ANIMATION_COMPLETE";
                    case LOCAL_VOICE_INTERACTION_STARTED: return "LOCAL_VOICE_INTERACTION_STARTED";
                    case ATTACH_AGENT: return "ATTACH_AGENT";
                    case APPLICATION_INFO_CHANGED: return "APPLICATION_INFO_CHANGED";
                    case RUN_ISOLATED_ENTRY_POINT: return "RUN_ISOLATED_ENTRY_POINT";
                    case EXECUTE_TRANSACTION: return "EXECUTE_TRANSACTION";
                    case RELAUNCH_ACTIVITY: return "RELAUNCH_ACTIVITY";
                    case PURGE_RESOURCES: return "PURGE_RESOURCES";
                }
            }
            return Integer.toString(code);
        }
        public void handleMessage(Message msg) {
            if (DEBUG_MESSAGES) Slog.v(TAG, ">>> handling: " + codeToString(msg.what));
            switch (msg.what) {
                case BIND_APPLICATION:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "bindApplication");
                    AppBindData data = (AppBindData)msg.obj;
                    handleBindApplication(data);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case EXIT_APPLICATION:
                    if (mInitialApplication != null) {
                        mInitialApplication.onTerminate();
                    }
                    Looper.myLooper().quit();
                    break;
                case RECEIVER:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "broadcastReceiveComp");
                    handleReceiver((ReceiverData)msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case CREATE_SERVICE:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, ("serviceCreate: " + String.valueOf(msg.obj)));
                    handleCreateService((CreateServiceData)msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case BIND_SERVICE:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "serviceBind");
                    handleBindService((BindServiceData)msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case UNBIND_SERVICE:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "serviceUnbind");
                    handleUnbindService((BindServiceData)msg.obj);
                    schedulePurgeIdler();
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case SERVICE_ARGS:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, ("serviceStart: " + String.valueOf(msg.obj)));
                    handleServiceArgs((ServiceArgsData)msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case STOP_SERVICE:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "serviceStop");
                    handleStopService((IBinder)msg.obj);
                    schedulePurgeIdler();
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case CONFIGURATION_CHANGED:
                    handleConfigurationChanged((Configuration) msg.obj);
                    break;
                case CLEAN_UP_CONTEXT:
                    ContextCleanupInfo cci = (ContextCleanupInfo)msg.obj;
                    cci.context.performFinalCleanup(cci.who, cci.what);
                    break;
                case GC_WHEN_IDLE:
                    scheduleGcIdler();
                    break;
                case DUMP_SERVICE:
                    handleDumpService((DumpComponentInfo)msg.obj);
                    break;
                case LOW_MEMORY:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "lowMemory");
                    handleLowMemory();
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case PROFILER_CONTROL:
                    handleProfilerControl(msg.arg1 != 0, (ProfilerInfo)msg.obj, msg.arg2);
                    break;
                case CREATE_BACKUP_AGENT:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "backupCreateAgent");
                    handleCreateBackupAgent((CreateBackupAgentData)msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case DESTROY_BACKUP_AGENT:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "backupDestroyAgent");
                    handleDestroyBackupAgent((CreateBackupAgentData)msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case SUICIDE:
                    Process.killProcess(Process.myPid());
                    break;
                case REMOVE_PROVIDER:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "providerRemove");
                    completeRemoveProvider((ProviderRefCount)msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case DISPATCH_PACKAGE_BROADCAST:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "broadcastPackage");
                    handleDispatchPackageBroadcast(msg.arg1, (String[])msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case SCHEDULE_CRASH:
                    throw new RemoteServiceException((String)msg.obj);
                case DUMP_HEAP:
                    handleDumpHeap((DumpHeapData) msg.obj);
                    break;
                case DUMP_ACTIVITY:
                    handleDumpActivity((DumpComponentInfo)msg.obj);
                    break;
                case DUMP_PROVIDER:
                    handleDumpProvider((DumpComponentInfo)msg.obj);
                    break;
                case SLEEPING:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "sleeping");
                    handleSleeping((IBinder)msg.obj, msg.arg1 != 0);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case SET_CORE_SETTINGS:
                    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "setCoreSettings");
                    handleSetCoreSettings((Bundle) msg.obj);
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    break;
                case UPDATE_PACKAGE_COMPATIBILITY_INFO:
                    handleUpdatePackageCompatibilityInfo((UpdateCompatibilityData)msg.obj);
                    break;
                case UNSTABLE_PROVIDER_DIED:
                    handleUnstableProviderDied((IBinder)msg.obj, false);
                    break;
                case REQUEST_ASSIST_CONTEXT_EXTRAS:
                    handleRequestAssistContextExtras((RequestAssistContextExtras)msg.obj);
                    break;
                case TRANSLUCENT_CONVERSION_COMPLETE:
                    handleTranslucentConversionComplete((IBinder)msg.obj, msg.arg1 == 1);
                    break;
                case INSTALL_PROVIDER:
                    handleInstallProvider((ProviderInfo) msg.obj);
                    break;
                case ON_NEW_ACTIVITY_OPTIONS:
                    Pair<IBinder, ActivityOptions> pair = (Pair<IBinder, ActivityOptions>) msg.obj;
                    onNewActivityOptions(pair.first, pair.second);
                    break;
                case ENTER_ANIMATION_COMPLETE:
                    handleEnterAnimationComplete((IBinder) msg.obj);
                    break;
                case START_BINDER_TRACKING:
                    handleStartBinderTracking();
                    break;
                case STOP_BINDER_TRACKING_AND_DUMP:
                    handleStopBinderTrackingAndDump((ParcelFileDescriptor) msg.obj);
                    break;
                case LOCAL_VOICE_INTERACTION_STARTED:
                    handleLocalVoiceInteractionStarted((IBinder) ((SomeArgs) msg.obj).arg1,
                            (IVoiceInteractor) ((SomeArgs) msg.obj).arg2);
                    break;
                case ATTACH_AGENT: {
                    Application app = getApplication();
                    handleAttachAgent((String) msg.obj, app != null ? app.mLoadedApk : null);
                    break;
                }
                case APPLICATION_INFO_CHANGED:
                    mUpdatingSystemConfig = true;
                    try {
                        handleApplicationInfoChanged((ApplicationInfo) msg.obj);
                    } finally {
                        mUpdatingSystemConfig = false;
                    }
                    break;
                case RUN_ISOLATED_ENTRY_POINT:
                    handleRunIsolatedEntryPoint((String) ((SomeArgs) msg.obj).arg1,
                            (String[]) ((SomeArgs) msg.obj).arg2);
                    break;
                case EXECUTE_TRANSACTION:
                    final ClientTransaction transaction = (ClientTransaction) msg.obj;
                    mTransactionExecutor.execute(transaction);
                    if (isSystem()) {
                        // Client transactions inside system process are recycled on the client side
                        // instead of ClientLifecycleManager to avoid being cleared before this
                        // message is handled.
                        transaction.recycle();
                    }
                    // TODO(lifecycler): Recycle locally scheduled transactions.
                    break;
                case RELAUNCH_ACTIVITY:
                    handleRelaunchActivityLocally((IBinder) msg.obj);
                    break;
                case PURGE_RESOURCES:
                    schedulePurgeIdler();
                    break;
            }
            Object obj = msg.obj;
            if (obj instanceof SomeArgs) {
                ((SomeArgs) obj).recycle();
            }
            if (DEBUG_MESSAGES) Slog.v(TAG, "<<< done: " + codeToString(msg.what));
        }
    }

    private class Idler implements MessageQueue.IdleHandler {
        @Override
        public final boolean queueIdle() {
            ActivityClientRecord a = mNewActivities;
            boolean stopProfiling = false;
            if (mBoundApplication != null && mProfiler.profileFd != null
                    && mProfiler.autoStopProfiler) {
                stopProfiling = true;
            }
            if (a != null) {
                mNewActivities = null;
                IActivityTaskManager am = ActivityTaskManager.getService();
                ActivityClientRecord prev;
                do {
                    if (localLOGV) Slog.v(
                        TAG, "Reporting idle of " + a +
                        " finished=" +
                        (a.activity != null && a.activity.mFinished));
                    if (a.activity != null && !a.activity.mFinished) {
                        try {
                            am.activityIdle(a.token, a.createdConfig, stopProfiling);
                            a.createdConfig = null;
                        } catch (RemoteException ex) {
                            throw ex.rethrowFromSystemServer();
                        }
                    }
                    prev = a;
                    a = a.nextIdle;
                    prev.nextIdle = null;
                } while (a != null);
            }
            if (stopProfiling) {
                mProfiler.stopProfiling();
            }
            applyPendingProcessState();
            return false;
        }
    }

    final class GcIdler implements MessageQueue.IdleHandler {
        @Override
        public final boolean queueIdle() {
            doGcIfNeeded();
            purgePendingResources();
            return false;
        }
    }

    final class PurgeIdler implements MessageQueue.IdleHandler {
        @Override
        public boolean queueIdle() {
            purgePendingResources();
            return false;
        }
    }

    @UnsupportedAppUsage
    public static ActivityThread currentActivityThread() {
        return sCurrentActivityThread;
    }

    public static boolean isSystem() {
        return (sCurrentActivityThread != null) ? sCurrentActivityThread.mSystemThread : false;
    }

    public static String currentOpPackageName() {
        ActivityThread am = currentActivityThread();
        return (am != null && am.getApplication() != null)
                ? am.getApplication().getOpPackageName() : null;
    }

    @UnsupportedAppUsage
    public static String currentPackageName() {
        ActivityThread am = currentActivityThread();
        return (am != null && am.mBoundApplication != null)
            ? am.mBoundApplication.appInfo.packageName : null;
    }

    @UnsupportedAppUsage
    public static String currentProcessName() {
        ActivityThread am = currentActivityThread();
        return (am != null && am.mBoundApplication != null)
            ? am.mBoundApplication.processName : null;
    }

    @UnsupportedAppUsage
    public static Application currentApplication() {
        ActivityThread am = currentActivityThread();
        return am != null ? am.mInitialApplication : null;
    }

    @UnsupportedAppUsage
    public static IPackageManager getPackageManager() {
        if (sPackageManager != null) {
            //Slog.v("PackageManager", "returning cur default = " + sPackageManager);
            return sPackageManager;
        }
        IBinder b = ServiceManager.getService("package");
        //Slog.v("PackageManager", "default service binder = " + b);
        sPackageManager = IPackageManager.Stub.asInterface(b);
        //Slog.v("PackageManager", "default service = " + sPackageManager);
        return sPackageManager;
    }

    private Configuration mMainThreadConfig = new Configuration();

    Configuration applyConfigCompatMainThread(int displayDensity, Configuration config,
            CompatibilityInfo compat) {
        if (config == null) {
            return null;
        }
        if (!compat.supportsScreen()) {
            mMainThreadConfig.setTo(config);
            config = mMainThreadConfig;
            compat.applyToConfiguration(displayDensity, config);
        }
        return config;
    }

    /**
     * Creates the top level resources for the given package. Will return an existing
     * Resources if one has already been created.
     */
    Resources getTopLevelResources(String resDir, String[] splitResDirs, String[] overlayDirs,
            String[] libDirs, int displayId, LoadedApk pkgInfo) {
        return mResourcesManager.getResources(null, resDir, splitResDirs, overlayDirs, libDirs,
                displayId, null, pkgInfo.getCompatibilityInfo(), pkgInfo.getClassLoader());
    }

    @UnsupportedAppUsage
    final Handler getHandler() {
        return mH;
    }

    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    public final LoadedApk getPackageInfo(String packageName, CompatibilityInfo compatInfo,
            int flags) {
        return getPackageInfo(packageName, compatInfo, flags, UserHandle.myUserId());
    }

    public final LoadedApk getPackageInfo(String packageName, CompatibilityInfo compatInfo,
            int flags, int userId) {
        final boolean differentUser = (UserHandle.myUserId() != userId);
        ApplicationInfo ai;
        try {
            ai = getPackageManager().getApplicationInfo(packageName,
                    PackageManager.GET_SHARED_LIBRARY_FILES
                            | PackageManager.MATCH_DEBUG_TRIAGED_MISSING,
                    (userId < 0) ? UserHandle.myUserId() : userId);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }

        synchronized (mResourcesManager) {
            WeakReference<LoadedApk> ref;
            if (differentUser) {
                // Caching not supported across users
                ref = null;
            } else if ((flags & Context.CONTEXT_INCLUDE_CODE) != 0) {
                ref = mPackages.get(packageName);
            } else {
                ref = mResourcePackages.get(packageName);
            }

            LoadedApk packageInfo = ref != null ? ref.get() : null;
            if (ai != null && packageInfo != null) {
                if (!isLoadedApkResourceDirsUpToDate(packageInfo, ai)) {
                    packageInfo.updateApplicationInfo(ai, null);
                }

                if (packageInfo.isSecurityViolation()
                        && (flags&Context.CONTEXT_IGNORE_SECURITY) == 0) {
                    throw new SecurityException(
                            "Requesting code from " + packageName
                            + " to be run in process "
                            + mBoundApplication.processName
                            + "/" + mBoundApplication.appInfo.uid);
                }
                return packageInfo;
            }
        }

        if (ai != null) {
            return getPackageInfo(ai, compatInfo, flags);
        }

        return null;
    }

    @UnsupportedAppUsage
    public final LoadedApk getPackageInfo(ApplicationInfo ai, CompatibilityInfo compatInfo,
            int flags) {
        boolean includeCode = (flags&Context.CONTEXT_INCLUDE_CODE) != 0;
        boolean securityViolation = includeCode && ai.uid != 0
                && ai.uid != Process.SYSTEM_UID && (mBoundApplication != null
                        ? !UserHandle.isSameApp(ai.uid, mBoundApplication.appInfo.uid)
                        : true);
        boolean registerPackage = includeCode && (flags&Context.CONTEXT_REGISTER_PACKAGE) != 0;
        if ((flags&(Context.CONTEXT_INCLUDE_CODE
                |Context.CONTEXT_IGNORE_SECURITY))
                == Context.CONTEXT_INCLUDE_CODE) {
            if (securityViolation) {
                String msg = "Requesting code from " + ai.packageName
                        + " (with uid " + ai.uid + ")";
                if (mBoundApplication != null) {
                    msg = msg + " to be run in process "
                        + mBoundApplication.processName + " (with uid "
                        + mBoundApplication.appInfo.uid + ")";
                }
                throw new SecurityException(msg);
            }
        }
        return getPackageInfo(ai, compatInfo, null, securityViolation, includeCode,
                registerPackage);
    }

    @Override
    @UnsupportedAppUsage
    public final LoadedApk getPackageInfoNoCheck(ApplicationInfo ai,
            CompatibilityInfo compatInfo) {
        return getPackageInfo(ai, compatInfo, null, false, true, false);
    }

    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    public final LoadedApk peekPackageInfo(String packageName, boolean includeCode) {
        synchronized (mResourcesManager) {
            WeakReference<LoadedApk> ref;
            if (includeCode) {
                ref = mPackages.get(packageName);
            } else {
                ref = mResourcePackages.get(packageName);
            }
            return ref != null ? ref.get() : null;
        }
    }

    private LoadedApk getPackageInfo(ApplicationInfo aInfo, CompatibilityInfo compatInfo,
            ClassLoader baseLoader, boolean securityViolation, boolean includeCode,
            boolean registerPackage) {
        final boolean differentUser = (UserHandle.myUserId() != UserHandle.getUserId(aInfo.uid));
        synchronized (mResourcesManager) {
            WeakReference<LoadedApk> ref;
            if (differentUser) {
                // Caching not supported across users
                ref = null;
            } else if (includeCode) {
                ref = mPackages.get(aInfo.packageName);
            } else {
                ref = mResourcePackages.get(aInfo.packageName);
            }

            LoadedApk packageInfo = ref != null ? ref.get() : null;

            if (packageInfo != null) {
                if (!isLoadedApkResourceDirsUpToDate(packageInfo, aInfo)) {
                    packageInfo.updateApplicationInfo(aInfo, null);
                }

                return packageInfo;
            }

            if (localLOGV) {
                Slog.v(TAG, (includeCode ? "Loading code package "
                        : "Loading resource-only package ") + aInfo.packageName
                        + " (in " + (mBoundApplication != null
                        ? mBoundApplication.processName : null)
                        + ")");
            }

            packageInfo =
                    new LoadedApk(this, aInfo, compatInfo, baseLoader,
                            securityViolation, includeCode
                            && (aInfo.flags & ApplicationInfo.FLAG_HAS_CODE) != 0, registerPackage);

            if (mSystemThread && "android".equals(aInfo.packageName)) {
                packageInfo.installSystemApplicationInfo(aInfo,
                        getSystemContext().mPackageInfo.getClassLoader());
            }

            if (differentUser) {
                // Caching not supported across users
            } else if (includeCode) {
                mPackages.put(aInfo.packageName,
                        new WeakReference<LoadedApk>(packageInfo));
            } else {
                mResourcePackages.put(aInfo.packageName,
                        new WeakReference<LoadedApk>(packageInfo));
            }

            return packageInfo;
        }
    }

    private static boolean isLoadedApkResourceDirsUpToDate(LoadedApk loadedApk,
            ApplicationInfo appInfo) {
        Resources packageResources = loadedApk.mResources;
        String[] overlayDirs = ArrayUtils.defeatNullable(loadedApk.getOverlayDirs());
        String[] resourceDirs = ArrayUtils.defeatNullable(appInfo.resourceDirs);

        return (packageResources == null || packageResources.getAssets().isUpToDate())
                && overlayDirs.length == resourceDirs.length
                && ArrayUtils.containsAll(overlayDirs, resourceDirs);
    }

    @UnsupportedAppUsage
    ActivityThread() {
        mResourcesManager = ResourcesManager.getInstance();
    }

    @UnsupportedAppUsage
    public ApplicationThread getApplicationThread()
    {
        return mAppThread;
    }

    @UnsupportedAppUsage
    public Instrumentation getInstrumentation()
    {
        return mInstrumentation;
    }

    public boolean isProfiling() {
        return mProfiler != null && mProfiler.profileFile != null
                && mProfiler.profileFd == null;
    }

    public String getProfileFilePath() {
        return mProfiler.profileFile;
    }

    @UnsupportedAppUsage
    public Looper getLooper() {
        return mLooper;
    }

    public Executor getExecutor() {
        return mExecutor;
    }

    @UnsupportedAppUsage
    public Application getApplication() {
        return mInitialApplication;
    }

    @UnsupportedAppUsage
    public String getProcessName() {
        return mBoundApplication.processName;
    }

    @UnsupportedAppUsage
    public ContextImpl getSystemContext() {
        synchronized (this) {
            if (mSystemContext == null) {
                mSystemContext = ContextImpl.createSystemContext(this);
            }
            return mSystemContext;
        }
    }

    public ContextImpl getSystemUiContext() {
        synchronized (this) {
            if (mSystemUiContext == null) {
                mSystemUiContext = ContextImpl.createSystemUiContext(getSystemContext());
            }
            return mSystemUiContext;
        }
    }

    /**
     * Create the context instance base on system resources & display information which used for UI.
     * @param displayId The ID of the display where the UI is shown.
     * @see ContextImpl#createSystemUiContext(ContextImpl, int)
     */
    public ContextImpl createSystemUiContext(int displayId) {
        return ContextImpl.createSystemUiContext(getSystemUiContext(), displayId);
    }

    public void installSystemApplicationInfo(ApplicationInfo info, ClassLoader classLoader) {
        synchronized (this) {
            getSystemContext().installSystemApplicationInfo(info, classLoader);
            getSystemUiContext().installSystemApplicationInfo(info, classLoader);

            // give ourselves a default profiler
            mProfiler = new Profiler();
        }
    }

    @UnsupportedAppUsage
    void scheduleGcIdler() {
        if (!mGcIdlerScheduled) {
            mGcIdlerScheduled = true;
            Looper.myQueue().addIdleHandler(mGcIdler);
        }
        mH.removeMessages(H.GC_WHEN_IDLE);
    }

    void unscheduleGcIdler() {
        if (mGcIdlerScheduled) {
            mGcIdlerScheduled = false;
            Looper.myQueue().removeIdleHandler(mGcIdler);
        }
        mH.removeMessages(H.GC_WHEN_IDLE);
    }

    void schedulePurgeIdler() {
        if (!mPurgeIdlerScheduled) {
            mPurgeIdlerScheduled = true;
            Looper.myQueue().addIdleHandler(mPurgeIdler);
        }
        mH.removeMessages(H.PURGE_RESOURCES);
    }

    void unschedulePurgeIdler() {
        if (mPurgeIdlerScheduled) {
            mPurgeIdlerScheduled = false;
            Looper.myQueue().removeIdleHandler(mPurgeIdler);
        }
        mH.removeMessages(H.PURGE_RESOURCES);
    }

    void doGcIfNeeded() {
        doGcIfNeeded("bg");
    }

    void doGcIfNeeded(String reason) {
        mGcIdlerScheduled = false;
        final long now = SystemClock.uptimeMillis();
        //Slog.i(TAG, "**** WE MIGHT WANT TO GC: then=" + Binder.getLastGcTime()
        //        + "m now=" + now);
        if ((BinderInternal.getLastGcTime()+MIN_TIME_BETWEEN_GCS) < now) {
            //Slog.i(TAG, "**** WE DO, WE DO WANT TO GC!");
            BinderInternal.forceGc(reason);
        }
    }

    private static final String HEAP_FULL_COLUMN
            = "%13s %8s %8s %8s %8s %8s %8s %8s %8s %8s %8s";
    private static final String HEAP_COLUMN
            = "%13s %8s %8s %8s %8s %8s %8s %8s";
    private static final String ONE_COUNT_COLUMN = "%21s %8d";
    private static final String TWO_COUNT_COLUMNS = "%21s %8d %21s %8d";
    private static final String ONE_COUNT_COLUMN_HEADER = "%21s %8s";

    // Formatting for checkin service - update version if row format changes
    private static final int ACTIVITY_THREAD_CHECKIN_VERSION = 4;

    static void printRow(PrintWriter pw, String format, Object...objs) {
        pw.println(String.format(format, objs));
    }

    public static void dumpMemInfoTable(PrintWriter pw, Debug.MemoryInfo memInfo, boolean checkin,
            boolean dumpFullInfo, boolean dumpDalvik, boolean dumpSummaryOnly,
            int pid, String processName,
            long nativeMax, long nativeAllocated, long nativeFree,
            long dalvikMax, long dalvikAllocated, long dalvikFree) {

        // For checkin, we print one long comma-separated list of values
        if (checkin) {
            // NOTE: if you change anything significant below, also consider changing
            // ACTIVITY_THREAD_CHECKIN_VERSION.

            // Header
            pw.print(ACTIVITY_THREAD_CHECKIN_VERSION); pw.print(',');
            pw.print(pid); pw.print(',');
            pw.print(processName); pw.print(',');

            // Heap info - max
            pw.print(nativeMax); pw.print(',');
            pw.print(dalvikMax); pw.print(',');
            pw.print("N/A,");
            pw.print(nativeMax + dalvikMax); pw.print(',');

            // Heap info - allocated
            pw.print(nativeAllocated); pw.print(',');
            pw.print(dalvikAllocated); pw.print(',');
            pw.print("N/A,");
            pw.print(nativeAllocated + dalvikAllocated); pw.print(',');

            // Heap info - free
            pw.print(nativeFree); pw.print(',');
            pw.print(dalvikFree); pw.print(',');
            pw.print("N/A,");
            pw.print(nativeFree + dalvikFree); pw.print(',');

            // Heap info - proportional set size
            pw.print(memInfo.nativePss); pw.print(',');
            pw.print(memInfo.dalvikPss); pw.print(',');
            pw.print(memInfo.otherPss); pw.print(',');
            pw.print(memInfo.getTotalPss()); pw.print(',');

            // Heap info - swappable set size
            pw.print(memInfo.nativeSwappablePss); pw.print(',');
            pw.print(memInfo.dalvikSwappablePss); pw.print(',');
            pw.print(memInfo.otherSwappablePss); pw.print(',');
            pw.print(memInfo.getTotalSwappablePss()); pw.print(',');

            // Heap info - shared dirty
            pw.print(memInfo.nativeSharedDirty); pw.print(',');
            pw.print(memInfo.dalvikSharedDirty); pw.print(',');
            pw.print(memInfo.otherSharedDirty); pw.print(',');
            pw.print(memInfo.getTotalSharedDirty()); pw.print(',');

            // Heap info - shared clean
            pw.print(memInfo.nativeSharedClean); pw.print(',');
            pw.print(memInfo.dalvikSharedClean); pw.print(',');
            pw.print(memInfo.otherSharedClean); pw.print(',');
            pw.print(memInfo.getTotalSharedClean()); pw.print(',');

            // Heap info - private Dirty
            pw.print(memInfo.nativePrivateDirty); pw.print(',');
            pw.print(memInfo.dalvikPrivateDirty); pw.print(',');
            pw.print(memInfo.otherPrivateDirty); pw.print(',');
            pw.print(memInfo.getTotalPrivateDirty()); pw.print(',');

            // Heap info - private Clean
            pw.print(memInfo.nativePrivateClean); pw.print(',');
            pw.print(memInfo.dalvikPrivateClean); pw.print(',');
            pw.print(memInfo.otherPrivateClean); pw.print(',');
            pw.print(memInfo.getTotalPrivateClean()); pw.print(',');

            // Heap info - swapped out
            pw.print(memInfo.nativeSwappedOut); pw.print(',');
            pw.print(memInfo.dalvikSwappedOut); pw.print(',');
            pw.print(memInfo.otherSwappedOut); pw.print(',');
            pw.print(memInfo.getTotalSwappedOut()); pw.print(',');

            // Heap info - swapped out pss
            if (memInfo.hasSwappedOutPss) {
                pw.print(memInfo.nativeSwappedOutPss); pw.print(',');
                pw.print(memInfo.dalvikSwappedOutPss); pw.print(',');
                pw.print(memInfo.otherSwappedOutPss); pw.print(',');
                pw.print(memInfo.getTotalSwappedOutPss()); pw.print(',');
            } else {
                pw.print("N/A,");
                pw.print("N/A,");
                pw.print("N/A,");
                pw.print("N/A,");
            }

            // Heap info - other areas
            for (int i=0; i<Debug.MemoryInfo.NUM_OTHER_STATS; i++) {
                pw.print(Debug.MemoryInfo.getOtherLabel(i)); pw.print(',');
                pw.print(memInfo.getOtherPss(i)); pw.print(',');
                pw.print(memInfo.getOtherSwappablePss(i)); pw.print(',');
                pw.print(memInfo.getOtherSharedDirty(i)); pw.print(',');
                pw.print(memInfo.getOtherSharedClean(i)); pw.print(',');
                pw.print(memInfo.getOtherPrivateDirty(i)); pw.print(',');
                pw.print(memInfo.getOtherPrivateClean(i)); pw.print(',');
                pw.print(memInfo.getOtherSwappedOut(i)); pw.print(',');
                if (memInfo.hasSwappedOutPss) {
                    pw.print(memInfo.getOtherSwappedOutPss(i)); pw.print(',');
                } else {
                    pw.print("N/A,");
                }
            }
            return;
        }

        if (!dumpSummaryOnly) {
            if (dumpFullInfo) {
                printRow(pw, HEAP_FULL_COLUMN, "", "Pss", "Pss", "Shared", "Private",
                        "Shared", "Private", memInfo.hasSwappedOutPss ? "SwapPss" : "Swap",
                        "Heap", "Heap", "Heap");
                printRow(pw, HEAP_FULL_COLUMN, "", "Total", "Clean", "Dirty", "Dirty",
                        "Clean", "Clean", "Dirty",
                        "Size", "Alloc", "Free");
                printRow(pw, HEAP_FULL_COLUMN, "", "------", "------", "------", "------",
                        "------", "------", "------", "------", "------", "------");
                printRow(pw, HEAP_FULL_COLUMN, "Native Heap", memInfo.nativePss,
                        memInfo.nativeSwappablePss, memInfo.nativeSharedDirty,
                        memInfo.nativePrivateDirty, memInfo.nativeSharedClean,
                        memInfo.nativePrivateClean, memInfo.hasSwappedOutPss ?
                        memInfo.nativeSwappedOutPss : memInfo.nativeSwappedOut,
                        nativeMax, nativeAllocated, nativeFree);
                printRow(pw, HEAP_FULL_COLUMN, "Dalvik Heap", memInfo.dalvikPss,
                        memInfo.dalvikSwappablePss, memInfo.dalvikSharedDirty,
                        memInfo.dalvikPrivateDirty, memInfo.dalvikSharedClean,
                        memInfo.dalvikPrivateClean, memInfo.hasSwappedOutPss ?
                        memInfo.dalvikSwappedOutPss : memInfo.dalvikSwappedOut,
                        dalvikMax, dalvikAllocated, dalvikFree);
            } else {
                printRow(pw, HEAP_COLUMN, "", "Pss", "Private",
                        "Private", memInfo.hasSwappedOutPss ? "SwapPss" : "Swap",
                        "Heap", "Heap", "Heap");
                printRow(pw, HEAP_COLUMN, "", "Total", "Dirty",
                        "Clean", "Dirty", "Size", "Alloc", "Free");
                printRow(pw, HEAP_COLUMN, "", "------", "------", "------",
                        "------", "------", "------", "------", "------");
                printRow(pw, HEAP_COLUMN, "Native Heap", memInfo.nativePss,
                        memInfo.nativePrivateDirty,
                        memInfo.nativePrivateClean,
                        memInfo.hasSwappedOutPss ? memInfo.nativeSwappedOutPss :
                        memInfo.nativeSwappedOut,
                        nativeMax, nativeAllocated, nativeFree);
                printRow(pw, HEAP_COLUMN, "Dalvik Heap", memInfo.dalvikPss,
                        memInfo.dalvikPrivateDirty,
                        memInfo.dalvikPrivateClean,
                        memInfo.hasSwappedOutPss ? memInfo.dalvikSwappedOutPss :
                        memInfo.dalvikSwappedOut,
                        dalvikMax, dalvikAllocated, dalvikFree);
            }

            int otherPss = memInfo.otherPss;
            int otherSwappablePss = memInfo.otherSwappablePss;
            int otherSharedDirty = memInfo.otherSharedDirty;
            int otherPrivateDirty = memInfo.otherPrivateDirty;
            int otherSharedClean = memInfo.otherSharedClean;
            int otherPrivateClean = memInfo.otherPrivateClean;
            int otherSwappedOut = memInfo.otherSwappedOut;
            int otherSwappedOutPss = memInfo.otherSwappedOutPss;

            for (int i=0; i<Debug.MemoryInfo.NUM_OTHER_STATS; i++) {
                final int myPss = memInfo.getOtherPss(i);
                final int mySwappablePss = memInfo.getOtherSwappablePss(i);
                final int mySharedDirty = memInfo.getOtherSharedDirty(i);
                final int myPrivateDirty = memInfo.getOtherPrivateDirty(i);
                final int mySharedClean = memInfo.getOtherSharedClean(i);
                final int myPrivateClean = memInfo.getOtherPrivateClean(i);
                final int mySwappedOut = memInfo.getOtherSwappedOut(i);
                final int mySwappedOutPss = memInfo.getOtherSwappedOutPss(i);
                if (myPss != 0 || mySharedDirty != 0 || myPrivateDirty != 0
                        || mySharedClean != 0 || myPrivateClean != 0
                        || (memInfo.hasSwappedOutPss ? mySwappedOutPss : mySwappedOut) != 0) {
                    if (dumpFullInfo) {
                        printRow(pw, HEAP_FULL_COLUMN, Debug.MemoryInfo.getOtherLabel(i),
                                myPss, mySwappablePss, mySharedDirty, myPrivateDirty,
                                mySharedClean, myPrivateClean,
                                memInfo.hasSwappedOutPss ? mySwappedOutPss : mySwappedOut,
                                "", "", "");
                    } else {
                        printRow(pw, HEAP_COLUMN, Debug.MemoryInfo.getOtherLabel(i),
                                myPss, myPrivateDirty,
                                myPrivateClean,
                                memInfo.hasSwappedOutPss ? mySwappedOutPss : mySwappedOut,
                                "", "", "");
                    }
                    otherPss -= myPss;
                    otherSwappablePss -= mySwappablePss;
                    otherSharedDirty -= mySharedDirty;
                    otherPrivateDirty -= myPrivateDirty;
                    otherSharedClean -= mySharedClean;
                    otherPrivateClean -= myPrivateClean;
                    otherSwappedOut -= mySwappedOut;
                    otherSwappedOutPss -= mySwappedOutPss;
                }
            }

            if (dumpFullInfo) {
                printRow(pw, HEAP_FULL_COLUMN, "Unknown", otherPss, otherSwappablePss,
                        otherSharedDirty, otherPrivateDirty, otherSharedClean, otherPrivateClean,
                        memInfo.hasSwappedOutPss ? otherSwappedOutPss : otherSwappedOut,
                        "", "", "");
                printRow(pw, HEAP_FULL_COLUMN, "TOTAL", memInfo.getTotalPss(),
                        memInfo.getTotalSwappablePss(),
                        memInfo.getTotalSharedDirty(), memInfo.getTotalPrivateDirty(),
                        memInfo.getTotalSharedClean(), memInfo.getTotalPrivateClean(),
                        memInfo.hasSwappedOutPss ? memInfo.getTotalSwappedOutPss() :
                        memInfo.getTotalSwappedOut(),
                        nativeMax+dalvikMax, nativeAllocated+dalvikAllocated,
                        nativeFree+dalvikFree);
            } else {
                printRow(pw, HEAP_COLUMN, "Unknown", otherPss,
                        otherPrivateDirty, otherPrivateClean,
                        memInfo.hasSwappedOutPss ? otherSwappedOutPss : otherSwappedOut,
                        "", "", "");
                printRow(pw, HEAP_COLUMN, "TOTAL", memInfo.getTotalPss(),
                        memInfo.getTotalPrivateDirty(),
                        memInfo.getTotalPrivateClean(),
                        memInfo.hasSwappedOutPss ? memInfo.getTotalSwappedOutPss() :
                        memInfo.getTotalSwappedOut(),
                        nativeMax+dalvikMax,
                        nativeAllocated+dalvikAllocated, nativeFree+dalvikFree);
            }

            if (dumpDalvik) {
                pw.println(" ");
                pw.println(" Dalvik Details");

                for (int i=Debug.MemoryInfo.NUM_OTHER_STATS;
                     i<Debug.MemoryInfo.NUM_OTHER_STATS + Debug.MemoryInfo.NUM_DVK_STATS; i++) {
                    final int myPss = memInfo.getOtherPss(i);
                    final int mySwappablePss = memInfo.getOtherSwappablePss(i);
                    final int mySharedDirty = memInfo.getOtherSharedDirty(i);
                    final int myPrivateDirty = memInfo.getOtherPrivateDirty(i);
                    final int mySharedClean = memInfo.getOtherSharedClean(i);
                    final int myPrivateClean = memInfo.getOtherPrivateClean(i);
                    final int mySwappedOut = memInfo.getOtherSwappedOut(i);
                    final int mySwappedOutPss = memInfo.getOtherSwappedOutPss(i);
                    if (myPss != 0 || mySharedDirty != 0 || myPrivateDirty != 0
                            || mySharedClean != 0 || myPrivateClean != 0
                            || (memInfo.hasSwappedOutPss ? mySwappedOutPss : mySwappedOut) != 0) {
                        if (dumpFullInfo) {
                            printRow(pw, HEAP_FULL_COLUMN, Debug.MemoryInfo.getOtherLabel(i),
                                    myPss, mySwappablePss, mySharedDirty, myPrivateDirty,
                                    mySharedClean, myPrivateClean,
                                    memInfo.hasSwappedOutPss ? mySwappedOutPss : mySwappedOut,
                                    "", "", "");
                        } else {
                            printRow(pw, HEAP_COLUMN, Debug.MemoryInfo.getOtherLabel(i),
                                    myPss, myPrivateDirty,
                                    myPrivateClean,
                                    memInfo.hasSwappedOutPss ? mySwappedOutPss : mySwappedOut,
                                    "", "", "");
                        }
                    }
                }
            }
        }

        pw.println(" ");
        pw.println(" App Summary");
        printRow(pw, ONE_COUNT_COLUMN_HEADER, "", "Pss(KB)");
        printRow(pw, ONE_COUNT_COLUMN_HEADER, "", "------");
        printRow(pw, ONE_COUNT_COLUMN,
            "Java Heap:", memInfo.getSummaryJavaHeap());
        printRow(pw, ONE_COUNT_COLUMN,
            "Native Heap:", memInfo.getSummaryNativeHeap());
        printRow(pw, ONE_COUNT_COLUMN,
            "Code:", memInfo.getSummaryCode());
        printRow(pw, ONE_COUNT_COLUMN,
            "Stack:", memInfo.getSummaryStack());
        printRow(pw, ONE_COUNT_COLUMN,
            "Graphics:", memInfo.getSummaryGraphics());
        printRow(pw, ONE_COUNT_COLUMN,
            "Private Other:", memInfo.getSummaryPrivateOther());
        printRow(pw, ONE_COUNT_COLUMN,
            "System:", memInfo.getSummarySystem());
        pw.println(" ");
        if (memInfo.hasSwappedOutPss) {
            printRow(pw, TWO_COUNT_COLUMNS,
                "TOTAL:", memInfo.getSummaryTotalPss(),
                "TOTAL SWAP PSS:", memInfo.getSummaryTotalSwapPss());
        } else {
            printRow(pw, TWO_COUNT_COLUMNS,
                "TOTAL:", memInfo.getSummaryTotalPss(),
                "TOTAL SWAP (KB):", memInfo.getSummaryTotalSwap());
        }
    }

    /**
     * Dump heap info to proto.
     *
     * @param hasSwappedOutPss determines whether to use dirtySwap or dirtySwapPss
     */
    private static void dumpMemoryInfo(ProtoOutputStream proto, long fieldId, String name,
            int pss, int cleanPss, int sharedDirty, int privateDirty,
            int sharedClean, int privateClean,
            boolean hasSwappedOutPss, int dirtySwap, int dirtySwapPss) {
        final long token = proto.start(fieldId);

        proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.NAME, name);
        proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.TOTAL_PSS_KB, pss);
        proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.CLEAN_PSS_KB, cleanPss);
        proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.SHARED_DIRTY_KB, sharedDirty);
        proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.PRIVATE_DIRTY_KB, privateDirty);
        proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.SHARED_CLEAN_KB, sharedClean);
        proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.PRIVATE_CLEAN_KB, privateClean);
        if (hasSwappedOutPss) {
            proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.DIRTY_SWAP_PSS_KB, dirtySwapPss);
        } else {
            proto.write(MemInfoDumpProto.ProcessMemory.MemoryInfo.DIRTY_SWAP_KB, dirtySwap);
        }

        proto.end(token);
    }

    /**
     * Dump mem info data to proto.
     */
    public static void dumpMemInfoTable(ProtoOutputStream proto, Debug.MemoryInfo memInfo,
            boolean dumpDalvik, boolean dumpSummaryOnly,
            long nativeMax, long nativeAllocated, long nativeFree,
            long dalvikMax, long dalvikAllocated, long dalvikFree) {

        if (!dumpSummaryOnly) {
            final long nhToken = proto.start(MemInfoDumpProto.ProcessMemory.NATIVE_HEAP);
            dumpMemoryInfo(proto, MemInfoDumpProto.ProcessMemory.HeapInfo.MEM_INFO, "Native Heap",
                    memInfo.nativePss, memInfo.nativeSwappablePss, memInfo.nativeSharedDirty,
                    memInfo.nativePrivateDirty, memInfo.nativeSharedClean,
                    memInfo.nativePrivateClean, memInfo.hasSwappedOutPss,
                    memInfo.nativeSwappedOut, memInfo.nativeSwappedOutPss);
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_SIZE_KB, nativeMax);
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_ALLOC_KB, nativeAllocated);
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_FREE_KB, nativeFree);
            proto.end(nhToken);

            final long dvToken = proto.start(MemInfoDumpProto.ProcessMemory.DALVIK_HEAP);
            dumpMemoryInfo(proto, MemInfoDumpProto.ProcessMemory.HeapInfo.MEM_INFO, "Dalvik Heap",
                    memInfo.dalvikPss, memInfo.dalvikSwappablePss, memInfo.dalvikSharedDirty,
                    memInfo.dalvikPrivateDirty, memInfo.dalvikSharedClean,
                    memInfo.dalvikPrivateClean, memInfo.hasSwappedOutPss,
                    memInfo.dalvikSwappedOut, memInfo.dalvikSwappedOutPss);
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_SIZE_KB, dalvikMax);
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_ALLOC_KB, dalvikAllocated);
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_FREE_KB, dalvikFree);
            proto.end(dvToken);

            int otherPss = memInfo.otherPss;
            int otherSwappablePss = memInfo.otherSwappablePss;
            int otherSharedDirty = memInfo.otherSharedDirty;
            int otherPrivateDirty = memInfo.otherPrivateDirty;
            int otherSharedClean = memInfo.otherSharedClean;
            int otherPrivateClean = memInfo.otherPrivateClean;
            int otherSwappedOut = memInfo.otherSwappedOut;
            int otherSwappedOutPss = memInfo.otherSwappedOutPss;

            for (int i = 0; i < Debug.MemoryInfo.NUM_OTHER_STATS; i++) {
                final int myPss = memInfo.getOtherPss(i);
                final int mySwappablePss = memInfo.getOtherSwappablePss(i);
                final int mySharedDirty = memInfo.getOtherSharedDirty(i);
                final int myPrivateDirty = memInfo.getOtherPrivateDirty(i);
                final int mySharedClean = memInfo.getOtherSharedClean(i);
                final int myPrivateClean = memInfo.getOtherPrivateClean(i);
                final int mySwappedOut = memInfo.getOtherSwappedOut(i);
                final int mySwappedOutPss = memInfo.getOtherSwappedOutPss(i);
                if (myPss != 0 || mySharedDirty != 0 || myPrivateDirty != 0
                        || mySharedClean != 0 || myPrivateClean != 0
                        || (memInfo.hasSwappedOutPss ? mySwappedOutPss : mySwappedOut) != 0) {
                    dumpMemoryInfo(proto, MemInfoDumpProto.ProcessMemory.OTHER_HEAPS,
                            Debug.MemoryInfo.getOtherLabel(i),
                            myPss, mySwappablePss, mySharedDirty, myPrivateDirty,
                            mySharedClean, myPrivateClean,
                            memInfo.hasSwappedOutPss, mySwappedOut, mySwappedOutPss);

                    otherPss -= myPss;
                    otherSwappablePss -= mySwappablePss;
                    otherSharedDirty -= mySharedDirty;
                    otherPrivateDirty -= myPrivateDirty;
                    otherSharedClean -= mySharedClean;
                    otherPrivateClean -= myPrivateClean;
                    otherSwappedOut -= mySwappedOut;
                    otherSwappedOutPss -= mySwappedOutPss;
                }
            }

            dumpMemoryInfo(proto, MemInfoDumpProto.ProcessMemory.UNKNOWN_HEAP, "Unknown",
                    otherPss, otherSwappablePss,
                    otherSharedDirty, otherPrivateDirty, otherSharedClean, otherPrivateClean,
                    memInfo.hasSwappedOutPss, otherSwappedOut, otherSwappedOutPss);
            final long tToken = proto.start(MemInfoDumpProto.ProcessMemory.TOTAL_HEAP);
            dumpMemoryInfo(proto, MemInfoDumpProto.ProcessMemory.HeapInfo.MEM_INFO, "TOTAL",
                    memInfo.getTotalPss(), memInfo.getTotalSwappablePss(),
                    memInfo.getTotalSharedDirty(), memInfo.getTotalPrivateDirty(),
                    memInfo.getTotalSharedClean(), memInfo.getTotalPrivateClean(),
                    memInfo.hasSwappedOutPss, memInfo.getTotalSwappedOut(),
                    memInfo.getTotalSwappedOutPss());
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_SIZE_KB,
                    nativeMax + dalvikMax);
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_ALLOC_KB,
                    nativeAllocated + dalvikAllocated);
            proto.write(MemInfoDumpProto.ProcessMemory.HeapInfo.HEAP_FREE_KB,
                    nativeFree + dalvikFree);
            proto.end(tToken);

            if (dumpDalvik) {
                for (int i = Debug.MemoryInfo.NUM_OTHER_STATS;
                        i < Debug.MemoryInfo.NUM_OTHER_STATS + Debug.MemoryInfo.NUM_DVK_STATS;
                        i++) {
                    final int myPss = memInfo.getOtherPss(i);
                    final int mySwappablePss = memInfo.getOtherSwappablePss(i);
                    final int mySharedDirty = memInfo.getOtherSharedDirty(i);
                    final int myPrivateDirty = memInfo.getOtherPrivateDirty(i);
                    final int mySharedClean = memInfo.getOtherSharedClean(i);
                    final int myPrivateClean = memInfo.getOtherPrivateClean(i);
                    final int mySwappedOut = memInfo.getOtherSwappedOut(i);
                    final int mySwappedOutPss = memInfo.getOtherSwappedOutPss(i);
                    if (myPss != 0 || mySharedDirty != 0 || myPrivateDirty != 0
                            || mySharedClean != 0 || myPrivateClean != 0
                            || (memInfo.hasSwappedOutPss ? mySwappedOutPss : mySwappedOut) != 0) {
                        dumpMemoryInfo(proto, MemInfoDumpProto.ProcessMemory.DALVIK_DETAILS,
                                Debug.MemoryInfo.getOtherLabel(i),
                                myPss, mySwappablePss, mySharedDirty, myPrivateDirty,
                                mySharedClean, myPrivateClean,
                                memInfo.hasSwappedOutPss, mySwappedOut, mySwappedOutPss);
                    }
                }
            }
        }

        final long asToken = proto.start(MemInfoDumpProto.ProcessMemory.APP_SUMMARY);
        proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.JAVA_HEAP_PSS_KB,
                memInfo.getSummaryJavaHeap());
        proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.NATIVE_HEAP_PSS_KB,
                memInfo.getSummaryNativeHeap());
        proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.CODE_PSS_KB,
                memInfo.getSummaryCode());
        proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.STACK_PSS_KB,
                memInfo.getSummaryStack());
        proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.GRAPHICS_PSS_KB,
                memInfo.getSummaryGraphics());
        proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.PRIVATE_OTHER_PSS_KB,
                memInfo.getSummaryPrivateOther());
        proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.SYSTEM_PSS_KB,
                memInfo.getSummarySystem());
        if (memInfo.hasSwappedOutPss) {
            proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.TOTAL_SWAP_PSS,
                    memInfo.getSummaryTotalSwapPss());
        } else {
            proto.write(MemInfoDumpProto.ProcessMemory.AppSummary.TOTAL_SWAP_PSS,
                    memInfo.getSummaryTotalSwap());
        }
        proto.end(asToken);
    }

    @UnsupportedAppUsage
    public void registerOnActivityPausedListener(Activity activity,
            OnActivityPausedListener listener) {
        synchronized (mOnPauseListeners) {
            ArrayList<OnActivityPausedListener> list = mOnPauseListeners.get(activity);
            if (list == null) {
                list = new ArrayList<OnActivityPausedListener>();
                mOnPauseListeners.put(activity, list);
            }
            list.add(listener);
        }
    }

    @UnsupportedAppUsage
    public void unregisterOnActivityPausedListener(Activity activity,
            OnActivityPausedListener listener) {
        synchronized (mOnPauseListeners) {
            ArrayList<OnActivityPausedListener> list = mOnPauseListeners.get(activity);
            if (list != null) {
                list.remove(listener);
            }
        }
    }

    public final ActivityInfo resolveActivityInfo(Intent intent) {
        ActivityInfo aInfo = intent.resolveActivityInfo(
                mInitialApplication.getPackageManager(), PackageManager.GET_SHARED_LIBRARY_FILES);
        if (aInfo == null) {
            // Throw an exception.
            Instrumentation.checkStartActivityResult(
                    ActivityManager.START_CLASS_NOT_FOUND, intent);
        }
        return aInfo;
    }

    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    public final Activity startActivityNow(Activity parent, String id,
        Intent intent, ActivityInfo activityInfo, IBinder token, Bundle state,
        Activity.NonConfigurationInstances lastNonConfigurationInstances, IBinder assistToken) {
        ActivityClientRecord r = new ActivityClientRecord();
            r.token = token;
            r.assistToken = assistToken;
            r.ident = 0;
            r.intent = intent;
            r.state = state;
            r.parent = parent;
            r.embeddedID = id;
            r.activityInfo = activityInfo;
            r.lastNonConfigurationInstances = lastNonConfigurationInstances;
        if (localLOGV) {
            ComponentName compname = intent.getComponent();
            String name;
            if (compname != null) {
                name = compname.toShortString();
            } else {
                name = "(Intent " + intent + ").getComponent() returned null";
            }
            Slog.v(TAG, "Performing launch: action=" + intent.getAction()
                    + ", comp=" + name
                    + ", token=" + token);
        }
        // TODO(lifecycler): Can't switch to use #handleLaunchActivity() because it will try to
        // call #reportSizeConfigurations(), but the server might not know anything about the
        // activity if it was launched from LocalAcvitivyManager.
        return performLaunchActivity(r, null /* customIntent */);
    }

    @UnsupportedAppUsage
    public final Activity getActivity(IBinder token) {
        final ActivityClientRecord activityRecord = mActivities.get(token);
        return activityRecord != null ? activityRecord.activity : null;
    }

    @Override
    public ActivityClientRecord getActivityClient(IBinder token) {
        return mActivities.get(token);
    }

    @Override
    public void updatePendingConfiguration(Configuration config) {
        synchronized (mResourcesManager) {
            if (mPendingConfiguration == null || mPendingConfiguration.isOtherSeqNewer(config)) {
                mPendingConfiguration = config;
            }
        }
    }

    @Override
    public void updateProcessState(int processState, boolean fromIpc) {
        synchronized (mAppThread) {
            if (mLastProcessState == processState) {
                return;
            }
            mLastProcessState = processState;
            // Defer the top state for VM to avoid aggressive JIT compilation affecting activity
            // launch time.
            if (processState == ActivityManager.PROCESS_STATE_TOP
                    && mNumLaunchingActivities.get() > 0) {
                mPendingProcessState = processState;
                mH.postDelayed(this::applyPendingProcessState, PENDING_TOP_PROCESS_STATE_TIMEOUT);
            } else {
                mPendingProcessState = PROCESS_STATE_UNKNOWN;
                updateVmProcessState(processState);
            }
            if (localLOGV) {
                Slog.i(TAG, "******************* PROCESS STATE CHANGED TO: " + processState
                        + (fromIpc ? " (from ipc" : ""));
            }
        }
    }

    /** Update VM state based on ActivityManager.PROCESS_STATE_* constants. */
    private void updateVmProcessState(int processState) {
        // TODO: Tune this since things like gmail sync are important background but not jank
        // perceptible.
        final int state = processState <= ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND
                ? VM_PROCESS_STATE_JANK_PERCEPTIBLE
                : VM_PROCESS_STATE_JANK_IMPERCEPTIBLE;
        VMRuntime.getRuntime().updateProcessState(state);
    }

    private void applyPendingProcessState() {
        synchronized (mAppThread) {
            if (mPendingProcessState == PROCESS_STATE_UNKNOWN) {
                return;
            }
            final int pendingState = mPendingProcessState;
            mPendingProcessState = PROCESS_STATE_UNKNOWN;
            // Only apply the pending state if the last state doesn't change.
            if (pendingState == mLastProcessState) {
                updateVmProcessState(pendingState);
            }
        }
    }

    @Override
    public void countLaunchingActivities(int num) {
        mNumLaunchingActivities.getAndAdd(num);
    }

    @UnsupportedAppUsage
    public final void sendActivityResult(
            IBinder token, String id, int requestCode,
            int resultCode, Intent data) {
        if (DEBUG_RESULTS) Slog.v(TAG, "sendActivityResult: id=" + id
                + " req=" + requestCode + " res=" + resultCode + " data=" + data);
        ArrayList<ResultInfo> list = new ArrayList<ResultInfo>();
        list.add(new ResultInfo(id, requestCode, resultCode, data));
        final ClientTransaction clientTransaction = ClientTransaction.obtain(mAppThread, token);
        clientTransaction.addCallback(ActivityResultItem.obtain(list));
        try {
            mAppThread.scheduleTransaction(clientTransaction);
        } catch (RemoteException e) {
            // Local scheduling
        }
    }

    @Override
    TransactionExecutor getTransactionExecutor() {
        return mTransactionExecutor;
    }

    void sendMessage(int what, Object obj) {
        sendMessage(what, obj, 0, 0, false);
    }

    private void sendMessage(int what, Object obj, int arg1) {
        sendMessage(what, obj, arg1, 0, false);
    }

    private void sendMessage(int what, Object obj, int arg1, int arg2) {
        sendMessage(what, obj, arg1, arg2, false);
    }

    private void sendMessage(int what, Object obj, int arg1, int arg2, boolean async) {
        if (DEBUG_MESSAGES) {
            Slog.v(TAG,
                    "SCHEDULE " + what + " " + mH.codeToString(what) + ": " + arg1 + " / " + obj);
        }
        Message msg = Message.obtain();
        msg.what = what;
        msg.obj = obj;
        msg.arg1 = arg1;
        msg.arg2 = arg2;
        if (async) {
            msg.setAsynchronous(true);
        }
        mH.sendMessage(msg);
    }

    private void sendMessage(int what, Object obj, int arg1, int arg2, int seq) {
        if (DEBUG_MESSAGES) Slog.v(
                TAG, "SCHEDULE " + mH.codeToString(what) + " arg1=" + arg1 + " arg2=" + arg2 +
                        "seq= " + seq);
        Message msg = Message.obtain();
        msg.what = what;
        SomeArgs args = SomeArgs.obtain();
        args.arg1 = obj;
        args.argi1 = arg1;
        args.argi2 = arg2;
        args.argi3 = seq;
        msg.obj = args;
        mH.sendMessage(msg);
    }

    final void scheduleContextCleanup(ContextImpl context, String who,
            String what) {
        ContextCleanupInfo cci = new ContextCleanupInfo();
        cci.context = context;
        cci.who = who;
        cci.what = what;
        sendMessage(H.CLEAN_UP_CONTEXT, cci);
    }

    /**  Core implementation of activity launch. */
    private Activity performLaunchActivity(ActivityClientRecord r, Intent customIntent) {
        ActivityInfo aInfo = r.activityInfo;
        if (r.packageInfo == null) {
            r.packageInfo = getPackageInfo(aInfo.applicationInfo, r.compatInfo,
                    Context.CONTEXT_INCLUDE_CODE);
        }

        ComponentName component = r.intent.getComponent();
        if (component == null) {
            component = r.intent.resolveActivity(
                mInitialApplication.getPackageManager());
            r.intent.setComponent(component);
        }

        if (r.activityInfo.targetActivity != null) {
            component = new ComponentName(r.activityInfo.packageName,
                    r.activityInfo.targetActivity);
        }

        ContextImpl appContext = createBaseContextForActivity(r);
        Activity activity = null;
        try {
            java.lang.ClassLoader cl = appContext.getClassLoader();
            activity = mInstrumentation.newActivity(
                    cl, component.getClassName(), r.intent);
            StrictMode.incrementExpectedActivityCount(activity.getClass());
            r.intent.setExtrasClassLoader(cl);
            r.intent.prepareToEnterProcess();
            if (r.state != null) {
                r.state.setClassLoader(cl);
            }
        } catch (Exception e) {
            if (!mInstrumentation.onException(activity, e)) {
                throw new RuntimeException(
                    "Unable to instantiate activity " + component
                    + ": " + e.toString(), e);
            }
        }

        try {
            Application app = r.packageInfo.makeApplication(false, mInstrumentation);

            if (localLOGV) Slog.v(TAG, "Performing launch of " + r);
            if (localLOGV) Slog.v(
                    TAG, r + ": app=" + app
                    + ", appName=" + app.getPackageName()
                    + ", pkg=" + r.packageInfo.getPackageName()
                    + ", comp=" + r.intent.getComponent().toShortString()
                    + ", dir=" + r.packageInfo.getAppDir());

            if (activity != null) {
                CharSequence title = r.activityInfo.loadLabel(appContext.getPackageManager());
                Configuration config = new Configuration(mCompatConfiguration);
                if (r.overrideConfig != null) {
                    config.updateFrom(r.overrideConfig);
                }
                if (DEBUG_CONFIGURATION) Slog.v(TAG, "Launching activity "
                        + r.activityInfo.name + " with config " + config);
                Window window = null;
                if (r.mPendingRemoveWindow != null && r.mPreserveWindow) {
                    window = r.mPendingRemoveWindow;
                    r.mPendingRemoveWindow = null;
                    r.mPendingRemoveWindowManager = null;
                }
                appContext.setOuterContext(activity);
                activity.attach(appContext, this, getInstrumentation(), r.token,
                        r.ident, app, r.intent, r.activityInfo, title, r.parent,
                        r.embeddedID, r.lastNonConfigurationInstances, config,
                        r.referrer, r.voiceInteractor, window, r.configCallback,
                        r.assistToken);

                if (customIntent != null) {
                    activity.mIntent = customIntent;
                }
                r.lastNonConfigurationInstances = null;
                checkAndBlockForNetworkAccess();
                activity.mStartedActivity = false;
                int theme = r.activityInfo.getThemeResource();
                if (theme != 0) {
                    activity.setTheme(theme);
                }

                activity.mCalled = false;
                if (r.isPersistable()) {
                    mInstrumentation.callActivityOnCreate(activity, r.state, r.persistentState);
                } else {
                    mInstrumentation.callActivityOnCreate(activity, r.state);
                }
                if (!activity.mCalled) {
                    throw new SuperNotCalledException(
                        "Activity " + r.intent.getComponent().toShortString() +
                        " did not call through to super.onCreate()");
                }
                r.activity = activity;
            }
            r.setState(ON_CREATE);

            // updatePendingActivityConfiguration() reads from mActivities to update
            // ActivityClientRecord which runs in a different thread. Protect modifications to
            // mActivities to avoid race.
            synchronized (mResourcesManager) {
                mActivities.put(r.token, r);
            }

        } catch (SuperNotCalledException e) {
            throw e;

        } catch (Exception e) {
            if (!mInstrumentation.onException(activity, e)) {
                throw new RuntimeException(
                    "Unable to start activity " + component
                    + ": " + e.toString(), e);
            }
        }

        return activity;
    }

    @Override
    public void handleStartActivity(ActivityClientRecord r,
            PendingTransactionActions pendingActions) {
        final Activity activity = r.activity;
        if (r.activity == null) {
            // TODO(lifecycler): What do we do in this case?
            return;
        }
        if (!r.stopped) {
            throw new IllegalStateException("Can't start activity that is not stopped.");
        }
        if (r.activity.mFinished) {
            // TODO(lifecycler): How can this happen?
            return;
        }

        // Start
        activity.performStart("handleStartActivity");
        r.setState(ON_START);

        if (pendingActions == null) {
            // No more work to do.
            return;
        }

        // Restore instance state
        if (pendingActions.shouldRestoreInstanceState()) {
            if (r.isPersistable()) {
                if (r.state != null || r.persistentState != null) {
                    mInstrumentation.callActivityOnRestoreInstanceState(activity, r.state,
                            r.persistentState);
                }
            } else if (r.state != null) {
                mInstrumentation.callActivityOnRestoreInstanceState(activity, r.state);
            }
        }

        // Call postOnCreate()
        if (pendingActions.shouldCallOnPostCreate()) {
            activity.mCalled = false;
            if (r.isPersistable()) {
                mInstrumentation.callActivityOnPostCreate(activity, r.state,
                        r.persistentState);
            } else {
                mInstrumentation.callActivityOnPostCreate(activity, r.state);
            }
            if (!activity.mCalled) {
                throw new SuperNotCalledException(
                        "Activity " + r.intent.getComponent().toShortString()
                                + " did not call through to super.onPostCreate()");
            }
        }
    }

    /**
     * Checks if {@link #mNetworkBlockSeq} is {@link #INVALID_PROC_STATE_SEQ} and if so, returns
     * immediately. Otherwise, makes a blocking call to ActivityManagerService to wait for the
     * network rules to get updated.
     */
    private void checkAndBlockForNetworkAccess() {
        synchronized (mNetworkPolicyLock) {
            if (mNetworkBlockSeq != INVALID_PROC_STATE_SEQ) {
                try {
                    ActivityManager.getService().waitForNetworkStateUpdate(mNetworkBlockSeq);
                    mNetworkBlockSeq = INVALID_PROC_STATE_SEQ;
                } catch (RemoteException ignored) {}
            }
        }
    }

    private ContextImpl createBaseContextForActivity(ActivityClientRecord r) {
        final int displayId;
        try {
            displayId = ActivityTaskManager.getService().getActivityDisplayId(r.token);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }

        ContextImpl appContext = ContextImpl.createActivityContext(
                this, r.packageInfo, r.activityInfo, r.token, displayId, r.overrideConfig);

        final DisplayManagerGlobal dm = DisplayManagerGlobal.getInstance();
        // For debugging purposes, if the activity's package name contains the value of
        // the "debug.use-second-display" system property as a substring, then show
        // its content on a secondary display if there is one.
        String pkgName = SystemProperties.get("debug.second-display.pkg");
        if (pkgName != null && !pkgName.isEmpty()
                && r.packageInfo.mPackageName.contains(pkgName)) {
            for (int id : dm.getDisplayIds()) {
                if (id != Display.DEFAULT_DISPLAY) {
                    Display display =
                            dm.getCompatibleDisplay(id, appContext.getResources());
                    appContext = (ContextImpl) appContext.createDisplayContext(display);
                    break;
                }
            }
        }
        return appContext;
    }

    /**
     * Extended implementation of activity launch. Used when server requests a launch or relaunch.
     */
    @Override
    public Activity handleLaunchActivity(ActivityClientRecord r,
            PendingTransactionActions pendingActions, Intent customIntent) {
        // If we are getting ready to gc after going to the background, well
        // we are back active so skip it.
        unscheduleGcIdler();
        mSomeActivitiesChanged = true;

        if (r.profilerInfo != null) {
            mProfiler.setProfiler(r.profilerInfo);
            mProfiler.startProfiling();
        }

        // Make sure we are running with the most recent config.
        handleConfigurationChanged(null, null);

        if (localLOGV) Slog.v(
            TAG, "Handling launch of " + r);

        // Initialize before creating the activity
        if (!ThreadedRenderer.sRendererDisabled
                && (r.activityInfo.flags & ActivityInfo.FLAG_HARDWARE_ACCELERATED) != 0) {
            HardwareRenderer.preload();
        }
        WindowManagerGlobal.initialize();

        // Hint the GraphicsEnvironment that an activity is launching on the process.
        GraphicsEnvironment.hintActivityLaunch();

        final Activity a = performLaunchActivity(r, customIntent);

        if (a != null) {
            r.createdConfig = new Configuration(mConfiguration);
            reportSizeConfigurations(r);
            if (!r.activity.mFinished && pendingActions != null) {
                pendingActions.setOldState(r.state);
                pendingActions.setRestoreInstanceState(true);
                pendingActions.setCallOnPostCreate(true);
            }
        } else {
            // If there was an error, for any reason, tell the activity manager to stop us.
            try {
                ActivityTaskManager.getService()
                        .finishActivity(r.token, Activity.RESULT_CANCELED, null,
                                Activity.DONT_FINISH_TASK_WITH_ACTIVITY);
            } catch (RemoteException ex) {
                throw ex.rethrowFromSystemServer();
            }
        }

        return a;
    }

    private void reportSizeConfigurations(ActivityClientRecord r) {
        if (mActivitiesToBeDestroyed.containsKey(r.token)) {
            // Size configurations of a destroyed activity is meaningless.
            return;
        }
        Configuration[] configurations = r.activity.getResources().getSizeConfigurations();
        if (configurations == null || r.activity.mFinished) {
            return;
        }
        SparseIntArray horizontal = new SparseIntArray();
        SparseIntArray vertical = new SparseIntArray();
        SparseIntArray smallest = new SparseIntArray();
        for (int i = configurations.length - 1; i >= 0; i--) {
            Configuration config = configurations[i];
            if (config.screenHeightDp != Configuration.SCREEN_HEIGHT_DP_UNDEFINED) {
                vertical.put(config.screenHeightDp, 0);
            }
            if (config.screenWidthDp != Configuration.SCREEN_WIDTH_DP_UNDEFINED) {
                horizontal.put(config.screenWidthDp, 0);
            }
            if (config.smallestScreenWidthDp != Configuration.SMALLEST_SCREEN_WIDTH_DP_UNDEFINED) {
                smallest.put(config.smallestScreenWidthDp, 0);
            }
        }
        try {
            ActivityTaskManager.getService().reportSizeConfigurations(r.token,
                    horizontal.copyKeys(), vertical.copyKeys(), smallest.copyKeys());
        } catch (RemoteException ex) {
            throw ex.rethrowFromSystemServer();
        }
    }

    private void deliverNewIntents(ActivityClientRecord r, List<ReferrerIntent> intents) {
        final int N = intents.size();
        for (int i=0; i<N; i++) {
            ReferrerIntent intent = intents.get(i);
            intent.setExtrasClassLoader(r.activity.getClassLoader());
            intent.prepareToEnterProcess();
            r.activity.mFragments.noteStateNotSaved();
            mInstrumentation.callActivityOnNewIntent(r.activity, intent);
        }
    }

    @Override
    public void handleNewIntent(IBinder token, List<ReferrerIntent> intents) {
        final ActivityClientRecord r = mActivities.get(token);
        if (r == null) {
            return;
        }

        checkAndBlockForNetworkAccess();
        deliverNewIntents(r, intents);
    }

    public void handleRequestAssistContextExtras(RequestAssistContextExtras cmd) {
        // Filling for autofill has a few differences:
        // - it does not need an AssistContent
        // - it does not call onProvideAssistData()
        // - it needs an IAutoFillCallback
        boolean forAutofill = cmd.requestType == ActivityManager.ASSIST_CONTEXT_AUTOFILL;

        // TODO: decide if lastSessionId logic applies to autofill sessions
        if (mLastSessionId != cmd.sessionId) {
            // Clear the existing structures
            mLastSessionId = cmd.sessionId;
            for (int i = mLastAssistStructures.size() - 1; i >= 0; i--) {
                AssistStructure structure = mLastAssistStructures.get(i).get();
                if (structure != null) {
                    structure.clearSendChannel();
                }
                mLastAssistStructures.remove(i);
            }
        }

        Bundle data = new Bundle();
        AssistStructure structure = null;
        AssistContent content = forAutofill ? null : new AssistContent();
        final long startTime = SystemClock.uptimeMillis();
        ActivityClientRecord r = mActivities.get(cmd.activityToken);
        Uri referrer = null;
        if (r != null) {
            if (!forAutofill) {
                r.activity.getApplication().dispatchOnProvideAssistData(r.activity, data);
                r.activity.onProvideAssistData(data);
                referrer = r.activity.onProvideReferrer();
            }
            if (cmd.requestType == ActivityManager.ASSIST_CONTEXT_FULL || forAutofill) {
                structure = new AssistStructure(r.activity, forAutofill, cmd.flags);
                Intent activityIntent = r.activity.getIntent();
                boolean notSecure = r.window == null ||
                        (r.window.getAttributes().flags
                                & WindowManager.LayoutParams.FLAG_SECURE) == 0;
                if (activityIntent != null && notSecure) {
                    if (!forAutofill) {
                        Intent intent = new Intent(activityIntent);
                        intent.setFlags(intent.getFlags() & ~(Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION));
                        intent.removeUnsafeExtras();
                        content.setDefaultIntent(intent);
                    }
                } else {
                    if (!forAutofill) {
                        content.setDefaultIntent(new Intent());
                    }
                }
                if (!forAutofill) {
                    r.activity.onProvideAssistContent(content);
                }
            }

        }
        if (structure == null) {
            structure = new AssistStructure();
        }

        // TODO: decide if lastSessionId logic applies to autofill sessions

        structure.setAcquisitionStartTime(startTime);
        structure.setAcquisitionEndTime(SystemClock.uptimeMillis());

        mLastAssistStructures.add(new WeakReference<>(structure));
        IActivityTaskManager mgr = ActivityTaskManager.getService();
        try {
            mgr.reportAssistContextExtras(cmd.requestToken, data, structure, content, referrer);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** Fetches the user actions for the corresponding activity */
    private void handleRequestDirectActions(@NonNull IBinder activityToken,
            @NonNull IVoiceInteractor interactor, @NonNull CancellationSignal cancellationSignal,
            @NonNull RemoteCallback callback) {
        final ActivityClientRecord r = mActivities.get(activityToken);
        if (r == null) {
            Log.w(TAG, "requestDirectActions(): no activity for " + activityToken);
            callback.sendResult(null);
            return;
        }
        final int lifecycleState = r.getLifecycleState();
        if (lifecycleState < ON_START || lifecycleState >= ON_STOP) {
            Log.w(TAG, "requestDirectActions(" + r + "): wrong lifecycle: " + lifecycleState);
            callback.sendResult(null);
            return;
        }
        if (r.activity.mVoiceInteractor == null
                || r.activity.mVoiceInteractor.mInteractor.asBinder()
                != interactor.asBinder()) {
            if (r.activity.mVoiceInteractor != null) {
                r.activity.mVoiceInteractor.destroy();
            }
            r.activity.mVoiceInteractor = new VoiceInteractor(interactor, r.activity,
                    r.activity, Looper.myLooper());
        }
        r.activity.onGetDirectActions(cancellationSignal, (actions) -> {
            Preconditions.checkNotNull(actions);
            Preconditions.checkCollectionElementsNotNull(actions, "actions");
            if (!actions.isEmpty()) {
                final int actionCount = actions.size();
                for (int i = 0; i < actionCount; i++) {
                    final DirectAction action = actions.get(i);
                    action.setSource(r.activity.getTaskId(), r.activity.getAssistToken());
                }
                final Bundle result = new Bundle();
                result.putParcelable(DirectAction.KEY_ACTIONS_LIST,
                        new ParceledListSlice<>(actions));
                callback.sendResult(result);
            } else {
                callback.sendResult(null);
            }
        });
    }

    /** Performs an actions in the corresponding activity */
    private void handlePerformDirectAction(@NonNull IBinder activityToken,
            @NonNull String actionId, @Nullable Bundle arguments,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull RemoteCallback resultCallback) {
        final ActivityClientRecord r = mActivities.get(activityToken);
        if (r != null) {
            final int lifecycleState = r.getLifecycleState();
            if (lifecycleState < ON_START || lifecycleState >= ON_STOP) {
                resultCallback.sendResult(null);
                return;
            }
            final Bundle nonNullArguments = (arguments != null) ? arguments : Bundle.EMPTY;
            r.activity.onPerformDirectAction(actionId, nonNullArguments, cancellationSignal,
                    resultCallback::sendResult);
        } else {
            resultCallback.sendResult(null);
        }
    }

    public void handleTranslucentConversionComplete(IBinder token, boolean drawComplete) {
        ActivityClientRecord r = mActivities.get(token);
        if (r != null) {
            r.activity.onTranslucentConversionComplete(drawComplete);
        }
    }

    public void onNewActivityOptions(IBinder token, ActivityOptions options) {
        ActivityClientRecord r = mActivities.get(token);
        if (r != null) {
            r.activity.onNewActivityOptions(options);
        }
    }

    public void handleInstallProvider(ProviderInfo info) {
        final StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskWrites();
        try {
            installContentProviders(mInitialApplication, Arrays.asList(info));
        } finally {
            StrictMode.setThreadPolicy(oldPolicy);
        }
    }

    private void handleEnterAnimationComplete(IBinder token) {
        ActivityClientRecord r = mActivities.get(token);
        if (r != null) {
            r.activity.dispatchEnterAnimationComplete();
        }
    }

    private void handleStartBinderTracking() {
        Binder.enableTracing();
    }

    private void handleStopBinderTrackingAndDump(ParcelFileDescriptor fd) {
        try {
            Binder.disableTracing();
            Binder.getTransactionTracker().writeTracesToFile(fd);
        } finally {
            IoUtils.closeQuietly(fd);
            Binder.getTransactionTracker().clearTraces();
        }
    }

    @Override
    public void handleMultiWindowModeChanged(IBinder token, boolean isInMultiWindowMode,
            Configuration overrideConfig) {
        final ActivityClientRecord r = mActivities.get(token);
        if (r != null) {
            final Configuration newConfig = new Configuration(mConfiguration);
            if (overrideConfig != null) {
                newConfig.updateFrom(overrideConfig);
            }
            r.activity.dispatchMultiWindowModeChanged(isInMultiWindowMode, newConfig);
        }
    }

    @Override
    public void handlePictureInPictureModeChanged(IBinder token, boolean isInPipMode,
            Configuration overrideConfig) {
        final ActivityClientRecord r = mActivities.get(token);
        if (r != null) {
            final Configuration newConfig = new Configuration(mConfiguration);
            if (overrideConfig != null) {
                newConfig.updateFrom(overrideConfig);
            }
            r.activity.dispatchPictureInPictureModeChanged(isInPipMode, newConfig);
        }
    }

    private void handleLocalVoiceInteractionStarted(IBinder token, IVoiceInteractor interactor) {
        final ActivityClientRecord r = mActivities.get(token);
        if (r != null) {
            r.voiceInteractor = interactor;
            r.activity.setVoiceInteractor(interactor);
            if (interactor == null) {
                r.activity.onLocalVoiceInteractionStopped();
            } else {
                r.activity.onLocalVoiceInteractionStarted();
            }
        }
    }

    private static boolean attemptAttachAgent(String agent, ClassLoader classLoader) {
        try {
            VMDebug.attachAgent(agent, classLoader);
            return true;
        } catch (IOException e) {
            Slog.e(TAG, "Attaching agent with " + classLoader + " failed: " + agent);
            return false;
        }
    }

    static void handleAttachAgent(String agent, LoadedApk loadedApk) {
        ClassLoader classLoader = loadedApk != null ? loadedApk.getClassLoader() : null;
        if (attemptAttachAgent(agent, classLoader)) {
            return;
        }
        if (classLoader != null) {
            attemptAttachAgent(agent, null);
        }
    }

    private static final ThreadLocal<Intent> sCurrentBroadcastIntent = new ThreadLocal<Intent>();

    /**
     * Return the Intent that's currently being handled by a
     * BroadcastReceiver on this thread, or null if none.
     * @hide
     */
    public static Intent getIntentBeingBroadcast() {
        return sCurrentBroadcastIntent.get();
    }

    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    private void handleReceiver(ReceiverData data) {
        // If we are getting ready to gc after going to the background, well
        // we are back active so skip it.
        unscheduleGcIdler();

        String component = data.intent.getComponent().getClassName();

        LoadedApk packageInfo = getPackageInfoNoCheck(
                data.info.applicationInfo, data.compatInfo);

        IActivityManager mgr = ActivityManager.getService();

        Application app;
        BroadcastReceiver receiver;
        ContextImpl context;
        try {
            app = packageInfo.makeApplication(false, mInstrumentation);
            context = (ContextImpl) app.getBaseContext();
            if (data.info.splitName != null) {
                context = (ContextImpl) context.createContextForSplit(data.info.splitName);
            }
            java.lang.ClassLoader cl = context.getClassLoader();
            data.intent.setExtrasClassLoader(cl);
            data.intent.prepareToEnterProcess();
            data.setExtrasClassLoader(cl);
            receiver = packageInfo.getAppFactory()
                    .instantiateReceiver(cl, data.info.name, data.intent);
        } catch (Exception e) {
            if (DEBUG_BROADCAST) Slog.i(TAG,
                    "Finishing failed broadcast to " + data.intent.getComponent());
            data.sendFinished(mgr);
            throw new RuntimeException(
                "Unable to instantiate receiver " + component
                + ": " + e.toString(), e);
        }

        try {
            if (localLOGV) Slog.v(
                TAG, "Performing receive of " + data.intent
                + ": app=" + app
                + ", appName=" + app.getPackageName()
                + ", pkg=" + packageInfo.getPackageName()
                + ", comp=" + data.intent.getComponent().toShortString()
                + ", dir=" + packageInfo.getAppDir());

            sCurrentBroadcastIntent.set(data.intent);
            receiver.setPendingResult(data);
            receiver.onReceive(context.getReceiverRestrictedContext(),
                    data.intent);
        } catch (Exception e) {
            if (DEBUG_BROADCAST) Slog.i(TAG,
                    "Finishing failed broadcast to " + data.intent.getComponent());
            data.sendFinished(mgr);
            if (!mInstrumentation.onException(receiver, e)) {
                throw new RuntimeException(
                    "Unable to start receiver " + component
                    + ": " + e.toString(), e);
            }
        } finally {
            sCurrentBroadcastIntent.set(null);
        }

        if (receiver.getPendingResult() != null) {
            data.finish();
        }
    }

    // Instantiate a BackupAgent and tell it that it's alive
    private void handleCreateBackupAgent(CreateBackupAgentData data) {
        if (DEBUG_BACKUP) Slog.v(TAG, "handleCreateBackupAgent: " + data);

        // Sanity check the requested target package's uid against ours
        try {
            PackageInfo requestedPackage = getPackageManager().getPackageInfo(
                    data.appInfo.packageName, 0, UserHandle.myUserId());
            if (requestedPackage.applicationInfo.uid != Process.myUid()) {
                Slog.w(TAG, "Asked to instantiate non-matching package "
                        + data.appInfo.packageName);
                return;
            }
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }

        // no longer idle; we have backup work to do
        unscheduleGcIdler();

        // instantiate the BackupAgent class named in the manifest
        LoadedApk packageInfo = getPackageInfoNoCheck(data.appInfo, data.compatInfo);
        String packageName = packageInfo.mPackageName;
        if (packageName == null) {
            Slog.d(TAG, "Asked to create backup agent for nonexistent package");
            return;
        }

        String classname = data.appInfo.backupAgentName;
        // full backup operation but no app-supplied agent?  use the default implementation
        if (classname == null && (data.backupMode == ApplicationThreadConstants.BACKUP_MODE_FULL
                || data.backupMode == ApplicationThreadConstants.BACKUP_MODE_RESTORE_FULL)) {
            classname = "android.app.backup.FullBackupAgent";
        }

        try {
            IBinder binder = null;
            ArrayMap<String, BackupAgent> backupAgents = getBackupAgentsForUser(data.userId);
            BackupAgent agent = backupAgents.get(packageName);
            if (agent != null) {
                // reusing the existing instance
                if (DEBUG_BACKUP) {
                    Slog.v(TAG, "Reusing existing agent instance");
                }
                binder = agent.onBind();
            } else {
                try {
                    if (DEBUG_BACKUP) Slog.v(TAG, "Initializing agent class " + classname);

                    java.lang.ClassLoader cl = packageInfo.getClassLoader();
                    agent = (BackupAgent) cl.loadClass(classname).newInstance();

                    // set up the agent's context
                    ContextImpl context = ContextImpl.createAppContext(this, packageInfo);
                    context.setOuterContext(agent);
                    agent.attach(context);

                    agent.onCreate(UserHandle.of(data.userId));
                    binder = agent.onBind();
                    backupAgents.put(packageName, agent);
                } catch (Exception e) {
                    // If this is during restore, fail silently; otherwise go
                    // ahead and let the user see the crash.
                    Slog.e(TAG, "Agent threw during creation: " + e);
                    if (data.backupMode != ApplicationThreadConstants.BACKUP_MODE_RESTORE
                            && data.backupMode !=
                                    ApplicationThreadConstants.BACKUP_MODE_RESTORE_FULL) {
                        throw e;
                    }
                    // falling through with 'binder' still null
                }
            }

            // tell the OS that we're live now
            try {
                ActivityManager.getService().backupAgentCreated(packageName, binder, data.userId);
            } catch (RemoteException e) {
                throw e.rethrowFromSystemServer();
            }
        } catch (Exception e) {
            throw new RuntimeException("Unable to create BackupAgent "
                    + classname + ": " + e.toString(), e);
        }
    }

    // Tear down a BackupAgent
    private void handleDestroyBackupAgent(CreateBackupAgentData data) {
        if (DEBUG_BACKUP) Slog.v(TAG, "handleDestroyBackupAgent: " + data);

        LoadedApk packageInfo = getPackageInfoNoCheck(data.appInfo, data.compatInfo);
        String packageName = packageInfo.mPackageName;
        ArrayMap<String, BackupAgent> backupAgents = getBackupAgentsForUser(data.userId);
        BackupAgent agent = backupAgents.get(packageName);
        if (agent != null) {
            try {
                agent.onDestroy();
            } catch (Exception e) {
                Slog.w(TAG, "Exception thrown in onDestroy by backup agent of " + data.appInfo);
                e.printStackTrace();
            }
            backupAgents.remove(packageName);
        } else {
            Slog.w(TAG, "Attempt to destroy unknown backup agent " + data);
        }
    }

    private ArrayMap<String, BackupAgent> getBackupAgentsForUser(int userId) {
        ArrayMap<String, BackupAgent> backupAgents = mBackupAgentsByUser.get(userId);
        if (backupAgents == null) {
            backupAgents = new ArrayMap<>();
            mBackupAgentsByUser.put(userId, backupAgents);
        }
        return backupAgents;
    }

    @UnsupportedAppUsage
    private void handleCreateService(CreateServiceData data) {
        // If we are getting ready to gc after going to the background, well
        // we are back active so skip it.
        unscheduleGcIdler();

        LoadedApk packageInfo = getPackageInfoNoCheck(
                data.info.applicationInfo, data.compatInfo);
        Service service = null;
        try {
            java.lang.ClassLoader cl = packageInfo.getClassLoader();
            service = packageInfo.getAppFactory()
                    .instantiateService(cl, data.info.name, data.intent);
        } catch (Exception e) {
            if (!mInstrumentation.onException(service, e)) {
                throw new RuntimeException(
                    "Unable to instantiate service " + data.info.name
                    + ": " + e.toString(), e);
            }
        }

        try {
            if (localLOGV) Slog.v(TAG, "Creating service " + data.info.name);

            ContextImpl context = ContextImpl.createAppContext(this, packageInfo);
            context.setOuterContext(service);

            Application app = packageInfo.makeApplication(false, mInstrumentation);
            service.attach(context, this, data.info.name, data.token, app,
                    ActivityManager.getService());
            service.onCreate();
            mServices.put(data.token, service);
            try {
                ActivityManager.getService().serviceDoneExecuting(
                        data.token, SERVICE_DONE_EXECUTING_ANON, 0, 0);
            } catch (RemoteException e) {
                throw e.rethrowFromSystemServer();
            }
        } catch (Exception e) {
            if (!mInstrumentation.onException(service, e)) {
                throw new RuntimeException(
                    "Unable to create service " + data.info.name
                    + ": " + e.toString(), e);
            }
        }
    }

    private void handleBindService(BindServiceData data) {
        Service s = mServices.get(data.token);
        if (DEBUG_SERVICE)
            Slog.v(TAG, "handleBindService s=" + s + " rebind=" + data.rebind);
        if (s != null) {
            try {
                data.intent.setExtrasClassLoader(s.getClassLoader());
                data.intent.prepareToEnterProcess();
                try {
                    if (!data.rebind) {
                        IBinder binder = s.onBind(data.intent);
                        ActivityManager.getService().publishService(
                                data.token, data.intent, binder);
                    } else {
                        s.onRebind(data.intent);
                        ActivityManager.getService().serviceDoneExecuting(
                                data.token, SERVICE_DONE_EXECUTING_ANON, 0, 0);
                    }
                } catch (RemoteException ex) {
                    throw ex.rethrowFromSystemServer();
                }
            } catch (Exception e) {
                if (!mInstrumentation.onException(s, e)) {
                    throw new RuntimeException(
                            "Unable to bind to service " + s
                            + " with " + data.intent + ": " + e.toString(), e);
                }
            }
        }
    }

    private void handleUnbindService(BindServiceData data) {
        Service s = mServices.get(data.token);
        if (s != null) {
            try {
                data.intent.setExtrasClassLoader(s.getClassLoader());
                data.intent.prepareToEnterProcess();
                boolean doRebind = s.onUnbind(data.intent);
                try {
                    if (doRebind) {
                        ActivityManager.getService().unbindFinished(
                                data.token, data.intent, doRebind);
                    } else {
                        ActivityManager.getService().serviceDoneExecuting(
                                data.token, SERVICE_DONE_EXECUTING_ANON, 0, 0);
                    }
                } catch (RemoteException ex) {
                    throw ex.rethrowFromSystemServer();
                }
            } catch (Exception e) {
                if (!mInstrumentation.onException(s, e)) {
                    throw new RuntimeException(
                            "Unable to unbind to service " + s
                            + " with " + data.intent + ": " + e.toString(), e);
                }
            }
        }
    }

    private void handleDumpService(DumpComponentInfo info) {
        final StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskWrites();
        try {
            Service s = mServices.get(info.token);
            if (s != null) {
                PrintWriter pw = new FastPrintWriter(new FileOutputStream(
                        info.fd.getFileDescriptor()));
                s.dump(info.fd.getFileDescriptor(), pw, info.args);
                pw.flush();
            }
        } finally {
            IoUtils.closeQuietly(info.fd);
            StrictMode.setThreadPolicy(oldPolicy);
        }
    }

    private void handleDumpActivity(DumpComponentInfo info) {
        final StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskWrites();
        try {
            ActivityClientRecord r = mActivities.get(info.token);
            if (r != null && r.activity != null) {
                PrintWriter pw = new FastPrintWriter(new FileOutputStream(
                        info.fd.getFileDescriptor()));
                r.activity.dump(info.prefix, info.fd.getFileDescriptor(), pw, info.args);
                pw.flush();
            }
        } finally {
            IoUtils.closeQuietly(info.fd);
            StrictMode.setThreadPolicy(oldPolicy);
        }
    }

    private void handleDumpProvider(DumpComponentInfo info) {
        final StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskWrites();
        try {
            ProviderClientRecord r = mLocalProviders.get(info.token);
            if (r != null && r.mLocalProvider != null) {
                PrintWriter pw = new FastPrintWriter(new FileOutputStream(
                        info.fd.getFileDescriptor()));
                r.mLocalProvider.dump(info.fd.getFileDescriptor(), pw, info.args);
                pw.flush();
            }
        } finally {
            IoUtils.closeQuietly(info.fd);
            StrictMode.setThreadPolicy(oldPolicy);
        }
    }

    private void handleServiceArgs(ServiceArgsData data) {
        Service s = mServices.get(data.token);
        if (s != null) {
            try {
                if (data.args != null) {
                    data.args.setExtrasClassLoader(s.getClassLoader());
                    data.args.prepareToEnterProcess();
                }
                int res;
                if (!data.taskRemoved) {
                    res = s.onStartCommand(data.args, data.flags, data.startId);
                } else {
                    s.onTaskRemoved(data.args);
                    res = Service.START_TASK_REMOVED_COMPLETE;
                }

                QueuedWork.waitToFinish();

                try {
                    ActivityManager.getService().serviceDoneExecuting(
                            data.token, SERVICE_DONE_EXECUTING_START, data.startId, res);
                } catch (RemoteException e) {
                    throw e.rethrowFromSystemServer();
                }
            } catch (Exception e) {
                if (!mInstrumentation.onException(s, e)) {
                    throw new RuntimeException(
                            "Unable to start service " + s
                            + " with " + data.args + ": " + e.toString(), e);
                }
            }
        }
    }

    private void handleStopService(IBinder token) {
        Service s = mServices.remove(token);
        if (s != null) {
            try {
                if (localLOGV) Slog.v(TAG, "Destroying service " + s);
                s.onDestroy();
                s.detachAndCleanUp();
                Context context = s.getBaseContext();
                if (context instanceof ContextImpl) {
                    final String who = s.getClassName();
                    ((ContextImpl) context).scheduleFinalCleanup(who, "Service");
                }

                QueuedWork.waitToFinish();

                try {
                    ActivityManager.getService().serviceDoneExecuting(
                            token, SERVICE_DONE_EXECUTING_STOP, 0, 0);
                } catch (RemoteException e) {
                    throw e.rethrowFromSystemServer();
                }
            } catch (Exception e) {
                if (!mInstrumentation.onException(s, e)) {
                    throw new RuntimeException(
                            "Unable to stop service " + s
                            + ": " + e.toString(), e);
                }
                Slog.i(TAG, "handleStopService: exception for " + token, e);
            }
        } else {
            Slog.i(TAG, "handleStopService: token=" + token + " not found.");
        }
        //Slog.i(TAG, "Running services: " + mServices);
    }

    /**
     * Resume the activity.
     * @param token Target activity token.
     * @param finalStateRequest Flag indicating if this is part of final state resolution for a
     *                          transaction.
     * @param reason Reason for performing the action.
     *
     * @return The {@link ActivityClientRecord} that was resumed, {@code null} otherwise.
     */
    @VisibleForTesting
    public ActivityClientRecord performResumeActivity(IBinder token, boolean finalStateRequest,
            String reason) {
        final ActivityClientRecord r = mActivities.get(token);
        if (localLOGV) {
            Slog.v(TAG, "Performing resume of " + r + " finished=" + r.activity.mFinished);
        }
        if (r == null || r.activity.mFinished) {
            return null;
        }
        if (r.getLifecycleState() == ON_RESUME) {
            if (!finalStateRequest) {
                final RuntimeException e = new IllegalStateException(
                        "Trying to resume activity which is already resumed");
                Slog.e(TAG, e.getMessage(), e);
                Slog.e(TAG, r.getStateString());
                // TODO(lifecycler): A double resume request is possible when an activity
                // receives two consequent transactions with relaunch requests and "resumed"
                // final state requests and the second relaunch is omitted. We still try to
                // handle two resume requests for the final state. For cases other than this
                // one, we don't expect it to happen.
            }
            return null;
        }
        if (finalStateRequest) {
            r.hideForNow = false;
            r.activity.mStartedActivity = false;
        }
        try {
            r.activity.onStateNotSaved();
            r.activity.mFragments.noteStateNotSaved();
            checkAndBlockForNetworkAccess();
            if (r.pendingIntents != null) {
                deliverNewIntents(r, r.pendingIntents);
                r.pendingIntents = null;
            }
            if (r.pendingResults != null) {
                deliverResults(r, r.pendingResults, reason);
                r.pendingResults = null;
            }
            r.activity.performResume(r.startsNotResumed, reason);

            r.state = null;
            r.persistentState = null;
            r.setState(ON_RESUME);

            reportTopResumedActivityChanged(r, r.isTopResumedActivity, "topWhenResuming");
        } catch (Exception e) {
            if (!mInstrumentation.onException(r.activity, e)) {
                throw new RuntimeException("Unable to resume activity "
                        + r.intent.getComponent().toShortString() + ": " + e.toString(), e);
            }
        }
        return r;
    }

    static final void cleanUpPendingRemoveWindows(ActivityClientRecord r, boolean force) {
        if (r.mPreserveWindow && !force) {
            return;
        }
        if (r.mPendingRemoveWindow != null) {
            r.mPendingRemoveWindowManager.removeViewImmediate(
                    r.mPendingRemoveWindow.getDecorView());
            IBinder wtoken = r.mPendingRemoveWindow.getDecorView().getWindowToken();
            if (wtoken != null) {
                WindowManagerGlobal.getInstance().closeAll(wtoken,
                        r.activity.getClass().getName(), "Activity");
            }
        }
        r.mPendingRemoveWindow = null;
        r.mPendingRemoveWindowManager = null;
    }

    @Override
    public void handleResumeActivity(IBinder token, boolean finalStateRequest, boolean isForward,
            String reason) {
        // If we are getting ready to gc after going to the background, well
        // we are back active so skip it.
        unscheduleGcIdler();
        mSomeActivitiesChanged = true;

        // TODO Push resumeArgs into the activity for consideration
        final ActivityClientRecord r = performResumeActivity(token, finalStateRequest, reason);
        if (r == null) {
            // We didn't actually resume the activity, so skipping any follow-up actions.
            return;
        }
        if (mActivitiesToBeDestroyed.containsKey(token)) {
            // Although the activity is resumed, it is going to be destroyed. So the following
            // UI operations are unnecessary and also prevents exception because its token may
            // be gone that window manager cannot recognize it. All necessary cleanup actions
            // performed below will be done while handling destruction.
            return;
        }

        final Activity a = r.activity;

        if (localLOGV) {
            Slog.v(TAG, "Resume " + r + " started activity: " + a.mStartedActivity
                    + ", hideForNow: " + r.hideForNow + ", finished: " + a.mFinished);
        }

        final int forwardBit = isForward
                ? WindowManager.LayoutParams.SOFT_INPUT_IS_FORWARD_NAVIGATION : 0;

        // If the window hasn't yet been added to the window manager,
        // and this guy didn't finish itself or start another activity,
        // then go ahead and add the window.
        boolean willBeVisible = !a.mStartedActivity;
        if (!willBeVisible) {
            try {
                willBeVisible = ActivityTaskManager.getService().willActivityBeVisible(
                        a.getActivityToken());
            } catch (RemoteException e) {
                throw e.rethrowFromSystemServer();
            }
        }
        if (r.window == null && !a.mFinished && willBeVisible) {
            r.window = r.activity.getWindow();
            View decor = r.window.getDecorView();
            decor.setVisibility(View.INVISIBLE);
            ViewManager wm = a.getWindowManager();
            WindowManager.LayoutParams l = r.window.getAttributes();
            a.mDecor = decor;
            l.type = WindowManager.LayoutParams.TYPE_BASE_APPLICATION;
            l.softInputMode |= forwardBit;
            if (r.mPreserveWindow) {
                a.mWindowAdded = true;
                r.mPreserveWindow = false;
                // Normally the ViewRoot sets up callbacks with the Activity
                // in addView->ViewRootImpl#setView. If we are instead reusing
                // the decor view we have to notify the view root that the
                // callbacks may have changed.
                ViewRootImpl impl = decor.getViewRootImpl();
                if (impl != null) {
                    impl.notifyChildRebuilt();
                }
            }
            if (a.mVisibleFromClient) {
                if (!a.mWindowAdded) {
                    a.mWindowAdded = true;
                    wm.addView(decor, l);
                } else {
                    // The activity will get a callback for this {@link LayoutParams} change
                    // earlier. However, at that time the decor will not be set (this is set
                    // in this method), so no action will be taken. This call ensures the
                    // callback occurs with the decor set.
                    a.onWindowAttributesChanged(l);
                }
            }

            // If the window has already been added, but during resume
            // we started another activity, then don't yet make the
            // window visible.
        } else if (!willBeVisible) {
            if (localLOGV) Slog.v(TAG, "Launch " + r + " mStartedActivity set");
            r.hideForNow = true;
        }

        // Get rid of anything left hanging around.
        cleanUpPendingRemoveWindows(r, false /* force */);

        // The window is now visible if it has been added, we are not
        // simply finishing, and we are not starting another activity.
        if (!r.activity.mFinished && willBeVisible && r.activity.mDecor != null && !r.hideForNow) {
            if (r.newConfig != null) {
                performConfigurationChangedForActivity(r, r.newConfig);
                if (DEBUG_CONFIGURATION) {
                    Slog.v(TAG, "Resuming activity " + r.activityInfo.name + " with newConfig "
                            + r.activity.mCurrentConfig);
                }
                r.newConfig = null;
            }
            if (localLOGV) Slog.v(TAG, "Resuming " + r + " with isForward=" + isForward);
            WindowManager.LayoutParams l = r.window.getAttributes();
            if ((l.softInputMode
                    & WindowManager.LayoutParams.SOFT_INPUT_IS_FORWARD_NAVIGATION)
                    != forwardBit) {
                l.softInputMode = (l.softInputMode
                        & (~WindowManager.LayoutParams.SOFT_INPUT_IS_FORWARD_NAVIGATION))
                        | forwardBit;
            }

            if (r.activity.mVisibleFromClient) {
                ViewManager wm = a.getWindowManager();
                View decor = r.window.getDecorView();
                wm.updateViewLayout(decor, l);
             }

            r.activity.mVisibleFromServer = true;
            mNumVisibleActivities++;
            if (r.activity.mVisibleFromClient) {
                r.activity.makeVisible();
            }
        }

        r.nextIdle = mNewActivities;
        mNewActivities = r;
        if (localLOGV) Slog.v(TAG, "Scheduling idle handler for " + r);
        Looper.myQueue().addIdleHandler(new Idler());
    }


    @Override
    public void handleTopResumedActivityChanged(IBinder token, boolean onTop, String reason) {
        ActivityClientRecord r = mActivities.get(token);
        if (r == null || r.activity == null) {
            Slog.w(TAG, "Not found target activity to report position change for token: " + token);
            return;
        }

        if (DEBUG_ORDER) {
            Slog.d(TAG, "Received position change to top: " + onTop + " for activity: " + r);
        }

        if (r.isTopResumedActivity == onTop) {
            throw new IllegalStateException("Activity top position already set to onTop=" + onTop);
        }

        r.isTopResumedActivity = onTop;

        if (r.getLifecycleState() == ON_RESUME) {
            reportTopResumedActivityChanged(r, onTop, "topStateChangedWhenResumed");
        } else {
            if (DEBUG_ORDER) {
                Slog.d(TAG, "Won't deliver top position change in state=" + r.getLifecycleState());
            }
        }
    }

    /**
     * Call {@link Activity#onTopResumedActivityChanged(boolean)} if its top resumed state changed
     * since the last report.
     */
    private void reportTopResumedActivityChanged(ActivityClientRecord r, boolean onTop,
            String reason) {
        if (r.lastReportedTopResumedState != onTop) {
            r.lastReportedTopResumedState = onTop;
            r.activity.performTopResumedActivityChanged(onTop, reason);
        }
    }

    @Override
    public void handlePauseActivity(IBinder token, boolean finished, boolean userLeaving,
            int configChanges, PendingTransactionActions pendingActions, String reason) {
        ActivityClientRecord r = mActivities.get(token);
        if (r != null) {
            if (userLeaving) {
                performUserLeavingActivity(r);
            }

            r.activity.mConfigChangeFlags |= configChanges;
            performPauseActivity(r, finished, reason, pendingActions);

            // Make sure any pending writes are now committed.
            if (r.isPreHoneycomb()) {
                QueuedWork.waitToFinish();
            }
            mSomeActivitiesChanged = true;
        }
    }

    final void performUserLeavingActivity(ActivityClientRecord r) {
        mInstrumentation.callActivityOnUserLeaving(r.activity);
    }

    final Bundle performPauseActivity(IBinder token, boolean finished, String reason,
            PendingTransactionActions pendingActions) {
        ActivityClientRecord r = mActivities.get(token);
        return r != null ? performPauseActivity(r, finished, reason, pendingActions) : null;
    }

    /**
     * Pause the activity.
     * @return Saved instance state for pre-Honeycomb apps if it was saved, {@code null} otherwise.
     */
    private Bundle performPauseActivity(ActivityClientRecord r, boolean finished, String reason,
            PendingTransactionActions pendingActions) {
        if (r.paused) {
            if (r.activity.mFinished) {
                // If we are finishing, we won't call onResume() in certain cases.
                // So here we likewise don't want to call onPause() if the activity
                // isn't resumed.
                return null;
            }
            RuntimeException e = new RuntimeException(
                    "Performing pause of activity that is not resumed: "
                    + r.intent.getComponent().toShortString());
            Slog.e(TAG, e.getMessage(), e);
        }
        if (finished) {
            r.activity.mFinished = true;
        }

        // Pre-Honeycomb apps always save their state before pausing
        final boolean shouldSaveState = !r.activity.mFinished && r.isPreHoneycomb();
        if (shouldSaveState) {
            callActivityOnSaveInstanceState(r);
        }

        performPauseActivityIfNeeded(r, reason);

        // Notify any outstanding on paused listeners
        ArrayList<OnActivityPausedListener> listeners;
        synchronized (mOnPauseListeners) {
            listeners = mOnPauseListeners.remove(r.activity);
        }
        int size = (listeners != null ? listeners.size() : 0);
        for (int i = 0; i < size; i++) {
            listeners.get(i).onPaused(r.activity);
        }

        final Bundle oldState = pendingActions != null ? pendingActions.getOldState() : null;
        if (oldState != null) {
            // We need to keep around the original state, in case we need to be created again.
            // But we only do this for pre-Honeycomb apps, which always save their state when
            // pausing, so we can not have them save their state when restarting from a paused
            // state. For HC and later, we want to (and can) let the state be saved as the
            // normal part of stopping the activity.
            if (r.isPreHoneycomb()) {
                r.state = oldState;
            }
        }

        return shouldSaveState ? r.state : null;
    }

    private void performPauseActivityIfNeeded(ActivityClientRecord r, String reason) {
        if (r.paused) {
            // You are already paused silly...
            return;
        }

        // Always reporting top resumed position loss when pausing an activity. If necessary, it
        // will be restored in performResumeActivity().
        reportTopResumedActivityChanged(r, false /* onTop */, "pausing");

        try {
            r.activity.mCalled = false;
            mInstrumentation.callActivityOnPause(r.activity);
            if (!r.activity.mCalled) {
                throw new SuperNotCalledException("Activity " + safeToComponentShortString(r.intent)
                        + " did not call through to super.onPause()");
            }
        } catch (SuperNotCalledException e) {
            throw e;
        } catch (Exception e) {
            if (!mInstrumentation.onException(r.activity, e)) {
                throw new RuntimeException("Unable to pause activity "
                        + safeToComponentShortString(r.intent) + ": " + e.toString(), e);
            }
        }
        r.setState(ON_PAUSE);
    }

    /** Called from {@link LocalActivityManager}. */
    @UnsupportedAppUsage
    final void performStopActivity(IBinder token, boolean saveState, String reason) {
        ActivityClientRecord r = mActivities.get(token);
        performStopActivityInner(r, null /* stopInfo */, false /* keepShown */, saveState,
                false /* finalStateRequest */, reason);
    }

    private static final class ProviderRefCount {
        public final ContentProviderHolder holder;
        public final ProviderClientRecord client;
        public int stableCount;
        public int unstableCount;

        // When this is set, the stable and unstable ref counts are 0 and
        // we have a pending operation scheduled to remove the ref count
        // from the activity manager.  On the activity manager we are still
        // holding an unstable ref, though it is not reflected in the counts
        // here.
        public boolean removePending;

        ProviderRefCount(ContentProviderHolder inHolder,
                ProviderClientRecord inClient, int sCount, int uCount) {
            holder = inHolder;
            client = inClient;
            stableCount = sCount;
            unstableCount = uCount;
        }
    }

    /**
     * Core implementation of stopping an activity.  Note this is a little
     * tricky because the server's meaning of stop is slightly different
     * than our client -- for the server, stop means to save state and give
     * it the result when it is done, but the window may still be visible.
     * For the client, we want to call onStop()/onStart() to indicate when
     * the activity's UI visibility changes.
     * @param r Target activity client record.
     * @param info Action that will report activity stop to server.
     * @param keepShown Flag indicating whether the activity is still shown.
     * @param saveState Flag indicating whether the activity state should be saved.
     * @param finalStateRequest Flag indicating if this call is handling final lifecycle state
     *                          request for a transaction.
     * @param reason Reason for performing this operation.
     */
    private void performStopActivityInner(ActivityClientRecord r, StopInfo info, boolean keepShown,
            boolean saveState, boolean finalStateRequest, String reason) {
        if (localLOGV) Slog.v(TAG, "Performing stop of " + r);
        if (r != null) {
            if (!keepShown && r.stopped) {
                if (r.activity.mFinished) {
                    // If we are finishing, we won't call onResume() in certain
                    // cases.  So here we likewise don't want to call onStop()
                    // if the activity isn't resumed.
                    return;
                }
                if (!finalStateRequest) {
                    final RuntimeException e = new RuntimeException(
                            "Performing stop of activity that is already stopped: "
                                    + r.intent.getComponent().toShortString());
                    Slog.e(TAG, e.getMessage(), e);
                    Slog.e(TAG, r.getStateString());
                }
            }

            // One must first be paused before stopped...
            performPauseActivityIfNeeded(r, reason);

            if (info != null) {
                try {
                    // First create a thumbnail for the activity...
                    // For now, don't create the thumbnail here; we are
                    // doing that by doing a screen snapshot.
                    info.setDescription(r.activity.onCreateDescription());
                } catch (Exception e) {
                    if (!mInstrumentation.onException(r.activity, e)) {
                        throw new RuntimeException(
                                "Unable to save state of activity "
                                + r.intent.getComponent().toShortString()
                                + ": " + e.toString(), e);
                    }
                }
            }

            if (!keepShown) {
                callActivityOnStop(r, saveState, reason);
            }
        }
    }

    /**
     * Calls {@link Activity#onStop()} and {@link Activity#onSaveInstanceState(Bundle)}, and updates
     * the client record's state.
     * All calls to stop an activity must be done through this method to make sure that
     * {@link Activity#onSaveInstanceState(Bundle)} is also executed in the same call.
     */
    private void callActivityOnStop(ActivityClientRecord r, boolean saveState, String reason) {
        // Before P onSaveInstanceState was called before onStop, starting with P it's
        // called after. Before Honeycomb state was always saved before onPause.
        final boolean shouldSaveState = saveState && !r.activity.mFinished && r.state == null
                && !r.isPreHoneycomb();
        final boolean isPreP = r.isPreP();
        if (shouldSaveState && isPreP) {
            callActivityOnSaveInstanceState(r);
        }

        try {
            r.activity.performStop(r.mPreserveWindow, reason);
        } catch (SuperNotCalledException e) {
            throw e;
        } catch (Exception e) {
            if (!mInstrumentation.onException(r.activity, e)) {
                throw new RuntimeException(
                        "Unable to stop activity "
                                + r.intent.getComponent().toShortString()
                                + ": " + e.toString(), e);
            }
        }
        r.setState(ON_STOP);

        if (shouldSaveState && !isPreP) {
            callActivityOnSaveInstanceState(r);
        }
    }

    private void updateVisibility(ActivityClientRecord r, boolean show) {
        View v = r.activity.mDecor;
        if (v != null) {
            if (show) {
                if (!r.activity.mVisibleFromServer) {
                    r.activity.mVisibleFromServer = true;
                    mNumVisibleActivities++;
                    if (r.activity.mVisibleFromClient) {
                        r.activity.makeVisible();
                    }
                }
                if (r.newConfig != null) {
                    performConfigurationChangedForActivity(r, r.newConfig);
                    if (DEBUG_CONFIGURATION) Slog.v(TAG, "Updating activity vis "
                            + r.activityInfo.name + " with new config "
                            + r.activity.mCurrentConfig);
                    r.newConfig = null;
                }
            } else {
                if (r.activity.mVisibleFromServer) {
                    r.activity.mVisibleFromServer = false;
                    mNumVisibleActivities--;
                    v.setVisibility(View.INVISIBLE);
                }
            }
        }
    }

    @Override
    public void handleStopActivity(IBinder token, boolean show, int configChanges,
            PendingTransactionActions pendingActions, boolean finalStateRequest, String reason) {
        final ActivityClientRecord r = mActivities.get(token);
        r.activity.mConfigChangeFlags |= configChanges;

        final StopInfo stopInfo = new StopInfo();
        performStopActivityInner(r, stopInfo, show, true /* saveState */, finalStateRequest,
                reason);

        if (localLOGV) Slog.v(
            TAG, "Finishing stop of " + r + ": show=" + show
            + " win=" + r.window);

        updateVisibility(r, show);

        // Make sure any pending writes are now committed.
        if (!r.isPreHoneycomb()) {
            QueuedWork.waitToFinish();
        }

        stopInfo.setActivity(r);
        stopInfo.setState(r.state);
        stopInfo.setPersistentState(r.persistentState);
        pendingActions.setStopInfo(stopInfo);
        mSomeActivitiesChanged = true;
    }

    /**
     * Schedule the call to tell the activity manager we have stopped.  We don't do this
     * immediately, because we want to have a chance for any other pending work (in particular
     * memory trim requests) to complete before you tell the activity manager to proceed and allow
     * us to go fully into the background.
     */
    @Override
    public void reportStop(PendingTransactionActions pendingActions) {
        mH.post(pendingActions.getStopInfo());
    }

    @Override
    public void performRestartActivity(IBinder token, boolean start) {
        ActivityClientRecord r = mActivities.get(token);
        if (r.stopped) {
            r.activity.performRestart(start, "performRestartActivity");
            if (start) {
                r.setState(ON_START);
            }
        }
    }

    @Override
    public void handleWindowVisibility(IBinder token, boolean show) {
        ActivityClientRecord r = mActivities.get(token);

        if (r == null) {
            Log.w(TAG, "handleWindowVisibility: no activity for token " + token);
            return;
        }

        if (!show && !r.stopped) {
            performStopActivityInner(r, null /* stopInfo */, show, false /* saveState */,
                    false /* finalStateRequest */, "handleWindowVisibility");
        } else if (show && r.getLifecycleState() == ON_STOP) {
            // If we are getting ready to gc after going to the background, well
            // we are back active so skip it.
            unscheduleGcIdler();

            r.activity.performRestart(true /* start */, "handleWindowVisibility");
            r.setState(ON_START);
        }
        if (r.activity.mDecor != null) {
            if (false) Slog.v(
                TAG, "Handle window " + r + " visibility: " + show);
            updateVisibility(r, show);
        }
        mSomeActivitiesChanged = true;
    }

    // TODO: This method should be changed to use {@link #performStopActivityInner} to perform to
    // stop operation on the activity to reduce code duplication and the chance of fixing a bug in
    // one place and missing the other.
    private void handleSleeping(IBinder token, boolean sleeping) {
        ActivityClientRecord r = mActivities.get(token);

        if (r == null) {
            Log.w(TAG, "handleSleeping: no activity for token " + token);
            return;
        }

        if (sleeping) {
            if (!r.stopped && !r.isPreHoneycomb()) {
                callActivityOnStop(r, true /* saveState */, "sleeping");
            }

            // Make sure any pending writes are now committed.
            if (!r.isPreHoneycomb()) {
                QueuedWork.waitToFinish();
            }

            // Tell activity manager we slept.
            try {
                ActivityTaskManager.getService().activitySlept(r.token);
            } catch (RemoteException ex) {
                throw ex.rethrowFromSystemServer();
            }
        } else {
            if (r.stopped && r.activity.mVisibleFromServer) {
                r.activity.performRestart(true /* start */, "handleSleeping");
                r.setState(ON_START);
            }
        }
    }

    private void handleSetCoreSettings(Bundle coreSettings) {
        synchronized (mResourcesManager) {
            mCoreSettings = coreSettings;
        }
        onCoreSettingsChange();
    }

    private void onCoreSettingsChange() {
        if (updateDebugViewAttributeState()) {
            // request all activities to relaunch for the changes to take place
            relaunchAllActivities(false /* preserveWindows */);
        }
    }

    private boolean updateDebugViewAttributeState() {
        boolean previousState = View.sDebugViewAttributes;

        View.sDebugViewAttributesApplicationPackage = mCoreSettings.getString(
                Settings.Global.DEBUG_VIEW_ATTRIBUTES_APPLICATION_PACKAGE, "");
        String currentPackage = (mBoundApplication != null && mBoundApplication.appInfo != null)
                ? mBoundApplication.appInfo.packageName : "<unknown-app>";
        View.sDebugViewAttributes =
                mCoreSettings.getInt(Settings.Global.DEBUG_VIEW_ATTRIBUTES, 0) != 0
                        || View.sDebugViewAttributesApplicationPackage.equals(currentPackage);
        return previousState != View.sDebugViewAttributes;
    }

    private void relaunchAllActivities(boolean preserveWindows) {
        for (Map.Entry<IBinder, ActivityClientRecord> entry : mActivities.entrySet()) {
            final ActivityClientRecord r = entry.getValue();
            if (!r.activity.mFinished) {
                if (preserveWindows && r.window != null) {
                    r.mPreserveWindow = true;
                }
                scheduleRelaunchActivity(entry.getKey());
            }
        }
    }

    private void handleUpdatePackageCompatibilityInfo(UpdateCompatibilityData data) {
        LoadedApk apk = peekPackageInfo(data.pkg, false);
        if (apk != null) {
            apk.setCompatibilityInfo(data.info);
        }
        apk = peekPackageInfo(data.pkg, true);
        if (apk != null) {
            apk.setCompatibilityInfo(data.info);
        }
        handleConfigurationChanged(mConfiguration, data.info);
        WindowManagerGlobal.getInstance().reportNewConfiguration(mConfiguration);
    }

    private void deliverResults(ActivityClientRecord r, List<ResultInfo> results, String reason) {
        final int N = results.size();
        for (int i=0; i<N; i++) {
            ResultInfo ri = results.get(i);
            try {
                if (ri.mData != null) {
                    ri.mData.setExtrasClassLoader(r.activity.getClassLoader());
                    ri.mData.prepareToEnterProcess();
                }
                if (DEBUG_RESULTS) Slog.v(TAG,
                        "Delivering result to activity " + r + " : " + ri);
                r.activity.dispatchActivityResult(ri.mResultWho,
                        ri.mRequestCode, ri.mResultCode, ri.mData, reason);
            } catch (Exception e) {
                if (!mInstrumentation.onException(r.activity, e)) {
                    throw new RuntimeException(
                            "Failure delivering result " + ri + " to activity "
                            + r.intent.getComponent().toShortString()
                            + ": " + e.toString(), e);
                }
            }
        }
    }

    @Override
    public void handleSendResult(IBinder token, List<ResultInfo> results, String reason) {
        ActivityClientRecord r = mActivities.get(token);
        if (DEBUG_RESULTS) Slog.v(TAG, "Handling send result to " + r);
        if (r != null) {
            final boolean resumed = !r.paused;
            if (!r.activity.mFinished && r.activity.mDecor != null
                    && r.hideForNow && resumed) {
                // We had hidden the activity because it started another
                // one...  we have gotten a result back and we are not
                // paused, so make sure our window is visible.
                updateVisibility(r, true);
            }
            if (resumed) {
                try {
                    // Now we are idle.
                    r.activity.mCalled = false;
                    mInstrumentation.callActivityOnPause(r.activity);
                    if (!r.activity.mCalled) {
                        throw new SuperNotCalledException(
                            "Activity " + r.intent.getComponent().toShortString()
                            + " did not call through to super.onPause()");
                    }
                } catch (SuperNotCalledException e) {
                    throw e;
                } catch (Exception e) {
                    if (!mInstrumentation.onException(r.activity, e)) {
                        throw new RuntimeException(
                                "Unable to pause activity "
                                + r.intent.getComponent().toShortString()
                                + ": " + e.toString(), e);
                    }
                }
            }
            checkAndBlockForNetworkAccess();
            deliverResults(r, results, reason);
            if (resumed) {
                r.activity.performResume(false, reason);
            }
        }
    }

    /** Core implementation of activity destroy call. */
    ActivityClientRecord performDestroyActivity(IBinder token, boolean finishing,
            int configChanges, boolean getNonConfigInstance, String reason) {
        ActivityClientRecord r = mActivities.get(token);
        Class<? extends Activity> activityClass = null;
        if (localLOGV) Slog.v(TAG, "Performing finish of " + r);
        if (r != null) {
            activityClass = r.activity.getClass();
            r.activity.mConfigChangeFlags |= configChanges;
            if (finishing) {
                r.activity.mFinished = true;
            }

            performPauseActivityIfNeeded(r, "destroy");

            if (!r.stopped) {
                callActivityOnStop(r, false /* saveState */, "destroy");
            }
            if (getNonConfigInstance) {
                try {
                    r.lastNonConfigurationInstances
                            = r.activity.retainNonConfigurationInstances();
                } catch (Exception e) {
                    if (!mInstrumentation.onException(r.activity, e)) {
                        throw new RuntimeException(
                                "Unable to retain activity "
                                + r.intent.getComponent().toShortString()
                                + ": " + e.toString(), e);
                    }
                }
            }
            try {
                r.activity.mCalled = false;
                mInstrumentation.callActivityOnDestroy(r.activity);
                if (!r.activity.mCalled) {
                    throw new SuperNotCalledException(
                        "Activity " + safeToComponentShortString(r.intent) +
                        " did not call through to super.onDestroy()");
                }
                if (r.window != null) {
                    r.window.closeAllPanels();
                }
            } catch (SuperNotCalledException e) {
                throw e;
            } catch (Exception e) {
                if (!mInstrumentation.onException(r.activity, e)) {
                    throw new RuntimeException(
                            "Unable to destroy activity " + safeToComponentShortString(r.intent)
                            + ": " + e.toString(), e);
                }
            }
            r.setState(ON_DESTROY);
        }
        schedulePurgeIdler();
        // updatePendingActivityConfiguration() reads from mActivities to update
        // ActivityClientRecord which runs in a different thread. Protect modifications to
        // mActivities to avoid race.
        synchronized (mResourcesManager) {
            mActivities.remove(token);
        }
        StrictMode.decrementExpectedActivityCount(activityClass);
        return r;
    }

    private static String safeToComponentShortString(Intent intent) {
        ComponentName component = intent.getComponent();
        return component == null ? "[Unknown]" : component.toShortString();
    }

    @Override
    public Map<IBinder, ClientTransactionItem> getActivitiesToBeDestroyed() {
        return mActivitiesToBeDestroyed;
    }

    @Override
    public void handleDestroyActivity(IBinder token, boolean finishing, int configChanges,
            boolean getNonConfigInstance, String reason) {
        ActivityClientRecord r = performDestroyActivity(token, finishing,
                configChanges, getNonConfigInstance, reason);
        if (r != null) {
            cleanUpPendingRemoveWindows(r, finishing);
            WindowManager wm = r.activity.getWindowManager();
            View v = r.activity.mDecor;
            if (v != null) {
                if (r.activity.mVisibleFromServer) {
                    mNumVisibleActivities--;
                }
                IBinder wtoken = v.getWindowToken();
                if (r.activity.mWindowAdded) {
                    if (r.mPreserveWindow) {
                        // Hold off on removing this until the new activity's
                        // window is being added.
                        r.mPendingRemoveWindow = r.window;
                        r.mPendingRemoveWindowManager = wm;
                        // We can only keep the part of the view hierarchy that we control,
                        // everything else must be removed, because it might not be able to
                        // behave properly when activity is relaunching.
                        r.window.clearContentView();
                    } else {
                        wm.removeViewImmediate(v);
                    }
                }
                if (wtoken != null && r.mPendingRemoveWindow == null) {
                    WindowManagerGlobal.getInstance().closeAll(wtoken,
                            r.activity.getClass().getName(), "Activity");
                } else if (r.mPendingRemoveWindow != null) {
                    // We're preserving only one window, others should be closed so app views
                    // will be detached before the final tear down. It should be done now because
                    // some components (e.g. WebView) rely on detach callbacks to perform receiver
                    // unregister and other cleanup.
                    WindowManagerGlobal.getInstance().closeAllExceptView(token, v,
                            r.activity.getClass().getName(), "Activity");
                }
                r.activity.mDecor = null;
            }
            if (r.mPendingRemoveWindow == null) {
                // If we are delaying the removal of the activity window, then
                // we can't clean up all windows here.  Note that we can't do
                // so later either, which means any windows that aren't closed
                // by the app will leak.  Well we try to warning them a lot
                // about leaking windows, because that is a bug, so if they are
                // using this recreate facility then they get to live with leaks.
                WindowManagerGlobal.getInstance().closeAll(token,
                        r.activity.getClass().getName(), "Activity");
            }

            // Mocked out contexts won't be participating in the normal
            // process lifecycle, but if we're running with a proper
            // ApplicationContext we need to have it tear down things
            // cleanly.
            Context c = r.activity.getBaseContext();
            if (c instanceof ContextImpl) {
                ((ContextImpl) c).scheduleFinalCleanup(
                        r.activity.getClass().getName(), "Activity");
            }
        }
        if (finishing) {
            try {
                ActivityTaskManager.getService().activityDestroyed(token);
            } catch (RemoteException ex) {
                throw ex.rethrowFromSystemServer();
            }
        }
        mSomeActivitiesChanged = true;
    }

    @Override
    public ActivityClientRecord prepareRelaunchActivity(IBinder token,
            List<ResultInfo> pendingResults, List<ReferrerIntent> pendingNewIntents,
            int configChanges, MergedConfiguration config, boolean preserveWindow) {
        ActivityClientRecord target = null;
        boolean scheduleRelaunch = false;

        synchronized (mResourcesManager) {
            for (int i=0; i<mRelaunchingActivities.size(); i++) {
                ActivityClientRecord r = mRelaunchingActivities.get(i);
                if (DEBUG_ORDER) Slog.d(TAG, "requestRelaunchActivity: " + this + ", trying: " + r);
                if (r.token == token) {
                    target = r;
                    if (pendingResults != null) {
                        if (r.pendingResults != null) {
                            r.pendingResults.addAll(pendingResults);
                        } else {
                            r.pendingResults = pendingResults;
                        }
                    }
                    if (pendingNewIntents != null) {
                        if (r.pendingIntents != null) {
                            r.pendingIntents.addAll(pendingNewIntents);
                        } else {
                            r.pendingIntents = pendingNewIntents;
                        }
                    }
                    break;
                }
            }

            if (target == null) {
                if (DEBUG_ORDER) Slog.d(TAG, "requestRelaunchActivity: target is null");
                target = new ActivityClientRecord();
                target.token = token;
                target.pendingResults = pendingResults;
                target.pendingIntents = pendingNewIntents;
                target.mPreserveWindow = preserveWindow;
                mRelaunchingActivities.add(target);
                scheduleRelaunch = true;
            }
            target.createdConfig = config.getGlobalConfiguration();
            target.overrideConfig = config.getOverrideConfiguration();
            target.pendingConfigChanges |= configChanges;
        }

        return scheduleRelaunch ? target : null;
    }

    @Override
    public void handleRelaunchActivity(ActivityClientRecord tmp,
            PendingTransactionActions pendingActions) {
        // If we are getting ready to gc after going to the background, well
        // we are back active so skip it.
        unscheduleGcIdler();
        mSomeActivitiesChanged = true;

        Configuration changedConfig = null;
        int configChanges = 0;

        // First: make sure we have the most recent configuration and most
        // recent version of the activity, or skip it if some previous call
        // had taken a more recent version.
        synchronized (mResourcesManager) {
            int N = mRelaunchingActivities.size();
            IBinder token = tmp.token;
            tmp = null;
            for (int i=0; i<N; i++) {
                ActivityClientRecord r = mRelaunchingActivities.get(i);
                if (r.token == token) {
                    tmp = r;
                    configChanges |= tmp.pendingConfigChanges;
                    mRelaunchingActivities.remove(i);
                    i--;
                    N--;
                }
            }

            if (tmp == null) {
                if (DEBUG_CONFIGURATION) Slog.v(TAG, "Abort, activity not relaunching!");
                return;
            }

            if (DEBUG_CONFIGURATION) Slog.v(TAG, "Relaunching activity "
                    + tmp.token + " with configChanges=0x"
                    + Integer.toHexString(configChanges));

            if (mPendingConfiguration != null) {
                changedConfig = mPendingConfiguration;
                mPendingConfiguration = null;
            }
        }

        if (tmp.createdConfig != null) {
            // If the activity manager is passing us its current config,
            // assume that is really what we want regardless of what we
            // may have pending.
            if (mConfiguration == null
                    || (tmp.createdConfig.isOtherSeqNewer(mConfiguration)
                            && mConfiguration.diff(tmp.createdConfig) != 0)) {
                if (changedConfig == null
                        || tmp.createdConfig.isOtherSeqNewer(changedConfig)) {
                    changedConfig = tmp.createdConfig;
                }
            }
        }

        if (DEBUG_CONFIGURATION) Slog.v(TAG, "Relaunching activity "
                + tmp.token + ": changedConfig=" + changedConfig);

        // If there was a pending configuration change, execute it first.
        if (changedConfig != null) {
            mCurDefaultDisplayDpi = changedConfig.densityDpi;
            updateDefaultDensity();
            handleConfigurationChanged(changedConfig, null);
        }

        ActivityClientRecord r = mActivities.get(tmp.token);
        if (DEBUG_CONFIGURATION) Slog.v(TAG, "Handling relaunch of " + r);
        if (r == null) {
            return;
        }

        r.activity.mConfigChangeFlags |= configChanges;
        r.mPreserveWindow = tmp.mPreserveWindow;

        r.activity.mChangingConfigurations = true;

        // If we are preserving the main window across relaunches we would also like to preserve
        // the children. However the client side view system does not support preserving
        // the child views so we notify the window manager to expect these windows to
        // be replaced and defer requests to destroy or hide them. This way we can achieve
        // visual continuity. It's important that we do this here prior to pause and destroy
        // as that is when we may hide or remove the child views.
        //
        // There is another scenario, if we have decided locally to relaunch the app from a
        // call to recreate, then none of the windows will be prepared for replacement or
        // preserved by the server, so we want to notify it that we are preparing to replace
        // everything
        try {
            if (r.mPreserveWindow) {
                WindowManagerGlobal.getWindowSession().prepareToReplaceWindows(
                        r.token, true /* childrenOnly */);
            }
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }

        handleRelaunchActivityInner(r, configChanges, tmp.pendingResults, tmp.pendingIntents,
                pendingActions, tmp.startsNotResumed, tmp.overrideConfig, "handleRelaunchActivity");

        if (pendingActions != null) {
            // Only report a successful relaunch to WindowManager.
            pendingActions.setReportRelaunchToWindowManager(true);
        }
    }

    /**
     * Post a message to relaunch the activity. We do this instead of launching it immediately,
     * because this will destroy the activity from which it was called and interfere with the
     * lifecycle changes it was going through before. We need to make sure that we have finished
     * handling current transaction item before relaunching the activity.
     */
    void scheduleRelaunchActivity(IBinder token) {
        mH.removeMessages(H.RELAUNCH_ACTIVITY, token);
        sendMessage(H.RELAUNCH_ACTIVITY, token);
    }

    /** Performs the activity relaunch locally vs. requesting from system-server. */
    private void handleRelaunchActivityLocally(IBinder token) {
        final ActivityClientRecord r = mActivities.get(token);
        if (r == null) {
            Log.w(TAG, "Activity to relaunch no longer exists");
            return;
        }

        final int prevState = r.getLifecycleState();

        if (prevState < ON_RESUME || prevState > ON_STOP) {
            Log.w(TAG, "Activity state must be in [ON_RESUME..ON_STOP] in order to be relaunched,"
                    + "current state is " + prevState);
            return;
        }


        // Initialize a relaunch request.
        final MergedConfiguration mergedConfiguration = new MergedConfiguration(
                r.createdConfig != null ? r.createdConfig : mConfiguration,
                r.overrideConfig);
        final ActivityRelaunchItem activityRelaunchItem = ActivityRelaunchItem.obtain(
                null /* pendingResults */, null /* pendingIntents */, 0 /* configChanges */,
                mergedConfiguration, r.mPreserveWindow);
        // Make sure to match the existing lifecycle state in the end of the transaction.
        final ActivityLifecycleItem lifecycleRequest =
                TransactionExecutorHelper.getLifecycleRequestForCurrentState(r);
        // Schedule the transaction.
        final ClientTransaction transaction = ClientTransaction.obtain(this.mAppThread, r.token);
        transaction.addCallback(activityRelaunchItem);
        transaction.setLifecycleStateRequest(lifecycleRequest);
        executeTransaction(transaction);
    }

    private void handleRelaunchActivityInner(ActivityClientRecord r, int configChanges,
            List<ResultInfo> pendingResults, List<ReferrerIntent> pendingIntents,
            PendingTransactionActions pendingActions, boolean startsNotResumed,
            Configuration overrideConfig, String reason) {
        // Preserve last used intent, it may be set from Activity#setIntent().
        final Intent customIntent = r.activity.mIntent;
        // Need to ensure state is saved.
        if (!r.paused) {
            performPauseActivity(r, false, reason, null /* pendingActions */);
        }
        if (!r.stopped) {
            callActivityOnStop(r, true /* saveState */, reason);
        }

        handleDestroyActivity(r.token, false, configChanges, true, reason);

        r.activity = null;
        r.window = null;
        r.hideForNow = false;
        r.nextIdle = null;
        // Merge any pending results and pending intents; don't just replace them
        if (pendingResults != null) {
            if (r.pendingResults == null) {
                r.pendingResults = pendingResults;
            } else {
                r.pendingResults.addAll(pendingResults);
            }
        }
        if (pendingIntents != null) {
            if (r.pendingIntents == null) {
                r.pendingIntents = pendingIntents;
            } else {
                r.pendingIntents.addAll(pendingIntents);
            }
        }
        r.startsNotResumed = startsNotResumed;
        r.overrideConfig = overrideConfig;

        handleLaunchActivity(r, pendingActions, customIntent);
    }

    @Override
    public void reportRelaunch(IBinder token, PendingTransactionActions pendingActions) {
        try {
            ActivityTaskManager.getService().activityRelaunched(token);
            final ActivityClientRecord r = mActivities.get(token);
            if (pendingActions.shouldReportRelaunchToWindowManager() && r != null
                    && r.window != null) {
                r.window.reportActivityRelaunched();
            }
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    private void callActivityOnSaveInstanceState(ActivityClientRecord r) {
        r.state = new Bundle();
        r.state.setAllowFds(false);
        if (r.isPersistable()) {
            r.persistentState = new PersistableBundle();
            mInstrumentation.callActivityOnSaveInstanceState(r.activity, r.state,
                    r.persistentState);
        } else {
            mInstrumentation.callActivityOnSaveInstanceState(r.activity, r.state);
        }
    }

    ArrayList<ComponentCallbacks2> collectComponentCallbacks(
            boolean allActivities, Configuration newConfig) {
        ArrayList<ComponentCallbacks2> callbacks
                = new ArrayList<ComponentCallbacks2>();

        synchronized (mResourcesManager) {
            final int NAPP = mAllApplications.size();
            for (int i=0; i<NAPP; i++) {
                callbacks.add(mAllApplications.get(i));
            }
            final int NACT = mActivities.size();
            for (int i=0; i<NACT; i++) {
                ActivityClientRecord ar = mActivities.valueAt(i);
                Activity a = ar.activity;
                if (a != null) {
                    Configuration thisConfig = applyConfigCompatMainThread(
                            mCurDefaultDisplayDpi, newConfig,
                            ar.packageInfo.getCompatibilityInfo());
                    if (!ar.activity.mFinished && (allActivities || !ar.paused)) {
                        // If the activity is currently resumed, its configuration
                        // needs to change right now.
                        callbacks.add(a);
                    } else if (thisConfig != null) {
                        // Otherwise, we will tell it about the change
                        // the next time it is resumed or shown.  Note that
                        // the activity manager may, before then, decide the
                        // activity needs to be destroyed to handle its new
                        // configuration.
                        if (DEBUG_CONFIGURATION) {
                            Slog.v(TAG, "Setting activity "
                                    + ar.activityInfo.name + " newConfig=" + thisConfig);
                        }
                        ar.newConfig = thisConfig;
                    }
                }
            }
            final int NSVC = mServices.size();
            for (int i=0; i<NSVC; i++) {
                callbacks.add(mServices.valueAt(i));
            }
        }
        synchronized (mProviderMap) {
            final int NPRV = mLocalProviders.size();
            for (int i=0; i<NPRV; i++) {
                callbacks.add(mLocalProviders.valueAt(i).mLocalProvider);
            }
        }

        return callbacks;
    }

    /**
     * Updates the configuration for an Activity. The ActivityClientRecord's
     * {@link ActivityClientRecord#overrideConfig} is used to compute the final Configuration for
     * that Activity. {@link ActivityClientRecord#tmpConfig} is used as a temporary for delivering
     * the updated Configuration.
     * @param r ActivityClientRecord representing the Activity.
     * @param newBaseConfig The new configuration to use. This may be augmented with
     *                      {@link ActivityClientRecord#overrideConfig}.
     */
    private void performConfigurationChangedForActivity(ActivityClientRecord r,
            Configuration newBaseConfig) {
        performConfigurationChangedForActivity(r, newBaseConfig,
                r.activity.getDisplayId(), false /* movedToDifferentDisplay */);
    }

    /**
     * Updates the configuration for an Activity. The ActivityClientRecord's
     * {@link ActivityClientRecord#overrideConfig} is used to compute the final Configuration for
     * that Activity. {@link ActivityClientRecord#tmpConfig} is used as a temporary for delivering
     * the updated Configuration.
     * @param r ActivityClientRecord representing the Activity.
     * @param newBaseConfig The new configuration to use. This may be augmented with
     *                      {@link ActivityClientRecord#overrideConfig}.
     * @param displayId The id of the display where the Activity currently resides.
     * @param movedToDifferentDisplay Indicates if the activity was moved to different display.
     * @return {@link Configuration} instance sent to client, null if not sent.
     */
    private Configuration performConfigurationChangedForActivity(ActivityClientRecord r,
            Configuration newBaseConfig, int displayId, boolean movedToDifferentDisplay) {
        r.tmpConfig.setTo(newBaseConfig);
        if (r.overrideConfig != null) {
            r.tmpConfig.updateFrom(r.overrideConfig);
        }
        final Configuration reportedConfig = performActivityConfigurationChanged(r.activity,
                r.tmpConfig, r.overrideConfig, displayId, movedToDifferentDisplay);
        freeTextLayoutCachesIfNeeded(r.activity.mCurrentConfig.diff(r.tmpConfig));
        return reportedConfig;
    }

    /**
     * Creates a new Configuration only if override would modify base. Otherwise returns base.
     * @param base The base configuration.
     * @param override The update to apply to the base configuration. Can be null.
     * @return A Configuration representing base with override applied.
     */
    private static Configuration createNewConfigAndUpdateIfNotNull(@NonNull Configuration base,
            @Nullable Configuration override) {
        if (override == null) {
            return base;
        }
        Configuration newConfig = new Configuration(base);
        newConfig.updateFrom(override);
        return newConfig;
    }

    /**
     * Decides whether to update a component's configuration and whether to inform it.
     * @param cb The component callback to notify of configuration change.
     * @param newConfig The new configuration.
     */
    private void performConfigurationChanged(ComponentCallbacks2 cb, Configuration newConfig) {
        if (!REPORT_TO_ACTIVITY) {
            return;
        }

        // ContextThemeWrappers may override the configuration for that context. We must check and
        // apply any overrides defined.
        Configuration contextThemeWrapperOverrideConfig = null;
        if (cb instanceof ContextThemeWrapper) {
            final ContextThemeWrapper contextThemeWrapper = (ContextThemeWrapper) cb;
            contextThemeWrapperOverrideConfig = contextThemeWrapper.getOverrideConfiguration();
        }

        // Apply the ContextThemeWrapper override if necessary.
        // NOTE: Make sure the configurations are not modified, as they are treated as immutable
        // in many places.
        final Configuration configToReport = createNewConfigAndUpdateIfNotNull(
                newConfig, contextThemeWrapperOverrideConfig);
        cb.onConfigurationChanged(configToReport);
    }

    /**
     * Decides whether to update an Activity's configuration and whether to inform it.
     * @param activity The activity to notify of configuration change.
     * @param newConfig The new configuration.
     * @param amOverrideConfig The override config that differentiates the Activity's configuration
     *                         from the base global configuration. This is supplied by
     *                         ActivityManager.
     * @param displayId Id of the display where activity currently resides.
     * @param movedToDifferentDisplay Indicates if the activity was moved to different display.
     * @return Configuration sent to client, null if no changes and not moved to different display.
     */
    private Configuration performActivityConfigurationChanged(Activity activity,
            Configuration newConfig, Configuration amOverrideConfig, int displayId,
            boolean movedToDifferentDisplay) {
        if (activity == null) {
            throw new IllegalArgumentException("No activity provided.");
        }
        final IBinder activityToken = activity.getActivityToken();
        if (activityToken == null) {
            throw new IllegalArgumentException("Activity token not set. Is the activity attached?");
        }

        boolean shouldChangeConfig = false;
        if (activity.mCurrentConfig == null) {
            shouldChangeConfig = true;
        } else {
            // If the new config is the same as the config this Activity is already running with and
            // the override config also didn't change, then don't bother calling
            // onConfigurationChanged.
            final int diff = activity.mCurrentConfig.diffPublicOnly(newConfig);

            if (diff != 0 || !mResourcesManager.isSameResourcesOverrideConfig(activityToken,
                    amOverrideConfig)) {
                // Always send the task-level config changes. For system-level configuration, if
                // this activity doesn't handle any of the config changes, then don't bother
                // calling onConfigurationChanged as we're going to destroy it.
                if (!mUpdatingSystemConfig
                        || (~activity.mActivityInfo.getRealConfigChanged() & diff) == 0
                        || !REPORT_TO_ACTIVITY) {
                    shouldChangeConfig = true;
                }
            }
        }
        if (!shouldChangeConfig && !movedToDifferentDisplay) {
            // Nothing significant, don't proceed with updating and reporting.
            return null;
        }

        // Propagate the configuration change to ResourcesManager and Activity.

        // ContextThemeWrappers may override the configuration for that context. We must check and
        // apply any overrides defined.
        Configuration contextThemeWrapperOverrideConfig = activity.getOverrideConfiguration();

        // We only update an Activity's configuration if this is not a global configuration change.
        // This must also be done before the callback, or else we violate the contract that the new
        // resources are available in ComponentCallbacks2#onConfigurationChanged(Configuration).
        // Also apply the ContextThemeWrapper override if necessary.
        // NOTE: Make sure the configurations are not modified, as they are treated as immutable in
        // many places.
        final Configuration finalOverrideConfig = createNewConfigAndUpdateIfNotNull(
                amOverrideConfig, contextThemeWrapperOverrideConfig);
        mResourcesManager.updateResourcesForActivity(activityToken, finalOverrideConfig,
                displayId, movedToDifferentDisplay);

        activity.mConfigChangeFlags = 0;
        activity.mCurrentConfig = new Configuration(newConfig);

        // Apply the ContextThemeWrapper override if necessary.
        // NOTE: Make sure the configurations are not modified, as they are treated as immutable
        // in many places.
        final Configuration configToReport = createNewConfigAndUpdateIfNotNull(newConfig,
                contextThemeWrapperOverrideConfig);

        if (!REPORT_TO_ACTIVITY) {
            // Not configured to report to activity.
            return configToReport;
        }

        if (movedToDifferentDisplay) {
            activity.dispatchMovedToDisplay(displayId, configToReport);
        }

        if (shouldChangeConfig) {
            activity.mCalled = false;
            activity.onConfigurationChanged(configToReport);
            if (!activity.mCalled) {
                throw new SuperNotCalledException("Activity " + activity.getLocalClassName() +
                                " did not call through to super.onConfigurationChanged()");
            }
        }

        return configToReport;
    }

    public final void applyConfigurationToResources(Configuration config) {
        synchronized (mResourcesManager) {
            mResourcesManager.applyConfigurationToResourcesLocked(config, null);
        }
    }

    final Configuration applyCompatConfiguration(int displayDensity) {
        Configuration config = mConfiguration;
        if (mCompatConfiguration == null) {
            mCompatConfiguration = new Configuration();
        }
        mCompatConfiguration.setTo(mConfiguration);
        if (mResourcesManager.applyCompatConfigurationLocked(displayDensity,
                mCompatConfiguration)) {
            config = mCompatConfiguration;
        }
        return config;
    }

    @Override
    public void handleConfigurationChanged(Configuration config) {
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "configChanged");
        mCurDefaultDisplayDpi = config.densityDpi;
        mUpdatingSystemConfig = true;
        try {
            handleConfigurationChanged(config, null /* compat */);
        } finally {
            mUpdatingSystemConfig = false;
        }
        Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
    }

    private void handleConfigurationChanged(Configuration config, CompatibilityInfo compat) {

        int configDiff;
        boolean equivalent;

        final Theme systemTheme = getSystemContext().getTheme();
        final Theme systemUiTheme = getSystemUiContext().getTheme();

        synchronized (mResourcesManager) {
            if (mPendingConfiguration != null) {
                if (!mPendingConfiguration.isOtherSeqNewer(config)) {
                    config = mPendingConfiguration;
                    mCurDefaultDisplayDpi = config.densityDpi;
                    updateDefaultDensity();
                }
                mPendingConfiguration = null;
            }

            if (config == null) {
                return;
            }

            // This flag tracks whether the new configuration is fundamentally equivalent to the
            // existing configuration. This is necessary to determine whether non-activity callbacks
            // should receive notice when the only changes are related to non-public fields.
            // We do not gate calling {@link #performActivityConfigurationChanged} based on this
            // flag as that method uses the same check on the activity config override as well.
            equivalent = mConfiguration != null && (0 == mConfiguration.diffPublicOnly(config));

            if (DEBUG_CONFIGURATION) Slog.v(TAG, "Handle configuration changed: "
                    + config);

            mResourcesManager.applyConfigurationToResourcesLocked(config, compat);
            updateLocaleListFromAppContext(mInitialApplication.getApplicationContext(),
                    mResourcesManager.getConfiguration().getLocales());

            if (mConfiguration == null) {
                mConfiguration = new Configuration();
            }
            if (!mConfiguration.isOtherSeqNewer(config) && compat == null) {
                return;
            }

            configDiff = mConfiguration.updateFrom(config);
            config = applyCompatConfiguration(mCurDefaultDisplayDpi);

            if ((systemTheme.getChangingConfigurations() & configDiff) != 0) {
                systemTheme.rebase();
            }

            if ((systemUiTheme.getChangingConfigurations() & configDiff) != 0) {
                systemUiTheme.rebase();
            }
        }

        ArrayList<ComponentCallbacks2> callbacks = collectComponentCallbacks(false, config);

        freeTextLayoutCachesIfNeeded(configDiff);

        if (callbacks != null) {
            final int N = callbacks.size();
            for (int i=0; i<N; i++) {
                ComponentCallbacks2 cb = callbacks.get(i);
                if (cb instanceof Activity) {
                    // If callback is an Activity - call corresponding method to consider override
                    // config and avoid onConfigurationChanged if it hasn't changed.
                    Activity a = (Activity) cb;
                    performConfigurationChangedForActivity(mActivities.get(a.getActivityToken()),
                            config);
                } else if (!equivalent) {
                    performConfigurationChanged(cb, config);
                }
            }
        }
    }

    /**
     * Updates the application info.
     *
     * This only works in the system process. Must be called on the main thread.
     */
    public void handleSystemApplicationInfoChanged(@NonNull ApplicationInfo ai) {
        Preconditions.checkState(mSystemThread, "Must only be called in the system process");
        handleApplicationInfoChanged(ai);
    }

    @VisibleForTesting(visibility = PACKAGE)
    public void handleApplicationInfoChanged(@NonNull final ApplicationInfo ai) {
        // Updates triggered by package installation go through a package update
        // receiver. Here we try to capture ApplicationInfo changes that are
        // caused by other sources, such as overlays. That means we want to be as conservative
        // about code changes as possible. Take the diff of the old ApplicationInfo and the new
        // to see if anything needs to change.
        LoadedApk apk;
        LoadedApk resApk;
        // Update all affected loaded packages with new package information
        synchronized (mResourcesManager) {
            WeakReference<LoadedApk> ref = mPackages.get(ai.packageName);
            apk = ref != null ? ref.get() : null;
            ref = mResourcePackages.get(ai.packageName);
            resApk = ref != null ? ref.get() : null;
        }

        final String[] oldResDirs = new String[2];

        if (apk != null) {
            oldResDirs[0] = apk.getResDir();
            final ArrayList<String> oldPaths = new ArrayList<>();
            LoadedApk.makePaths(this, apk.getApplicationInfo(), oldPaths);
            apk.updateApplicationInfo(ai, oldPaths);
        }
        if (resApk != null) {
            oldResDirs[1] = resApk.getResDir();
            final ArrayList<String> oldPaths = new ArrayList<>();
            LoadedApk.makePaths(this, resApk.getApplicationInfo(), oldPaths);
            resApk.updateApplicationInfo(ai, oldPaths);
        }

        synchronized (mResourcesManager) {
            // Update all affected Resources objects to use new ResourcesImpl
            mResourcesManager.applyNewResourceDirsLocked(ai, oldResDirs);
        }

        ApplicationPackageManager.configurationChanged();

        // Trigger a regular Configuration change event, only with a different assetsSeq number
        // so that we actually call through to all components.
        // TODO(adamlesinski): Change this to make use of ActivityManager's upcoming ability to
        // store configurations per-process.
        Configuration newConfig = new Configuration();
        newConfig.assetsSeq = (mConfiguration != null ? mConfiguration.assetsSeq : 0) + 1;
        handleConfigurationChanged(newConfig, null);

        // Preserve windows to avoid black flickers when overlays change.
        relaunchAllActivities(true /* preserveWindows */);
    }

    static void freeTextLayoutCachesIfNeeded(int configDiff) {
        if (configDiff != 0) {
            // Ask text layout engine to free its caches if there is a locale change
            boolean hasLocaleConfigChange = ((configDiff & ActivityInfo.CONFIG_LOCALE) != 0);
            if (hasLocaleConfigChange) {
                Canvas.freeTextLayoutCaches();
                if (DEBUG_CONFIGURATION) Slog.v(TAG, "Cleared TextLayout Caches");
            }
        }
    }

    @Override
    public void updatePendingActivityConfiguration(IBinder activityToken,
            Configuration overrideConfig) {
        final ActivityClientRecord r;
        synchronized (mResourcesManager) {
            r = mActivities.get(activityToken);
        }

        if (r == null) {
            if (DEBUG_CONFIGURATION) {
                Slog.w(TAG, "Not found target activity to update its pending config.");
            }
            return;
        }

        synchronized (r) {
            r.mPendingOverrideConfig = overrideConfig;
        }
    }

    /**
     * Handle new activity configuration and/or move to a different display.
     * @param activityToken Target activity token.
     * @param overrideConfig Activity override config.
     * @param displayId Id of the display where activity was moved to, -1 if there was no move and
     *                  value didn't change.
     */
    @Override
    public void handleActivityConfigurationChanged(IBinder activityToken,
            Configuration overrideConfig, int displayId) {
        ActivityClientRecord r = mActivities.get(activityToken);
        // Check input params.
        if (r == null || r.activity == null) {
            if (DEBUG_CONFIGURATION) Slog.w(TAG, "Not found target activity to report to: " + r);
            return;
        }
        final boolean movedToDifferentDisplay = displayId != INVALID_DISPLAY
                && displayId != r.activity.getDisplayId();

        synchronized (r) {
            if (r.mPendingOverrideConfig != null
                    && !r.mPendingOverrideConfig.isOtherSeqNewer(overrideConfig)) {
                overrideConfig = r.mPendingOverrideConfig;
            }
            r.mPendingOverrideConfig = null;
        }

        if (r.overrideConfig != null && !r.overrideConfig.isOtherSeqNewer(overrideConfig)
                && !movedToDifferentDisplay) {
            if (DEBUG_CONFIGURATION) {
                Slog.v(TAG, "Activity already handled newer configuration so drop this"
                        + " transaction. overrideConfig=" + overrideConfig + " r.overrideConfig="
                        + r.overrideConfig);
            }
            return;
        }

        // Perform updates.
        r.overrideConfig = overrideConfig;
        final ViewRootImpl viewRoot = r.activity.mDecor != null
            ? r.activity.mDecor.getViewRootImpl() : null;

        if (movedToDifferentDisplay) {
            if (DEBUG_CONFIGURATION) Slog.v(TAG, "Handle activity moved to display, activity:"
                    + r.activityInfo.name + ", displayId=" + displayId
                    + ", config=" + overrideConfig);

            final Configuration reportedConfig = performConfigurationChangedForActivity(r,
                    mCompatConfiguration, displayId, true /* movedToDifferentDisplay */);
            if (viewRoot != null) {
                viewRoot.onMovedToDisplay(displayId, reportedConfig);
            }
        } else {
            if (DEBUG_CONFIGURATION) Slog.v(TAG, "Handle activity config changed: "
                    + r.activityInfo.name + ", config=" + overrideConfig);
            performConfigurationChangedForActivity(r, mCompatConfiguration);
        }
        // Notify the ViewRootImpl instance about configuration changes. It may have initiated this
        // update to make sure that resources are updated before updating itself.
        if (viewRoot != null) {
            viewRoot.updateConfiguration(displayId);
        }
        mSomeActivitiesChanged = true;
    }

    final void handleProfilerControl(boolean start, ProfilerInfo profilerInfo, int profileType) {
        if (start) {
            try {
                switch (profileType) {
                    default:
                        mProfiler.setProfiler(profilerInfo);
                        mProfiler.startProfiling();
                        break;
                }
            } catch (RuntimeException e) {
                Slog.w(TAG, "Profiling failed on path " + profilerInfo.profileFile
                        + " -- can the process access this path?");
            } finally {
                profilerInfo.closeFd();
            }
        } else {
            switch (profileType) {
                default:
                    mProfiler.stopProfiling();
                    break;
            }
        }
    }

    /**
     * Public entrypoint to stop profiling. This is required to end profiling when the app crashes,
     * so that profiler data won't be lost.
     *
     * @hide
     */
    public void stopProfiling() {
        if (mProfiler != null) {
            mProfiler.stopProfiling();
        }
    }

    static void handleDumpHeap(DumpHeapData dhd) {
        if (dhd.runGc) {
            System.gc();
            System.runFinalization();
            System.gc();
        }
        try (ParcelFileDescriptor fd = dhd.fd) {
            if (dhd.managed) {
                Debug.dumpHprofData(dhd.path, fd.getFileDescriptor());
            } else if (dhd.mallocInfo) {
                Debug.dumpNativeMallocInfo(fd.getFileDescriptor());
            } else {
                Debug.dumpNativeHeap(fd.getFileDescriptor());
            }
        } catch (IOException e) {
            if (dhd.managed) {
                Slog.w(TAG, "Managed heap dump failed on path " + dhd.path
                        + " -- can the process access this path?", e);
            } else {
                Slog.w(TAG, "Failed to dump heap", e);
            }
        } catch (RuntimeException e) {
            // This should no longer happening now that we're copying the file descriptor.
            Slog.wtf(TAG, "Heap dumper threw a runtime exception", e);
        }
        try {
            ActivityManager.getService().dumpHeapFinished(dhd.path);
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
        if (dhd.finishCallback != null) {
            dhd.finishCallback.sendResult(null);
        }
    }

    final void handleDispatchPackageBroadcast(int cmd, String[] packages) {
        boolean hasPkgInfo = false;
        switch (cmd) {
            case ApplicationThreadConstants.PACKAGE_REMOVED:
            case ApplicationThreadConstants.PACKAGE_REMOVED_DONT_KILL:
            {
                final boolean killApp = cmd == ApplicationThreadConstants.PACKAGE_REMOVED;
                if (packages == null) {
                    break;
                }
                synchronized (mResourcesManager) {
                    for (int i = packages.length - 1; i >= 0; i--) {
                        if (!hasPkgInfo) {
                            WeakReference<LoadedApk> ref = mPackages.get(packages[i]);
                            if (ref != null && ref.get() != null) {
                                hasPkgInfo = true;
                            } else {
                                ref = mResourcePackages.get(packages[i]);
                                if (ref != null && ref.get() != null) {
                                    hasPkgInfo = true;
                                }
                            }
                        }
                        if (killApp) {
                            mPackages.remove(packages[i]);
                            mResourcePackages.remove(packages[i]);
                        }
                    }
                }
                break;
            }
            case ApplicationThreadConstants.PACKAGE_REPLACED:
            {
                if (packages == null) {
                    break;
                }

                List<String> packagesHandled = new ArrayList<>();

                synchronized (mResourcesManager) {
                    for (int i = packages.length - 1; i >= 0; i--) {
                        String packageName = packages[i];
                        WeakReference<LoadedApk> ref = mPackages.get(packageName);
                        LoadedApk pkgInfo = ref != null ? ref.get() : null;
                        if (pkgInfo != null) {
                            hasPkgInfo = true;
                        } else {
                            ref = mResourcePackages.get(packageName);
                            pkgInfo = ref != null ? ref.get() : null;
                            if (pkgInfo != null) {
                                hasPkgInfo = true;
                            }
                        }
                        // If the package is being replaced, yet it still has a valid
                        // LoadedApk object, the package was updated with _DONT_KILL.
                        // Adjust it's internal references to the application info and
                        // resources.
                        if (pkgInfo != null) {
                            packagesHandled.add(packageName);
                            try {
                                final ApplicationInfo aInfo =
                                        sPackageManager.getApplicationInfo(
                                                packageName,
                                                PackageManager.GET_SHARED_LIBRARY_FILES,
                                                UserHandle.myUserId());

                                if (mActivities.size() > 0) {
                                    for (ActivityClientRecord ar : mActivities.values()) {
                                        if (ar.activityInfo.applicationInfo.packageName
                                                .equals(packageName)) {
                                            ar.activityInfo.applicationInfo = aInfo;
                                            ar.packageInfo = pkgInfo;
                                        }
                                    }
                                }

                                final String[] oldResDirs = { pkgInfo.getResDir() };

                                final ArrayList<String> oldPaths = new ArrayList<>();
                                LoadedApk.makePaths(this, pkgInfo.getApplicationInfo(), oldPaths);
                                pkgInfo.updateApplicationInfo(aInfo, oldPaths);

                                synchronized (mResourcesManager) {
                                    // Update affected Resources objects to use new ResourcesImpl
                                    mResourcesManager.applyNewResourceDirsLocked(aInfo, oldResDirs);
                                }
                            } catch (RemoteException e) {
                            }
                        }
                    }
                }

                try {
                    getPackageManager().notifyPackagesReplacedReceived(
                            packagesHandled.toArray(new String[0]));
                } catch (RemoteException ignored) {
                }

                break;
            }
        }
        ApplicationPackageManager.handlePackageBroadcast(cmd, packages, hasPkgInfo);
    }

    final void handleLowMemory() {
        ArrayList<ComponentCallbacks2> callbacks = collectComponentCallbacks(true, null);

        final int N = callbacks.size();
        for (int i=0; i<N; i++) {
            callbacks.get(i).onLowMemory();
        }

        // Ask SQLite to free up as much memory as it can, mostly from its page caches.
        if (Process.myUid() != Process.SYSTEM_UID) {
            int sqliteReleased = SQLiteDatabase.releaseMemory();
            EventLog.writeEvent(SQLITE_MEM_RELEASED_EVENT_LOG_TAG, sqliteReleased);
        }

        // Ask graphics to free up as much as possible (font/image caches)
        Canvas.freeCaches();

        // Ask text layout engine to free also as much as possible
        Canvas.freeTextLayoutCaches();

        BinderInternal.forceGc("mem");
    }

    private void handleTrimMemory(int level) {
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "trimMemory");
        if (DEBUG_MEMORY_TRIM) Slog.v(TAG, "Trimming memory to level: " + level);

        ArrayList<ComponentCallbacks2> callbacks = collectComponentCallbacks(true, null);

        final int N = callbacks.size();
        for (int i = 0; i < N; i++) {
            callbacks.get(i).onTrimMemory(level);
        }

        WindowManagerGlobal.getInstance().trimMemory(level);
        Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);

        if (SystemProperties.getInt("debug.am.run_gc_trim_level", Integer.MAX_VALUE) <= level) {
            unscheduleGcIdler();
            doGcIfNeeded("tm");
        }
        if (SystemProperties.getInt("debug.am.run_mallopt_trim_level", Integer.MAX_VALUE)
                <= level) {
            unschedulePurgeIdler();
            purgePendingResources();
        }
    }

    private void setupGraphicsSupport(Context context) {
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "setupGraphicsSupport");

        // The system package doesn't have real data directories, so don't set up cache paths.
        if (!"android".equals(context.getPackageName())) {
            // This cache location probably points at credential-encrypted
            // storage which may not be accessible yet; assign it anyway instead
            // of pointing at device-encrypted storage.
            final File cacheDir = context.getCacheDir();
            if (cacheDir != null) {
                // Provide a usable directory for temporary files
                System.setProperty("java.io.tmpdir", cacheDir.getAbsolutePath());
            } else {
                Log.v(TAG, "Unable to initialize \"java.io.tmpdir\" property "
                        + "due to missing cache directory");
            }

            // Setup a location to store generated/compiled graphics code.
            final Context deviceContext = context.createDeviceProtectedStorageContext();
            final File codeCacheDir = deviceContext.getCodeCacheDir();
            if (codeCacheDir != null) {
                try {
                    int uid = Process.myUid();
                    String[] packages = getPackageManager().getPackagesForUid(uid);
                    if (packages != null) {
                        HardwareRenderer.setupDiskCache(codeCacheDir);
                        RenderScriptCacheDir.setupDiskCache(codeCacheDir);
                    }
                } catch (RemoteException e) {
                    Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                    throw e.rethrowFromSystemServer();
                }
            } else {
                Log.w(TAG, "Unable to use shader/script cache: missing code-cache directory");
            }
        }

        GraphicsEnvironment.getInstance().setup(context, mCoreSettings);
        Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
    }

    private void updateDefaultDensity() {
        final int densityDpi = mCurDefaultDisplayDpi;
        if (!mDensityCompatMode
                && densityDpi != Configuration.DENSITY_DPI_UNDEFINED
                && densityDpi != DisplayMetrics.DENSITY_DEVICE) {
            DisplayMetrics.DENSITY_DEVICE = densityDpi;
            Bitmap.setDefaultDensity(densityDpi);
        }
    }

    /**
     * Returns the correct library directory for the current ABI.
     * <p>
     * If we're dealing with a multi-arch application that has both 32 and 64 bit shared
     * libraries, we might need to choose the secondary depending on what the current
     * runtime's instruction set is.
     */
    private String getInstrumentationLibrary(ApplicationInfo appInfo, InstrumentationInfo insInfo) {
        if (appInfo.primaryCpuAbi != null && appInfo.secondaryCpuAbi != null
                && appInfo.secondaryCpuAbi.equals(insInfo.secondaryCpuAbi)) {
            // Get the instruction set supported by the secondary ABI. In the presence
            // of a native bridge this might be different than the one secondary ABI used.
            String secondaryIsa =
                    VMRuntime.getInstructionSet(appInfo.secondaryCpuAbi);
            final String secondaryDexCodeIsa =
                    SystemProperties.get("ro.dalvik.vm.isa." + secondaryIsa);
            secondaryIsa = secondaryDexCodeIsa.isEmpty() ? secondaryIsa : secondaryDexCodeIsa;

            final String runtimeIsa = VMRuntime.getRuntime().vmInstructionSet();
            if (runtimeIsa.equals(secondaryIsa)) {
                return insInfo.secondaryNativeLibraryDir;
            }
        }
        return insInfo.nativeLibraryDir;
    }

    /**
     * The LocaleList set for the app's resources may have been shuffled so that the preferred
     * Locale is at position 0. We must find the index of this preferred Locale in the
     * original LocaleList.
     */
    private void updateLocaleListFromAppContext(Context context, LocaleList newLocaleList) {
        final Locale bestLocale = context.getResources().getConfiguration().getLocales().get(0);
        final int newLocaleListSize = newLocaleList.size();
        for (int i = 0; i < newLocaleListSize; i++) {
            if (bestLocale.equals(newLocaleList.get(i))) {
                LocaleList.setDefault(newLocaleList, i);
                return;
            }
        }

        // The app may have overridden the LocaleList with its own Locale
        // (not present in the available list). Push the chosen Locale
        // to the front of the list.
        LocaleList.setDefault(new LocaleList(bestLocale, newLocaleList));
    }

    @UnsupportedAppUsage
    private void handleBindApplication(AppBindData data) {
        // Register the UI Thread as a sensitive thread to the runtime.
        VMRuntime.registerSensitiveThread();
        // In the case the stack depth property exists, pass it down to the runtime.
        String property = SystemProperties.get("debug.allocTracker.stackDepth");
        if (property.length() != 0) {
            VMDebug.setAllocTrackerStackDepth(Integer.parseInt(property));
        }
        if (data.trackAllocation) {
            DdmVmInternal.enableRecentAllocations(true);
        }

        // Note when this process has started.
        Process.setStartTimes(SystemClock.elapsedRealtime(), SystemClock.uptimeMillis());

        mBoundApplication = data;
        mConfiguration = new Configuration(data.config);
        mCompatConfiguration = new Configuration(data.config);

        mProfiler = new Profiler();
        String agent = null;
        if (data.initProfilerInfo != null) {
            mProfiler.profileFile = data.initProfilerInfo.profileFile;
            mProfiler.profileFd = data.initProfilerInfo.profileFd;
            mProfiler.samplingInterval = data.initProfilerInfo.samplingInterval;
            mProfiler.autoStopProfiler = data.initProfilerInfo.autoStopProfiler;
            mProfiler.streamingOutput = data.initProfilerInfo.streamingOutput;
            if (data.initProfilerInfo.attachAgentDuringBind) {
                agent = data.initProfilerInfo.agent;
            }
        }

        // send up app name; do this *before* waiting for debugger
        Process.setArgV0(data.processName);
        android.ddm.DdmHandleAppName.setAppName(data.processName,
                                                UserHandle.myUserId());
        VMRuntime.setProcessPackageName(data.appInfo.packageName);

        // Pass data directory path to ART. This is used for caching information and
        // should be set before any application code is loaded.
        VMRuntime.setProcessDataDirectory(data.appInfo.dataDir);

        if (mProfiler.profileFd != null) {
            mProfiler.startProfiling();
        }

        // If the app is Honeycomb MR1 or earlier, switch its AsyncTask
        // implementation to use the pool executor.  Normally, we use the
        // serialized executor as the default. This has to happen in the
        // main thread so the main looper is set right.
        if (data.appInfo.targetSdkVersion <= android.os.Build.VERSION_CODES.HONEYCOMB_MR1) {
            AsyncTask.setDefaultExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
        }

        // Let the util.*Array classes maintain "undefined" for apps targeting Pie or earlier.
        UtilConfig.setThrowExceptionForUpperArrayOutOfBounds(
                data.appInfo.targetSdkVersion >= Build.VERSION_CODES.Q);

        Message.updateCheckRecycle(data.appInfo.targetSdkVersion);

        // Prior to P, internal calls to decode Bitmaps used BitmapFactory,
        // which may scale up to account for density. In P, we switched to
        // ImageDecoder, which skips the upscale to save memory. ImageDecoder
        // needs to still scale up in older apps, in case they rely on the
        // size of the Bitmap without considering its density.
        ImageDecoder.sApiLevel = data.appInfo.targetSdkVersion;

        /*
         * Before spawning a new process, reset the time zone to be the system time zone.
         * This needs to be done because the system time zone could have changed after the
         * the spawning of this process. Without doing this this process would have the incorrect
         * system time zone.
         */
        TimeZone.setDefault(null);

        /*
         * Set the LocaleList. This may change once we create the App Context.
         */
        LocaleList.setDefault(data.config.getLocales());

        synchronized (mResourcesManager) {
            /*
             * Update the system configuration since its preloaded and might not
             * reflect configuration changes. The configuration object passed
             * in AppBindData can be safely assumed to be up to date
             */
            mResourcesManager.applyConfigurationToResourcesLocked(data.config, data.compatInfo);
            mCurDefaultDisplayDpi = data.config.densityDpi;

            // This calls mResourcesManager so keep it within the synchronized block.
            applyCompatConfiguration(mCurDefaultDisplayDpi);
        }

        data.info = getPackageInfoNoCheck(data.appInfo, data.compatInfo);

        if (agent != null) {
            handleAttachAgent(agent, data.info);
        }

        /**
         * Switch this process to density compatibility mode if needed.
         */
        if ((data.appInfo.flags&ApplicationInfo.FLAG_SUPPORTS_SCREEN_DENSITIES)
                == 0) {
            mDensityCompatMode = true;
            Bitmap.setDefaultDensity(DisplayMetrics.DENSITY_DEFAULT);
        }
        updateDefaultDensity();

        final String use24HourSetting = mCoreSettings.getString(Settings.System.TIME_12_24);
        Boolean is24Hr = null;
        if (use24HourSetting != null) {
            is24Hr = "24".equals(use24HourSetting) ? Boolean.TRUE : Boolean.FALSE;
        }
        // null : use locale default for 12/24 hour formatting,
        // false : use 12 hour format,
        // true : use 24 hour format.
        DateFormat.set24HourTimePref(is24Hr);

        updateDebugViewAttributeState();

        StrictMode.initThreadDefaults(data.appInfo);
        StrictMode.initVmDefaults(data.appInfo);

        if (data.debugMode != ApplicationThreadConstants.DEBUG_OFF) {
            // XXX should have option to change the port.
            Debug.changeDebugPort(8100);
            if (data.debugMode == ApplicationThreadConstants.DEBUG_WAIT) {
                Slog.w(TAG, "Application " + data.info.getPackageName()
                      + " is waiting for the debugger on port 8100...");

                IActivityManager mgr = ActivityManager.getService();
                try {
                    mgr.showWaitingForDebugger(mAppThread, true);
                } catch (RemoteException ex) {
                    throw ex.rethrowFromSystemServer();
                }

                Debug.waitForDebugger();

                try {
                    mgr.showWaitingForDebugger(mAppThread, false);
                } catch (RemoteException ex) {
                    throw ex.rethrowFromSystemServer();
                }

            } else {
                Slog.w(TAG, "Application " + data.info.getPackageName()
                      + " can be debugged on port 8100...");
            }
        }

        // Allow binder tracing, and application-generated systrace messages if we're profileable.
        boolean isAppProfileable = data.appInfo.isProfileableByShell();
        Trace.setAppTracingAllowed(isAppProfileable);
        if (isAppProfileable && data.enableBinderTracking) {
            Binder.enableTracing();
        }

        // Initialize heap profiling.
        if (isAppProfileable || Build.IS_ENG) {
            nInitZygoteChildHeapProfiling();
        }

        // Allow renderer debugging features if we're debuggable.
        boolean isAppDebuggable = (data.appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        HardwareRenderer.setDebuggingEnabled(isAppDebuggable || Build.IS_ENG);
        HardwareRenderer.setPackageName(data.appInfo.packageName);

        /**
         * Initialize the default http proxy in this process for the reasons we set the time zone.
         */
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "Setup proxies");
        final IBinder b = ServiceManager.getService(Context.CONNECTIVITY_SERVICE);
        if (b != null) {
            // In pre-boot mode (doing initial launch to collect password), not
            // all system is up.  This includes the connectivity service, so don't
            // crash if we can't get it.
            final IConnectivityManager service = IConnectivityManager.Stub.asInterface(b);
            try {
                Proxy.setHttpProxySystemProperty(service.getProxyForNetwork(null));
            } catch (RemoteException e) {
                Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
                throw e.rethrowFromSystemServer();
            }
        }
        Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);

        // Instrumentation info affects the class loader, so load it before
        // setting up the app context.
        final InstrumentationInfo ii;
        if (data.instrumentationName != null) {
            try {
                ii = new ApplicationPackageManager(null, getPackageManager())
                        .getInstrumentationInfo(data.instrumentationName, 0);
            } catch (PackageManager.NameNotFoundException e) {
                throw new RuntimeException(
                        "Unable to find instrumentation info for: " + data.instrumentationName);
            }

            // Warn of potential ABI mismatches.
            if (!Objects.equals(data.appInfo.primaryCpuAbi, ii.primaryCpuAbi)
                    || !Objects.equals(data.appInfo.secondaryCpuAbi, ii.secondaryCpuAbi)) {
                Slog.w(TAG, "Package uses different ABI(s) than its instrumentation: "
                        + "package[" + data.appInfo.packageName + "]: "
                        + data.appInfo.primaryCpuAbi + ", " + data.appInfo.secondaryCpuAbi
                        + " instrumentation[" + ii.packageName + "]: "
                        + ii.primaryCpuAbi + ", " + ii.secondaryCpuAbi);
            }

            mInstrumentationPackageName = ii.packageName;
            mInstrumentationAppDir = ii.sourceDir;
            mInstrumentationSplitAppDirs = ii.splitSourceDirs;
            mInstrumentationLibDir = getInstrumentationLibrary(data.appInfo, ii);
            mInstrumentedAppDir = data.info.getAppDir();
            mInstrumentedSplitAppDirs = data.info.getSplitAppDirs();
            mInstrumentedLibDir = data.info.getLibDir();
        } else {
            ii = null;
        }

        final ContextImpl appContext = ContextImpl.createAppContext(this, data.info);
        updateLocaleListFromAppContext(appContext,
                mResourcesManager.getConfiguration().getLocales());

        if (!Process.isIsolated()) {
            final int oldMask = StrictMode.allowThreadDiskWritesMask();
            try {
                setupGraphicsSupport(appContext);
            } finally {
                StrictMode.setThreadPolicyMask(oldMask);
            }
        } else {
            HardwareRenderer.setIsolatedProcess(true);
        }

        // Install the Network Security Config Provider. This must happen before the application
        // code is loaded to prevent issues with instances of TLS objects being created before
        // the provider is installed.
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "NetworkSecurityConfigProvider.install");
        NetworkSecurityConfigProvider.install(appContext);
        Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);

        // Continue loading instrumentation.
        if (ii != null) {
            ApplicationInfo instrApp;
            try {
                instrApp = getPackageManager().getApplicationInfo(ii.packageName, 0,
                        UserHandle.myUserId());
            } catch (RemoteException e) {
                instrApp = null;
            }
            if (instrApp == null) {
                instrApp = new ApplicationInfo();
            }
            ii.copyTo(instrApp);
            instrApp.initForUser(UserHandle.myUserId());
            final LoadedApk pi = getPackageInfo(instrApp, data.compatInfo,
                    appContext.getClassLoader(), false, true, false);

            // The test context's op package name == the target app's op package name, because
            // the app ops manager checks the op package name against the real calling UID,
            // which is what the target package name is associated with.
            final ContextImpl instrContext = ContextImpl.createAppContext(this, pi,
                    appContext.getOpPackageName());

            try {
                final ClassLoader cl = instrContext.getClassLoader();
                mInstrumentation = (Instrumentation)
                    cl.loadClass(data.instrumentationName.getClassName()).newInstance();
            } catch (Exception e) {
                throw new RuntimeException(
                    "Unable to instantiate instrumentation "
                    + data.instrumentationName + ": " + e.toString(), e);
            }

            final ComponentName component = new ComponentName(ii.packageName, ii.name);
            mInstrumentation.init(this, instrContext, appContext, component,
                    data.instrumentationWatcher, data.instrumentationUiAutomationConnection);

            if (mProfiler.profileFile != null && !ii.handleProfiling
                    && mProfiler.profileFd == null) {
                mProfiler.handlingProfiling = true;
                final File file = new File(mProfiler.profileFile);
                file.getParentFile().mkdirs();
                Debug.startMethodTracing(file.toString(), 8 * 1024 * 1024);
            }
        } else {
            mInstrumentation = new Instrumentation();
            mInstrumentation.basicInit(this);
        }

        if ((data.appInfo.flags&ApplicationInfo.FLAG_LARGE_HEAP) != 0) {
            dalvik.system.VMRuntime.getRuntime().clearGrowthLimit();
        } else {
            // Small heap, clamp to the current growth limit and let the heap release
            // pages after the growth limit to the non growth limit capacity. b/18387825
            dalvik.system.VMRuntime.getRuntime().clampGrowthLimit();
        }

        // Allow disk access during application and provider setup. This could
        // block processing ordered broadcasts, but later processing would
        // probably end up doing the same disk access.
        Application app;
        final StrictMode.ThreadPolicy savedPolicy = StrictMode.allowThreadDiskWrites();
        final StrictMode.ThreadPolicy writesAllowedPolicy = StrictMode.getThreadPolicy();
        try {
            // If the app is being launched for full backup or restore, bring it up in
            // a restricted environment with the base application class.
            app = data.info.makeApplication(data.restrictedBackupMode, null);

            // Propagate autofill compat state
            app.setAutofillOptions(data.autofillOptions);

            // Propagate Content Capture options
            app.setContentCaptureOptions(data.contentCaptureOptions);

            mInitialApplication = app;

            // don't bring up providers in restricted mode; they may depend on the
            // app's custom Application class
            if (!data.restrictedBackupMode) {
                if (!ArrayUtils.isEmpty(data.providers)) {
                    installContentProviders(app, data.providers);
                }
            }

            // Do this after providers, since instrumentation tests generally start their
            // test thread at this point, and we don't want that racing.
            try {
                mInstrumentation.onCreate(data.instrumentationArgs);
            }
            catch (Exception e) {
                throw new RuntimeException(
                    "Exception thrown in onCreate() of "
                    + data.instrumentationName + ": " + e.toString(), e);
            }
            try {
                mInstrumentation.callApplicationOnCreate(app);
            } catch (Exception e) {
                if (!mInstrumentation.onException(app, e)) {
                    throw new RuntimeException(
                      "Unable to create application " + app.getClass().getName()
                      + ": " + e.toString(), e);
                }
            }
        } finally {
            // If the app targets < O-MR1, or doesn't change the thread policy
            // during startup, clobber the policy to maintain behavior of b/36951662
            if (data.appInfo.targetSdkVersion < Build.VERSION_CODES.O_MR1
                    || StrictMode.getThreadPolicy().equals(writesAllowedPolicy)) {
                StrictMode.setThreadPolicy(savedPolicy);
            }
        }

        // Preload fonts resources
        FontsContract.setApplicationContextForResources(appContext);
        if (!Process.isIsolated()) {
            try {
                final ApplicationInfo info =
                        getPackageManager().getApplicationInfo(
                                data.appInfo.packageName,
                                PackageManager.GET_META_DATA /*flags*/,
                                UserHandle.myUserId());
                if (info.metaData != null) {
                    final int preloadedFontsResource = info.metaData.getInt(
                            ApplicationInfo.METADATA_PRELOADED_FONTS, 0);
                    if (preloadedFontsResource != 0) {
                        data.info.getResources().preloadFonts(preloadedFontsResource);
                    }
                }
            } catch (RemoteException e) {
                throw e.rethrowFromSystemServer();
            }
        }
    }

    /*package*/ final void finishInstrumentation(int resultCode, Bundle results) {
        IActivityManager am = ActivityManager.getService();
        if (mProfiler.profileFile != null && mProfiler.handlingProfiling
                && mProfiler.profileFd == null) {
            Debug.stopMethodTracing();
        }
        //Slog.i(TAG, "am: " + ActivityManager.getService()
        //      + ", app thr: " + mAppThread);
        try {
            am.finishInstrumentation(mAppThread, resultCode, results);
        } catch (RemoteException ex) {
            throw ex.rethrowFromSystemServer();
        }
    }

    @UnsupportedAppUsage
    private void installContentProviders(
            Context context, List<ProviderInfo> providers) {
        final ArrayList<ContentProviderHolder> results = new ArrayList<>();

        for (ProviderInfo cpi : providers) {
            if (DEBUG_PROVIDER) {
                StringBuilder buf = new StringBuilder(128);
                buf.append("Pub ");
                buf.append(cpi.authority);
                buf.append(": ");
                buf.append(cpi.name);
                Log.i(TAG, buf.toString());
            }
            ContentProviderHolder cph = installProvider(context, null, cpi,
                    false /*noisy*/, true /*noReleaseNeeded*/, true /*stable*/);
            if (cph != null) {
                cph.noReleaseNeeded = true;
                results.add(cph);
            }
        }

        try {
            ActivityManager.getService().publishContentProviders(
                getApplicationThread(), results);
        } catch (RemoteException ex) {
            throw ex.rethrowFromSystemServer();
        }
    }

    @UnsupportedAppUsage
    public final IContentProvider acquireProvider(
            Context c, String auth, int userId, boolean stable) {
        final IContentProvider provider = acquireExistingProvider(c, auth, userId, stable);
        if (provider != null) {
            return provider;
        }

        // There is a possible race here.  Another thread may try to acquire
        // the same provider at the same time.  When this happens, we want to ensure
        // that the first one wins.
        // Note that we cannot hold the lock while acquiring and installing the
        // provider since it might take a long time to run and it could also potentially
        // be re-entrant in the case where the provider is in the same process.
        ContentProviderHolder holder = null;
        try {
            synchronized (getGetProviderLock(auth, userId)) {
                holder = ActivityManager.getService().getContentProvider(
                        getApplicationThread(), c.getOpPackageName(), auth, userId, stable);
            }
        } catch (RemoteException ex) {
            throw ex.rethrowFromSystemServer();
        }
        if (holder == null) {
            return null;
        }

        // Install provider will increment the reference count for us, and break
        // any ties in the race.
        holder = installProvider(c, holder, holder.info,
                true /*noisy*/, holder.noReleaseNeeded, stable);
        return holder.provider;
    }

    private Object getGetProviderLock(String auth, int userId) {
        final ProviderKey key = new ProviderKey(auth, userId);
        synchronized (mGetProviderLocks) {
            Object lock = mGetProviderLocks.get(key);
            if (lock == null) {
                lock = key;
                mGetProviderLocks.put(key, lock);
            }
            return lock;
        }
    }

    private final void incProviderRefLocked(ProviderRefCount prc, boolean stable) {
        if (stable) {
            prc.stableCount += 1;
            if (prc.stableCount == 1) {
                // We are acquiring a new stable reference on the provider.
                int unstableDelta;
                if (prc.removePending) {
                    // We have a pending remove operation, which is holding the
                    // last unstable reference.  At this point we are converting
                    // that unstable reference to our new stable reference.
                    unstableDelta = -1;
                    // Cancel the removal of the provider.
                    if (DEBUG_PROVIDER) {
                        Slog.v(TAG, "incProviderRef: stable "
                                + "snatched provider from the jaws of death");
                    }
                    prc.removePending = false;
                    // There is a race! It fails to remove the message, which
                    // will be handled in completeRemoveProvider().
                    mH.removeMessages(H.REMOVE_PROVIDER, prc);
                } else {
                    unstableDelta = 0;
                }
                try {
                    if (DEBUG_PROVIDER) {
                        Slog.v(TAG, "incProviderRef Now stable - "
                                + prc.holder.info.name + ": unstableDelta="
                                + unstableDelta);
                    }
                    ActivityManager.getService().refContentProvider(
                            prc.holder.connection, 1, unstableDelta);
                } catch (RemoteException e) {
                    //do nothing content provider object is dead any way
                }
            }
        } else {
            prc.unstableCount += 1;
            if (prc.unstableCount == 1) {
                // We are acquiring a new unstable reference on the provider.
                if (prc.removePending) {
                    // Oh look, we actually have a remove pending for the
                    // provider, which is still holding the last unstable
                    // reference.  We just need to cancel that to take new
                    // ownership of the reference.
                    if (DEBUG_PROVIDER) {
                        Slog.v(TAG, "incProviderRef: unstable "
                                + "snatched provider from the jaws of death");
                    }
                    prc.removePending = false;
                    mH.removeMessages(H.REMOVE_PROVIDER, prc);
                } else {
                    // First unstable ref, increment our count in the
                    // activity manager.
                    try {
                        if (DEBUG_PROVIDER) {
                            Slog.v(TAG, "incProviderRef: Now unstable - "
                                    + prc.holder.info.name);
                        }
                        ActivityManager.getService().refContentProvider(
                                prc.holder.connection, 0, 1);
                    } catch (RemoteException e) {
                        //do nothing content provider object is dead any way
                    }
                }
            }
        }
    }

    @UnsupportedAppUsage
    public final IContentProvider acquireExistingProvider(
            Context c, String auth, int userId, boolean stable) {
        synchronized (mProviderMap) {
            final ProviderKey key = new ProviderKey(auth, userId);
            final ProviderClientRecord pr = mProviderMap.get(key);
            if (pr == null) {
                return null;
            }

            IContentProvider provider = pr.mProvider;
            IBinder jBinder = provider.asBinder();
            if (!jBinder.isBinderAlive()) {
                // The hosting process of the provider has died; we can't
                // use this one.
                Log.i(TAG, "Acquiring provider " + auth + " for user " + userId
                        + ": existing object's process dead");
                handleUnstableProviderDiedLocked(jBinder, true);
                return null;
            }

            // Only increment the ref count if we have one.  If we don't then the
            // provider is not reference counted and never needs to be released.
            ProviderRefCount prc = mProviderRefCountMap.get(jBinder);
            if (prc != null) {
                incProviderRefLocked(prc, stable);
            }
            return provider;
        }
    }

    @UnsupportedAppUsage
    public final boolean releaseProvider(IContentProvider provider, boolean stable) {
        if (provider == null) {
            return false;
        }

        IBinder jBinder = provider.asBinder();
        synchronized (mProviderMap) {
            ProviderRefCount prc = mProviderRefCountMap.get(jBinder);
            if (prc == null) {
                // The provider has no ref count, no release is needed.
                return false;
            }

            boolean lastRef = false;
            if (stable) {
                if (prc.stableCount == 0) {
                    if (DEBUG_PROVIDER) Slog.v(TAG,
                            "releaseProvider: stable ref count already 0, how?");
                    return false;
                }
                prc.stableCount -= 1;
                if (prc.stableCount == 0) {
                    // What we do at this point depends on whether there are
                    // any unstable refs left: if there are, we just tell the
                    // activity manager to decrement its stable count; if there
                    // aren't, we need to enqueue this provider to be removed,
                    // and convert to holding a single unstable ref while
                    // doing so.
                    lastRef = prc.unstableCount == 0;
                    try {
                        if (DEBUG_PROVIDER) {
                            Slog.v(TAG, "releaseProvider: No longer stable w/lastRef="
                                    + lastRef + " - " + prc.holder.info.name);
                        }
                        ActivityManager.getService().refContentProvider(
                                prc.holder.connection, -1, lastRef ? 1 : 0);
                    } catch (RemoteException e) {
                        //do nothing content provider object is dead any way
                    }
                }
            } else {
                if (prc.unstableCount == 0) {
                    if (DEBUG_PROVIDER) Slog.v(TAG,
                            "releaseProvider: unstable ref count already 0, how?");
                    return false;
                }
                prc.unstableCount -= 1;
                if (prc.unstableCount == 0) {
                    // If this is the last reference, we need to enqueue
                    // this provider to be removed instead of telling the
                    // activity manager to remove it at this point.
                    lastRef = prc.stableCount == 0;
                    if (!lastRef) {
                        try {
                            if (DEBUG_PROVIDER) {
                                Slog.v(TAG, "releaseProvider: No longer unstable - "
                                        + prc.holder.info.name);
                            }
                            ActivityManager.getService().refContentProvider(
                                    prc.holder.connection, 0, -1);
                        } catch (RemoteException e) {
                            //do nothing content provider object is dead any way
                        }
                    }
                }
            }

            if (lastRef) {
                if (!prc.removePending) {
                    // Schedule the actual remove asynchronously, since we don't know the context
                    // this will be called in.
                    if (DEBUG_PROVIDER) {
                        Slog.v(TAG, "releaseProvider: Enqueueing pending removal - "
                                + prc.holder.info.name);
                    }
                    prc.removePending = true;
                    Message msg = mH.obtainMessage(H.REMOVE_PROVIDER, prc);
                    mH.sendMessageDelayed(msg, CONTENT_PROVIDER_RETAIN_TIME);
                } else {
                    Slog.w(TAG, "Duplicate remove pending of provider " + prc.holder.info.name);
                }
            }
            return true;
        }
    }

    final void completeRemoveProvider(ProviderRefCount prc) {
        synchronized (mProviderMap) {
            if (!prc.removePending) {
                // There was a race!  Some other client managed to acquire
                // the provider before the removal was completed.
                // Abort the removal.  We will do it later.
                if (DEBUG_PROVIDER) Slog.v(TAG, "completeRemoveProvider: lost the race, "
                        + "provider still in use");
                return;
            }

            // More complicated race!! Some client managed to acquire the
            // provider and release it before the removal was completed.
            // Continue the removal, and abort the next remove message.
            prc.removePending = false;

            final IBinder jBinder = prc.holder.provider.asBinder();
            ProviderRefCount existingPrc = mProviderRefCountMap.get(jBinder);
            if (existingPrc == prc) {
                mProviderRefCountMap.remove(jBinder);
            }

            for (int i=mProviderMap.size()-1; i>=0; i--) {
                ProviderClientRecord pr = mProviderMap.valueAt(i);
                IBinder myBinder = pr.mProvider.asBinder();
                if (myBinder == jBinder) {
                    mProviderMap.removeAt(i);
                }
            }
        }

        try {
            if (DEBUG_PROVIDER) {
                Slog.v(TAG, "removeProvider: Invoking ActivityManagerService."
                        + "removeContentProvider(" + prc.holder.info.name + ")");
            }
            ActivityManager.getService().removeContentProvider(
                    prc.holder.connection, false);
        } catch (RemoteException e) {
            //do nothing content provider object is dead any way
        }
    }

    @UnsupportedAppUsage
    final void handleUnstableProviderDied(IBinder provider, boolean fromClient) {
        synchronized (mProviderMap) {
            handleUnstableProviderDiedLocked(provider, fromClient);
        }
    }

    final void handleUnstableProviderDiedLocked(IBinder provider, boolean fromClient) {
        ProviderRefCount prc = mProviderRefCountMap.get(provider);
        if (prc != null) {
            if (DEBUG_PROVIDER) Slog.v(TAG, "Cleaning up dead provider "
                    + provider + " " + prc.holder.info.name);
            mProviderRefCountMap.remove(provider);
            for (int i=mProviderMap.size()-1; i>=0; i--) {
                ProviderClientRecord pr = mProviderMap.valueAt(i);
                if (pr != null && pr.mProvider.asBinder() == provider) {
                    Slog.i(TAG, "Removing dead content provider:" + pr.mProvider.toString());
                    mProviderMap.removeAt(i);
                }
            }

            if (fromClient) {
                // We found out about this due to execution in our client
                // code.  Tell the activity manager about it now, to ensure
                // that the next time we go to do anything with the provider
                // it knows it is dead (so we don't race with its death
                // notification).
                try {
                    ActivityManager.getService().unstableProviderDied(
                            prc.holder.connection);
                } catch (RemoteException e) {
                    //do nothing content provider object is dead any way
                }
            }
        }
    }

    final void appNotRespondingViaProvider(IBinder provider) {
        synchronized (mProviderMap) {
            ProviderRefCount prc = mProviderRefCountMap.get(provider);
            if (prc != null) {
                try {
                    ActivityManager.getService()
                            .appNotRespondingViaProvider(prc.holder.connection);
                } catch (RemoteException e) {
                    throw e.rethrowFromSystemServer();
                }
            }
        }
    }

    private ProviderClientRecord installProviderAuthoritiesLocked(IContentProvider provider,
            ContentProvider localProvider, ContentProviderHolder holder) {
        final String auths[] = holder.info.authority.split(";");
        final int userId = UserHandle.getUserId(holder.info.applicationInfo.uid);

        if (provider != null) {
            // If this provider is hosted by the core OS and cannot be upgraded,
            // then I guess we're okay doing blocking calls to it.
            for (String auth : auths) {
                switch (auth) {
                    case ContactsContract.AUTHORITY:
                    case CallLog.AUTHORITY:
                    case CallLog.SHADOW_AUTHORITY:
                    case BlockedNumberContract.AUTHORITY:
                    case CalendarContract.AUTHORITY:
                    case Downloads.Impl.AUTHORITY:
                    case "telephony":
                        Binder.allowBlocking(provider.asBinder());
                }
            }
        }

        final ProviderClientRecord pcr = new ProviderClientRecord(
                auths, provider, localProvider, holder);
        for (String auth : auths) {
            final ProviderKey key = new ProviderKey(auth, userId);
            final ProviderClientRecord existing = mProviderMap.get(key);
            if (existing != null) {
                Slog.w(TAG, "Content provider " + pcr.mHolder.info.name
                        + " already published as " + auth);
            } else {
                mProviderMap.put(key, pcr);
            }
        }
        return pcr;
    }

    /**
     * Installs the provider.
     *
     * Providers that are local to the process or that come from the system server
     * may be installed permanently which is indicated by setting noReleaseNeeded to true.
     * Other remote providers are reference counted.  The initial reference count
     * for all reference counted providers is one.  Providers that are not reference
     * counted do not have a reference count (at all).
     *
     * This method detects when a provider has already been installed.  When this happens,
     * it increments the reference count of the existing provider (if appropriate)
     * and returns the existing provider.  This can happen due to concurrent
     * attempts to acquire the same provider.
     */
    @UnsupportedAppUsage
    private ContentProviderHolder installProvider(Context context,
            ContentProviderHolder holder, ProviderInfo info,
            boolean noisy, boolean noReleaseNeeded, boolean stable) {
        ContentProvider localProvider = null;
        IContentProvider provider;
        if (holder == null || holder.provider == null) {
            if (DEBUG_PROVIDER || noisy) {
                Slog.d(TAG, "Loading provider " + info.authority + ": "
                        + info.name);
            }
            Context c = null;
            ApplicationInfo ai = info.applicationInfo;
            if (context.getPackageName().equals(ai.packageName)) {
                c = context;
            } else if (mInitialApplication != null &&
                    mInitialApplication.getPackageName().equals(ai.packageName)) {
                c = mInitialApplication;
            } else {
                try {
                    c = context.createPackageContext(ai.packageName,
                            Context.CONTEXT_INCLUDE_CODE);
                } catch (PackageManager.NameNotFoundException e) {
                    // Ignore
                }
            }
            if (c == null) {
                Slog.w(TAG, "Unable to get context for package " +
                      ai.packageName +
                      " while loading content provider " +
                      info.name);
                return null;
            }

            if (info.splitName != null) {
                try {
                    c = c.createContextForSplit(info.splitName);
                } catch (NameNotFoundException e) {
                    throw new RuntimeException(e);
                }
            }

            try {
                final java.lang.ClassLoader cl = c.getClassLoader();
                LoadedApk packageInfo = peekPackageInfo(ai.packageName, true);
                if (packageInfo == null) {
                    // System startup case.
                    packageInfo = getSystemContext().mPackageInfo;
                }
                localProvider = packageInfo.getAppFactory()
                        .instantiateProvider(cl, info.name);
                provider = localProvider.getIContentProvider();
                if (provider == null) {
                    Slog.e(TAG, "Failed to instantiate class " +
                          info.name + " from sourceDir " +
                          info.applicationInfo.sourceDir);
                    return null;
                }
                if (DEBUG_PROVIDER) Slog.v(
                    TAG, "Instantiating local provider " + info.name);
                // XXX Need to create the correct context for this provider.
                localProvider.attachInfo(c, info);
            } catch (java.lang.Exception e) {
                if (!mInstrumentation.onException(null, e)) {
                    throw new RuntimeException(
                            "Unable to get provider " + info.name
                            + ": " + e.toString(), e);
                }
                return null;
            }
        } else {
            provider = holder.provider;
            if (DEBUG_PROVIDER) Slog.v(TAG, "Installing external provider " + info.authority + ": "
                    + info.name);
        }

        ContentProviderHolder retHolder;

        synchronized (mProviderMap) {
            if (DEBUG_PROVIDER) Slog.v(TAG, "Checking to add " + provider
                    + " / " + info.name);
            IBinder jBinder = provider.asBinder();
            if (localProvider != null) {
                ComponentName cname = new ComponentName(info.packageName, info.name);
                ProviderClientRecord pr = mLocalProvidersByName.get(cname);
                if (pr != null) {
                    if (DEBUG_PROVIDER) {
                        Slog.v(TAG, "installProvider: lost the race, "
                                + "using existing local provider");
                    }
                    provider = pr.mProvider;
                } else {
                    holder = new ContentProviderHolder(info);
                    holder.provider = provider;
                    holder.noReleaseNeeded = true;
                    pr = installProviderAuthoritiesLocked(provider, localProvider, holder);
                    mLocalProviders.put(jBinder, pr);
                    mLocalProvidersByName.put(cname, pr);
                }
                retHolder = pr.mHolder;
            } else {
                ProviderRefCount prc = mProviderRefCountMap.get(jBinder);
                if (prc != null) {
                    if (DEBUG_PROVIDER) {
                        Slog.v(TAG, "installProvider: lost the race, updating ref count");
                    }
                    // We need to transfer our new reference to the existing
                    // ref count, releasing the old one...  but only if
                    // release is needed (that is, it is not running in the
                    // system process).
                    if (!noReleaseNeeded) {
                        incProviderRefLocked(prc, stable);
                        try {
                            ActivityManager.getService().removeContentProvider(
                                    holder.connection, stable);
                        } catch (RemoteException e) {
                            //do nothing content provider object is dead any way
                        }
                    }
                } else {
                    ProviderClientRecord client = installProviderAuthoritiesLocked(
                            provider, localProvider, holder);
                    if (noReleaseNeeded) {
                        prc = new ProviderRefCount(holder, client, 1000, 1000);
                    } else {
                        prc = stable
                                ? new ProviderRefCount(holder, client, 1, 0)
                                : new ProviderRefCount(holder, client, 0, 1);
                    }
                    mProviderRefCountMap.put(jBinder, prc);
                }
                retHolder = prc.holder;
            }
        }
        return retHolder;
    }

    private void handleRunIsolatedEntryPoint(String entryPoint, String[] entryPointArgs) {
        try {
            Method main = Class.forName(entryPoint).getMethod("main", String[].class);
            main.invoke(null, new Object[]{entryPointArgs});
        } catch (ReflectiveOperationException e) {
            throw new AndroidRuntimeException("runIsolatedEntryPoint failed", e);
        }
        // The process will be empty after this method returns; exit the VM now.
        System.exit(0);
    }

    @UnsupportedAppUsage
    private void attach(boolean system, long startSeq) {
        sCurrentActivityThread = this;
        mSystemThread = system;
        if (!system) {
            android.ddm.DdmHandleAppName.setAppName("<pre-initialized>",
                                                    UserHandle.myUserId());
            RuntimeInit.setApplicationObject(mAppThread.asBinder());
            final IActivityManager mgr = ActivityManager.getService();
            try {
                mgr.attachApplication(mAppThread, startSeq);
            } catch (RemoteException ex) {
                throw ex.rethrowFromSystemServer();
            }
            // Watch for getting close to heap limit.
            BinderInternal.addGcWatcher(new Runnable() {
                @Override public void run() {
                    if (!mSomeActivitiesChanged) {
                        return;
                    }
                    Runtime runtime = Runtime.getRuntime();
                    long dalvikMax = runtime.maxMemory();
                    long dalvikUsed = runtime.totalMemory() - runtime.freeMemory();
                    if (dalvikUsed > ((3*dalvikMax)/4)) {
                        if (DEBUG_MEMORY_TRIM) Slog.d(TAG, "Dalvik max=" + (dalvikMax/1024)
                                + " total=" + (runtime.totalMemory()/1024)
                                + " used=" + (dalvikUsed/1024));
                        mSomeActivitiesChanged = false;
                        try {
                            ActivityTaskManager.getService().releaseSomeActivities(mAppThread);
                        } catch (RemoteException e) {
                            throw e.rethrowFromSystemServer();
                        }
                    }
                }
            });
        } else {
            // Don't set application object here -- if the system crashes,
            // we can't display an alert, we just want to die die die.
            android.ddm.DdmHandleAppName.setAppName("system_process",
                    UserHandle.myUserId());
            try {
                mInstrumentation = new Instrumentation();
                mInstrumentation.basicInit(this);
                ContextImpl context = ContextImpl.createAppContext(
                        this, getSystemContext().mPackageInfo);
                mInitialApplication = context.mPackageInfo.makeApplication(true, null);
                mInitialApplication.onCreate();
            } catch (Exception e) {
                throw new RuntimeException(
                        "Unable to instantiate Application():" + e.toString(), e);
            }
        }

        ViewRootImpl.ConfigChangedCallback configChangedCallback
                = (Configuration globalConfig) -> {
            synchronized (mResourcesManager) {
                // We need to apply this change to the resources immediately, because upon returning
                // the view hierarchy will be informed about it.
                if (mResourcesManager.applyConfigurationToResourcesLocked(globalConfig,
                        null /* compat */)) {
                    updateLocaleListFromAppContext(mInitialApplication.getApplicationContext(),
                            mResourcesManager.getConfiguration().getLocales());

                    // This actually changed the resources! Tell everyone about it.
                    if (mPendingConfiguration == null
                            || mPendingConfiguration.isOtherSeqNewer(globalConfig)) {
                        mPendingConfiguration = globalConfig;
                        sendMessage(H.CONFIGURATION_CHANGED, globalConfig);
                    }
                }
            }
        };
        ViewRootImpl.addConfigCallback(configChangedCallback);
    }

    @UnsupportedAppUsage
    public static ActivityThread systemMain() {
        // The system process on low-memory devices do not get to use hardware
        // accelerated drawing, since this can add too much overhead to the
        // process.
        if (!ActivityManager.isHighEndGfx()) {
            ThreadedRenderer.disable(true);
        } else {
            ThreadedRenderer.enableForegroundTrimming();
        }
        ActivityThread thread = new ActivityThread();
        thread.attach(true, 0);
        return thread;
    }

    public static void updateHttpProxy(@NonNull Context context) {
        final ConnectivityManager cm = ConnectivityManager.from(context);
        Proxy.setHttpProxySystemProperty(cm.getDefaultProxy());
    }

    @UnsupportedAppUsage
    public final void installSystemProviders(List<ProviderInfo> providers) {
        if (providers != null) {
            installContentProviders(mInitialApplication, providers);
        }
    }

    public int getIntCoreSetting(String key, int defaultValue) {
        synchronized (mResourcesManager) {
            if (mCoreSettings != null) {
                return mCoreSettings.getInt(key, defaultValue);
            }
            return defaultValue;
        }
    }

    private static class AndroidOs extends ForwardingOs {
        /**
         * Install selective syscall interception. For example, this is used to
         * implement special filesystem paths that will be redirected to
         * {@link ContentResolver#openFileDescriptor(Uri, String)}.
         */
        public static void install() {
            // If feature is disabled, we don't need to install
            if (!DEPRECATE_DATA_COLUMNS) return;

            // Install interception and make sure it sticks!
            Os def = null;
            do {
                def = Os.getDefault();
            } while (!Os.compareAndSetDefault(def, new AndroidOs(def)));
        }

        private AndroidOs(Os os) {
            super(os);
        }

        private FileDescriptor openDeprecatedDataPath(String path, int mode) throws ErrnoException {
            final Uri uri = ContentResolver.translateDeprecatedDataPath(path);
            Log.v(TAG, "Redirecting " + path + " to " + uri);

            final ContentResolver cr = currentActivityThread().getApplication()
                    .getContentResolver();
            try {
                final FileDescriptor fd = new FileDescriptor();
                fd.setInt$(cr.openFileDescriptor(uri,
                        FileUtils.translateModePosixToString(mode)).detachFd());
                return fd;
            } catch (SecurityException e) {
                throw new ErrnoException(e.getMessage(), OsConstants.EACCES);
            } catch (FileNotFoundException e) {
                throw new ErrnoException(e.getMessage(), OsConstants.ENOENT);
            }
        }

        private void deleteDeprecatedDataPath(String path) throws ErrnoException {
            final Uri uri = ContentResolver.translateDeprecatedDataPath(path);
            Log.v(TAG, "Redirecting " + path + " to " + uri);

            final ContentResolver cr = currentActivityThread().getApplication()
                    .getContentResolver();
            try {
                if (cr.delete(uri, null, null) == 0) {
                    throw new FileNotFoundException();
                }
            } catch (SecurityException e) {
                throw new ErrnoException(e.getMessage(), OsConstants.EACCES);
            } catch (FileNotFoundException e) {
                throw new ErrnoException(e.getMessage(), OsConstants.ENOENT);
            }
        }

        @Override
        public boolean access(String path, int mode) throws ErrnoException {
            if (path != null && path.startsWith(DEPRECATE_DATA_PREFIX)) {
                // If we opened it okay, then access check succeeded
                IoUtils.closeQuietly(
                        openDeprecatedDataPath(path, FileUtils.translateModeAccessToPosix(mode)));
                return true;
            } else {
                return super.access(path, mode);
            }
        }

        @Override
        public FileDescriptor open(String path, int flags, int mode) throws ErrnoException {
            if (path != null && path.startsWith(DEPRECATE_DATA_PREFIX)) {
                return openDeprecatedDataPath(path, mode);
            } else {
                return super.open(path, flags, mode);
            }
        }

        @Override
        public StructStat stat(String path) throws ErrnoException {
            if (path != null && path.startsWith(DEPRECATE_DATA_PREFIX)) {
                final FileDescriptor fd = openDeprecatedDataPath(path, OsConstants.O_RDONLY);
                try {
                    return android.system.Os.fstat(fd);
                } finally {
                    IoUtils.closeQuietly(fd);
                }
            } else {
                return super.stat(path);
            }
        }

        @Override
        public void unlink(String path) throws ErrnoException {
            if (path != null && path.startsWith(DEPRECATE_DATA_PREFIX)) {
                deleteDeprecatedDataPath(path);
            } else {
                super.unlink(path);
            }
        }

        @Override
        public void remove(String path) throws ErrnoException {
            if (path != null && path.startsWith(DEPRECATE_DATA_PREFIX)) {
                deleteDeprecatedDataPath(path);
            } else {
                super.remove(path);
            }
        }

        @Override
        public void rename(String oldPath, String newPath) throws ErrnoException {
            try {
                super.rename(oldPath, newPath);
            } catch (ErrnoException e) {
                if (e.errno == OsConstants.EXDEV) {
                    Log.v(TAG, "Recovering failed rename " + oldPath + " to " + newPath);
                    try {
                        Files.move(new File(oldPath).toPath(), new File(newPath).toPath());
                    } catch (IOException e2) {
                        throw e;
                    }
                } else {
                    throw e;
                }
            }
        }
    }

    public static void main(String[] args) {
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "ActivityThreadMain");

        // Install selective syscall interception
        AndroidOs.install();

        // CloseGuard defaults to true and can be quite spammy.  We
        // disable it here, but selectively enable it later (via
        // StrictMode) on debug builds, but using DropBox, not logs.
        CloseGuard.setEnabled(false);

        Environment.initForCurrentUser();

        // Make sure TrustedCertificateStore looks in the right place for CA certificates
        final File configDir = Environment.getUserConfigDirectory(UserHandle.myUserId());
        TrustedCertificateStore.setDefaultUserDirectory(configDir);

        Process.setArgV0("<pre-initialized>");

        Looper.prepareMainLooper();

        // Find the value for {@link #PROC_START_SEQ_IDENT} if provided on the command line.
        // It will be in the format "seq=114"
        long startSeq = 0;
        if (args != null) {
            for (int i = args.length - 1; i >= 0; --i) {
                if (args[i] != null && args[i].startsWith(PROC_START_SEQ_IDENT)) {
                    startSeq = Long.parseLong(
                            args[i].substring(PROC_START_SEQ_IDENT.length()));
                }
            }
        }
        ActivityThread thread = new ActivityThread();
        thread.attach(false, startSeq);

        if (sMainThreadHandler == null) {
            sMainThreadHandler = thread.getHandler();
        }

        if (false) {
            Looper.myLooper().setMessageLogging(new
                    LogPrinter(Log.DEBUG, "ActivityThread"));
        }

        // End of event ActivityThreadMain.
        Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
        Looper.loop();

        throw new RuntimeException("Main thread loop unexpectedly exited");
    }

    private void purgePendingResources() {
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "purgePendingResources");
        nPurgePendingResources();
        Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
    }

    // ------------------ Regular JNI ------------------------
    private native void nPurgePendingResources();
    private native void nDumpGraphicsInfo(FileDescriptor fd);
    private native void nInitZygoteChildHeapProfiling();
}
