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

package android.view;

import static android.view.Display.DEFAULT_DISPLAY;
import static android.view.Display.INVALID_DISPLAY;
import static android.view.View.PFLAG_DRAW_ANIMATION;
import static android.view.WindowCallbacks.RESIZE_MODE_DOCKED_DIVIDER;
import static android.view.WindowCallbacks.RESIZE_MODE_FREEFORM;
import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
import static android.view.WindowManager.LayoutParams.PRIVATE_FLAG_FORCE_DECOR_VIEW_VISIBILITY;
import static android.view.WindowManager.LayoutParams.TYPE_INPUT_METHOD;
import static android.view.WindowManager.LayoutParams.TYPE_STATUS_BAR_PANEL;
import static android.view.WindowManager.LayoutParams.TYPE_VOLUME_OVERLAY;

import android.Manifest;
import android.animation.LayoutTransition;
import android.annotation.AnyThread;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.UnsupportedAppUsage;
import android.app.ActivityManager;
import android.app.ActivityThread;
import android.app.ResourcesManager;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.res.CompatibilityInfo;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.FrameInfo;
import android.graphics.HardwareRenderer.FrameDrawingCallback;
import android.graphics.Matrix;
import android.graphics.PixelFormat;
import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.PorterDuff;
import android.graphics.RecordingCanvas;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.RenderNode;
import android.graphics.drawable.Drawable;
import android.hardware.display.DisplayManager;
import android.hardware.display.DisplayManager.DisplayListener;
import android.hardware.input.InputManager;
import android.media.AudioManager;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.Trace;
import android.sysprop.DisplayProperties;
import android.util.AndroidRuntimeException;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.LongArray;
import android.util.MergedConfiguration;
import android.util.Slog;
import android.util.SparseArray;
import android.util.TimeUtils;
import android.util.TypedValue;
import android.view.Surface.OutOfResourcesException;
import android.view.SurfaceControl.Transaction;
import android.view.View.AttachInfo;
import android.view.View.FocusDirection;
import android.view.View.MeasureSpec;
import android.view.WindowManager.LayoutParams.SoftInputModeFlags;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.accessibility.AccessibilityManager.AccessibilityStateChangeListener;
import android.view.accessibility.AccessibilityManager.HighTextContrastChangeListener;
import android.view.accessibility.AccessibilityNodeIdManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityNodeInfo.AccessibilityAction;
import android.view.accessibility.AccessibilityNodeProvider;
import android.view.accessibility.AccessibilityWindowInfo;
import android.view.accessibility.IAccessibilityInteractionConnection;
import android.view.accessibility.IAccessibilityInteractionConnectionCallback;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillManager;
import android.view.contentcapture.ContentCaptureManager;
import android.view.contentcapture.ContentCaptureSession;
import android.view.contentcapture.MainContentCaptureSession;
import android.view.inputmethod.InputMethodManager;
import android.widget.Scroller;

import com.android.internal.R;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.os.IResultReceiver;
import com.android.internal.os.SomeArgs;
import com.android.internal.policy.PhoneFallbackEventHandler;
import com.android.internal.util.Preconditions;
import com.android.internal.view.BaseSurfaceHolder;
import com.android.internal.view.RootViewSurfaceTaker;
import com.android.internal.view.SurfaceCallbackHelper;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CountDownLatch;

/**
 * The top of a view hierarchy, implementing the needed protocol between View
 * and the WindowManager.  This is for the most part an internal implementation
 * detail of {@link WindowManagerGlobal}.
 *
 * {@hide}
 */
@SuppressWarnings({"EmptyCatchBlock", "PointlessBooleanExpression"})
public final class ViewRootImpl implements ViewParent,
        View.AttachInfo.Callbacks, ThreadedRenderer.DrawCallbacks {
    private static final String TAG = "ViewRootImpl";
    private static final boolean DBG = false;
    private static final boolean LOCAL_LOGV = false;
    /** @noinspection PointlessBooleanExpression*/
    private static final boolean DEBUG_DRAW = false || LOCAL_LOGV;
    private static final boolean DEBUG_LAYOUT = false || LOCAL_LOGV;
    private static final boolean DEBUG_DIALOG = false || LOCAL_LOGV;
    private static final boolean DEBUG_INPUT_RESIZE = false || LOCAL_LOGV;
    private static final boolean DEBUG_ORIENTATION = false || LOCAL_LOGV;
    private static final boolean DEBUG_TRACKBALL = false || LOCAL_LOGV;
    private static final boolean DEBUG_IMF = false || LOCAL_LOGV;
    private static final boolean DEBUG_CONFIGURATION = false || LOCAL_LOGV;
    private static final boolean DEBUG_FPS = false;
    private static final boolean DEBUG_INPUT_STAGES = false || LOCAL_LOGV;
    private static final boolean DEBUG_KEEP_SCREEN_ON = false || LOCAL_LOGV;
    private static final boolean DEBUG_CONTENT_CAPTURE = false || LOCAL_LOGV;

    /**
     * Set to false if we do not want to use the multi threaded renderer even though
     * threaded renderer (aka hardware renderering) is used. Note that by disabling
     * this, WindowCallbacks will not fire.
     */
    private static final boolean MT_RENDERER_AVAILABLE = true;

    /**
     * If set to 2, the view system will switch from using rectangles retrieved from window to
     * dispatch to the view hierarchy to using {@link InsetsController}, that derives the insets
     * directly from the full configuration, enabling richer information about the insets state, as
     * well as new APIs to control it frame-by-frame, and synchronize animations with it.
     * <p>
     * Only set this to 2 once the new insets system is productionized and the old APIs are
     * fully migrated over.
     * <p>
     * If set to 1, this will switch to a mode where we only use the new approach for IME, but not
     * for the status/navigation bar.
     */
    private static final String USE_NEW_INSETS_PROPERTY = "persist.wm.new_insets";

    /**
     * @see #USE_NEW_INSETS_PROPERTY
     * @hide
     */
    public static int sNewInsetsMode =
            SystemProperties.getInt(USE_NEW_INSETS_PROPERTY, 0);

    /**
     * @see #USE_NEW_INSETS_PROPERTY
     * @hide
     */
    public static final int NEW_INSETS_MODE_NONE = 0;

    /**
     * @see #USE_NEW_INSETS_PROPERTY
     * @hide
     */
    public static final int NEW_INSETS_MODE_IME = 1;

    /**
     * @see #USE_NEW_INSETS_PROPERTY
     * @hide
     */
    public static final int NEW_INSETS_MODE_FULL = 2;

    /**
     * Set this system property to true to force the view hierarchy to render
     * at 60 Hz. This can be used to measure the potential framerate.
     */
    private static final String PROPERTY_PROFILE_RENDERING = "viewroot.profile_rendering";

    // properties used by emulator to determine display shape
    public static final String PROPERTY_EMULATOR_WIN_OUTSET_BOTTOM_PX =
            "ro.emu.win_outset_bottom_px";

    /**
     * Maximum time we allow the user to roll the trackball enough to generate
     * a key event, before resetting the counters.
     */
    static final int MAX_TRACKBALL_DELAY = 250;

    /**
     * Initial value for {@link #mContentCaptureEnabled}.
     */
    private static final int CONTENT_CAPTURE_ENABLED_NOT_CHECKED = 0;

    /**
     * Value for {@link #mContentCaptureEnabled} when it was checked and set to {@code true}.
     */
    private static final int CONTENT_CAPTURE_ENABLED_TRUE = 1;

    /**
     * Value for {@link #mContentCaptureEnabled} when it was checked and set to {@code false}.
     */
    private static final int CONTENT_CAPTURE_ENABLED_FALSE = 2;

    @UnsupportedAppUsage
    static final ThreadLocal<HandlerActionQueue> sRunQueues = new ThreadLocal<HandlerActionQueue>();

    static final ArrayList<Runnable> sFirstDrawHandlers = new ArrayList<>();
    static boolean sFirstDrawComplete = false;

    /**
     * Callback for notifying about global configuration changes.
     */
    public interface ConfigChangedCallback {

        /** Notifies about global config change. */
        void onConfigurationChanged(Configuration globalConfig);
    }

    private static final ArrayList<ConfigChangedCallback> sConfigCallbacks = new ArrayList<>();

    /**
     * Callback for notifying activities about override configuration changes.
     */
    public interface ActivityConfigCallback {

        /**
         * Notifies about override config change and/or move to different display.
         * @param overrideConfig New override config to apply to activity.
         * @param newDisplayId New display id, {@link Display#INVALID_DISPLAY} if not changed.
         */
        void onConfigurationChanged(Configuration overrideConfig, int newDisplayId);
    }

    /**
     * Callback used to notify corresponding activity about override configuration change and make
     * sure that all resources are set correctly before updating the ViewRootImpl's internal state.
     */
    private ActivityConfigCallback mActivityConfigCallback;

    /**
     * Used when configuration change first updates the config of corresponding activity.
     * In that case we receive a call back from {@link ActivityThread} and this flag is used to
     * preserve the initial value.
     *
     * @see #performConfigurationChange(Configuration, Configuration, boolean, int)
     */
    private boolean mForceNextConfigUpdate;

    /**
     * Signals that compatibility booleans have been initialized according to
     * target SDK versions.
     */
    private static boolean sCompatibilityDone = false;

    /**
     * Always assign focus if a focusable View is available.
     */
    private static boolean sAlwaysAssignFocus;

    /**
     * This list must only be modified by the main thread, so a lock is only needed when changing
     * the list or when accessing the list from a non-main thread.
     */
    @GuardedBy("mWindowCallbacks")
    final ArrayList<WindowCallbacks> mWindowCallbacks = new ArrayList<>();
    @UnsupportedAppUsage
    public final Context mContext;

    @UnsupportedAppUsage
    final IWindowSession mWindowSession;
    @NonNull Display mDisplay;
    final DisplayManager mDisplayManager;
    final String mBasePackageName;

    final int[] mTmpLocation = new int[2];

    final TypedValue mTmpValue = new TypedValue();

    final Thread mThread;

    final WindowLeaked mLocation;

    public final WindowManager.LayoutParams mWindowAttributes = new WindowManager.LayoutParams();

    final W mWindow;

    final int mTargetSdkVersion;

    int mSeq;

    @UnsupportedAppUsage
    View mView;

    View mAccessibilityFocusedHost;
    AccessibilityNodeInfo mAccessibilityFocusedVirtualView;

    // True if the window currently has pointer capture enabled.
    boolean mPointerCapture;

    int mViewVisibility;
    boolean mAppVisible = true;
    // For recents to freeform transition we need to keep drawing after the app receives information
    // that it became invisible. This will ignore that information and depend on the decor view
    // visibility to control drawing. The decor view visibility will get adjusted when the app get
    // stopped and that's when the app will stop drawing further frames.
    private boolean mForceDecorViewVisibility = false;
    // Used for tracking app visibility updates separately in case we get double change. This will
    // make sure that we always call relayout for the corresponding window.
    private boolean mAppVisibilityChanged;
    int mOrigWindowType = -1;

    /** Whether the window had focus during the most recent traversal. */
    boolean mHadWindowFocus;

    /**
     * Whether the window lost focus during a previous traversal and has not
     * yet gained it back. Used to determine whether a WINDOW_STATE_CHANGE
     * accessibility events should be sent during traversal.
     */
    boolean mLostWindowFocus;

    // Set to true if the owner of this window is in the stopped state,
    // so the window should no longer be active.
    @UnsupportedAppUsage
    boolean mStopped = false;

    // Set to true if the owner of this window is in ambient mode,
    // which means it won't receive input events.
    boolean mIsAmbientMode = false;

    // Set to true to stop input during an Activity Transition.
    boolean mPausedForTransition = false;

    boolean mLastInCompatMode = false;

    SurfaceHolder.Callback2 mSurfaceHolderCallback;
    BaseSurfaceHolder mSurfaceHolder;
    boolean mIsCreating;
    boolean mDrawingAllowed;

    final Region mTransparentRegion;
    final Region mPreviousTransparentRegion;

    @UnsupportedAppUsage
    int mWidth;
    @UnsupportedAppUsage
    int mHeight;
    @UnsupportedAppUsage
    Rect mDirty;
    public boolean mIsAnimating;

    private boolean mUseMTRenderer;
    private boolean mDragResizing;
    private boolean mInvalidateRootRequested;
    private int mResizeMode;
    private int mCanvasOffsetX;
    private int mCanvasOffsetY;
    private boolean mActivityRelaunched;

    CompatibilityInfo.Translator mTranslator;

    @UnsupportedAppUsage
    final View.AttachInfo mAttachInfo;
    InputChannel mInputChannel;
    InputQueue.Callback mInputQueueCallback;
    InputQueue mInputQueue;
    @UnsupportedAppUsage
    FallbackEventHandler mFallbackEventHandler;
    Choreographer mChoreographer;

    final Rect mTempRect; // used in the transaction to not thrash the heap.
    final Rect mVisRect; // used to retrieve visible rect of focused view.
    private final Rect mTempBoundsRect = new Rect(); // used to set the size of the bounds surface.

    // This is used to reduce the race between window focus changes being dispatched from
    // the window manager and input events coming through the input system.
    @GuardedBy("this")
    boolean mWindowFocusChanged;
    @GuardedBy("this")
    boolean mUpcomingWindowFocus;
    @GuardedBy("this")
    boolean mUpcomingInTouchMode;

    public boolean mTraversalScheduled;
    int mTraversalBarrier;
    boolean mWillDrawSoon;
    /** Set to true while in performTraversals for detecting when die(true) is called from internal
     * callbacks such as onMeasure, onPreDraw, onDraw and deferring doDie() until later. */
    boolean mIsInTraversal;
    boolean mApplyInsetsRequested;
    boolean mLayoutRequested;
    boolean mFirst;

    @Nullable
    int mContentCaptureEnabled = CONTENT_CAPTURE_ENABLED_NOT_CHECKED;
    boolean mPerformContentCapture;

    boolean mReportNextDraw;
    boolean mFullRedrawNeeded;
    boolean mNewSurfaceNeeded;
    boolean mHasHadWindowFocus;
    boolean mLastWasImTarget;
    boolean mForceNextWindowRelayout;
    CountDownLatch mWindowDrawCountDown;

    boolean mIsDrawing;
    int mLastSystemUiVisibility;
    int mClientWindowLayoutFlags;
    boolean mLastOverscanRequested;

    // Pool of queued input events.
    private static final int MAX_QUEUED_INPUT_EVENT_POOL_SIZE = 10;
    private QueuedInputEvent mQueuedInputEventPool;
    private int mQueuedInputEventPoolSize;

    /* Input event queue.
     * Pending input events are input events waiting to be delivered to the input stages
     * and handled by the application.
     */
    QueuedInputEvent mPendingInputEventHead;
    QueuedInputEvent mPendingInputEventTail;
    int mPendingInputEventCount;
    boolean mProcessInputEventsScheduled;
    boolean mUnbufferedInputDispatch;
    String mPendingInputEventQueueLengthCounterName = "pq";

    InputStage mFirstInputStage;
    InputStage mFirstPostImeInputStage;
    InputStage mSyntheticInputStage;

    private final UnhandledKeyManager mUnhandledKeyManager = new UnhandledKeyManager();

    boolean mWindowAttributesChanged = false;
    int mWindowAttributesChangesFlag = 0;

    // These can be accessed by any thread, must be protected with a lock.
    // Surface can never be reassigned or cleared (use Surface.clear()).
    @UnsupportedAppUsage
    public final Surface mSurface = new Surface();
    private final SurfaceControl mSurfaceControl = new SurfaceControl();

    /**
     * Child surface of {@code mSurface} with the same bounds as its parent, and crop bounds
     * are set to the parent's bounds adjusted for surface insets. This surface is created when
     * {@link ViewRootImpl#createBoundsSurface(int)} is called.
     * By parenting to this bounds surface, child surfaces can ensure they do not draw into the
     * surface inset regions set by the parent window.
     */
    public final Surface mBoundsSurface = new Surface();
    private SurfaceSession mSurfaceSession;
    private SurfaceControl mBoundsSurfaceControl;
    private final Transaction mTransaction = new Transaction();

    @UnsupportedAppUsage
    boolean mAdded;
    boolean mAddedTouchMode;

    final Rect mTmpFrame = new Rect();

    // These are accessed by multiple threads.
    final Rect mWinFrame; // frame given by window manager.

    final Rect mPendingOverscanInsets = new Rect();
    final Rect mPendingVisibleInsets = new Rect();
    final Rect mPendingStableInsets = new Rect();
    final Rect mPendingContentInsets = new Rect();
    final Rect mPendingOutsets = new Rect();
    final Rect mPendingBackDropFrame = new Rect();
    final DisplayCutout.ParcelableWrapper mPendingDisplayCutout =
            new DisplayCutout.ParcelableWrapper(DisplayCutout.NO_CUTOUT);
    boolean mPendingAlwaysConsumeSystemBars;
    private InsetsState mTempInsets = new InsetsState();
    final ViewTreeObserver.InternalInsetsInfo mLastGivenInsets
            = new ViewTreeObserver.InternalInsetsInfo();

    final Rect mDispatchContentInsets = new Rect();
    final Rect mDispatchStableInsets = new Rect();
    DisplayCutout mDispatchDisplayCutout = DisplayCutout.NO_CUTOUT;

    private WindowInsets mLastWindowInsets;

    /** Last applied configuration obtained from resources. */
    private final Configuration mLastConfigurationFromResources = new Configuration();
    /** Last configuration reported from WM or via {@link #MSG_UPDATE_CONFIGURATION}. */
    private final MergedConfiguration mLastReportedMergedConfiguration = new MergedConfiguration();
    /** Configurations waiting to be applied. */
    private final MergedConfiguration mPendingMergedConfiguration = new MergedConfiguration();

    boolean mScrollMayChange;
    @SoftInputModeFlags
    int mSoftInputMode;
    @UnsupportedAppUsage
    WeakReference<View> mLastScrolledFocus;
    int mScrollY;
    int mCurScrollY;
    Scroller mScroller;
    static final Interpolator mResizeInterpolator = new AccelerateDecelerateInterpolator();
    private ArrayList<LayoutTransition> mPendingTransitions;

    final ViewConfiguration mViewConfiguration;

    /* Drag/drop */
    ClipDescription mDragDescription;
    View mCurrentDragView;
    volatile Object mLocalDragState;
    final PointF mDragPoint = new PointF();
    final PointF mLastTouchPoint = new PointF();
    int mLastTouchSource;

    private boolean mProfileRendering;
    private Choreographer.FrameCallback mRenderProfiler;
    private boolean mRenderProfilingEnabled;

    // Variables to track frames per second, enabled via DEBUG_FPS flag
    private long mFpsStartTime = -1;
    private long mFpsPrevTime = -1;
    private int mFpsNumFrames;

    private int mPointerIconType = PointerIcon.TYPE_NOT_SPECIFIED;
    private PointerIcon mCustomPointerIcon = null;

    /**
     * see {@link #playSoundEffect(int)}
     */
    AudioManager mAudioManager;

    final AccessibilityManager mAccessibilityManager;

    AccessibilityInteractionController mAccessibilityInteractionController;

    final AccessibilityInteractionConnectionManager mAccessibilityInteractionConnectionManager =
            new AccessibilityInteractionConnectionManager();
    final HighContrastTextManager mHighContrastTextManager;

    SendWindowContentChangedAccessibilityEvent mSendWindowContentChangedAccessibilityEvent;

    HashSet<View> mTempHashSet;

    private final int mDensity;
    private final int mNoncompatDensity;

    private boolean mInLayout = false;
    ArrayList<View> mLayoutRequesters = new ArrayList<View>();
    boolean mHandlingLayoutInLayoutRequest = false;

    private int mViewLayoutDirectionInitial;

    /** Set to true once doDie() has been called. */
    private boolean mRemoved;

    private boolean mNeedsRendererSetup;

    private final InputEventCompatProcessor mInputCompatProcessor;

    /**
     * Consistency verifier for debugging purposes.
     */
    protected final InputEventConsistencyVerifier mInputEventConsistencyVerifier =
            InputEventConsistencyVerifier.isInstrumentationEnabled() ?
                    new InputEventConsistencyVerifier(this, 0) : null;

    private final InsetsController mInsetsController = new InsetsController(this);

    private final GestureExclusionTracker mGestureExclusionTracker = new GestureExclusionTracker();

    static final class SystemUiVisibilityInfo {
        int seq;
        int globalVisibility;
        int localValue;
        int localChanges;
    }

    private String mTag = TAG;

    public ViewRootImpl(Context context, Display display) {
        mContext = context;
        mWindowSession = WindowManagerGlobal.getWindowSession();
        mDisplay = display;
        mBasePackageName = context.getBasePackageName();
        mThread = Thread.currentThread();
        mLocation = new WindowLeaked(null);
        mLocation.fillInStackTrace();
        mWidth = -1;
        mHeight = -1;
        mDirty = new Rect();
        mTempRect = new Rect();
        mVisRect = new Rect();
        mWinFrame = new Rect();
        mWindow = new W(this);
        mTargetSdkVersion = context.getApplicationInfo().targetSdkVersion;
        mViewVisibility = View.GONE;
        mTransparentRegion = new Region();
        mPreviousTransparentRegion = new Region();
        mFirst = true; // true for the first time the view is added
        mPerformContentCapture = true; // also true for the first time the view is added
        mAdded = false;
        mAttachInfo = new View.AttachInfo(mWindowSession, mWindow, display, this, mHandler, this,
                context);
        mAccessibilityManager = AccessibilityManager.getInstance(context);
        mAccessibilityManager.addAccessibilityStateChangeListener(
                mAccessibilityInteractionConnectionManager, mHandler);
        mHighContrastTextManager = new HighContrastTextManager();
        mAccessibilityManager.addHighTextContrastStateChangeListener(
                mHighContrastTextManager, mHandler);
        mViewConfiguration = ViewConfiguration.get(context);
        mDensity = context.getResources().getDisplayMetrics().densityDpi;
        mNoncompatDensity = context.getResources().getDisplayMetrics().noncompatDensityDpi;
        mFallbackEventHandler = new PhoneFallbackEventHandler(context);
        mChoreographer = Choreographer.getInstance();
        mDisplayManager = (DisplayManager)context.getSystemService(Context.DISPLAY_SERVICE);

        String processorOverrideName = context.getResources().getString(
                                    R.string.config_inputEventCompatProcessorOverrideClassName);
        if (processorOverrideName.isEmpty()) {
            // No compatibility processor override, using default.
            mInputCompatProcessor = new InputEventCompatProcessor(context);
        } else {
            InputEventCompatProcessor compatProcessor = null;
            try {
                final Class<? extends InputEventCompatProcessor> klass =
                        (Class<? extends InputEventCompatProcessor>) Class.forName(
                                processorOverrideName);
                compatProcessor = klass.getConstructor(Context.class).newInstance(context);
            } catch (Exception e) {
                Log.e(TAG, "Unable to create the InputEventCompatProcessor. ", e);
            } finally {
                mInputCompatProcessor = compatProcessor;
            }
        }

        if (!sCompatibilityDone) {
            sAlwaysAssignFocus = mTargetSdkVersion < Build.VERSION_CODES.P;

            sCompatibilityDone = true;
        }

        loadSystemProperties();
    }

    public static void addFirstDrawHandler(Runnable callback) {
        synchronized (sFirstDrawHandlers) {
            if (!sFirstDrawComplete) {
                sFirstDrawHandlers.add(callback);
            }
        }
    }

    /** Add static config callback to be notified about global config changes. */
    @UnsupportedAppUsage
    public static void addConfigCallback(ConfigChangedCallback callback) {
        synchronized (sConfigCallbacks) {
            sConfigCallbacks.add(callback);
        }
    }

    /** Add activity config callback to be notified about override config changes. */
    public void setActivityConfigCallback(ActivityConfigCallback callback) {
        mActivityConfigCallback = callback;
    }

    public void addWindowCallbacks(WindowCallbacks callback) {
        synchronized (mWindowCallbacks) {
            mWindowCallbacks.add(callback);
        }
    }

    public void removeWindowCallbacks(WindowCallbacks callback) {
        synchronized (mWindowCallbacks) {
            mWindowCallbacks.remove(callback);
        }
    }

    public void reportDrawFinish() {
        if (mWindowDrawCountDown != null) {
            mWindowDrawCountDown.countDown();
        }
    }

    // FIXME for perf testing only
    private boolean mProfile = false;

    /**
     * Call this to profile the next traversal call.
     * FIXME for perf testing only. Remove eventually
     */
    public void profile() {
        mProfile = true;
    }

    /**
     * Indicates whether we are in touch mode. Calling this method triggers an IPC
     * call and should be avoided whenever possible.
     *
     * @return True, if the device is in touch mode, false otherwise.
     *
     * @hide
     */
    static boolean isInTouchMode() {
        IWindowSession windowSession = WindowManagerGlobal.peekWindowSession();
        if (windowSession != null) {
            try {
                return windowSession.getInTouchMode();
            } catch (RemoteException e) {
            }
        }
        return false;
    }

    /**
     * Notifies us that our child has been rebuilt, following
     * a window preservation operation. In these cases we
     * keep the same DecorView, but the activity controlling it
     * is a different instance, and we need to update our
     * callbacks.
     *
     * @hide
     */
    public void notifyChildRebuilt() {
        if (mView instanceof RootViewSurfaceTaker) {
            if (mSurfaceHolderCallback != null) {
                mSurfaceHolder.removeCallback(mSurfaceHolderCallback);
            }

            mSurfaceHolderCallback =
                ((RootViewSurfaceTaker)mView).willYouTakeTheSurface();

            if (mSurfaceHolderCallback != null) {
                mSurfaceHolder = new TakenSurfaceHolder();
                mSurfaceHolder.setFormat(PixelFormat.UNKNOWN);
                mSurfaceHolder.addCallback(mSurfaceHolderCallback);
            } else {
                mSurfaceHolder = null;
            }

            mInputQueueCallback =
                ((RootViewSurfaceTaker)mView).willYouTakeTheInputQueue();
            if (mInputQueueCallback != null) {
                mInputQueueCallback.onInputQueueCreated(mInputQueue);
            }
        }
    }

    /**
     * We have one child
     */
    public void setView(View view, WindowManager.LayoutParams attrs, View panelParentView) {
        synchronized (this) {
            if (mView == null) {
                mView = view;

                mAttachInfo.mDisplayState = mDisplay.getState();
                mDisplayManager.registerDisplayListener(mDisplayListener, mHandler);

                mViewLayoutDirectionInitial = mView.getRawLayoutDirection();
                mFallbackEventHandler.setView(view);
                mWindowAttributes.copyFrom(attrs);
                if (mWindowAttributes.packageName == null) {
                    mWindowAttributes.packageName = mBasePackageName;
                }
                attrs = mWindowAttributes;
                setTag();

                if (DEBUG_KEEP_SCREEN_ON && (mClientWindowLayoutFlags
                        & WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) != 0
                        && (attrs.flags&WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) == 0) {
                    Slog.d(mTag, "setView: FLAG_KEEP_SCREEN_ON changed from true to false!");
                }
                // Keep track of the actual window flags supplied by the client.
                mClientWindowLayoutFlags = attrs.flags;

                setAccessibilityFocus(null, null);

                if (view instanceof RootViewSurfaceTaker) {
                    mSurfaceHolderCallback =
                            ((RootViewSurfaceTaker)view).willYouTakeTheSurface();
                    if (mSurfaceHolderCallback != null) {
                        mSurfaceHolder = new TakenSurfaceHolder();
                        mSurfaceHolder.setFormat(PixelFormat.UNKNOWN);
                        mSurfaceHolder.addCallback(mSurfaceHolderCallback);
                    }
                }

                // Compute surface insets required to draw at specified Z value.
                // TODO: Use real shadow insets for a constant max Z.
                if (!attrs.hasManualSurfaceInsets) {
                    attrs.setSurfaceInsets(view, false /*manual*/, true /*preservePrevious*/);
                }

                CompatibilityInfo compatibilityInfo =
                        mDisplay.getDisplayAdjustments().getCompatibilityInfo();
                mTranslator = compatibilityInfo.getTranslator();

                // If the application owns the surface, don't enable hardware acceleration
                if (mSurfaceHolder == null) {
                    // While this is supposed to enable only, it can effectively disable
                    // the acceleration too.
                    enableHardwareAcceleration(attrs);
                    final boolean useMTRenderer = MT_RENDERER_AVAILABLE
                            && mAttachInfo.mThreadedRenderer != null;
                    if (mUseMTRenderer != useMTRenderer) {
                        // Shouldn't be resizing, as it's done only in window setup,
                        // but end just in case.
                        endDragResizing();
                        mUseMTRenderer = useMTRenderer;
                    }
                }

                boolean restore = false;
                if (mTranslator != null) {
                    mSurface.setCompatibilityTranslator(mTranslator);
                    restore = true;
                    attrs.backup();
                    mTranslator.translateWindowLayout(attrs);
                }
                if (DEBUG_LAYOUT) Log.d(mTag, "WindowLayout in setView:" + attrs);

                if (!compatibilityInfo.supportsScreen()) {
                    attrs.privateFlags |= WindowManager.LayoutParams.PRIVATE_FLAG_COMPATIBLE_WINDOW;
                    mLastInCompatMode = true;
                }

                mSoftInputMode = attrs.softInputMode;
                mWindowAttributesChanged = true;
                mWindowAttributesChangesFlag = WindowManager.LayoutParams.EVERYTHING_CHANGED;
                mAttachInfo.mRootView = view;
                mAttachInfo.mScalingRequired = mTranslator != null;
                mAttachInfo.mApplicationScale =
                        mTranslator == null ? 1.0f : mTranslator.applicationScale;
                if (panelParentView != null) {
                    mAttachInfo.mPanelParentWindowToken
                            = panelParentView.getApplicationWindowToken();
                }
                mAdded = true;
                int res; /* = WindowManagerImpl.ADD_OKAY; */

                // Schedule the first layout -before- adding to the window
                // manager, to make sure we do the relayout before receiving
                // any other events from the system.
                requestLayout();
                if ((mWindowAttributes.inputFeatures
                        & WindowManager.LayoutParams.INPUT_FEATURE_NO_INPUT_CHANNEL) == 0) {
                    mInputChannel = new InputChannel();
                }
                mForceDecorViewVisibility = (mWindowAttributes.privateFlags
                        & PRIVATE_FLAG_FORCE_DECOR_VIEW_VISIBILITY) != 0;
                try {
                    mOrigWindowType = mWindowAttributes.type;
                    mAttachInfo.mRecomputeGlobalAttributes = true;
                    collectViewAttributes();
                    res = mWindowSession.addToDisplay(mWindow, mSeq, mWindowAttributes,
                            getHostVisibility(), mDisplay.getDisplayId(), mTmpFrame,
                            mAttachInfo.mContentInsets, mAttachInfo.mStableInsets,
                            mAttachInfo.mOutsets, mAttachInfo.mDisplayCutout, mInputChannel,
                            mTempInsets);
                    setFrame(mTmpFrame);
                } catch (RemoteException e) {
                    mAdded = false;
                    mView = null;
                    mAttachInfo.mRootView = null;
                    mInputChannel = null;
                    mFallbackEventHandler.setView(null);
                    unscheduleTraversals();
                    setAccessibilityFocus(null, null);
                    throw new RuntimeException("Adding window failed", e);
                } finally {
                    if (restore) {
                        attrs.restore();
                    }
                }

                if (mTranslator != null) {
                    mTranslator.translateRectInScreenToAppWindow(mAttachInfo.mContentInsets);
                }
                mPendingOverscanInsets.set(0, 0, 0, 0);
                mPendingContentInsets.set(mAttachInfo.mContentInsets);
                mPendingStableInsets.set(mAttachInfo.mStableInsets);
                mPendingDisplayCutout.set(mAttachInfo.mDisplayCutout);
                mPendingVisibleInsets.set(0, 0, 0, 0);
                mAttachInfo.mAlwaysConsumeSystemBars =
                        (res & WindowManagerGlobal.ADD_FLAG_ALWAYS_CONSUME_SYSTEM_BARS) != 0;
                mPendingAlwaysConsumeSystemBars = mAttachInfo.mAlwaysConsumeSystemBars;
                mInsetsController.onStateChanged(mTempInsets);
                if (DEBUG_LAYOUT) Log.v(mTag, "Added window " + mWindow);
                if (res < WindowManagerGlobal.ADD_OKAY) {
                    mFallbackEventHandler.setView(null);
                    switch (res) {
                        case WindowManagerGlobal.ADD_BAD_APP_TOKEN:
                        case WindowManagerGlobal.ADD_BAD_SUBWINDOW_TOKEN:
                            throw new WindowManager.BadTokenException(
                                    "Unable to add window -- token " + attrs.token
                                    + " is not valid; is your activity running?");
                        case WindowManagerGlobal.ADD_NOT_APP_TOKEN:
                            throw new WindowManager.BadTokenException(
                                    "Unable to add window -- token " + attrs.token
                                    + " is not for an application");
                        case WindowManagerGlobal.ADD_APP_EXITING:
                            throw new WindowManager.BadTokenException(
                                    "Unable to add window -- app for token " + attrs.token
                                    + " is exiting");
                        case WindowManagerGlobal.ADD_DUPLICATE_ADD:
                            throw new WindowManager.BadTokenException(
                                    "Unable to add window -- window " + mWindow
                                    + " has already been added");
                        case WindowManagerGlobal.ADD_STARTING_NOT_NEEDED:
                            // Silently ignore -- we would have just removed it
                            // right away, anyway.
                            return;
                        case WindowManagerGlobal.ADD_MULTIPLE_SINGLETON:
                            throw new WindowManager.BadTokenException("Unable to add window "
                                    + mWindow + " -- another window of type "
                                    + mWindowAttributes.type + " already exists");
                        case WindowManagerGlobal.ADD_PERMISSION_DENIED:
                            throw new WindowManager.BadTokenException("Unable to add window "
                                    + mWindow + " -- permission denied for window type "
                                    + mWindowAttributes.type);
                        case WindowManagerGlobal.ADD_INVALID_DISPLAY:
                            throw new WindowManager.InvalidDisplayException("Unable to add window "
                                    + mWindow + " -- the specified display can not be found");
                        case WindowManagerGlobal.ADD_INVALID_TYPE:
                            throw new WindowManager.InvalidDisplayException("Unable to add window "
                                    + mWindow + " -- the specified window type "
                                    + mWindowAttributes.type + " is not valid");
                    }
                    throw new RuntimeException(
                            "Unable to add window -- unknown error code " + res);
                }

                if (view instanceof RootViewSurfaceTaker) {
                    mInputQueueCallback =
                        ((RootViewSurfaceTaker)view).willYouTakeTheInputQueue();
                }
                if (mInputChannel != null) {
                    if (mInputQueueCallback != null) {
                        mInputQueue = new InputQueue();
                        mInputQueueCallback.onInputQueueCreated(mInputQueue);
                    }
                    mInputEventReceiver = new WindowInputEventReceiver(mInputChannel,
                            Looper.myLooper());
                }

                view.assignParent(this);
                mAddedTouchMode = (res & WindowManagerGlobal.ADD_FLAG_IN_TOUCH_MODE) != 0;
                mAppVisible = (res & WindowManagerGlobal.ADD_FLAG_APP_VISIBLE) != 0;

                if (mAccessibilityManager.isEnabled()) {
                    mAccessibilityInteractionConnectionManager.ensureConnection();
                }

                if (view.getImportantForAccessibility() == View.IMPORTANT_FOR_ACCESSIBILITY_AUTO) {
                    view.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
                }

                // Set up the input pipeline.
                CharSequence counterSuffix = attrs.getTitle();
                mSyntheticInputStage = new SyntheticInputStage();
                InputStage viewPostImeStage = new ViewPostImeInputStage(mSyntheticInputStage);
                InputStage nativePostImeStage = new NativePostImeInputStage(viewPostImeStage,
                        "aq:native-post-ime:" + counterSuffix);
                InputStage earlyPostImeStage = new EarlyPostImeInputStage(nativePostImeStage);
                InputStage imeStage = new ImeInputStage(earlyPostImeStage,
                        "aq:ime:" + counterSuffix);
                InputStage viewPreImeStage = new ViewPreImeInputStage(imeStage);
                InputStage nativePreImeStage = new NativePreImeInputStage(viewPreImeStage,
                        "aq:native-pre-ime:" + counterSuffix);

                mFirstInputStage = nativePreImeStage;
                mFirstPostImeInputStage = earlyPostImeStage;
                mPendingInputEventQueueLengthCounterName = "aq:pending:" + counterSuffix;
            }
        }
    }

    private void setTag() {
        final String[] split = mWindowAttributes.getTitle().toString().split("\\.");
        if (split.length > 0) {
            mTag = TAG + "[" + split[split.length - 1] + "]";
        }
    }

    /** Whether the window is in local focus mode or not */
    private boolean isInLocalFocusMode() {
        return (mWindowAttributes.flags & WindowManager.LayoutParams.FLAG_LOCAL_FOCUS_MODE) != 0;
    }

    @UnsupportedAppUsage
    public int getWindowFlags() {
        return mWindowAttributes.flags;
    }

    public int getDisplayId() {
        return mDisplay.getDisplayId();
    }

    public CharSequence getTitle() {
        return mWindowAttributes.getTitle();
    }

    /**
     * @return the width of the root view. Note that this will return {@code -1} until the first
     *         layout traversal, when the width is set.
     *
     * @hide
     */
    public int getWidth() {
        return mWidth;
    }

    /**
     * @return the height of the root view. Note that this will return {@code -1} until the first
     *         layout traversal, when the height is set.
     *
     * @hide
     */
    public int getHeight() {
        return mHeight;
    }

    /**
     * Destroys hardware rendering resources for this ViewRootImpl
     *
     * May be called on any thread
     */
    @AnyThread
    void destroyHardwareResources() {
        final ThreadedRenderer renderer = mAttachInfo.mThreadedRenderer;
        if (renderer != null) {
            // This is called by WindowManagerGlobal which may or may not be on the right thread
            if (Looper.myLooper() != mAttachInfo.mHandler.getLooper()) {
                mAttachInfo.mHandler.postAtFrontOfQueue(this::destroyHardwareResources);
                return;
            }
            renderer.destroyHardwareResources(mView);
            renderer.destroy();
        }
    }

    @UnsupportedAppUsage
    public void detachFunctor(long functor) {
        if (mAttachInfo.mThreadedRenderer != null) {
            // Fence so that any pending invokeFunctor() messages will be processed
            // before we return from detachFunctor.
            mAttachInfo.mThreadedRenderer.stopDrawing();
        }
    }

    /**
     * Schedules the functor for execution in either kModeProcess or
     * kModeProcessNoContext, depending on whether or not there is an EGLContext.
     *
     * @param functor The native functor to invoke
     * @param waitForCompletion If true, this will not return until the functor
     *                          has invoked. If false, the functor may be invoked
     *                          asynchronously.
     */
    @UnsupportedAppUsage
    public static void invokeFunctor(long functor, boolean waitForCompletion) {
        ThreadedRenderer.invokeFunctor(functor, waitForCompletion);
    }

    /**
     * @param animator animator to register with the hardware renderer
     */
    public void registerAnimatingRenderNode(RenderNode animator) {
        if (mAttachInfo.mThreadedRenderer != null) {
            mAttachInfo.mThreadedRenderer.registerAnimatingRenderNode(animator);
        } else {
            if (mAttachInfo.mPendingAnimatingRenderNodes == null) {
                mAttachInfo.mPendingAnimatingRenderNodes = new ArrayList<RenderNode>();
            }
            mAttachInfo.mPendingAnimatingRenderNodes.add(animator);
        }
    }

    /**
     * @param animator animator to register with the hardware renderer
     */
    public void registerVectorDrawableAnimator(NativeVectorDrawableAnimator animator) {
        if (mAttachInfo.mThreadedRenderer != null) {
            mAttachInfo.mThreadedRenderer.registerVectorDrawableAnimator(animator);
        }
    }

    /**
     * Registers a callback to be executed when the next frame is being drawn on RenderThread. This
     * callback will be executed on a RenderThread worker thread, and only used for the next frame
     * and thus it will only fire once.
     *
     * @param callback The callback to register.
     */
    public void registerRtFrameCallback(@NonNull FrameDrawingCallback callback) {
        if (mAttachInfo.mThreadedRenderer != null) {
            mAttachInfo.mThreadedRenderer.registerRtFrameCallback(frame -> {
                try {
                    callback.onFrameDraw(frame);
                } catch (Exception e) {
                    Log.e(TAG, "Exception while executing onFrameDraw", e);
                }
            });
        }
    }

    @UnsupportedAppUsage
    private void enableHardwareAcceleration(WindowManager.LayoutParams attrs) {
        mAttachInfo.mHardwareAccelerated = false;
        mAttachInfo.mHardwareAccelerationRequested = false;

        // Don't enable hardware acceleration when the application is in compatibility mode
        if (mTranslator != null) return;

        // Try to enable hardware acceleration if requested
        final boolean hardwareAccelerated =
                (attrs.flags & WindowManager.LayoutParams.FLAG_HARDWARE_ACCELERATED) != 0;

        if (hardwareAccelerated) {
            if (!ThreadedRenderer.isAvailable()) {
                return;
            }

            // Persistent processes (including the system) should not do
            // accelerated rendering on low-end devices.  In that case,
            // sRendererDisabled will be set.  In addition, the system process
            // itself should never do accelerated rendering.  In that case, both
            // sRendererDisabled and sSystemRendererDisabled are set.  When
            // sSystemRendererDisabled is set, PRIVATE_FLAG_FORCE_HARDWARE_ACCELERATED
            // can be used by code on the system process to escape that and enable
            // HW accelerated drawing.  (This is basically for the lock screen.)

            final boolean fakeHwAccelerated = (attrs.privateFlags &
                    WindowManager.LayoutParams.PRIVATE_FLAG_FAKE_HARDWARE_ACCELERATED) != 0;
            final boolean forceHwAccelerated = (attrs.privateFlags &
                    WindowManager.LayoutParams.PRIVATE_FLAG_FORCE_HARDWARE_ACCELERATED) != 0;

            if (fakeHwAccelerated) {
                // This is exclusively for the preview windows the window manager
                // shows for launching applications, so they will look more like
                // the app being launched.
                mAttachInfo.mHardwareAccelerationRequested = true;
            } else if (!ThreadedRenderer.sRendererDisabled
                    || (ThreadedRenderer.sSystemRendererDisabled && forceHwAccelerated)) {
                if (mAttachInfo.mThreadedRenderer != null) {
                    mAttachInfo.mThreadedRenderer.destroy();
                }

                final Rect insets = attrs.surfaceInsets;
                final boolean hasSurfaceInsets = insets.left != 0 || insets.right != 0
                        || insets.top != 0 || insets.bottom != 0;
                final boolean translucent = attrs.format != PixelFormat.OPAQUE || hasSurfaceInsets;
                final boolean wideGamut =
                        mContext.getResources().getConfiguration().isScreenWideColorGamut()
                        && attrs.getColorMode() == ActivityInfo.COLOR_MODE_WIDE_COLOR_GAMUT;

                mAttachInfo.mThreadedRenderer = ThreadedRenderer.create(mContext, translucent,
                        attrs.getTitle().toString());
                mAttachInfo.mThreadedRenderer.setWideGamut(wideGamut);
                updateForceDarkMode();
                if (mAttachInfo.mThreadedRenderer != null) {
                    mAttachInfo.mHardwareAccelerated =
                            mAttachInfo.mHardwareAccelerationRequested = true;
                }
            }
        }
    }

    private int getNightMode() {
        return mContext.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
    }

    private void updateForceDarkMode() {
        if (mAttachInfo.mThreadedRenderer == null) return;

        boolean useAutoDark = getNightMode() == Configuration.UI_MODE_NIGHT_YES;

        if (useAutoDark) {
            boolean forceDarkAllowedDefault =
                    SystemProperties.getBoolean(ThreadedRenderer.DEBUG_FORCE_DARK, false);
            TypedArray a = mContext.obtainStyledAttributes(R.styleable.Theme);
            useAutoDark = a.getBoolean(R.styleable.Theme_isLightTheme, true)
                    && a.getBoolean(R.styleable.Theme_forceDarkAllowed, forceDarkAllowedDefault);
            a.recycle();
        }

        if (mAttachInfo.mThreadedRenderer.setForceDark(useAutoDark)) {
            // TODO: Don't require regenerating all display lists to apply this setting
            invalidateWorld(mView);
        }
    }

    @UnsupportedAppUsage
    public View getView() {
        return mView;
    }

    final WindowLeaked getLocation() {
        return mLocation;
    }

    void setLayoutParams(WindowManager.LayoutParams attrs, boolean newView) {
        synchronized (this) {
            final int oldInsetLeft = mWindowAttributes.surfaceInsets.left;
            final int oldInsetTop = mWindowAttributes.surfaceInsets.top;
            final int oldInsetRight = mWindowAttributes.surfaceInsets.right;
            final int oldInsetBottom = mWindowAttributes.surfaceInsets.bottom;
            final int oldSoftInputMode = mWindowAttributes.softInputMode;
            final boolean oldHasManualSurfaceInsets = mWindowAttributes.hasManualSurfaceInsets;

            if (DEBUG_KEEP_SCREEN_ON && (mClientWindowLayoutFlags
                    & WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) != 0
                    && (attrs.flags&WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) == 0) {
                Slog.d(mTag, "setLayoutParams: FLAG_KEEP_SCREEN_ON from true to false!");
            }

            // Keep track of the actual window flags supplied by the client.
            mClientWindowLayoutFlags = attrs.flags;

            // Preserve compatible window flag if exists.
            final int compatibleWindowFlag = mWindowAttributes.privateFlags
                    & WindowManager.LayoutParams.PRIVATE_FLAG_COMPATIBLE_WINDOW;

            // Transfer over system UI visibility values as they carry current state.
            attrs.systemUiVisibility = mWindowAttributes.systemUiVisibility;
            attrs.subtreeSystemUiVisibility = mWindowAttributes.subtreeSystemUiVisibility;

            mWindowAttributesChangesFlag = mWindowAttributes.copyFrom(attrs);
            if ((mWindowAttributesChangesFlag
                    & WindowManager.LayoutParams.TRANSLUCENT_FLAGS_CHANGED) != 0) {
                // Recompute system ui visibility.
                mAttachInfo.mRecomputeGlobalAttributes = true;
            }
            if ((mWindowAttributesChangesFlag
                    & WindowManager.LayoutParams.LAYOUT_CHANGED) != 0) {
                // Request to update light center.
                mAttachInfo.mNeedsUpdateLightCenter = true;
            }
            if (mWindowAttributes.packageName == null) {
                mWindowAttributes.packageName = mBasePackageName;
            }
            mWindowAttributes.privateFlags |= compatibleWindowFlag;

            if (mWindowAttributes.preservePreviousSurfaceInsets) {
                // Restore old surface insets.
                mWindowAttributes.surfaceInsets.set(
                        oldInsetLeft, oldInsetTop, oldInsetRight, oldInsetBottom);
                mWindowAttributes.hasManualSurfaceInsets = oldHasManualSurfaceInsets;
            } else if (mWindowAttributes.surfaceInsets.left != oldInsetLeft
                    || mWindowAttributes.surfaceInsets.top != oldInsetTop
                    || mWindowAttributes.surfaceInsets.right != oldInsetRight
                    || mWindowAttributes.surfaceInsets.bottom != oldInsetBottom) {
                mNeedsRendererSetup = true;
            }

            applyKeepScreenOnFlag(mWindowAttributes);

            if (newView) {
                mSoftInputMode = attrs.softInputMode;
                requestLayout();
            }

            // Don't lose the mode we last auto-computed.
            if ((attrs.softInputMode & WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST)
                    == WindowManager.LayoutParams.SOFT_INPUT_ADJUST_UNSPECIFIED) {
                mWindowAttributes.softInputMode = (mWindowAttributes.softInputMode
                        & ~WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST)
                        | (oldSoftInputMode & WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST);
            }

            mWindowAttributesChanged = true;
            scheduleTraversals();
        }
    }

    void handleAppVisibility(boolean visible) {
        if (mAppVisible != visible) {
            mAppVisible = visible;
            mAppVisibilityChanged = true;
            scheduleTraversals();
            if (!mAppVisible) {
                WindowManagerGlobal.trimForeground();
            }
        }
    }

    void handleGetNewSurface() {
        mNewSurfaceNeeded = true;
        mFullRedrawNeeded = true;
        scheduleTraversals();
    }

    private final DisplayListener mDisplayListener = new DisplayListener() {
        @Override
        public void onDisplayChanged(int displayId) {
            if (mView != null && mDisplay.getDisplayId() == displayId) {
                final int oldDisplayState = mAttachInfo.mDisplayState;
                final int newDisplayState = mDisplay.getState();
                if (oldDisplayState != newDisplayState) {
                    mAttachInfo.mDisplayState = newDisplayState;
                    pokeDrawLockIfNeeded();
                    if (oldDisplayState != Display.STATE_UNKNOWN) {
                        final int oldScreenState = toViewScreenState(oldDisplayState);
                        final int newScreenState = toViewScreenState(newDisplayState);
                        if (oldScreenState != newScreenState) {
                            mView.dispatchScreenStateChanged(newScreenState);
                        }
                        if (oldDisplayState == Display.STATE_OFF) {
                            // Draw was suppressed so we need to for it to happen here.
                            mFullRedrawNeeded = true;
                            scheduleTraversals();
                        }
                    }
                }
            }
        }

        @Override
        public void onDisplayRemoved(int displayId) {
        }

        @Override
        public void onDisplayAdded(int displayId) {
        }

        private int toViewScreenState(int displayState) {
            return displayState == Display.STATE_OFF ?
                    View.SCREEN_STATE_OFF : View.SCREEN_STATE_ON;
        }
    };

    /**
     * Notify about move to a different display.
     * @param displayId The id of the display where this view root is moved to.
     * @param config Configuration of the resources on new display after move.
     *
     * @hide
     */
    public void onMovedToDisplay(int displayId, Configuration config) {
        if (mDisplay.getDisplayId() == displayId) {
            return;
        }

        // Get new instance of display based on current display adjustments. It may be updated later
        // if moving between the displays also involved a configuration change.
        updateInternalDisplay(displayId, mView.getResources());
        mAttachInfo.mDisplayState = mDisplay.getState();
        // Internal state updated, now notify the view hierarchy.
        mView.dispatchMovedToDisplay(mDisplay, config);
    }

    /**
     * Updates {@link #mDisplay} to the display object corresponding to {@param displayId}.
     * Uses DEFAULT_DISPLAY if there isn't a display object in the system corresponding
     * to {@param displayId}.
     */
    private void updateInternalDisplay(int displayId, Resources resources) {
        final Display preferredDisplay =
                ResourcesManager.getInstance().getAdjustedDisplay(displayId, resources);
        if (preferredDisplay == null) {
            // Fallback to use default display.
            Slog.w(TAG, "Cannot get desired display with Id: " + displayId);
            mDisplay = ResourcesManager.getInstance()
                    .getAdjustedDisplay(DEFAULT_DISPLAY, resources);
        } else {
            mDisplay = preferredDisplay;
        }
        mContext.updateDisplay(mDisplay.getDisplayId());
    }

    void pokeDrawLockIfNeeded() {
        final int displayState = mAttachInfo.mDisplayState;
        if (mView != null && mAdded && mTraversalScheduled
                && (displayState == Display.STATE_DOZE
                        || displayState == Display.STATE_DOZE_SUSPEND)) {
            try {
                mWindowSession.pokeDrawLock(mWindow);
            } catch (RemoteException ex) {
                // System server died, oh well.
            }
        }
    }

    @Override
    public void requestFitSystemWindows() {
        checkThread();
        mApplyInsetsRequested = true;
        scheduleTraversals();
    }

    void notifyInsetsChanged() {
        if (sNewInsetsMode == NEW_INSETS_MODE_NONE) {
            return;
        }
        mApplyInsetsRequested = true;

        // If this changes during traversal, no need to schedule another one as it will dispatch it
        // during the current traversal.
        if (!mIsInTraversal) {
            scheduleTraversals();
        }
    }

    @Override
    public void requestLayout() {
        if (!mHandlingLayoutInLayoutRequest) {
            checkThread();
            mLayoutRequested = true;
            scheduleTraversals();
        }
    }

    @Override
    public boolean isLayoutRequested() {
        return mLayoutRequested;
    }

    @Override
    public void onDescendantInvalidated(@NonNull View child, @NonNull View descendant) {
        // TODO: Re-enable after camera is fixed or consider targetSdk checking this
        // checkThread();
        if ((descendant.mPrivateFlags & PFLAG_DRAW_ANIMATION) != 0) {
            mIsAnimating = true;
        }
        invalidate();
    }

    @UnsupportedAppUsage
    void invalidate() {
        mDirty.set(0, 0, mWidth, mHeight);
        if (!mWillDrawSoon) {
            scheduleTraversals();
        }
    }

    void invalidateWorld(View view) {
        view.invalidate();
        if (view instanceof ViewGroup) {
            ViewGroup parent = (ViewGroup) view;
            for (int i = 0; i < parent.getChildCount(); i++) {
                invalidateWorld(parent.getChildAt(i));
            }
        }
    }

    @Override
    public void invalidateChild(View child, Rect dirty) {
        invalidateChildInParent(null, dirty);
    }

    @Override
    public ViewParent invalidateChildInParent(int[] location, Rect dirty) {
        checkThread();
        if (DEBUG_DRAW) Log.v(mTag, "Invalidate child: " + dirty);

        if (dirty == null) {
            invalidate();
            return null;
        } else if (dirty.isEmpty() && !mIsAnimating) {
            return null;
        }

        if (mCurScrollY != 0 || mTranslator != null) {
            mTempRect.set(dirty);
            dirty = mTempRect;
            if (mCurScrollY != 0) {
                dirty.offset(0, -mCurScrollY);
            }
            if (mTranslator != null) {
                mTranslator.translateRectInAppWindowToScreen(dirty);
            }
            if (mAttachInfo.mScalingRequired) {
                dirty.inset(-1, -1);
            }
        }

        invalidateRectOnScreen(dirty);

        return null;
    }

    private void invalidateRectOnScreen(Rect dirty) {
        final Rect localDirty = mDirty;

        // Add the new dirty rect to the current one
        localDirty.union(dirty.left, dirty.top, dirty.right, dirty.bottom);
        // Intersect with the bounds of the window to skip
        // updates that lie outside of the visible region
        final float appScale = mAttachInfo.mApplicationScale;
        final boolean intersected = localDirty.intersect(0, 0,
                (int) (mWidth * appScale + 0.5f), (int) (mHeight * appScale + 0.5f));
        if (!intersected) {
            localDirty.setEmpty();
        }
        if (!mWillDrawSoon && (intersected || mIsAnimating)) {
            scheduleTraversals();
        }
    }

    public void setIsAmbientMode(boolean ambient) {
        mIsAmbientMode = ambient;
    }

    interface WindowStoppedCallback {
        public void windowStopped(boolean stopped);
    }
    private final ArrayList<WindowStoppedCallback> mWindowStoppedCallbacks =  new ArrayList<>();

    void addWindowStoppedCallback(WindowStoppedCallback c) {
        mWindowStoppedCallbacks.add(c);
    }

    void removeWindowStoppedCallback(WindowStoppedCallback c) {
        mWindowStoppedCallbacks.remove(c);
    }

    void setWindowStopped(boolean stopped) {
        checkThread();
        if (mStopped != stopped) {
            mStopped = stopped;
            final ThreadedRenderer renderer = mAttachInfo.mThreadedRenderer;
            if (renderer != null) {
                if (DEBUG_DRAW) Log.d(mTag, "WindowStopped on " + getTitle() + " set to " + mStopped);
                renderer.setStopped(mStopped);
            }
            if (!mStopped) {
                mNewSurfaceNeeded = true;
                scheduleTraversals();
            } else {
                if (renderer != null) {
                    renderer.destroyHardwareResources(mView);
                }
            }

            for (int i = 0; i < mWindowStoppedCallbacks.size(); i++) {
                mWindowStoppedCallbacks.get(i).windowStopped(stopped);
            }

            if (mStopped) {
                if (mSurfaceHolder != null && mSurface.isValid()) {
                    notifySurfaceDestroyed();
                }
                destroySurface();
            }
        }
    }

    /**
     * Creates a surface as a child of {@code mSurface} with the same bounds as its parent and
     * crop bounds set to the parent's bounds adjusted for surface insets.
     *
     * @param zOrderLayer Z order relative to the parent surface.
     */
    public void createBoundsSurface(int zOrderLayer) {
        if (mSurfaceSession == null) {
            mSurfaceSession = new SurfaceSession();
        }
        if (mBoundsSurfaceControl != null && mBoundsSurface.isValid()) {
            return; // surface control for bounds surface already exists.
        }

        mBoundsSurfaceControl = new SurfaceControl.Builder(mSurfaceSession)
                .setName("Bounds for - " + getTitle().toString())
                .setParent(mSurfaceControl)
                .build();

        setBoundsSurfaceCrop();
        mTransaction.setLayer(mBoundsSurfaceControl, zOrderLayer)
                    .show(mBoundsSurfaceControl)
                    .apply();
        mBoundsSurface.copyFrom(mBoundsSurfaceControl);
    }

    private void setBoundsSurfaceCrop() {
        // mWinFrame is already adjusted for surface insets. So offset it and use it as
        // the cropping bounds.
        mTempBoundsRect.set(mWinFrame);
        mTempBoundsRect.offsetTo(mWindowAttributes.surfaceInsets.left,
                mWindowAttributes.surfaceInsets.top);
        mTransaction.setWindowCrop(mBoundsSurfaceControl, mTempBoundsRect);
    }

    /**
     * Called after window layout to update the bounds surface. If the surface insets have
     * changed or the surface has resized, update the bounds surface.
     */
    private void updateBoundsSurface() {
        if (mBoundsSurfaceControl != null && mSurface.isValid()) {
            setBoundsSurfaceCrop();
            mTransaction.deferTransactionUntilSurface(mBoundsSurfaceControl,
                    mSurface, mSurface.getNextFrameNumber())
                    .apply();
        }
    }

    private void destroySurface() {
        mSurface.release();
        mSurfaceControl.release();

        mSurfaceSession = null;

        if (mBoundsSurfaceControl != null) {
            mTransaction.remove(mBoundsSurfaceControl).apply();
            mBoundsSurface.release();
            mBoundsSurfaceControl = null;
        }
    }

    /**
     * Block the input events during an Activity Transition. The KEYCODE_BACK event is allowed
     * through to allow quick reversal of the Activity Transition.
     *
     * @param paused true to pause, false to resume.
     */
    public void setPausedForTransition(boolean paused) {
        mPausedForTransition = paused;
    }

    @Override
    public ViewParent getParent() {
        return null;
    }

    @Override
    public boolean getChildVisibleRect(View child, Rect r, android.graphics.Point offset) {
        if (child != mView) {
            throw new RuntimeException("child is not mine, honest!");
        }
        // Note: don't apply scroll offset, because we want to know its
        // visibility in the virtual canvas being given to the view hierarchy.
        return r.intersect(0, 0, mWidth, mHeight);
    }

    @Override
    public void bringChildToFront(View child) {
    }

    int getHostVisibility() {
        return (mAppVisible || mForceDecorViewVisibility) ? mView.getVisibility() : View.GONE;
    }

    /**
     * Add LayoutTransition to the list of transitions to be started in the next traversal.
     * This list will be cleared after the transitions on the list are start()'ed. These
     * transitionsa re added by LayoutTransition itself when it sets up animations. The setup
     * happens during the layout phase of traversal, which we want to complete before any of the
     * animations are started (because those animations may side-effect properties that layout
     * depends upon, like the bounding rectangles of the affected views). So we add the transition
     * to the list and it is started just prior to starting the drawing phase of traversal.
     *
     * @param transition The LayoutTransition to be started on the next traversal.
     *
     * @hide
     */
    public void requestTransitionStart(LayoutTransition transition) {
        if (mPendingTransitions == null || !mPendingTransitions.contains(transition)) {
            if (mPendingTransitions == null) {
                 mPendingTransitions = new ArrayList<LayoutTransition>();
            }
            mPendingTransitions.add(transition);
        }
    }

    /**
     * Notifies the HardwareRenderer that a new frame will be coming soon.
     * Currently only {@link ThreadedRenderer} cares about this, and uses
     * this knowledge to adjust the scheduling of off-thread animations
     */
    void notifyRendererOfFramePending() {
        if (mAttachInfo.mThreadedRenderer != null) {
            mAttachInfo.mThreadedRenderer.notifyFramePending();
        }
    }

    @UnsupportedAppUsage
    void scheduleTraversals() {
        if (!mTraversalScheduled) {
            mTraversalScheduled = true;
            mTraversalBarrier = mHandler.getLooper().getQueue().postSyncBarrier();
            mChoreographer.postCallback(
                    Choreographer.CALLBACK_TRAVERSAL, mTraversalRunnable, null);
            if (!mUnbufferedInputDispatch) {
                scheduleConsumeBatchedInput();
            }
            notifyRendererOfFramePending();
            pokeDrawLockIfNeeded();
        }
    }

    void unscheduleTraversals() {
        if (mTraversalScheduled) {
            mTraversalScheduled = false;
            mHandler.getLooper().getQueue().removeSyncBarrier(mTraversalBarrier);
            mChoreographer.removeCallbacks(
                    Choreographer.CALLBACK_TRAVERSAL, mTraversalRunnable, null);
        }
    }

    void doTraversal() {
        if (mTraversalScheduled) {
            mTraversalScheduled = false;
            mHandler.getLooper().getQueue().removeSyncBarrier(mTraversalBarrier);

            if (mProfile) {
                Debug.startMethodTracing("ViewAncestor");
            }

            performTraversals();

            if (mProfile) {
                Debug.stopMethodTracing();
                mProfile = false;
            }
        }
    }

    private void applyKeepScreenOnFlag(WindowManager.LayoutParams params) {
        // Update window's global keep screen on flag: if a view has requested
        // that the screen be kept on, then it is always set; otherwise, it is
        // set to whatever the client last requested for the global state.
        if (mAttachInfo.mKeepScreenOn) {
            params.flags |= WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON;
        } else {
            params.flags = (params.flags&~WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    | (mClientWindowLayoutFlags&WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }
    }

    private boolean collectViewAttributes() {
        if (mAttachInfo.mRecomputeGlobalAttributes) {
            //Log.i(mTag, "Computing view hierarchy attributes!");
            mAttachInfo.mRecomputeGlobalAttributes = false;
            boolean oldScreenOn = mAttachInfo.mKeepScreenOn;
            mAttachInfo.mKeepScreenOn = false;
            mAttachInfo.mSystemUiVisibility = 0;
            mAttachInfo.mHasSystemUiListeners = false;
            mView.dispatchCollectViewAttributes(mAttachInfo, 0);
            mAttachInfo.mSystemUiVisibility &= ~mAttachInfo.mDisabledSystemUiVisibility;
            WindowManager.LayoutParams params = mWindowAttributes;
            mAttachInfo.mSystemUiVisibility |= getImpliedSystemUiVisibility(params);
            if (mAttachInfo.mKeepScreenOn != oldScreenOn
                    || mAttachInfo.mSystemUiVisibility != params.subtreeSystemUiVisibility
                    || mAttachInfo.mHasSystemUiListeners != params.hasSystemUiListeners) {
                applyKeepScreenOnFlag(params);
                params.subtreeSystemUiVisibility = mAttachInfo.mSystemUiVisibility;
                params.hasSystemUiListeners = mAttachInfo.mHasSystemUiListeners;
                mView.dispatchWindowSystemUiVisiblityChanged(mAttachInfo.mSystemUiVisibility);
                return true;
            }
        }
        return false;
    }

    private int getImpliedSystemUiVisibility(WindowManager.LayoutParams params) {
        int vis = 0;
        // Translucent decor window flags imply stable system ui visibility.
        if ((params.flags & WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS) != 0) {
            vis |= View.SYSTEM_UI_FLAG_LAYOUT_STABLE | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN;
        }
        if ((params.flags & WindowManager.LayoutParams.FLAG_TRANSLUCENT_NAVIGATION) != 0) {
            vis |= View.SYSTEM_UI_FLAG_LAYOUT_STABLE | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION;
        }
        return vis;
    }

    private boolean measureHierarchy(final View host, final WindowManager.LayoutParams lp,
            final Resources res, final int desiredWindowWidth, final int desiredWindowHeight) {
        int childWidthMeasureSpec;
        int childHeightMeasureSpec;
        boolean windowSizeMayChange = false;

        if (DEBUG_ORIENTATION || DEBUG_LAYOUT) Log.v(mTag,
                "Measuring " + host + " in display " + desiredWindowWidth
                + "x" + desiredWindowHeight + "...");

        boolean goodMeasure = false;
        if (lp.width == ViewGroup.LayoutParams.WRAP_CONTENT) {
            // On large screens, we don't want to allow dialogs to just
            // stretch to fill the entire width of the screen to display
            // one line of text.  First try doing the layout at a smaller
            // size to see if it will fit.
            final DisplayMetrics packageMetrics = res.getDisplayMetrics();
            res.getValue(com.android.internal.R.dimen.config_prefDialogWidth, mTmpValue, true);
            int baseSize = 0;
            if (mTmpValue.type == TypedValue.TYPE_DIMENSION) {
                baseSize = (int)mTmpValue.getDimension(packageMetrics);
            }
            if (DEBUG_DIALOG) Log.v(mTag, "Window " + mView + ": baseSize=" + baseSize
                    + ", desiredWindowWidth=" + desiredWindowWidth);
            if (baseSize != 0 && desiredWindowWidth > baseSize) {
                childWidthMeasureSpec = getRootMeasureSpec(baseSize, lp.width);
                childHeightMeasureSpec = getRootMeasureSpec(desiredWindowHeight, lp.height);
                performMeasure(childWidthMeasureSpec, childHeightMeasureSpec);
                if (DEBUG_DIALOG) Log.v(mTag, "Window " + mView + ": measured ("
                        + host.getMeasuredWidth() + "," + host.getMeasuredHeight()
                        + ") from width spec: " + MeasureSpec.toString(childWidthMeasureSpec)
                        + " and height spec: " + MeasureSpec.toString(childHeightMeasureSpec));
                if ((host.getMeasuredWidthAndState()&View.MEASURED_STATE_TOO_SMALL) == 0) {
                    goodMeasure = true;
                } else {
                    // Didn't fit in that size... try expanding a bit.
                    baseSize = (baseSize+desiredWindowWidth)/2;
                    if (DEBUG_DIALOG) Log.v(mTag, "Window " + mView + ": next baseSize="
                            + baseSize);
                    childWidthMeasureSpec = getRootMeasureSpec(baseSize, lp.width);
                    performMeasure(childWidthMeasureSpec, childHeightMeasureSpec);
                    if (DEBUG_DIALOG) Log.v(mTag, "Window " + mView + ": measured ("
                            + host.getMeasuredWidth() + "," + host.getMeasuredHeight() + ")");
                    if ((host.getMeasuredWidthAndState()&View.MEASURED_STATE_TOO_SMALL) == 0) {
                        if (DEBUG_DIALOG) Log.v(mTag, "Good!");
                        goodMeasure = true;
                    }
                }
            }
        }

        if (!goodMeasure) {
            childWidthMeasureSpec = getRootMeasureSpec(desiredWindowWidth, lp.width);
            childHeightMeasureSpec = getRootMeasureSpec(desiredWindowHeight, lp.height);
            performMeasure(childWidthMeasureSpec, childHeightMeasureSpec);
            if (mWidth != host.getMeasuredWidth() || mHeight != host.getMeasuredHeight()) {
                windowSizeMayChange = true;
            }
        }

        if (DBG) {
            System.out.println("======================================");
            System.out.println("performTraversals -- after measure");
            host.debug();
        }

        return windowSizeMayChange;
    }

    /**
     * Modifies the input matrix such that it maps view-local coordinates to
     * on-screen coordinates.
     *
     * @param m input matrix to modify
     */
    void transformMatrixToGlobal(Matrix m) {
        m.preTranslate(mAttachInfo.mWindowLeft, mAttachInfo.mWindowTop);
    }

    /**
     * Modifies the input matrix such that it maps on-screen coordinates to
     * view-local coordinates.
     *
     * @param m input matrix to modify
     */
    void transformMatrixToLocal(Matrix m) {
        m.postTranslate(-mAttachInfo.mWindowLeft, -mAttachInfo.mWindowTop);
    }

    /* package */ WindowInsets getWindowInsets(boolean forceConstruct) {
        if (mLastWindowInsets == null || forceConstruct) {
            mDispatchContentInsets.set(mAttachInfo.mContentInsets);
            mDispatchStableInsets.set(mAttachInfo.mStableInsets);
            mDispatchDisplayCutout = mAttachInfo.mDisplayCutout.get();

            Rect contentInsets = mDispatchContentInsets;
            Rect stableInsets = mDispatchStableInsets;
            DisplayCutout displayCutout = mDispatchDisplayCutout;
            // For dispatch we preserve old logic, but for direct requests from Views we allow to
            // immediately use pending insets. This is such that getRootWindowInsets returns the
            // result from the layout hint before we ran a traversal shortly after adding a window.
            if (!forceConstruct
                    && (!mPendingContentInsets.equals(contentInsets) ||
                        !mPendingStableInsets.equals(stableInsets) ||
                        !mPendingDisplayCutout.get().equals(displayCutout))) {
                contentInsets = mPendingContentInsets;
                stableInsets = mPendingStableInsets;
                displayCutout = mPendingDisplayCutout.get();
            }
            Rect outsets = mAttachInfo.mOutsets;
            if (outsets.left > 0 || outsets.top > 0 || outsets.right > 0 || outsets.bottom > 0) {
                contentInsets = new Rect(contentInsets.left + outsets.left,
                        contentInsets.top + outsets.top, contentInsets.right + outsets.right,
                        contentInsets.bottom + outsets.bottom);
            }
            contentInsets = ensureInsetsNonNegative(contentInsets, "content");
            stableInsets = ensureInsetsNonNegative(stableInsets, "stable");
            mLastWindowInsets = mInsetsController.calculateInsets(
                    mContext.getResources().getConfiguration().isScreenRound(),
                    mAttachInfo.mAlwaysConsumeSystemBars, displayCutout,
                    contentInsets, stableInsets, mWindowAttributes.softInputMode);
        }
        return mLastWindowInsets;
    }

    private Rect ensureInsetsNonNegative(Rect insets, String kind) {
        if (insets.left < 0  || insets.top < 0  || insets.right < 0  || insets.bottom < 0) {
            Log.wtf(mTag, "Negative " + kind + "Insets: " + insets + ", mFirst=" + mFirst);
            return new Rect(Math.max(0, insets.left),
                    Math.max(0, insets.top),
                    Math.max(0, insets.right),
                    Math.max(0, insets.bottom));
        }
        return insets;
    }

    void dispatchApplyInsets(View host) {
        Trace.traceBegin(Trace.TRACE_TAG_VIEW, "dispatchApplyInsets");
        WindowInsets insets = getWindowInsets(true /* forceConstruct */);
        final boolean dispatchCutout = (mWindowAttributes.layoutInDisplayCutoutMode
                == LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS);
        if (!dispatchCutout) {
            // Window is either not laid out in cutout or the status bar inset takes care of
            // clearing the cutout, so we don't need to dispatch the cutout to the hierarchy.
            insets = insets.consumeDisplayCutout();
        }
        host.dispatchApplyWindowInsets(insets);
        Trace.traceEnd(Trace.TRACE_TAG_VIEW);
    }

    InsetsController getInsetsController() {
        return mInsetsController;
    }

    private static boolean shouldUseDisplaySize(final WindowManager.LayoutParams lp) {
        return lp.type == TYPE_STATUS_BAR_PANEL
                || lp.type == TYPE_INPUT_METHOD
                || lp.type == TYPE_VOLUME_OVERLAY;
    }

    private int dipToPx(int dip) {
        final DisplayMetrics displayMetrics = mContext.getResources().getDisplayMetrics();
        return (int) (displayMetrics.density * dip + 0.5f);
    }

    private void performTraversals() {
        // cache mView since it is used so much below...
        final View host = mView;

        if (DBG) {
            System.out.println("======================================");
            System.out.println("performTraversals");
            host.debug();
        }

        if (host == null || !mAdded)
            return;

        mIsInTraversal = true;
        mWillDrawSoon = true;
        boolean windowSizeMayChange = false;
        boolean surfaceChanged = false;
        WindowManager.LayoutParams lp = mWindowAttributes;

        int desiredWindowWidth;
        int desiredWindowHeight;

        final int viewVisibility = getHostVisibility();
        final boolean viewVisibilityChanged = !mFirst
                && (mViewVisibility != viewVisibility || mNewSurfaceNeeded
                // Also check for possible double visibility update, which will make current
                // viewVisibility value equal to mViewVisibility and we may miss it.
                || mAppVisibilityChanged);
        mAppVisibilityChanged = false;
        final boolean viewUserVisibilityChanged = !mFirst &&
                ((mViewVisibility == View.VISIBLE) != (viewVisibility == View.VISIBLE));

        WindowManager.LayoutParams params = null;
        if (mWindowAttributesChanged) {
            mWindowAttributesChanged = false;
            surfaceChanged = true;
            params = lp;
        }
        CompatibilityInfo compatibilityInfo =
                mDisplay.getDisplayAdjustments().getCompatibilityInfo();
        if (compatibilityInfo.supportsScreen() == mLastInCompatMode) {
            params = lp;
            mFullRedrawNeeded = true;
            mLayoutRequested = true;
            if (mLastInCompatMode) {
                params.privateFlags &= ~WindowManager.LayoutParams.PRIVATE_FLAG_COMPATIBLE_WINDOW;
                mLastInCompatMode = false;
            } else {
                params.privateFlags |= WindowManager.LayoutParams.PRIVATE_FLAG_COMPATIBLE_WINDOW;
                mLastInCompatMode = true;
            }
        }

        mWindowAttributesChangesFlag = 0;

        Rect frame = mWinFrame;
        if (mFirst) {
            mFullRedrawNeeded = true;
            mLayoutRequested = true;

            final Configuration config = mContext.getResources().getConfiguration();
            if (shouldUseDisplaySize(lp)) {
                // NOTE -- system code, won't try to do compat mode.
                Point size = new Point();
                mDisplay.getRealSize(size);
                desiredWindowWidth = size.x;
                desiredWindowHeight = size.y;
            } else {
                desiredWindowWidth = mWinFrame.width();
                desiredWindowHeight = mWinFrame.height();
            }

            // We used to use the following condition to choose 32 bits drawing caches:
            // PixelFormat.hasAlpha(lp.format) || lp.format == PixelFormat.RGBX_8888
            // However, windows are now always 32 bits by default, so choose 32 bits
            mAttachInfo.mUse32BitDrawingCache = true;
            mAttachInfo.mWindowVisibility = viewVisibility;
            mAttachInfo.mRecomputeGlobalAttributes = false;
            mLastConfigurationFromResources.setTo(config);
            mLastSystemUiVisibility = mAttachInfo.mSystemUiVisibility;
            // Set the layout direction if it has not been set before (inherit is the default)
            if (mViewLayoutDirectionInitial == View.LAYOUT_DIRECTION_INHERIT) {
                host.setLayoutDirection(config.getLayoutDirection());
            }
            host.dispatchAttachedToWindow(mAttachInfo, 0);
            mAttachInfo.mTreeObserver.dispatchOnWindowAttachedChange(true);
            dispatchApplyInsets(host);
        } else {
            desiredWindowWidth = frame.width();
            desiredWindowHeight = frame.height();
            if (desiredWindowWidth != mWidth || desiredWindowHeight != mHeight) {
                if (DEBUG_ORIENTATION) Log.v(mTag, "View " + host + " resized to: " + frame);
                mFullRedrawNeeded = true;
                mLayoutRequested = true;
                windowSizeMayChange = true;
            }
        }

        if (viewVisibilityChanged) {
            mAttachInfo.mWindowVisibility = viewVisibility;
            host.dispatchWindowVisibilityChanged(viewVisibility);
            if (viewUserVisibilityChanged) {
                host.dispatchVisibilityAggregated(viewVisibility == View.VISIBLE);
            }
            if (viewVisibility != View.VISIBLE || mNewSurfaceNeeded) {
                endDragResizing();
                destroyHardwareResources();
            }
            if (viewVisibility == View.GONE) {
                // After making a window gone, we will count it as being
                // shown for the first time the next time it gets focus.
                mHasHadWindowFocus = false;
            }
        }

        // Non-visible windows can't hold accessibility focus.
        if (mAttachInfo.mWindowVisibility != View.VISIBLE) {
            host.clearAccessibilityFocus();
        }

        // Execute enqueued actions on every traversal in case a detached view enqueued an action
        getRunQueue().executeActions(mAttachInfo.mHandler);

        boolean insetsChanged = false;

        boolean layoutRequested = mLayoutRequested && (!mStopped || mReportNextDraw);
        if (layoutRequested) {

            final Resources res = mView.getContext().getResources();

            if (mFirst) {
                // make sure touch mode code executes by setting cached value
                // to opposite of the added touch mode.
                mAttachInfo.mInTouchMode = !mAddedTouchMode;
                ensureTouchModeLocally(mAddedTouchMode);
            } else {
                if (!mPendingOverscanInsets.equals(mAttachInfo.mOverscanInsets)) {
                    insetsChanged = true;
                }
                if (!mPendingContentInsets.equals(mAttachInfo.mContentInsets)) {
                    insetsChanged = true;
                }
                if (!mPendingStableInsets.equals(mAttachInfo.mStableInsets)) {
                    insetsChanged = true;
                }
                if (!mPendingDisplayCutout.equals(mAttachInfo.mDisplayCutout)) {
                    insetsChanged = true;
                }
                if (!mPendingVisibleInsets.equals(mAttachInfo.mVisibleInsets)) {
                    mAttachInfo.mVisibleInsets.set(mPendingVisibleInsets);
                    if (DEBUG_LAYOUT) Log.v(mTag, "Visible insets changing to: "
                            + mAttachInfo.mVisibleInsets);
                }
                if (!mPendingOutsets.equals(mAttachInfo.mOutsets)) {
                    insetsChanged = true;
                }
                if (mPendingAlwaysConsumeSystemBars != mAttachInfo.mAlwaysConsumeSystemBars) {
                    insetsChanged = true;
                }
                if (lp.width == ViewGroup.LayoutParams.WRAP_CONTENT
                        || lp.height == ViewGroup.LayoutParams.WRAP_CONTENT) {
                    windowSizeMayChange = true;

                    if (shouldUseDisplaySize(lp)) {
                        // NOTE -- system code, won't try to do compat mode.
                        Point size = new Point();
                        mDisplay.getRealSize(size);
                        desiredWindowWidth = size.x;
                        desiredWindowHeight = size.y;
                    } else {
                        Configuration config = res.getConfiguration();
                        desiredWindowWidth = dipToPx(config.screenWidthDp);
                        desiredWindowHeight = dipToPx(config.screenHeightDp);
                    }
                }
            }

            // Ask host how big it wants to be
            windowSizeMayChange |= measureHierarchy(host, lp, res,
                    desiredWindowWidth, desiredWindowHeight);
        }

        if (collectViewAttributes()) {
            params = lp;
        }
        if (mAttachInfo.mForceReportNewAttributes) {
            mAttachInfo.mForceReportNewAttributes = false;
            params = lp;
        }

        if (mFirst || mAttachInfo.mViewVisibilityChanged) {
            mAttachInfo.mViewVisibilityChanged = false;
            int resizeMode = mSoftInputMode &
                    WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST;
            // If we are in auto resize mode, then we need to determine
            // what mode to use now.
            if (resizeMode == WindowManager.LayoutParams.SOFT_INPUT_ADJUST_UNSPECIFIED) {
                final int N = mAttachInfo.mScrollContainers.size();
                for (int i=0; i<N; i++) {
                    if (mAttachInfo.mScrollContainers.get(i).isShown()) {
                        resizeMode = WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE;
                    }
                }
                if (resizeMode == 0) {
                    resizeMode = WindowManager.LayoutParams.SOFT_INPUT_ADJUST_PAN;
                }
                if ((lp.softInputMode &
                        WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST) != resizeMode) {
                    lp.softInputMode = (lp.softInputMode &
                            ~WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST) |
                            resizeMode;
                    params = lp;
                }
            }
        }

        if (params != null) {
            if ((host.mPrivateFlags & View.PFLAG_REQUEST_TRANSPARENT_REGIONS) != 0) {
                if (!PixelFormat.formatHasAlpha(params.format)) {
                    params.format = PixelFormat.TRANSLUCENT;
                }
            }
            mAttachInfo.mOverscanRequested = (params.flags
                    & WindowManager.LayoutParams.FLAG_LAYOUT_IN_OVERSCAN) != 0;
        }

        if (mApplyInsetsRequested) {
            mApplyInsetsRequested = false;
            mLastOverscanRequested = mAttachInfo.mOverscanRequested;
            dispatchApplyInsets(host);
            if (mLayoutRequested) {
                // Short-circuit catching a new layout request here, so
                // we don't need to go through two layout passes when things
                // change due to fitting system windows, which can happen a lot.
                windowSizeMayChange |= measureHierarchy(host, lp,
                        mView.getContext().getResources(),
                        desiredWindowWidth, desiredWindowHeight);
            }
        }

        if (layoutRequested) {
            // Clear this now, so that if anything requests a layout in the
            // rest of this function we will catch it and re-run a full
            // layout pass.
            mLayoutRequested = false;
        }

        boolean windowShouldResize = layoutRequested && windowSizeMayChange
            && ((mWidth != host.getMeasuredWidth() || mHeight != host.getMeasuredHeight())
                || (lp.width == ViewGroup.LayoutParams.WRAP_CONTENT &&
                        frame.width() < desiredWindowWidth && frame.width() != mWidth)
                || (lp.height == ViewGroup.LayoutParams.WRAP_CONTENT &&
                        frame.height() < desiredWindowHeight && frame.height() != mHeight));
        windowShouldResize |= mDragResizing && mResizeMode == RESIZE_MODE_FREEFORM;

        // If the activity was just relaunched, it might have unfrozen the task bounds (while
        // relaunching), so we need to force a call into window manager to pick up the latest
        // bounds.
        windowShouldResize |= mActivityRelaunched;

        // Determine whether to compute insets.
        // If there are no inset listeners remaining then we may still need to compute
        // insets in case the old insets were non-empty and must be reset.
        final boolean computesInternalInsets =
                mAttachInfo.mTreeObserver.hasComputeInternalInsetsListeners()
                || mAttachInfo.mHasNonEmptyGivenInternalInsets;

        boolean insetsPending = false;
        int relayoutResult = 0;
        boolean updatedConfiguration = false;

        final int surfaceGenerationId = mSurface.getGenerationId();

        final boolean isViewVisible = viewVisibility == View.VISIBLE;
        final boolean windowRelayoutWasForced = mForceNextWindowRelayout;
        boolean surfaceSizeChanged = false;

        if (mFirst || windowShouldResize || insetsChanged ||
                viewVisibilityChanged || params != null || mForceNextWindowRelayout) {
            mForceNextWindowRelayout = false;

            if (isViewVisible) {
                // If this window is giving internal insets to the window
                // manager, and it is being added or changing its visibility,
                // then we want to first give the window manager "fake"
                // insets to cause it to effectively ignore the content of
                // the window during layout.  This avoids it briefly causing
                // other windows to resize/move based on the raw frame of the
                // window, waiting until we can finish laying out this window
                // and get back to the window manager with the ultimately
                // computed insets.
                insetsPending = computesInternalInsets && (mFirst || viewVisibilityChanged);
            }

            if (mSurfaceHolder != null) {
                mSurfaceHolder.mSurfaceLock.lock();
                mDrawingAllowed = true;
            }

            boolean hwInitialized = false;
            boolean contentInsetsChanged = false;
            boolean hadSurface = mSurface.isValid();

            try {
                if (DEBUG_LAYOUT) {
                    Log.i(mTag, "host=w:" + host.getMeasuredWidth() + ", h:" +
                            host.getMeasuredHeight() + ", params=" + params);
                }

                if (mAttachInfo.mThreadedRenderer != null) {
                    // relayoutWindow may decide to destroy mSurface. As that decision
                    // happens in WindowManager service, we need to be defensive here
                    // and stop using the surface in case it gets destroyed.
                    if (mAttachInfo.mThreadedRenderer.pause()) {
                        // Animations were running so we need to push a frame
                        // to resume them
                        mDirty.set(0, 0, mWidth, mHeight);
                    }
                    mChoreographer.mFrameInfo.addFlags(FrameInfo.FLAG_WINDOW_LAYOUT_CHANGED);
                }
                relayoutResult = relayoutWindow(params, viewVisibility, insetsPending);

                if (DEBUG_LAYOUT) Log.v(mTag, "relayout: frame=" + frame.toShortString()
                        + " overscan=" + mPendingOverscanInsets.toShortString()
                        + " content=" + mPendingContentInsets.toShortString()
                        + " visible=" + mPendingVisibleInsets.toShortString()
                        + " stable=" + mPendingStableInsets.toShortString()
                        + " cutout=" + mPendingDisplayCutout.get().toString()
                        + " outsets=" + mPendingOutsets.toShortString()
                        + " surface=" + mSurface);

                // If the pending {@link MergedConfiguration} handed back from
                // {@link #relayoutWindow} does not match the one last reported,
                // WindowManagerService has reported back a frame from a configuration not yet
                // handled by the client. In this case, we need to accept the configuration so we
                // do not lay out and draw with the wrong configuration.
                if (!mPendingMergedConfiguration.equals(mLastReportedMergedConfiguration)) {
                    if (DEBUG_CONFIGURATION) Log.v(mTag, "Visible with new config: "
                            + mPendingMergedConfiguration.getMergedConfiguration());
                    performConfigurationChange(mPendingMergedConfiguration, !mFirst,
                            INVALID_DISPLAY /* same display */);
                    updatedConfiguration = true;
                }

                final boolean overscanInsetsChanged = !mPendingOverscanInsets.equals(
                        mAttachInfo.mOverscanInsets);
                contentInsetsChanged = !mPendingContentInsets.equals(
                        mAttachInfo.mContentInsets);
                final boolean visibleInsetsChanged = !mPendingVisibleInsets.equals(
                        mAttachInfo.mVisibleInsets);
                final boolean stableInsetsChanged = !mPendingStableInsets.equals(
                        mAttachInfo.mStableInsets);
                final boolean cutoutChanged = !mPendingDisplayCutout.equals(
                        mAttachInfo.mDisplayCutout);
                final boolean outsetsChanged = !mPendingOutsets.equals(mAttachInfo.mOutsets);
                surfaceSizeChanged = (relayoutResult
                        & WindowManagerGlobal.RELAYOUT_RES_SURFACE_RESIZED) != 0;
                surfaceChanged |= surfaceSizeChanged;
                final boolean alwaysConsumeSystemBarsChanged =
                        mPendingAlwaysConsumeSystemBars != mAttachInfo.mAlwaysConsumeSystemBars;
                final boolean colorModeChanged = hasColorModeChanged(lp.getColorMode());
                if (contentInsetsChanged) {
                    mAttachInfo.mContentInsets.set(mPendingContentInsets);
                    if (DEBUG_LAYOUT) Log.v(mTag, "Content insets changing to: "
                            + mAttachInfo.mContentInsets);
                }
                if (overscanInsetsChanged) {
                    mAttachInfo.mOverscanInsets.set(mPendingOverscanInsets);
                    if (DEBUG_LAYOUT) Log.v(mTag, "Overscan insets changing to: "
                            + mAttachInfo.mOverscanInsets);
                    // Need to relayout with content insets.
                    contentInsetsChanged = true;
                }
                if (stableInsetsChanged) {
                    mAttachInfo.mStableInsets.set(mPendingStableInsets);
                    if (DEBUG_LAYOUT) Log.v(mTag, "Decor insets changing to: "
                            + mAttachInfo.mStableInsets);
                    // Need to relayout with content insets.
                    contentInsetsChanged = true;
                }
                if (cutoutChanged) {
                    mAttachInfo.mDisplayCutout.set(mPendingDisplayCutout);
                    if (DEBUG_LAYOUT) {
                        Log.v(mTag, "DisplayCutout changing to: " + mAttachInfo.mDisplayCutout);
                    }
                    // Need to relayout with content insets.
                    contentInsetsChanged = true;
                }
                if (alwaysConsumeSystemBarsChanged) {
                    mAttachInfo.mAlwaysConsumeSystemBars = mPendingAlwaysConsumeSystemBars;
                    contentInsetsChanged = true;
                }
                if (contentInsetsChanged || mLastSystemUiVisibility !=
                        mAttachInfo.mSystemUiVisibility || mApplyInsetsRequested
                        || mLastOverscanRequested != mAttachInfo.mOverscanRequested
                        || outsetsChanged) {
                    mLastSystemUiVisibility = mAttachInfo.mSystemUiVisibility;
                    mLastOverscanRequested = mAttachInfo.mOverscanRequested;
                    mAttachInfo.mOutsets.set(mPendingOutsets);
                    mApplyInsetsRequested = false;
                    dispatchApplyInsets(host);
                    // We applied insets so force contentInsetsChanged to ensure the
                    // hierarchy is measured below.
                    contentInsetsChanged = true;
                }
                if (visibleInsetsChanged) {
                    mAttachInfo.mVisibleInsets.set(mPendingVisibleInsets);
                    if (DEBUG_LAYOUT) Log.v(mTag, "Visible insets changing to: "
                            + mAttachInfo.mVisibleInsets);
                }
                if (colorModeChanged && mAttachInfo.mThreadedRenderer != null) {
                    mAttachInfo.mThreadedRenderer.setWideGamut(
                            lp.getColorMode() == ActivityInfo.COLOR_MODE_WIDE_COLOR_GAMUT);
                }

                if (!hadSurface) {
                    if (mSurface.isValid()) {
                        // If we are creating a new surface, then we need to
                        // completely redraw it.
                        mFullRedrawNeeded = true;
                        mPreviousTransparentRegion.setEmpty();

                        // Only initialize up-front if transparent regions are not
                        // requested, otherwise defer to see if the entire window
                        // will be transparent
                        if (mAttachInfo.mThreadedRenderer != null) {
                            try {
                                hwInitialized = mAttachInfo.mThreadedRenderer.initialize(
                                        mSurface);
                                if (hwInitialized && (host.mPrivateFlags
                                        & View.PFLAG_REQUEST_TRANSPARENT_REGIONS) == 0) {
                                    // Don't pre-allocate if transparent regions
                                    // are requested as they may not be needed
                                    mAttachInfo.mThreadedRenderer.allocateBuffers();
                                }
                            } catch (OutOfResourcesException e) {
                                handleOutOfResourcesException(e);
                                return;
                            }
                        }
                    }
                } else if (!mSurface.isValid()) {
                    // If the surface has been removed, then reset the scroll
                    // positions.
                    if (mLastScrolledFocus != null) {
                        mLastScrolledFocus.clear();
                    }
                    mScrollY = mCurScrollY = 0;
                    if (mView instanceof RootViewSurfaceTaker) {
                        ((RootViewSurfaceTaker) mView).onRootViewScrollYChanged(mCurScrollY);
                    }
                    if (mScroller != null) {
                        mScroller.abortAnimation();
                    }
                    // Our surface is gone
                    if (mAttachInfo.mThreadedRenderer != null &&
                            mAttachInfo.mThreadedRenderer.isEnabled()) {
                        mAttachInfo.mThreadedRenderer.destroy();
                    }
                } else if ((surfaceGenerationId != mSurface.getGenerationId()
                        || surfaceSizeChanged || windowRelayoutWasForced || colorModeChanged)
                        && mSurfaceHolder == null
                        && mAttachInfo.mThreadedRenderer != null) {
                    mFullRedrawNeeded = true;
                    try {
                        // Need to do updateSurface (which leads to CanvasContext::setSurface and
                        // re-create the EGLSurface) if either the Surface changed (as indicated by
                        // generation id), or WindowManager changed the surface size. The latter is
                        // because on some chips, changing the consumer side's BufferQueue size may
                        // not take effect immediately unless we create a new EGLSurface.
                        // Note that frame size change doesn't always imply surface size change (eg.
                        // drag resizing uses fullscreen surface), need to check surfaceSizeChanged
                        // flag from WindowManager.
                        mAttachInfo.mThreadedRenderer.updateSurface(mSurface);
                    } catch (OutOfResourcesException e) {
                        handleOutOfResourcesException(e);
                        return;
                    }
                }

                final boolean freeformResizing = (relayoutResult
                        & WindowManagerGlobal.RELAYOUT_RES_DRAG_RESIZING_FREEFORM) != 0;
                final boolean dockedResizing = (relayoutResult
                        & WindowManagerGlobal.RELAYOUT_RES_DRAG_RESIZING_DOCKED) != 0;
                final boolean dragResizing = freeformResizing || dockedResizing;
                if (mDragResizing != dragResizing) {
                    if (dragResizing) {
                        mResizeMode = freeformResizing
                                ? RESIZE_MODE_FREEFORM
                                : RESIZE_MODE_DOCKED_DIVIDER;
                        final boolean backdropSizeMatchesFrame =
                                mWinFrame.width() == mPendingBackDropFrame.width()
                                        && mWinFrame.height() == mPendingBackDropFrame.height();
                        // TODO: Need cutout?
                        startDragResizing(mPendingBackDropFrame, !backdropSizeMatchesFrame,
                                mPendingVisibleInsets, mPendingStableInsets, mResizeMode);
                    } else {
                        // We shouldn't come here, but if we come we should end the resize.
                        endDragResizing();
                    }
                }
                if (!mUseMTRenderer) {
                    if (dragResizing) {
                        mCanvasOffsetX = mWinFrame.left;
                        mCanvasOffsetY = mWinFrame.top;
                    } else {
                        mCanvasOffsetX = mCanvasOffsetY = 0;
                    }
                }
            } catch (RemoteException e) {
            }

            if (DEBUG_ORIENTATION) Log.v(
                    TAG, "Relayout returned: frame=" + frame + ", surface=" + mSurface);

            mAttachInfo.mWindowLeft = frame.left;
            mAttachInfo.mWindowTop = frame.top;

            // !!FIXME!! This next section handles the case where we did not get the
            // window size we asked for. We should avoid this by getting a maximum size from
            // the window session beforehand.
            if (mWidth != frame.width() || mHeight != frame.height()) {
                mWidth = frame.width();
                mHeight = frame.height();
            }

            if (mSurfaceHolder != null) {
                // The app owns the surface; tell it about what is going on.
                if (mSurface.isValid()) {
                    // XXX .copyFrom() doesn't work!
                    //mSurfaceHolder.mSurface.copyFrom(mSurface);
                    mSurfaceHolder.mSurface = mSurface;
                }
                mSurfaceHolder.setSurfaceFrameSize(mWidth, mHeight);
                mSurfaceHolder.mSurfaceLock.unlock();
                if (mSurface.isValid()) {
                    if (!hadSurface) {
                        mSurfaceHolder.ungetCallbacks();

                        mIsCreating = true;
                        SurfaceHolder.Callback callbacks[] = mSurfaceHolder.getCallbacks();
                        if (callbacks != null) {
                            for (SurfaceHolder.Callback c : callbacks) {
                                c.surfaceCreated(mSurfaceHolder);
                            }
                        }
                        surfaceChanged = true;
                    }
                    if (surfaceChanged || surfaceGenerationId != mSurface.getGenerationId()) {
                        SurfaceHolder.Callback callbacks[] = mSurfaceHolder.getCallbacks();
                        if (callbacks != null) {
                            for (SurfaceHolder.Callback c : callbacks) {
                                c.surfaceChanged(mSurfaceHolder, lp.format,
                                        mWidth, mHeight);
                            }
                        }
                    }
                    mIsCreating = false;
                } else if (hadSurface) {
                    notifySurfaceDestroyed();
                    mSurfaceHolder.mSurfaceLock.lock();
                    try {
                        mSurfaceHolder.mSurface = new Surface();
                    } finally {
                        mSurfaceHolder.mSurfaceLock.unlock();
                    }
                }
            }

            final ThreadedRenderer threadedRenderer = mAttachInfo.mThreadedRenderer;
            if (threadedRenderer != null && threadedRenderer.isEnabled()) {
                if (hwInitialized
                        || mWidth != threadedRenderer.getWidth()
                        || mHeight != threadedRenderer.getHeight()
                        || mNeedsRendererSetup) {
                    threadedRenderer.setup(mWidth, mHeight, mAttachInfo,
                            mWindowAttributes.surfaceInsets);
                    mNeedsRendererSetup = false;
                }
            }

            if (!mStopped || mReportNextDraw) {
                boolean focusChangedDueToTouchMode = ensureTouchModeLocally(
                        (relayoutResult&WindowManagerGlobal.RELAYOUT_RES_IN_TOUCH_MODE) != 0);
                if (focusChangedDueToTouchMode || mWidth != host.getMeasuredWidth()
                        || mHeight != host.getMeasuredHeight() || contentInsetsChanged ||
                        updatedConfiguration) {
                    int childWidthMeasureSpec = getRootMeasureSpec(mWidth, lp.width);
                    int childHeightMeasureSpec = getRootMeasureSpec(mHeight, lp.height);

                    if (DEBUG_LAYOUT) Log.v(mTag, "Ooops, something changed!  mWidth="
                            + mWidth + " measuredWidth=" + host.getMeasuredWidth()
                            + " mHeight=" + mHeight
                            + " measuredHeight=" + host.getMeasuredHeight()
                            + " coveredInsetsChanged=" + contentInsetsChanged);

                     // Ask host how big it wants to be
                    performMeasure(childWidthMeasureSpec, childHeightMeasureSpec);

                    // Implementation of weights from WindowManager.LayoutParams
                    // We just grow the dimensions as needed and re-measure if
                    // needs be
                    int width = host.getMeasuredWidth();
                    int height = host.getMeasuredHeight();
                    boolean measureAgain = false;

                    if (lp.horizontalWeight > 0.0f) {
                        width += (int) ((mWidth - width) * lp.horizontalWeight);
                        childWidthMeasureSpec = MeasureSpec.makeMeasureSpec(width,
                                MeasureSpec.EXACTLY);
                        measureAgain = true;
                    }
                    if (lp.verticalWeight > 0.0f) {
                        height += (int) ((mHeight - height) * lp.verticalWeight);
                        childHeightMeasureSpec = MeasureSpec.makeMeasureSpec(height,
                                MeasureSpec.EXACTLY);
                        measureAgain = true;
                    }

                    if (measureAgain) {
                        if (DEBUG_LAYOUT) Log.v(mTag,
                                "And hey let's measure once more: width=" + width
                                + " height=" + height);
                        performMeasure(childWidthMeasureSpec, childHeightMeasureSpec);
                    }

                    layoutRequested = true;
                }
            }
        } else {
            // Not the first pass and no window/insets/visibility change but the window
            // may have moved and we need check that and if so to update the left and right
            // in the attach info. We translate only the window frame since on window move
            // the window manager tells us only for the new frame but the insets are the
            // same and we do not want to translate them more than once.
            maybeHandleWindowMove(frame);
        }

        if (surfaceSizeChanged) {
            updateBoundsSurface();
        }

        final boolean didLayout = layoutRequested && (!mStopped || mReportNextDraw);
        boolean triggerGlobalLayoutListener = didLayout
                || mAttachInfo.mRecomputeGlobalAttributes;
        if (didLayout) {
            performLayout(lp, mWidth, mHeight);

            // By this point all views have been sized and positioned
            // We can compute the transparent area

            if ((host.mPrivateFlags & View.PFLAG_REQUEST_TRANSPARENT_REGIONS) != 0) {
                // start out transparent
                // TODO: AVOID THAT CALL BY CACHING THE RESULT?
                host.getLocationInWindow(mTmpLocation);
                mTransparentRegion.set(mTmpLocation[0], mTmpLocation[1],
                        mTmpLocation[0] + host.mRight - host.mLeft,
                        mTmpLocation[1] + host.mBottom - host.mTop);

                host.gatherTransparentRegion(mTransparentRegion);
                if (mTranslator != null) {
                    mTranslator.translateRegionInWindowToScreen(mTransparentRegion);
                }

                if (!mTransparentRegion.equals(mPreviousTransparentRegion)) {
                    mPreviousTransparentRegion.set(mTransparentRegion);
                    mFullRedrawNeeded = true;
                    // reconfigure window manager
                    try {
                        mWindowSession.setTransparentRegion(mWindow, mTransparentRegion);
                    } catch (RemoteException e) {
                    }
                }
            }

            if (DBG) {
                System.out.println("======================================");
                System.out.println("performTraversals -- after setFrame");
                host.debug();
            }
        }

        if (triggerGlobalLayoutListener) {
            mAttachInfo.mRecomputeGlobalAttributes = false;
            mAttachInfo.mTreeObserver.dispatchOnGlobalLayout();
        }

        if (computesInternalInsets) {
            // Clear the original insets.
            final ViewTreeObserver.InternalInsetsInfo insets = mAttachInfo.mGivenInternalInsets;
            insets.reset();

            // Compute new insets in place.
            mAttachInfo.mTreeObserver.dispatchOnComputeInternalInsets(insets);
            mAttachInfo.mHasNonEmptyGivenInternalInsets = !insets.isEmpty();

            // Tell the window manager.
            if (insetsPending || !mLastGivenInsets.equals(insets)) {
                mLastGivenInsets.set(insets);

                // Translate insets to screen coordinates if needed.
                final Rect contentInsets;
                final Rect visibleInsets;
                final Region touchableRegion;
                if (mTranslator != null) {
                    contentInsets = mTranslator.getTranslatedContentInsets(insets.contentInsets);
                    visibleInsets = mTranslator.getTranslatedVisibleInsets(insets.visibleInsets);
                    touchableRegion = mTranslator.getTranslatedTouchableArea(insets.touchableRegion);
                } else {
                    contentInsets = insets.contentInsets;
                    visibleInsets = insets.visibleInsets;
                    touchableRegion = insets.touchableRegion;
                }

                try {
                    mWindowSession.setInsets(mWindow, insets.mTouchableInsets,
                            contentInsets, visibleInsets, touchableRegion);
                } catch (RemoteException e) {
                }
            }
        }

        if (mFirst) {
            if (sAlwaysAssignFocus || !isInTouchMode()) {
                // handle first focus request
                if (DEBUG_INPUT_RESIZE) {
                    Log.v(mTag, "First: mView.hasFocus()=" + mView.hasFocus());
                }
                if (mView != null) {
                    if (!mView.hasFocus()) {
                        mView.restoreDefaultFocus();
                        if (DEBUG_INPUT_RESIZE) {
                            Log.v(mTag, "First: requested focused view=" + mView.findFocus());
                        }
                    } else {
                        if (DEBUG_INPUT_RESIZE) {
                            Log.v(mTag, "First: existing focused view=" + mView.findFocus());
                        }
                    }
                }
            } else {
                // Some views (like ScrollView) won't hand focus to descendants that aren't within
                // their viewport. Before layout, there's a good change these views are size 0
                // which means no children can get focus. After layout, this view now has size, but
                // is not guaranteed to hand-off focus to a focusable child (specifically, the edge-
                // case where the child has a size prior to layout and thus won't trigger
                // focusableViewAvailable).
                View focused = mView.findFocus();
                if (focused instanceof ViewGroup
                        && ((ViewGroup) focused).getDescendantFocusability()
                                == ViewGroup.FOCUS_AFTER_DESCENDANTS) {
                    focused.restoreDefaultFocus();
                }
            }
        }

        final boolean changedVisibility = (viewVisibilityChanged || mFirst) && isViewVisible;
        final boolean hasWindowFocus = mAttachInfo.mHasWindowFocus && isViewVisible;
        final boolean regainedFocus = hasWindowFocus && mLostWindowFocus;
        if (regainedFocus) {
            mLostWindowFocus = false;
        } else if (!hasWindowFocus && mHadWindowFocus) {
            mLostWindowFocus = true;
        }

        if (changedVisibility || regainedFocus) {
            // Toasts are presented as notifications - don't present them as windows as well
            boolean isToast = (mWindowAttributes == null) ? false
                    : (mWindowAttributes.type == WindowManager.LayoutParams.TYPE_TOAST);
            if (!isToast) {
                host.sendAccessibilityEvent(AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED);
            }
        }

        mFirst = false;
        mWillDrawSoon = false;
        mNewSurfaceNeeded = false;
        mActivityRelaunched = false;
        mViewVisibility = viewVisibility;
        mHadWindowFocus = hasWindowFocus;

        if (hasWindowFocus && !isInLocalFocusMode()) {
            final boolean imTarget = WindowManager.LayoutParams
                    .mayUseInputMethod(mWindowAttributes.flags);
            if (imTarget != mLastWasImTarget) {
                mLastWasImTarget = imTarget;
                InputMethodManager imm = mContext.getSystemService(InputMethodManager.class);
                if (imm != null && imTarget) {
                    imm.onPreWindowFocus(mView, hasWindowFocus);
                    imm.onPostWindowFocus(mView, mView.findFocus(),
                            mWindowAttributes.softInputMode,
                            !mHasHadWindowFocus, mWindowAttributes.flags);
                }
            }
        }

        // Remember if we must report the next draw.
        if ((relayoutResult & WindowManagerGlobal.RELAYOUT_RES_FIRST_TIME) != 0) {
            reportNextDraw();
        }

        boolean cancelDraw = mAttachInfo.mTreeObserver.dispatchOnPreDraw() || !isViewVisible;

        if (!cancelDraw) {
            if (mPendingTransitions != null && mPendingTransitions.size() > 0) {
                for (int i = 0; i < mPendingTransitions.size(); ++i) {
                    mPendingTransitions.get(i).startChangingAnimations();
                }
                mPendingTransitions.clear();
            }

            performDraw();
        } else {
            if (isViewVisible) {
                // Try again
                scheduleTraversals();
            } else if (mPendingTransitions != null && mPendingTransitions.size() > 0) {
                for (int i = 0; i < mPendingTransitions.size(); ++i) {
                    mPendingTransitions.get(i).endChangingAnimations();
                }
                mPendingTransitions.clear();
            }
        }

        if (mAttachInfo.mContentCaptureEvents != null) {
            notifyContentCatpureEvents();
        }

        mIsInTraversal = false;
    }

    private void notifyContentCatpureEvents() {
        Trace.traceBegin(Trace.TRACE_TAG_VIEW, "notifyContentCaptureEvents");
        try {
            MainContentCaptureSession mainSession = mAttachInfo.mContentCaptureManager
                    .getMainContentCaptureSession();
            for (int i = 0; i < mAttachInfo.mContentCaptureEvents.size(); i++) {
                int sessionId = mAttachInfo.mContentCaptureEvents.keyAt(i);
                mainSession.notifyViewTreeEvent(sessionId, /* started= */ true);
                ArrayList<Object> events = mAttachInfo.mContentCaptureEvents
                        .valueAt(i);
                for_each_event: for (int j = 0; j < events.size(); j++) {
                    Object event = events.get(j);
                    if (event instanceof AutofillId) {
                        mainSession.notifyViewDisappeared(sessionId, (AutofillId) event);
                    } else if (event instanceof View) {
                        View view = (View) event;
                        ContentCaptureSession session = view.getContentCaptureSession();
                        if (session == null) {
                            Log.w(mTag, "no content capture session on view: " + view);
                            continue for_each_event;
                        }
                        int actualId = session.getId();
                        if (actualId != sessionId) {
                            Log.w(mTag, "content capture session mismatch for view (" + view
                                    + "): was " + sessionId + " before, it's " + actualId + " now");
                            continue for_each_event;
                        }
                        ViewStructure structure = session.newViewStructure(view);
                        view.onProvideContentCaptureStructure(structure, /* flags= */ 0);
                        session.notifyViewAppeared(structure);
                    } else {
                        Log.w(mTag, "invalid content capture event: " + event);
                    }
                }
                mainSession.notifyViewTreeEvent(sessionId, /* started= */ false);
            }
            mAttachInfo.mContentCaptureEvents = null;
        } finally {
            Trace.traceEnd(Trace.TRACE_TAG_VIEW);
        }
    }

    private void notifySurfaceDestroyed() {
        mSurfaceHolder.ungetCallbacks();
        SurfaceHolder.Callback[] callbacks = mSurfaceHolder.getCallbacks();
        if (callbacks != null) {
            for (SurfaceHolder.Callback c : callbacks) {
                c.surfaceDestroyed(mSurfaceHolder);
            }
        }
    }

    private void maybeHandleWindowMove(Rect frame) {
        // TODO: Well, we are checking whether the frame has changed similarly
        // to how this is done for the insets. This is however incorrect since
        // the insets and the frame are translated. For example, the old frame
        // was (1, 1 - 1, 1) and was translated to say (2, 2 - 2, 2), now the new
        // reported frame is (2, 2 - 2, 2) which implies no change but this is not
        // true since we are comparing a not translated value to a translated one.
        // This scenario is rare but we may want to fix that.

        final boolean windowMoved = mAttachInfo.mWindowLeft != frame.left
                || mAttachInfo.mWindowTop != frame.top;
        if (windowMoved) {
            if (mTranslator != null) {
                mTranslator.translateRectInScreenToAppWinFrame(frame);
            }
            mAttachInfo.mWindowLeft = frame.left;
            mAttachInfo.mWindowTop = frame.top;
        }
        if (windowMoved || mAttachInfo.mNeedsUpdateLightCenter) {
            // Update the light position for the new offsets.
            if (mAttachInfo.mThreadedRenderer != null) {
                mAttachInfo.mThreadedRenderer.setLightCenter(mAttachInfo);
            }
            mAttachInfo.mNeedsUpdateLightCenter = false;
        }
    }

    private void handleWindowFocusChanged() {
        final boolean hasWindowFocus;
        final boolean inTouchMode;
        synchronized (this) {
            if (!mWindowFocusChanged) {
                return;
            }
            mWindowFocusChanged = false;
            hasWindowFocus = mUpcomingWindowFocus;
            inTouchMode = mUpcomingInTouchMode;
        }
        if (sNewInsetsMode != NEW_INSETS_MODE_NONE) {
            // TODO (b/131181940): Make sure this doesn't leak Activity with mActivityConfigCallback
            // config changes.
            if (hasWindowFocus) {
                mInsetsController.onWindowFocusGained();
            } else {
                mInsetsController.onWindowFocusLost();
            }
        }

        if (mAdded) {
            profileRendering(hasWindowFocus);

            if (hasWindowFocus) {
                ensureTouchModeLocally(inTouchMode);
                if (mAttachInfo.mThreadedRenderer != null && mSurface.isValid()) {
                    mFullRedrawNeeded = true;
                    try {
                        final WindowManager.LayoutParams lp = mWindowAttributes;
                        final Rect surfaceInsets = lp != null ? lp.surfaceInsets : null;
                        mAttachInfo.mThreadedRenderer.initializeIfNeeded(
                                mWidth, mHeight, mAttachInfo, mSurface, surfaceInsets);
                    } catch (OutOfResourcesException e) {
                        Log.e(mTag, "OutOfResourcesException locking surface", e);
                        try {
                            if (!mWindowSession.outOfMemory(mWindow)) {
                                Slog.w(mTag, "No processes killed for memory;"
                                        + " killing self");
                                Process.killProcess(Process.myPid());
                            }
                        } catch (RemoteException ex) {
                        }
                        // Retry in a bit.
                        mHandler.sendMessageDelayed(mHandler.obtainMessage(
                                MSG_WINDOW_FOCUS_CHANGED), 500);
                        return;
                    }
                }
            }

            mAttachInfo.mHasWindowFocus = hasWindowFocus;

            mLastWasImTarget = WindowManager.LayoutParams
                    .mayUseInputMethod(mWindowAttributes.flags);

            InputMethodManager imm = mContext.getSystemService(InputMethodManager.class);
            if (imm != null && mLastWasImTarget && !isInLocalFocusMode()) {
                imm.onPreWindowFocus(mView, hasWindowFocus);
            }
            if (mView != null) {
                mAttachInfo.mKeyDispatchState.reset();
                mView.dispatchWindowFocusChanged(hasWindowFocus);
                mAttachInfo.mTreeObserver.dispatchOnWindowFocusChange(hasWindowFocus);
                if (mAttachInfo.mTooltipHost != null) {
                    mAttachInfo.mTooltipHost.hideTooltip();
                }
            }

            // Note: must be done after the focus change callbacks,
            // so all of the view state is set up correctly.
            if (hasWindowFocus) {
                if (imm != null && mLastWasImTarget && !isInLocalFocusMode()) {
                    imm.onPostWindowFocus(mView, mView.findFocus(),
                            mWindowAttributes.softInputMode,
                            !mHasHadWindowFocus, mWindowAttributes.flags);
                }
                // Clear the forward bit.  We can just do this directly, since
                // the window manager doesn't care about it.
                mWindowAttributes.softInputMode &=
                        ~WindowManager.LayoutParams.SOFT_INPUT_IS_FORWARD_NAVIGATION;
                ((WindowManager.LayoutParams) mView.getLayoutParams())
                        .softInputMode &=
                        ~WindowManager.LayoutParams
                                .SOFT_INPUT_IS_FORWARD_NAVIGATION;
                mHasHadWindowFocus = true;

                // Refocusing a window that has a focused view should fire a
                // focus event for the view since the global focused view changed.
                fireAccessibilityFocusEventIfHasFocusedNode();
            } else {
                if (mPointerCapture) {
                    handlePointerCaptureChanged(false);
                }
            }
        }
        mFirstInputStage.onWindowFocusChanged(hasWindowFocus);

        // NOTE: there's no view visibility (appeared / disapparead) events when the windows focus
        // is lost, so we don't need to to force a flush - there might be other events such as
        // text changes, but these should be flushed independently.
        if (hasWindowFocus) {
            handleContentCaptureFlush();
        }
    }

    private void fireAccessibilityFocusEventIfHasFocusedNode() {
        if (!AccessibilityManager.getInstance(mContext).isEnabled()) {
            return;
        }
        final View focusedView = mView.findFocus();
        if (focusedView == null) {
            return;
        }
        final AccessibilityNodeProvider provider = focusedView.getAccessibilityNodeProvider();
        if (provider == null) {
            focusedView.sendAccessibilityEvent(AccessibilityEvent.TYPE_VIEW_FOCUSED);
        } else {
            final AccessibilityNodeInfo focusedNode = findFocusedVirtualNode(provider);
            if (focusedNode != null) {
                final int virtualId = AccessibilityNodeInfo.getVirtualDescendantId(
                        focusedNode.getSourceNodeId());
                // This is a best effort since clearing and setting the focus via the
                // provider APIs could have side effects. We don't have a provider API
                // similar to that on View to ask a given event to be fired.
                final AccessibilityEvent event = AccessibilityEvent.obtain(
                        AccessibilityEvent.TYPE_VIEW_FOCUSED);
                event.setSource(focusedView, virtualId);
                event.setPackageName(focusedNode.getPackageName());
                event.setChecked(focusedNode.isChecked());
                event.setContentDescription(focusedNode.getContentDescription());
                event.setPassword(focusedNode.isPassword());
                event.getText().add(focusedNode.getText());
                event.setEnabled(focusedNode.isEnabled());
                focusedView.getParent().requestSendAccessibilityEvent(focusedView, event);
                focusedNode.recycle();
            }
        }
    }

    private AccessibilityNodeInfo findFocusedVirtualNode(AccessibilityNodeProvider provider) {
        AccessibilityNodeInfo focusedNode = provider.findFocus(
                AccessibilityNodeInfo.FOCUS_INPUT);
        if (focusedNode != null) {
            return focusedNode;
        }

        if (!mContext.isAutofillCompatibilityEnabled()) {
            return null;
        }

        // Unfortunately some provider implementations don't properly
        // implement AccessibilityNodeProvider#findFocus
        AccessibilityNodeInfo current = provider.createAccessibilityNodeInfo(
                AccessibilityNodeProvider.HOST_VIEW_ID);
        if (current.isFocused()) {
            return current;
        }

        final Queue<AccessibilityNodeInfo> fringe = new LinkedList<>();
        fringe.offer(current);

        while (!fringe.isEmpty()) {
            current = fringe.poll();
            final LongArray childNodeIds = current.getChildNodeIds();
            if (childNodeIds== null || childNodeIds.size() <= 0) {
                continue;
            }
            final int childCount = childNodeIds.size();
            for (int i = 0; i < childCount; i++) {
                final int virtualId = AccessibilityNodeInfo.getVirtualDescendantId(
                        childNodeIds.get(i));
                final AccessibilityNodeInfo child = provider.createAccessibilityNodeInfo(virtualId);
                if (child != null) {
                    if (child.isFocused()) {
                        return child;
                    }
                    fringe.offer(child);
                }
            }
            current.recycle();
        }

        return null;
    }

    private void handleOutOfResourcesException(Surface.OutOfResourcesException e) {
        Log.e(mTag, "OutOfResourcesException initializing HW surface", e);
        try {
            if (!mWindowSession.outOfMemory(mWindow) &&
                    Process.myUid() != Process.SYSTEM_UID) {
                Slog.w(mTag, "No processes killed for memory; killing self");
                Process.killProcess(Process.myPid());
            }
        } catch (RemoteException ex) {
        }
        mLayoutRequested = true;    // ask wm for a new surface next time.
    }

    private void performMeasure(int childWidthMeasureSpec, int childHeightMeasureSpec) {
        if (mView == null) {
            return;
        }
        Trace.traceBegin(Trace.TRACE_TAG_VIEW, "measure");
        try {
            mView.measure(childWidthMeasureSpec, childHeightMeasureSpec);
        } finally {
            Trace.traceEnd(Trace.TRACE_TAG_VIEW);
        }
    }

    /**
     * Called by {@link android.view.View#isInLayout()} to determine whether the view hierarchy
     * is currently undergoing a layout pass.
     *
     * @return whether the view hierarchy is currently undergoing a layout pass
     */
    boolean isInLayout() {
        return mInLayout;
    }

    /**
     * Called by {@link android.view.View#requestLayout()} if the view hierarchy is currently
     * undergoing a layout pass. requestLayout() should not generally be called during layout,
     * unless the container hierarchy knows what it is doing (i.e., it is fine as long as
     * all children in that container hierarchy are measured and laid out at the end of the layout
     * pass for that container). If requestLayout() is called anyway, we handle it correctly
     * by registering all requesters during a frame as it proceeds. At the end of the frame,
     * we check all of those views to see if any still have pending layout requests, which
     * indicates that they were not correctly handled by their container hierarchy. If that is
     * the case, we clear all such flags in the tree, to remove the buggy flag state that leads
     * to blank containers, and force a second request/measure/layout pass in this frame. If
     * more requestLayout() calls are received during that second layout pass, we post those
     * requests to the next frame to avoid possible infinite loops.
     *
     * <p>The return value from this method indicates whether the request should proceed
     * (if it is a request during the first layout pass) or should be skipped and posted to the
     * next frame (if it is a request during the second layout pass).</p>
     *
     * @param view the view that requested the layout.
     *
     * @return true if request should proceed, false otherwise.
     */
    boolean requestLayoutDuringLayout(final View view) {
        if (view.mParent == null || view.mAttachInfo == null) {
            // Would not normally trigger another layout, so just let it pass through as usual
            return true;
        }
        if (!mLayoutRequesters.contains(view)) {
            mLayoutRequesters.add(view);
        }
        if (!mHandlingLayoutInLayoutRequest) {
            // Let the request proceed normally; it will be processed in a second layout pass
            // if necessary
            return true;
        } else {
            // Don't let the request proceed during the second layout pass.
            // It will post to the next frame instead.
            return false;
        }
    }

    private void performLayout(WindowManager.LayoutParams lp, int desiredWindowWidth,
            int desiredWindowHeight) {
        mLayoutRequested = false;
        mScrollMayChange = true;
        mInLayout = true;

        final View host = mView;
        if (host == null) {
            return;
        }
        if (DEBUG_ORIENTATION || DEBUG_LAYOUT) {
            Log.v(mTag, "Laying out " + host + " to (" +
                    host.getMeasuredWidth() + ", " + host.getMeasuredHeight() + ")");
        }

        Trace.traceBegin(Trace.TRACE_TAG_VIEW, "layout");
        try {
            host.layout(0, 0, host.getMeasuredWidth(), host.getMeasuredHeight());

            mInLayout = false;
            int numViewsRequestingLayout = mLayoutRequesters.size();
            if (numViewsRequestingLayout > 0) {
                // requestLayout() was called during layout.
                // If no layout-request flags are set on the requesting views, there is no problem.
                // If some requests are still pending, then we need to clear those flags and do
                // a full request/measure/layout pass to handle this situation.
                ArrayList<View> validLayoutRequesters = getValidLayoutRequesters(mLayoutRequesters,
                        false);
                if (validLayoutRequesters != null) {
                    // Set this flag to indicate that any further requests are happening during
                    // the second pass, which may result in posting those requests to the next
                    // frame instead
                    mHandlingLayoutInLayoutRequest = true;

                    // Process fresh layout requests, then measure and layout
                    int numValidRequests = validLayoutRequesters.size();
                    for (int i = 0; i < numValidRequests; ++i) {
                        final View view = validLayoutRequesters.get(i);
                        Log.w("View", "requestLayout() improperly called by " + view +
                                " during layout: running second layout pass");
                        view.requestLayout();
                    }
                    measureHierarchy(host, lp, mView.getContext().getResources(),
                            desiredWindowWidth, desiredWindowHeight);
                    mInLayout = true;
                    host.layout(0, 0, host.getMeasuredWidth(), host.getMeasuredHeight());

                    mHandlingLayoutInLayoutRequest = false;

                    // Check the valid requests again, this time without checking/clearing the
                    // layout flags, since requests happening during the second pass get noop'd
                    validLayoutRequesters = getValidLayoutRequesters(mLayoutRequesters, true);
                    if (validLayoutRequesters != null) {
                        final ArrayList<View> finalRequesters = validLayoutRequesters;
                        // Post second-pass requests to the next frame
                        getRunQueue().post(new Runnable() {
                            @Override
                            public void run() {
                                int numValidRequests = finalRequesters.size();
                                for (int i = 0; i < numValidRequests; ++i) {
                                    final View view = finalRequesters.get(i);
                                    Log.w("View", "requestLayout() improperly called by " + view +
                                            " during second layout pass: posting in next frame");
                                    view.requestLayout();
                                }
                            }
                        });
                    }
                }

            }
        } finally {
            Trace.traceEnd(Trace.TRACE_TAG_VIEW);
        }
        mInLayout = false;
    }

    /**
     * This method is called during layout when there have been calls to requestLayout() during
     * layout. It walks through the list of views that requested layout to determine which ones
     * still need it, based on visibility in the hierarchy and whether they have already been
     * handled (as is usually the case with ListView children).
     *
     * @param layoutRequesters The list of views that requested layout during layout
     * @param secondLayoutRequests Whether the requests were issued during the second layout pass.
     * If so, the FORCE_LAYOUT flag was not set on requesters.
     * @return A list of the actual views that still need to be laid out.
     */
    private ArrayList<View> getValidLayoutRequesters(ArrayList<View> layoutRequesters,
            boolean secondLayoutRequests) {

        int numViewsRequestingLayout = layoutRequesters.size();
        ArrayList<View> validLayoutRequesters = null;
        for (int i = 0; i < numViewsRequestingLayout; ++i) {
            View view = layoutRequesters.get(i);
            if (view != null && view.mAttachInfo != null && view.mParent != null &&
                    (secondLayoutRequests || (view.mPrivateFlags & View.PFLAG_FORCE_LAYOUT) ==
                            View.PFLAG_FORCE_LAYOUT)) {
                boolean gone = false;
                View parent = view;
                // Only trigger new requests for views in a non-GONE hierarchy
                while (parent != null) {
                    if ((parent.mViewFlags & View.VISIBILITY_MASK) == View.GONE) {
                        gone = true;
                        break;
                    }
                    if (parent.mParent instanceof View) {
                        parent = (View) parent.mParent;
                    } else {
                        parent = null;
                    }
                }
                if (!gone) {
                    if (validLayoutRequesters == null) {
                        validLayoutRequesters = new ArrayList<View>();
                    }
                    validLayoutRequesters.add(view);
                }
            }
        }
        if (!secondLayoutRequests) {
            // If we're checking the layout flags, then we need to clean them up also
            for (int i = 0; i < numViewsRequestingLayout; ++i) {
                View view = layoutRequesters.get(i);
                while (view != null &&
                        (view.mPrivateFlags & View.PFLAG_FORCE_LAYOUT) != 0) {
                    view.mPrivateFlags &= ~View.PFLAG_FORCE_LAYOUT;
                    if (view.mParent instanceof View) {
                        view = (View) view.mParent;
                    } else {
                        view = null;
                    }
                }
            }
        }
        layoutRequesters.clear();
        return validLayoutRequesters;
    }

    @Override
    public void requestTransparentRegion(View child) {
        // the test below should not fail unless someone is messing with us
        checkThread();
        if (mView == child) {
            mView.mPrivateFlags |= View.PFLAG_REQUEST_TRANSPARENT_REGIONS;
            // Need to make sure we re-evaluate the window attributes next
            // time around, to ensure the window has the correct format.
            mWindowAttributesChanged = true;
            mWindowAttributesChangesFlag = 0;
            requestLayout();
        }
    }

    /**
     * Figures out the measure spec for the root view in a window based on it's
     * layout params.
     *
     * @param windowSize
     *            The available width or height of the window
     *
     * @param rootDimension
     *            The layout params for one dimension (width or height) of the
     *            window.
     *
     * @return The measure spec to use to measure the root view.
     */
    private static int getRootMeasureSpec(int windowSize, int rootDimension) {
        int measureSpec;
        switch (rootDimension) {

        case ViewGroup.LayoutParams.MATCH_PARENT:
            // Window can't resize. Force root view to be windowSize.
            measureSpec = MeasureSpec.makeMeasureSpec(windowSize, MeasureSpec.EXACTLY);
            break;
        case ViewGroup.LayoutParams.WRAP_CONTENT:
            // Window can resize. Set max size for root view.
            measureSpec = MeasureSpec.makeMeasureSpec(windowSize, MeasureSpec.AT_MOST);
            break;
        default:
            // Window wants to be an exact size. Force root view to be that size.
            measureSpec = MeasureSpec.makeMeasureSpec(rootDimension, MeasureSpec.EXACTLY);
            break;
        }
        return measureSpec;
    }

    int mHardwareXOffset;
    int mHardwareYOffset;

    @Override
    public void onPreDraw(RecordingCanvas canvas) {
        // If mCurScrollY is not 0 then this influences the hardwareYOffset. The end result is we
        // can apply offsets that are not handled by anything else, resulting in underdraw as
        // the View is shifted (thus shifting the window background) exposing unpainted
        // content. To handle this with minimal glitches we just clear to BLACK if the window
        // is opaque. If it's not opaque then HWUI already internally does a glClear to
        // transparent, so there's no risk of underdraw on non-opaque surfaces.
        if (mCurScrollY != 0 && mHardwareYOffset != 0 && mAttachInfo.mThreadedRenderer.isOpaque()) {
            canvas.drawColor(Color.BLACK);
        }
        canvas.translate(-mHardwareXOffset, -mHardwareYOffset);
    }

    @Override
    public void onPostDraw(RecordingCanvas canvas) {
        drawAccessibilityFocusedDrawableIfNeeded(canvas);
        if (mUseMTRenderer) {
            for (int i = mWindowCallbacks.size() - 1; i >= 0; i--) {
                mWindowCallbacks.get(i).onPostDraw(canvas);
            }
        }
    }

    /**
     * @hide
     */
    void outputDisplayList(View view) {
        view.mRenderNode.output();
    }

    /**
     * @see #PROPERTY_PROFILE_RENDERING
     */
    private void profileRendering(boolean enabled) {
        if (mProfileRendering) {
            mRenderProfilingEnabled = enabled;

            if (mRenderProfiler != null) {
                mChoreographer.removeFrameCallback(mRenderProfiler);
            }
            if (mRenderProfilingEnabled) {
                if (mRenderProfiler == null) {
                    mRenderProfiler = new Choreographer.FrameCallback() {
                        @Override
                        public void doFrame(long frameTimeNanos) {
                            mDirty.set(0, 0, mWidth, mHeight);
                            scheduleTraversals();
                            if (mRenderProfilingEnabled) {
                                mChoreographer.postFrameCallback(mRenderProfiler);
                            }
                        }
                    };
                }
                mChoreographer.postFrameCallback(mRenderProfiler);
            } else {
                mRenderProfiler = null;
            }
        }
    }

    /**
     * Called from draw() when DEBUG_FPS is enabled
     */
    private void trackFPS() {
        // Tracks frames per second drawn. First value in a series of draws may be bogus
        // because it down not account for the intervening idle time
        long nowTime = System.currentTimeMillis();
        if (mFpsStartTime < 0) {
            mFpsStartTime = mFpsPrevTime = nowTime;
            mFpsNumFrames = 0;
        } else {
            ++mFpsNumFrames;
            String thisHash = Integer.toHexString(System.identityHashCode(this));
            long frameTime = nowTime - mFpsPrevTime;
            long totalTime = nowTime - mFpsStartTime;
            Log.v(mTag, "0x" + thisHash + "\tFrame time:\t" + frameTime);
            mFpsPrevTime = nowTime;
            if (totalTime > 1000) {
                float fps = (float) mFpsNumFrames * 1000 / totalTime;
                Log.v(mTag, "0x" + thisHash + "\tFPS:\t" + fps);
                mFpsStartTime = nowTime;
                mFpsNumFrames = 0;
            }
        }
    }

    /**
     * A count of the number of calls to pendingDrawFinished we
     * require to notify the WM drawing is complete.
     */
    int mDrawsNeededToReport = 0;

    /**
     * Delay notifying WM of draw finished until
     * a balanced call to pendingDrawFinished.
     */
    void drawPending() {
        mDrawsNeededToReport++;
    }

    void pendingDrawFinished() {
        if (mDrawsNeededToReport == 0) {
            throw new RuntimeException("Unbalanced drawPending/pendingDrawFinished calls");
        }
        mDrawsNeededToReport--;
        if (mDrawsNeededToReport == 0) {
            reportDrawFinished();
        }
    }

    private void postDrawFinished() {
        mHandler.sendEmptyMessage(MSG_DRAW_FINISHED);
    }

    private void reportDrawFinished() {
        try {
            mDrawsNeededToReport = 0;
            mWindowSession.finishDrawing(mWindow);
        } catch (RemoteException e) {
            // Have fun!
        }
    }

    private void performDraw() {
        if (mAttachInfo.mDisplayState == Display.STATE_OFF && !mReportNextDraw) {
            return;
        } else if (mView == null) {
            return;
        }

        final boolean fullRedrawNeeded = mFullRedrawNeeded || mReportNextDraw;
        mFullRedrawNeeded = false;

        mIsDrawing = true;
        Trace.traceBegin(Trace.TRACE_TAG_VIEW, "draw");

        boolean usingAsyncReport = false;
        if (mAttachInfo.mThreadedRenderer != null && mAttachInfo.mThreadedRenderer.isEnabled()) {
            ArrayList<Runnable> commitCallbacks = mAttachInfo.mTreeObserver
                    .captureFrameCommitCallbacks();
            if (mReportNextDraw) {
                usingAsyncReport = true;
                final Handler handler = mAttachInfo.mHandler;
                mAttachInfo.mThreadedRenderer.setFrameCompleteCallback((long frameNr) ->
                        handler.postAtFrontOfQueue(() -> {
                            // TODO: Use the frame number
                            pendingDrawFinished();
                            if (commitCallbacks != null) {
                                for (int i = 0; i < commitCallbacks.size(); i++) {
                                    commitCallbacks.get(i).run();
                                }
                            }
                        }));
            } else if (commitCallbacks != null && commitCallbacks.size() > 0) {
                final Handler handler = mAttachInfo.mHandler;
                mAttachInfo.mThreadedRenderer.setFrameCompleteCallback((long frameNr) ->
                        handler.postAtFrontOfQueue(() -> {
                            for (int i = 0; i < commitCallbacks.size(); i++) {
                                commitCallbacks.get(i).run();
                            }
                        }));
            }
        }

        try {
            boolean canUseAsync = draw(fullRedrawNeeded);
            if (usingAsyncReport && !canUseAsync) {
                mAttachInfo.mThreadedRenderer.setFrameCompleteCallback(null);
                usingAsyncReport = false;
            }
        } finally {
            mIsDrawing = false;
            Trace.traceEnd(Trace.TRACE_TAG_VIEW);
        }

        // For whatever reason we didn't create a HardwareRenderer, end any
        // hardware animations that are now dangling
        if (mAttachInfo.mPendingAnimatingRenderNodes != null) {
            final int count = mAttachInfo.mPendingAnimatingRenderNodes.size();
            for (int i = 0; i < count; i++) {
                mAttachInfo.mPendingAnimatingRenderNodes.get(i).endAllAnimators();
            }
            mAttachInfo.mPendingAnimatingRenderNodes.clear();
        }

        if (mReportNextDraw) {
            mReportNextDraw = false;

            // if we're using multi-thread renderer, wait for the window frame draws
            if (mWindowDrawCountDown != null) {
                try {
                    mWindowDrawCountDown.await();
                } catch (InterruptedException e) {
                    Log.e(mTag, "Window redraw count down interrupted!");
                }
                mWindowDrawCountDown = null;
            }

            if (mAttachInfo.mThreadedRenderer != null) {
                mAttachInfo.mThreadedRenderer.setStopped(mStopped);
            }

            if (LOCAL_LOGV) {
                Log.v(mTag, "FINISHED DRAWING: " + mWindowAttributes.getTitle());
            }

            if (mSurfaceHolder != null && mSurface.isValid()) {
                SurfaceCallbackHelper sch = new SurfaceCallbackHelper(this::postDrawFinished);
                SurfaceHolder.Callback callbacks[] = mSurfaceHolder.getCallbacks();

                sch.dispatchSurfaceRedrawNeededAsync(mSurfaceHolder, callbacks);
            } else if (!usingAsyncReport) {
                if (mAttachInfo.mThreadedRenderer != null) {
                    mAttachInfo.mThreadedRenderer.fence();
                }
                pendingDrawFinished();
            }
        }
        if (mPerformContentCapture) {
            performContentCaptureInitialReport();
        }
    }

    /**
     * Checks (and caches) if content capture is enabled for this context.
     */
    private boolean isContentCaptureEnabled() {
        switch (mContentCaptureEnabled) {
            case CONTENT_CAPTURE_ENABLED_TRUE:
                return true;
            case CONTENT_CAPTURE_ENABLED_FALSE:
                return false;
            case CONTENT_CAPTURE_ENABLED_NOT_CHECKED:
                final boolean reallyEnabled = isContentCaptureReallyEnabled();
                mContentCaptureEnabled = reallyEnabled ? CONTENT_CAPTURE_ENABLED_TRUE
                        : CONTENT_CAPTURE_ENABLED_FALSE;
                return reallyEnabled;
            default:
                Log.w(TAG, "isContentCaptureEnabled(): invalid state " + mContentCaptureEnabled);
                return false;
        }

    }

    /**
     * Checks (without caching) if content capture is enabled for this context.
     */
    private boolean isContentCaptureReallyEnabled() {
        // First check if context supports it, so it saves a service lookup when it doesn't
        if (mContext.getContentCaptureOptions() == null) return false;

        final ContentCaptureManager ccm = mAttachInfo.getContentCaptureManager(mContext);
        // Then check if it's enabled in the contex itself.
        if (ccm == null || !ccm.isContentCaptureEnabled()) return false;

        return true;
    }

    private void performContentCaptureInitialReport() {
        mPerformContentCapture = false; // One-time offer!
        final View rootView = mView;
        if (DEBUG_CONTENT_CAPTURE) {
            Log.v(mTag, "performContentCaptureInitialReport() on " + rootView);
        }
        if (Trace.isTagEnabled(Trace.TRACE_TAG_VIEW)) {
            Trace.traceBegin(Trace.TRACE_TAG_VIEW, "dispatchContentCapture() for "
                    + getClass().getSimpleName());
        }
        try {
            if (!isContentCaptureEnabled()) return;

            // Content capture is a go!
            rootView.dispatchInitialProvideContentCaptureStructure();
        } finally {
            Trace.traceEnd(Trace.TRACE_TAG_VIEW);
        }
    }

    private void handleContentCaptureFlush() {
        if (DEBUG_CONTENT_CAPTURE) {
            Log.v(mTag, "handleContentCaptureFlush()");
        }
        if (Trace.isTagEnabled(Trace.TRACE_TAG_VIEW)) {
            Trace.traceBegin(Trace.TRACE_TAG_VIEW, "flushContentCapture for "
                    + getClass().getSimpleName());
        }
        try {
            if (!isContentCaptureEnabled()) return;

            final ContentCaptureManager ccm = mAttachInfo.mContentCaptureManager;
            if (ccm == null) {
                Log.w(TAG, "No ContentCapture on AttachInfo");
                return;
            }
            ccm.flush(ContentCaptureSession.FLUSH_REASON_VIEW_ROOT_ENTERED);
        } finally {
            Trace.traceEnd(Trace.TRACE_TAG_VIEW);
        }
    }

    private boolean draw(boolean fullRedrawNeeded) {
        Surface surface = mSurface;
        if (!surface.isValid()) {
            return false;
        }

        if (DEBUG_FPS) {
            trackFPS();
        }

        if (!sFirstDrawComplete) {
            synchronized (sFirstDrawHandlers) {
                sFirstDrawComplete = true;
                final int count = sFirstDrawHandlers.size();
                for (int i = 0; i< count; i++) {
                    mHandler.post(sFirstDrawHandlers.get(i));
                }
            }
        }

        scrollToRectOrFocus(null, false);

        if (mAttachInfo.mViewScrollChanged) {
            mAttachInfo.mViewScrollChanged = false;
            mAttachInfo.mTreeObserver.dispatchOnScrollChanged();
        }

        boolean animating = mScroller != null && mScroller.computeScrollOffset();
        final int curScrollY;
        if (animating) {
            curScrollY = mScroller.getCurrY();
        } else {
            curScrollY = mScrollY;
        }
        if (mCurScrollY != curScrollY) {
            mCurScrollY = curScrollY;
            fullRedrawNeeded = true;
            if (mView instanceof RootViewSurfaceTaker) {
                ((RootViewSurfaceTaker) mView).onRootViewScrollYChanged(mCurScrollY);
            }
        }

        final float appScale = mAttachInfo.mApplicationScale;
        final boolean scalingRequired = mAttachInfo.mScalingRequired;

        final Rect dirty = mDirty;
        if (mSurfaceHolder != null) {
            // The app owns the surface, we won't draw.
            dirty.setEmpty();
            if (animating && mScroller != null) {
                mScroller.abortAnimation();
            }
            return false;
        }

        if (fullRedrawNeeded) {
            dirty.set(0, 0, (int) (mWidth * appScale + 0.5f), (int) (mHeight * appScale + 0.5f));
        }

        if (DEBUG_ORIENTATION || DEBUG_DRAW) {
            Log.v(mTag, "Draw " + mView + "/"
                    + mWindowAttributes.getTitle()
                    + ": dirty={" + dirty.left + "," + dirty.top
                    + "," + dirty.right + "," + dirty.bottom + "} surface="
                    + surface + " surface.isValid()=" + surface.isValid() + ", appScale:" +
                    appScale + ", width=" + mWidth + ", height=" + mHeight);
        }

        mAttachInfo.mTreeObserver.dispatchOnDraw();

        int xOffset = -mCanvasOffsetX;
        int yOffset = -mCanvasOffsetY + curScrollY;
        final WindowManager.LayoutParams params = mWindowAttributes;
        final Rect surfaceInsets = params != null ? params.surfaceInsets : null;
        if (surfaceInsets != null) {
            xOffset -= surfaceInsets.left;
            yOffset -= surfaceInsets.top;

            // Offset dirty rect for surface insets.
            dirty.offset(surfaceInsets.left, surfaceInsets.right);
        }

        boolean accessibilityFocusDirty = false;
        final Drawable drawable = mAttachInfo.mAccessibilityFocusDrawable;
        if (drawable != null) {
            final Rect bounds = mAttachInfo.mTmpInvalRect;
            final boolean hasFocus = getAccessibilityFocusedRect(bounds);
            if (!hasFocus) {
                bounds.setEmpty();
            }
            if (!bounds.equals(drawable.getBounds())) {
                accessibilityFocusDirty = true;
            }
        }

        mAttachInfo.mDrawingTime =
                mChoreographer.getFrameTimeNanos() / TimeUtils.NANOS_PER_MS;

        boolean useAsyncReport = false;
        if (!dirty.isEmpty() || mIsAnimating || accessibilityFocusDirty) {
            if (mAttachInfo.mThreadedRenderer != null && mAttachInfo.mThreadedRenderer.isEnabled()) {
                // If accessibility focus moved, always invalidate the root.
                boolean invalidateRoot = accessibilityFocusDirty || mInvalidateRootRequested;
                mInvalidateRootRequested = false;

                // Draw with hardware renderer.
                mIsAnimating = false;

                if (mHardwareYOffset != yOffset || mHardwareXOffset != xOffset) {
                    mHardwareYOffset = yOffset;
                    mHardwareXOffset = xOffset;
                    invalidateRoot = true;
                }

                if (invalidateRoot) {
                    mAttachInfo.mThreadedRenderer.invalidateRoot();
                }

                dirty.setEmpty();

                // Stage the content drawn size now. It will be transferred to the renderer
                // shortly before the draw commands get send to the renderer.
                final boolean updated = updateContentDrawBounds();

                if (mReportNextDraw) {
                    // report next draw overrides setStopped()
                    // This value is re-sync'd to the value of mStopped
                    // in the handling of mReportNextDraw post-draw.
                    mAttachInfo.mThreadedRenderer.setStopped(false);
                }

                if (updated) {
                    requestDrawWindow();
                }

                useAsyncReport = true;

                mAttachInfo.mThreadedRenderer.draw(mView, mAttachInfo, this);
            } else {
                // If we get here with a disabled & requested hardware renderer, something went
                // wrong (an invalidate posted right before we destroyed the hardware surface
                // for instance) so we should just bail out. Locking the surface with software
                // rendering at this point would lock it forever and prevent hardware renderer
                // from doing its job when it comes back.
                // Before we request a new frame we must however attempt to reinitiliaze the
                // hardware renderer if it's in requested state. This would happen after an
                // eglTerminate() for instance.
                if (mAttachInfo.mThreadedRenderer != null &&
                        !mAttachInfo.mThreadedRenderer.isEnabled() &&
                        mAttachInfo.mThreadedRenderer.isRequested() &&
                        mSurface.isValid()) {

                    try {
                        mAttachInfo.mThreadedRenderer.initializeIfNeeded(
                                mWidth, mHeight, mAttachInfo, mSurface, surfaceInsets);
                    } catch (OutOfResourcesException e) {
                        handleOutOfResourcesException(e);
                        return false;
                    }

                    mFullRedrawNeeded = true;
                    scheduleTraversals();
                    return false;
                }

                if (!drawSoftware(surface, mAttachInfo, xOffset, yOffset,
                        scalingRequired, dirty, surfaceInsets)) {
                    return false;
                }
            }
        }

        if (animating) {
            mFullRedrawNeeded = true;
            scheduleTraversals();
        }
        return useAsyncReport;
    }

    /**
     * @return true if drawing was successful, false if an error occurred
     */
    private boolean drawSoftware(Surface surface, AttachInfo attachInfo, int xoff, int yoff,
            boolean scalingRequired, Rect dirty, Rect surfaceInsets) {

        // Draw with software renderer.
        final Canvas canvas;

        // We already have the offset of surfaceInsets in xoff, yoff and dirty region,
        // therefore we need to add it back when moving the dirty region.
        int dirtyXOffset = xoff;
        int dirtyYOffset = yoff;
        if (surfaceInsets != null) {
            dirtyXOffset += surfaceInsets.left;
            dirtyYOffset += surfaceInsets.top;
        }

        try {
            dirty.offset(-dirtyXOffset, -dirtyYOffset);
            final int left = dirty.left;
            final int top = dirty.top;
            final int right = dirty.right;
            final int bottom = dirty.bottom;

            canvas = mSurface.lockCanvas(dirty);

            // TODO: Do this in native
            canvas.setDensity(mDensity);
        } catch (Surface.OutOfResourcesException e) {
            handleOutOfResourcesException(e);
            return false;
        } catch (IllegalArgumentException e) {
            Log.e(mTag, "Could not lock surface", e);
            // Don't assume this is due to out of memory, it could be
            // something else, and if it is something else then we could
            // kill stuff (or ourself) for no reason.
            mLayoutRequested = true;    // ask wm for a new surface next time.
            return false;
        } finally {
            dirty.offset(dirtyXOffset, dirtyYOffset);  // Reset to the original value.
        }

        try {
            if (DEBUG_ORIENTATION || DEBUG_DRAW) {
                Log.v(mTag, "Surface " + surface + " drawing to bitmap w="
                        + canvas.getWidth() + ", h=" + canvas.getHeight());
                //canvas.drawARGB(255, 255, 0, 0);
            }

            // If this bitmap's format includes an alpha channel, we
            // need to clear it before drawing so that the child will
            // properly re-composite its drawing on a transparent
            // background. This automatically respects the clip/dirty region
            // or
            // If we are applying an offset, we need to clear the area
            // where the offset doesn't appear to avoid having garbage
            // left in the blank areas.
            if (!canvas.isOpaque() || yoff != 0 || xoff != 0) {
                canvas.drawColor(0, PorterDuff.Mode.CLEAR);
            }

            dirty.setEmpty();
            mIsAnimating = false;
            mView.mPrivateFlags |= View.PFLAG_DRAWN;

            if (DEBUG_DRAW) {
                Context cxt = mView.getContext();
                Log.i(mTag, "Drawing: package:" + cxt.getPackageName() +
                        ", metrics=" + cxt.getResources().getDisplayMetrics() +
                        ", compatibilityInfo=" + cxt.getResources().getCompatibilityInfo());
            }
            canvas.translate(-xoff, -yoff);
            if (mTranslator != null) {
                mTranslator.translateCanvas(canvas);
            }
            canvas.setScreenDensity(scalingRequired ? mNoncompatDensity : 0);

            mView.draw(canvas);

            drawAccessibilityFocusedDrawableIfNeeded(canvas);
        } finally {
            try {
                surface.unlockCanvasAndPost(canvas);
            } catch (IllegalArgumentException e) {
                Log.e(mTag, "Could not unlock surface", e);
                mLayoutRequested = true;    // ask wm for a new surface next time.
                //noinspection ReturnInsideFinallyBlock
                return false;
            }

            if (LOCAL_LOGV) {
                Log.v(mTag, "Surface " + surface + " unlockCanvasAndPost");
            }
        }
        return true;
    }

    /**
     * We want to draw a highlight around the current accessibility focused.
     * Since adding a style for all possible view is not a viable option we
     * have this specialized drawing method.
     *
     * Note: We are doing this here to be able to draw the highlight for
     *       virtual views in addition to real ones.
     *
     * @param canvas The canvas on which to draw.
     */
    private void drawAccessibilityFocusedDrawableIfNeeded(Canvas canvas) {
        final Rect bounds = mAttachInfo.mTmpInvalRect;
        if (getAccessibilityFocusedRect(bounds)) {
            final Drawable drawable = getAccessibilityFocusedDrawable();
            if (drawable != null) {
                drawable.setBounds(bounds);
                drawable.draw(canvas);
            }
        } else if (mAttachInfo.mAccessibilityFocusDrawable != null) {
            mAttachInfo.mAccessibilityFocusDrawable.setBounds(0, 0, 0, 0);
        }
    }

    private boolean getAccessibilityFocusedRect(Rect bounds) {
        final AccessibilityManager manager = AccessibilityManager.getInstance(mView.mContext);
        if (!manager.isEnabled() || !manager.isTouchExplorationEnabled()) {
            return false;
        }

        final View host = mAccessibilityFocusedHost;
        if (host == null || host.mAttachInfo == null) {
            return false;
        }

        final AccessibilityNodeProvider provider = host.getAccessibilityNodeProvider();
        if (provider == null) {
            host.getBoundsOnScreen(bounds, true);
        } else if (mAccessibilityFocusedVirtualView != null) {
            mAccessibilityFocusedVirtualView.getBoundsInScreen(bounds);
        } else {
            return false;
        }

        // Transform the rect into window-relative coordinates.
        final AttachInfo attachInfo = mAttachInfo;
        bounds.offset(0, attachInfo.mViewRootImpl.mScrollY);
        bounds.offset(-attachInfo.mWindowLeft, -attachInfo.mWindowTop);
        if (!bounds.intersect(0, 0, attachInfo.mViewRootImpl.mWidth,
                attachInfo.mViewRootImpl.mHeight)) {
            // If no intersection, set bounds to empty.
            bounds.setEmpty();
        }
        return !bounds.isEmpty();
    }

    private Drawable getAccessibilityFocusedDrawable() {
        // Lazily load the accessibility focus drawable.
        if (mAttachInfo.mAccessibilityFocusDrawable == null) {
            final TypedValue value = new TypedValue();
            final boolean resolved = mView.mContext.getTheme().resolveAttribute(
                    R.attr.accessibilityFocusedDrawable, value, true);
            if (resolved) {
                mAttachInfo.mAccessibilityFocusDrawable =
                        mView.mContext.getDrawable(value.resourceId);
            }
        }
        return mAttachInfo.mAccessibilityFocusDrawable;
    }

    void updateSystemGestureExclusionRectsForView(View view) {
        mGestureExclusionTracker.updateRectsForView(view);
        mHandler.sendEmptyMessage(MSG_SYSTEM_GESTURE_EXCLUSION_CHANGED);
    }

    void systemGestureExclusionChanged() {
        final List<Rect> rectsForWindowManager = mGestureExclusionTracker.computeChangedRects();
        if (rectsForWindowManager != null && mView != null) {
            try {
                mWindowSession.reportSystemGestureExclusionChanged(mWindow, rectsForWindowManager);
            } catch (RemoteException e) {
                throw e.rethrowFromSystemServer();
            }
            mAttachInfo.mTreeObserver
                    .dispatchOnSystemGestureExclusionRectsChanged(rectsForWindowManager);
        }
    }

    void updateLocationInParentDisplay(int x, int y) {
        if (mAttachInfo != null
                && !mAttachInfo.mLocationInParentDisplay.equals(x, y)) {
            mAttachInfo.mLocationInParentDisplay.set(x, y);
        }
    }

    /**
     * Set the root-level system gesture exclusion rects. These are added to those provided by
     * the root's view hierarchy.
     */
    public void setRootSystemGestureExclusionRects(@NonNull List<Rect> rects) {
        mGestureExclusionTracker.setRootSystemGestureExclusionRects(rects);
        mHandler.sendEmptyMessage(MSG_SYSTEM_GESTURE_EXCLUSION_CHANGED);
    }

    /**
     * Returns the root-level system gesture exclusion rects. These do not include those provided by
     * the root's view hierarchy.
     */
    @NonNull
    public List<Rect> getRootSystemGestureExclusionRects() {
        return mGestureExclusionTracker.getRootSystemGestureExclusionRects();
    }

    /**
     * Requests that the root render node is invalidated next time we perform a draw, such that
     * {@link WindowCallbacks#onPostDraw} gets called.
     */
    public void requestInvalidateRootRenderNode() {
        mInvalidateRootRequested = true;
    }

    boolean scrollToRectOrFocus(Rect rectangle, boolean immediate) {
        final Rect ci = mAttachInfo.mContentInsets;
        final Rect vi = mAttachInfo.mVisibleInsets;
        int scrollY = 0;
        boolean handled = false;

        if (vi.left > ci.left || vi.top > ci.top
                || vi.right > ci.right || vi.bottom > ci.bottom) {
            // We'll assume that we aren't going to change the scroll
            // offset, since we want to avoid that unless it is actually
            // going to make the focus visible...  otherwise we scroll
            // all over the place.
            scrollY = mScrollY;
            // We can be called for two different situations: during a draw,
            // to update the scroll position if the focus has changed (in which
            // case 'rectangle' is null), or in response to a
            // requestChildRectangleOnScreen() call (in which case 'rectangle'
            // is non-null and we just want to scroll to whatever that
            // rectangle is).
            final View focus = mView.findFocus();
            if (focus == null) {
                return false;
            }
            View lastScrolledFocus = (mLastScrolledFocus != null) ? mLastScrolledFocus.get() : null;
            if (focus != lastScrolledFocus) {
                // If the focus has changed, then ignore any requests to scroll
                // to a rectangle; first we want to make sure the entire focus
                // view is visible.
                rectangle = null;
            }
            if (DEBUG_INPUT_RESIZE) Log.v(mTag, "Eval scroll: focus=" + focus
                    + " rectangle=" + rectangle + " ci=" + ci
                    + " vi=" + vi);
            if (focus == lastScrolledFocus && !mScrollMayChange && rectangle == null) {
                // Optimization: if the focus hasn't changed since last
                // time, and no layout has happened, then just leave things
                // as they are.
                if (DEBUG_INPUT_RESIZE) Log.v(mTag, "Keeping scroll y="
                        + mScrollY + " vi=" + vi.toShortString());
            } else {
                // We need to determine if the currently focused view is
                // within the visible part of the window and, if not, apply
                // a pan so it can be seen.
                mLastScrolledFocus = new WeakReference<View>(focus);
                mScrollMayChange = false;
                if (DEBUG_INPUT_RESIZE) Log.v(mTag, "Need to scroll?");
                // Try to find the rectangle from the focus view.
                if (focus.getGlobalVisibleRect(mVisRect, null)) {
                    if (DEBUG_INPUT_RESIZE) Log.v(mTag, "Root w="
                            + mView.getWidth() + " h=" + mView.getHeight()
                            + " ci=" + ci.toShortString()
                            + " vi=" + vi.toShortString());
                    if (rectangle == null) {
                        focus.getFocusedRect(mTempRect);
                        if (DEBUG_INPUT_RESIZE) Log.v(mTag, "Focus " + focus
                                + ": focusRect=" + mTempRect.toShortString());
                        if (mView instanceof ViewGroup) {
                            ((ViewGroup) mView).offsetDescendantRectToMyCoords(
                                    focus, mTempRect);
                        }
                        if (DEBUG_INPUT_RESIZE) Log.v(mTag,
                                "Focus in window: focusRect="
                                + mTempRect.toShortString()
                                + " visRect=" + mVisRect.toShortString());
                    } else {
                        mTempRect.set(rectangle);
                        if (DEBUG_INPUT_RESIZE) Log.v(mTag,
                                "Request scroll to rect: "
                                + mTempRect.toShortString()
                                + " visRect=" + mVisRect.toShortString());
                    }
                    if (mTempRect.intersect(mVisRect)) {
                        if (DEBUG_INPUT_RESIZE) Log.v(mTag,
                                "Focus window visible rect: "
                                + mTempRect.toShortString());
                        if (mTempRect.height() >
                                (mView.getHeight()-vi.top-vi.bottom)) {
                            // If the focus simply is not going to fit, then
                            // best is probably just to leave things as-is.
                            if (DEBUG_INPUT_RESIZE) Log.v(mTag,
                                    "Too tall; leaving scrollY=" + scrollY);
                        }
                        // Next, check whether top or bottom is covered based on the non-scrolled
                        // position, and calculate new scrollY (or set it to 0).
                        // We can't keep using mScrollY here. For example mScrollY is non-zero
                        // due to IME, then IME goes away. The current value of mScrollY leaves top
                        // and bottom both visible, but we still need to scroll it back to 0.
                        else if (mTempRect.top < vi.top) {
                            scrollY = mTempRect.top - vi.top;
                            if (DEBUG_INPUT_RESIZE) Log.v(mTag,
                                    "Top covered; scrollY=" + scrollY);
                        } else if (mTempRect.bottom > (mView.getHeight()-vi.bottom)) {
                            scrollY = mTempRect.bottom - (mView.getHeight()-vi.bottom);
                            if (DEBUG_INPUT_RESIZE) Log.v(mTag,
                                    "Bottom covered; scrollY=" + scrollY);
                        } else {
                            scrollY = 0;
                        }
                        handled = true;
                    }
                }
            }
        }

        if (scrollY != mScrollY) {
            if (DEBUG_INPUT_RESIZE) Log.v(mTag, "Pan scroll changed: old="
                    + mScrollY + " , new=" + scrollY);
            if (!immediate) {
                if (mScroller == null) {
                    mScroller = new Scroller(mView.getContext());
                }
                mScroller.startScroll(0, mScrollY, 0, scrollY-mScrollY);
            } else if (mScroller != null) {
                mScroller.abortAnimation();
            }
            mScrollY = scrollY;
        }

        return handled;
    }

    /**
     * @hide
     */
    @UnsupportedAppUsage
    public View getAccessibilityFocusedHost() {
        return mAccessibilityFocusedHost;
    }

    /**
     * @hide
     */
    @UnsupportedAppUsage
    public AccessibilityNodeInfo getAccessibilityFocusedVirtualView() {
        return mAccessibilityFocusedVirtualView;
    }

    void setAccessibilityFocus(View view, AccessibilityNodeInfo node) {
        // If we have a virtual view with accessibility focus we need
        // to clear the focus and invalidate the virtual view bounds.
        if (mAccessibilityFocusedVirtualView != null) {

            AccessibilityNodeInfo focusNode = mAccessibilityFocusedVirtualView;
            View focusHost = mAccessibilityFocusedHost;

            // Wipe the state of the current accessibility focus since
            // the call into the provider to clear accessibility focus
            // will fire an accessibility event which will end up calling
            // this method and we want to have clean state when this
            // invocation happens.
            mAccessibilityFocusedHost = null;
            mAccessibilityFocusedVirtualView = null;

            // Clear accessibility focus on the host after clearing state since
            // this method may be reentrant.
            focusHost.clearAccessibilityFocusNoCallbacks(
                    AccessibilityNodeInfo.ACTION_ACCESSIBILITY_FOCUS);

            AccessibilityNodeProvider provider = focusHost.getAccessibilityNodeProvider();
            if (provider != null) {
                // Invalidate the area of the cleared accessibility focus.
                focusNode.getBoundsInParent(mTempRect);
                focusHost.invalidate(mTempRect);
                // Clear accessibility focus in the virtual node.
                final int virtualNodeId = AccessibilityNodeInfo.getVirtualDescendantId(
                        focusNode.getSourceNodeId());
                provider.performAction(virtualNodeId,
                        AccessibilityNodeInfo.ACTION_CLEAR_ACCESSIBILITY_FOCUS, null);
            }
            focusNode.recycle();
        }
        if ((mAccessibilityFocusedHost != null) && (mAccessibilityFocusedHost != view))  {
            // Clear accessibility focus in the view.
            mAccessibilityFocusedHost.clearAccessibilityFocusNoCallbacks(
                    AccessibilityNodeInfo.ACTION_ACCESSIBILITY_FOCUS);
        }

        // Set the new focus host and node.
        mAccessibilityFocusedHost = view;
        mAccessibilityFocusedVirtualView = node;

        if (mAttachInfo.mThreadedRenderer != null) {
            mAttachInfo.mThreadedRenderer.invalidateRoot();
        }
    }

    boolean hasPointerCapture() {
        return mPointerCapture;
    }

    void requestPointerCapture(boolean enabled) {
        if (mPointerCapture == enabled) {
            return;
        }
        InputManager.getInstance().requestPointerCapture(mAttachInfo.mWindowToken, enabled);
    }

    private void handlePointerCaptureChanged(boolean hasCapture) {
        if (mPointerCapture == hasCapture) {
            return;
        }
        mPointerCapture = hasCapture;
        if (mView != null) {
            mView.dispatchPointerCaptureChanged(hasCapture);
        }
    }

    private boolean hasColorModeChanged(int colorMode) {
        if (mAttachInfo.mThreadedRenderer == null) {
            return false;
        }
        final boolean isWideGamut = colorMode == ActivityInfo.COLOR_MODE_WIDE_COLOR_GAMUT;
        if (mAttachInfo.mThreadedRenderer.isWideGamut() == isWideGamut) {
            return false;
        }
        if (isWideGamut && !mContext.getResources().getConfiguration().isScreenWideColorGamut()) {
            return false;
        }
        return true;
    }

    @Override
    public void requestChildFocus(View child, View focused) {
        if (DEBUG_INPUT_RESIZE) {
            Log.v(mTag, "Request child focus: focus now " + focused);
        }
        checkThread();
        scheduleTraversals();
    }

    @Override
    public void clearChildFocus(View child) {
        if (DEBUG_INPUT_RESIZE) {
            Log.v(mTag, "Clearing child focus");
        }
        checkThread();
        scheduleTraversals();
    }

    @Override
    public ViewParent getParentForAccessibility() {
        return null;
    }

    @Override
    public void focusableViewAvailable(View v) {
        checkThread();
        if (mView != null) {
            if (!mView.hasFocus()) {
                if (sAlwaysAssignFocus || !mAttachInfo.mInTouchMode) {
                    v.requestFocus();
                }
            } else {
                // the one case where will transfer focus away from the current one
                // is if the current view is a view group that prefers to give focus
                // to its children first AND the view is a descendant of it.
                View focused = mView.findFocus();
                if (focused instanceof ViewGroup) {
                    ViewGroup group = (ViewGroup) focused;
                    if (group.getDescendantFocusability() == ViewGroup.FOCUS_AFTER_DESCENDANTS
                            && isViewDescendantOf(v, focused)) {
                        v.requestFocus();
                    }
                }
            }
        }
    }

    @Override
    public void recomputeViewAttributes(View child) {
        checkThread();
        if (mView == child) {
            mAttachInfo.mRecomputeGlobalAttributes = true;
            if (!mWillDrawSoon) {
                scheduleTraversals();
            }
        }
    }

    void dispatchDetachedFromWindow() {
        if (mFirstInputStage != null) {
            mFirstInputStage.onDetachedFromWindow();
        }
        if (mView != null && mView.mAttachInfo != null) {
            mAttachInfo.mTreeObserver.dispatchOnWindowAttachedChange(false);
            mView.dispatchDetachedFromWindow();
        }

        mAccessibilityInteractionConnectionManager.ensureNoConnection();
        mAccessibilityManager.removeAccessibilityStateChangeListener(
                mAccessibilityInteractionConnectionManager);
        mAccessibilityManager.removeHighTextContrastStateChangeListener(
                mHighContrastTextManager);
        removeSendWindowContentChangedCallback();

        destroyHardwareRenderer();

        setAccessibilityFocus(null, null);

        mView.assignParent(null);
        mView = null;
        mAttachInfo.mRootView = null;

        destroySurface();

        if (mInputQueueCallback != null && mInputQueue != null) {
            mInputQueueCallback.onInputQueueDestroyed(mInputQueue);
            mInputQueue.dispose();
            mInputQueueCallback = null;
            mInputQueue = null;
        }
        if (mInputEventReceiver != null) {
            mInputEventReceiver.dispose();
            mInputEventReceiver = null;
        }
        try {
            mWindowSession.remove(mWindow);
        } catch (RemoteException e) {
        }

        // Dispose the input channel after removing the window so the Window Manager
        // doesn't interpret the input channel being closed as an abnormal termination.
        if (mInputChannel != null) {
            mInputChannel.dispose();
            mInputChannel = null;
        }

        mDisplayManager.unregisterDisplayListener(mDisplayListener);

        unscheduleTraversals();
    }

    /**
     * Notifies all callbacks that configuration and/or display has changed and updates internal
     * state.
     * @param mergedConfiguration New global and override config in {@link MergedConfiguration}
     *                            container.
     * @param force Flag indicating if we should force apply the config.
     * @param newDisplayId Id of new display if moved, {@link Display#INVALID_DISPLAY} if not
     *                     changed.
     */
    private void performConfigurationChange(MergedConfiguration mergedConfiguration, boolean force,
            int newDisplayId) {
        if (mergedConfiguration == null) {
            throw new IllegalArgumentException("No merged config provided.");
        }

        Configuration globalConfig = mergedConfiguration.getGlobalConfiguration();
        final Configuration overrideConfig = mergedConfiguration.getOverrideConfiguration();
        if (DEBUG_CONFIGURATION) Log.v(mTag,
                "Applying new config to window " + mWindowAttributes.getTitle()
                        + ", globalConfig: " + globalConfig
                        + ", overrideConfig: " + overrideConfig);

        final CompatibilityInfo ci = mDisplay.getDisplayAdjustments().getCompatibilityInfo();
        if (!ci.equals(CompatibilityInfo.DEFAULT_COMPATIBILITY_INFO)) {
            globalConfig = new Configuration(globalConfig);
            ci.applyToConfiguration(mNoncompatDensity, globalConfig);
        }

        synchronized (sConfigCallbacks) {
            for (int i=sConfigCallbacks.size()-1; i>=0; i--) {
                sConfigCallbacks.get(i).onConfigurationChanged(globalConfig);
            }
        }

        mLastReportedMergedConfiguration.setConfiguration(globalConfig, overrideConfig);

        mForceNextConfigUpdate = force;
        if (mActivityConfigCallback != null) {
            // An activity callback is set - notify it about override configuration update.
            // This basically initiates a round trip to ActivityThread and back, which will ensure
            // that corresponding activity and resources are updated before updating inner state of
            // ViewRootImpl. Eventually it will call #updateConfiguration().
            mActivityConfigCallback.onConfigurationChanged(overrideConfig, newDisplayId);
        } else {
            // There is no activity callback - update the configuration right away.
            updateConfiguration(newDisplayId);
        }
        mForceNextConfigUpdate = false;
    }

    /**
     * Update display and views if last applied merged configuration changed.
     * @param newDisplayId Id of new display if moved, {@link Display#INVALID_DISPLAY} otherwise.
     */
    public void updateConfiguration(int newDisplayId) {
        if (mView == null) {
            return;
        }

        // At this point the resources have been updated to
        // have the most recent config, whatever that is.  Use
        // the one in them which may be newer.
        final Resources localResources = mView.getResources();
        final Configuration config = localResources.getConfiguration();

        // Handle move to display.
        if (newDisplayId != INVALID_DISPLAY) {
            onMovedToDisplay(newDisplayId, config);
        }

        // Handle configuration change.
        if (mForceNextConfigUpdate || mLastConfigurationFromResources.diff(config) != 0) {
            // Update the display with new DisplayAdjustments.
            updateInternalDisplay(mDisplay.getDisplayId(), localResources);

            final int lastLayoutDirection = mLastConfigurationFromResources.getLayoutDirection();
            final int currentLayoutDirection = config.getLayoutDirection();
            mLastConfigurationFromResources.setTo(config);
            if (lastLayoutDirection != currentLayoutDirection
                    && mViewLayoutDirectionInitial == View.LAYOUT_DIRECTION_INHERIT) {
                mView.setLayoutDirection(currentLayoutDirection);
            }
            mView.dispatchConfigurationChanged(config);

            // We could have gotten this {@link Configuration} update after we called
            // {@link #performTraversals} with an older {@link Configuration}. As a result, our
            // window frame may be stale. We must ensure the next pass of {@link #performTraversals}
            // catches this.
            mForceNextWindowRelayout = true;
            requestLayout();
        }

        updateForceDarkMode();
    }

    /**
     * Return true if child is an ancestor of parent, (or equal to the parent).
     */
    public static boolean isViewDescendantOf(View child, View parent) {
        if (child == parent) {
            return true;
        }

        final ViewParent theParent = child.getParent();
        return (theParent instanceof ViewGroup) && isViewDescendantOf((View) theParent, parent);
    }

    private static void forceLayout(View view) {
        view.forceLayout();
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            final int count = group.getChildCount();
            for (int i = 0; i < count; i++) {
                forceLayout(group.getChildAt(i));
            }
        }
    }

    private static final int MSG_INVALIDATE = 1;
    private static final int MSG_INVALIDATE_RECT = 2;
    private static final int MSG_DIE = 3;
    private static final int MSG_RESIZED = 4;
    private static final int MSG_RESIZED_REPORT = 5;
    private static final int MSG_WINDOW_FOCUS_CHANGED = 6;
    private static final int MSG_DISPATCH_INPUT_EVENT = 7;
    private static final int MSG_DISPATCH_APP_VISIBILITY = 8;
    private static final int MSG_DISPATCH_GET_NEW_SURFACE = 9;
    private static final int MSG_DISPATCH_KEY_FROM_IME = 11;
    private static final int MSG_DISPATCH_KEY_FROM_AUTOFILL = 12;
    private static final int MSG_CHECK_FOCUS = 13;
    private static final int MSG_CLOSE_SYSTEM_DIALOGS = 14;
    private static final int MSG_DISPATCH_DRAG_EVENT = 15;
    private static final int MSG_DISPATCH_DRAG_LOCATION_EVENT = 16;
    private static final int MSG_DISPATCH_SYSTEM_UI_VISIBILITY = 17;
    private static final int MSG_UPDATE_CONFIGURATION = 18;
    private static final int MSG_PROCESS_INPUT_EVENTS = 19;
    private static final int MSG_CLEAR_ACCESSIBILITY_FOCUS_HOST = 21;
    private static final int MSG_INVALIDATE_WORLD = 22;
    private static final int MSG_WINDOW_MOVED = 23;
    private static final int MSG_SYNTHESIZE_INPUT_EVENT = 24;
    private static final int MSG_DISPATCH_WINDOW_SHOWN = 25;
    private static final int MSG_REQUEST_KEYBOARD_SHORTCUTS = 26;
    private static final int MSG_UPDATE_POINTER_ICON = 27;
    private static final int MSG_POINTER_CAPTURE_CHANGED = 28;
    private static final int MSG_DRAW_FINISHED = 29;
    private static final int MSG_INSETS_CHANGED = 30;
    private static final int MSG_INSETS_CONTROL_CHANGED = 31;
    private static final int MSG_SYSTEM_GESTURE_EXCLUSION_CHANGED = 32;
    private static final int MSG_LOCATION_IN_PARENT_DISPLAY_CHANGED = 33;

    final class ViewRootHandler extends Handler {
        @Override
        public String getMessageName(Message message) {
            switch (message.what) {
                case MSG_INVALIDATE:
                    return "MSG_INVALIDATE";
                case MSG_INVALIDATE_RECT:
                    return "MSG_INVALIDATE_RECT";
                case MSG_DIE:
                    return "MSG_DIE";
                case MSG_RESIZED:
                    return "MSG_RESIZED";
                case MSG_RESIZED_REPORT:
                    return "MSG_RESIZED_REPORT";
                case MSG_WINDOW_FOCUS_CHANGED:
                    return "MSG_WINDOW_FOCUS_CHANGED";
                case MSG_DISPATCH_INPUT_EVENT:
                    return "MSG_DISPATCH_INPUT_EVENT";
                case MSG_DISPATCH_APP_VISIBILITY:
                    return "MSG_DISPATCH_APP_VISIBILITY";
                case MSG_DISPATCH_GET_NEW_SURFACE:
                    return "MSG_DISPATCH_GET_NEW_SURFACE";
                case MSG_DISPATCH_KEY_FROM_IME:
                    return "MSG_DISPATCH_KEY_FROM_IME";
                case MSG_DISPATCH_KEY_FROM_AUTOFILL:
                    return "MSG_DISPATCH_KEY_FROM_AUTOFILL";
                case MSG_CHECK_FOCUS:
                    return "MSG_CHECK_FOCUS";
                case MSG_CLOSE_SYSTEM_DIALOGS:
                    return "MSG_CLOSE_SYSTEM_DIALOGS";
                case MSG_DISPATCH_DRAG_EVENT:
                    return "MSG_DISPATCH_DRAG_EVENT";
                case MSG_DISPATCH_DRAG_LOCATION_EVENT:
                    return "MSG_DISPATCH_DRAG_LOCATION_EVENT";
                case MSG_DISPATCH_SYSTEM_UI_VISIBILITY:
                    return "MSG_DISPATCH_SYSTEM_UI_VISIBILITY";
                case MSG_UPDATE_CONFIGURATION:
                    return "MSG_UPDATE_CONFIGURATION";
                case MSG_PROCESS_INPUT_EVENTS:
                    return "MSG_PROCESS_INPUT_EVENTS";
                case MSG_CLEAR_ACCESSIBILITY_FOCUS_HOST:
                    return "MSG_CLEAR_ACCESSIBILITY_FOCUS_HOST";
                case MSG_WINDOW_MOVED:
                    return "MSG_WINDOW_MOVED";
                case MSG_SYNTHESIZE_INPUT_EVENT:
                    return "MSG_SYNTHESIZE_INPUT_EVENT";
                case MSG_DISPATCH_WINDOW_SHOWN:
                    return "MSG_DISPATCH_WINDOW_SHOWN";
                case MSG_UPDATE_POINTER_ICON:
                    return "MSG_UPDATE_POINTER_ICON";
                case MSG_POINTER_CAPTURE_CHANGED:
                    return "MSG_POINTER_CAPTURE_CHANGED";
                case MSG_DRAW_FINISHED:
                    return "MSG_DRAW_FINISHED";
                case MSG_INSETS_CHANGED:
                    return "MSG_INSETS_CHANGED";
                case MSG_INSETS_CONTROL_CHANGED:
                    return "MSG_INSETS_CONTROL_CHANGED";
                case MSG_SYSTEM_GESTURE_EXCLUSION_CHANGED:
                    return "MSG_SYSTEM_GESTURE_EXCLUSION_CHANGED";
                case MSG_LOCATION_IN_PARENT_DISPLAY_CHANGED:
                    return "MSG_LOCATION_IN_PARENT_DISPLAY_CHANGED";
            }
            return super.getMessageName(message);
        }

        @Override
        public boolean sendMessageAtTime(Message msg, long uptimeMillis) {
            if (msg.what == MSG_REQUEST_KEYBOARD_SHORTCUTS && msg.obj == null) {
                // Debugging for b/27963013
                throw new NullPointerException(
                        "Attempted to call MSG_REQUEST_KEYBOARD_SHORTCUTS with null receiver:");
            }
            return super.sendMessageAtTime(msg, uptimeMillis);
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MSG_INVALIDATE:
                    ((View) msg.obj).invalidate();
                    break;
                case MSG_INVALIDATE_RECT:
                    final View.AttachInfo.InvalidateInfo info =
                            (View.AttachInfo.InvalidateInfo) msg.obj;
                    info.target.invalidate(info.left, info.top, info.right, info.bottom);
                    info.recycle();
                    break;
                case MSG_PROCESS_INPUT_EVENTS:
                    mProcessInputEventsScheduled = false;
                    doProcessInputEvents();
                    break;
                case MSG_DISPATCH_APP_VISIBILITY:
                    handleAppVisibility(msg.arg1 != 0);
                    break;
                case MSG_DISPATCH_GET_NEW_SURFACE:
                    handleGetNewSurface();
                    break;
                case MSG_RESIZED: {
                    // Recycled in the fall through...
                    SomeArgs args = (SomeArgs) msg.obj;
                    if (mWinFrame.equals(args.arg1)
                            && mPendingOverscanInsets.equals(args.arg5)
                            && mPendingContentInsets.equals(args.arg2)
                            && mPendingStableInsets.equals(args.arg6)
                            && mPendingDisplayCutout.get().equals(args.arg9)
                            && mPendingVisibleInsets.equals(args.arg3)
                            && mPendingOutsets.equals(args.arg7)
                            && mPendingBackDropFrame.equals(args.arg8)
                            && args.arg4 == null
                            && args.argi1 == 0
                            && mDisplay.getDisplayId() == args.argi3) {
                        break;
                    }
                } // fall through...
                case MSG_RESIZED_REPORT:
                    if (mAdded) {
                        SomeArgs args = (SomeArgs) msg.obj;

                        final int displayId = args.argi3;
                        MergedConfiguration mergedConfiguration = (MergedConfiguration) args.arg4;
                        final boolean displayChanged = mDisplay.getDisplayId() != displayId;
                        boolean configChanged = false;

                        if (!mLastReportedMergedConfiguration.equals(mergedConfiguration)) {
                            // If configuration changed - notify about that and, maybe,
                            // about move to display.
                            performConfigurationChange(mergedConfiguration, false /* force */,
                                    displayChanged
                                            ? displayId : INVALID_DISPLAY /* same display */);
                            configChanged = true;
                        } else if (displayChanged) {
                            // Moved to display without config change - report last applied one.
                            onMovedToDisplay(displayId, mLastConfigurationFromResources);
                        }

                        final boolean framesChanged = !mWinFrame.equals(args.arg1)
                                || !mPendingOverscanInsets.equals(args.arg5)
                                || !mPendingContentInsets.equals(args.arg2)
                                || !mPendingStableInsets.equals(args.arg6)
                                || !mPendingDisplayCutout.get().equals(args.arg9)
                                || !mPendingVisibleInsets.equals(args.arg3)
                                || !mPendingOutsets.equals(args.arg7);

                        setFrame((Rect) args.arg1);
                        mPendingOverscanInsets.set((Rect) args.arg5);
                        mPendingContentInsets.set((Rect) args.arg2);
                        mPendingStableInsets.set((Rect) args.arg6);
                        mPendingDisplayCutout.set((DisplayCutout) args.arg9);
                        mPendingVisibleInsets.set((Rect) args.arg3);
                        mPendingOutsets.set((Rect) args.arg7);
                        mPendingBackDropFrame.set((Rect) args.arg8);
                        mForceNextWindowRelayout = args.argi1 != 0;
                        mPendingAlwaysConsumeSystemBars = args.argi2 != 0;

                        args.recycle();

                        if (msg.what == MSG_RESIZED_REPORT) {
                            reportNextDraw();
                        }

                        if (mView != null && (framesChanged || configChanged)) {
                            forceLayout(mView);
                        }
                        requestLayout();
                    }
                    break;
                case MSG_INSETS_CHANGED:
                    mInsetsController.onStateChanged((InsetsState) msg.obj);
                    break;
                case MSG_INSETS_CONTROL_CHANGED: {
                    SomeArgs args = (SomeArgs) msg.obj;
                    mInsetsController.onControlsChanged((InsetsSourceControl[]) args.arg2);
                    mInsetsController.onStateChanged((InsetsState) args.arg1);
                    break;
                }
                case MSG_WINDOW_MOVED:
                    if (mAdded) {
                        final int w = mWinFrame.width();
                        final int h = mWinFrame.height();
                        final int l = msg.arg1;
                        final int t = msg.arg2;
                        mTmpFrame.left = l;
                        mTmpFrame.right = l + w;
                        mTmpFrame.top = t;
                        mTmpFrame.bottom = t + h;
                        setFrame(mTmpFrame);

                        mPendingBackDropFrame.set(mWinFrame);
                        maybeHandleWindowMove(mWinFrame);
                    }
                    break;
                case MSG_WINDOW_FOCUS_CHANGED: {
                    handleWindowFocusChanged();
                } break;
                case MSG_DIE:
                    doDie();
                    break;
                case MSG_DISPATCH_INPUT_EVENT: {
                    SomeArgs args = (SomeArgs) msg.obj;
                    InputEvent event = (InputEvent) args.arg1;
                    InputEventReceiver receiver = (InputEventReceiver) args.arg2;
                    enqueueInputEvent(event, receiver, 0, true);
                    args.recycle();
                } break;
                case MSG_SYNTHESIZE_INPUT_EVENT: {
                    InputEvent event = (InputEvent) msg.obj;
                    enqueueInputEvent(event, null, QueuedInputEvent.FLAG_UNHANDLED, true);
                } break;
                case MSG_DISPATCH_KEY_FROM_IME: {
                    if (LOCAL_LOGV) {
                        Log.v(TAG, "Dispatching key " + msg.obj + " from IME to " + mView);
                    }
                    KeyEvent event = (KeyEvent) msg.obj;
                    if ((event.getFlags() & KeyEvent.FLAG_FROM_SYSTEM) != 0) {
                        // The IME is trying to say this event is from the
                        // system!  Bad bad bad!
                        //noinspection UnusedAssignment
                        event = KeyEvent.changeFlags(event,
                                event.getFlags() & ~KeyEvent.FLAG_FROM_SYSTEM);
                    }
                    enqueueInputEvent(event, null, QueuedInputEvent.FLAG_DELIVER_POST_IME, true);
                } break;
                case MSG_DISPATCH_KEY_FROM_AUTOFILL: {
                    if (LOCAL_LOGV) {
                        Log.v(TAG, "Dispatching key " + msg.obj + " from Autofill to " + mView);
                    }
                    KeyEvent event = (KeyEvent) msg.obj;
                    enqueueInputEvent(event, null, 0, true);
                } break;
                case MSG_CHECK_FOCUS: {
                    InputMethodManager imm = mContext.getSystemService(InputMethodManager.class);
                    if (imm != null) {
                        imm.checkFocus();
                    }
                } break;
                case MSG_CLOSE_SYSTEM_DIALOGS: {
                    if (mView != null) {
                        mView.onCloseSystemDialogs((String) msg.obj);
                    }
                } break;
                case MSG_DISPATCH_DRAG_EVENT: {
                } // fall through
                case MSG_DISPATCH_DRAG_LOCATION_EVENT: {
                    DragEvent event = (DragEvent) msg.obj;
                    // only present when this app called startDrag()
                    event.mLocalState = mLocalDragState;
                    handleDragEvent(event);
                } break;
                case MSG_DISPATCH_SYSTEM_UI_VISIBILITY: {
                    handleDispatchSystemUiVisibilityChanged((SystemUiVisibilityInfo) msg.obj);
                } break;
                case MSG_UPDATE_CONFIGURATION: {
                    Configuration config = (Configuration) msg.obj;
                    if (config.isOtherSeqNewer(
                            mLastReportedMergedConfiguration.getMergedConfiguration())) {
                        // If we already have a newer merged config applied - use its global part.
                        config = mLastReportedMergedConfiguration.getGlobalConfiguration();
                    }

                    // Use the newer global config and last reported override config.
                    mPendingMergedConfiguration.setConfiguration(config,
                            mLastReportedMergedConfiguration.getOverrideConfiguration());

                    performConfigurationChange(mPendingMergedConfiguration, false /* force */,
                            INVALID_DISPLAY /* same display */);
                } break;
                case MSG_CLEAR_ACCESSIBILITY_FOCUS_HOST: {
                    setAccessibilityFocus(null, null);
                } break;
                case MSG_INVALIDATE_WORLD: {
                    if (mView != null) {
                        invalidateWorld(mView);
                    }
                } break;
                case MSG_DISPATCH_WINDOW_SHOWN: {
                    handleDispatchWindowShown();
                } break;
                case MSG_REQUEST_KEYBOARD_SHORTCUTS: {
                    final IResultReceiver receiver = (IResultReceiver) msg.obj;
                    final int deviceId = msg.arg1;
                    handleRequestKeyboardShortcuts(receiver, deviceId);
                } break;
                case MSG_UPDATE_POINTER_ICON: {
                    MotionEvent event = (MotionEvent) msg.obj;
                    resetPointerIcon(event);
                } break;
                case MSG_POINTER_CAPTURE_CHANGED: {
                    final boolean hasCapture = msg.arg1 != 0;
                    handlePointerCaptureChanged(hasCapture);
                } break;
                case MSG_DRAW_FINISHED: {
                    pendingDrawFinished();
                } break;
                case MSG_SYSTEM_GESTURE_EXCLUSION_CHANGED: {
                    systemGestureExclusionChanged();
                } break;
                case MSG_LOCATION_IN_PARENT_DISPLAY_CHANGED: {
                    updateLocationInParentDisplay(msg.arg1, msg.arg2);
                } break;
            }
        }
    }

    final ViewRootHandler mHandler = new ViewRootHandler();

    /**
     * Something in the current window tells us we need to change the touch mode.  For
     * example, we are not in touch mode, and the user touches the screen.
     *
     * If the touch mode has changed, tell the window manager, and handle it locally.
     *
     * @param inTouchMode Whether we want to be in touch mode.
     * @return True if the touch mode changed and focus changed was changed as a result
     */
    @UnsupportedAppUsage
    boolean ensureTouchMode(boolean inTouchMode) {
        if (DBG) Log.d("touchmode", "ensureTouchMode(" + inTouchMode + "), current "
                + "touch mode is " + mAttachInfo.mInTouchMode);
        if (mAttachInfo.mInTouchMode == inTouchMode) return false;

        // tell the window manager
        try {
            mWindowSession.setInTouchMode(inTouchMode);
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        }

        // handle the change
        return ensureTouchModeLocally(inTouchMode);
    }

    /**
     * Ensure that the touch mode for this window is set, and if it is changing,
     * take the appropriate action.
     * @param inTouchMode Whether we want to be in touch mode.
     * @return True if the touch mode changed and focus changed was changed as a result
     */
    private boolean ensureTouchModeLocally(boolean inTouchMode) {
        if (DBG) Log.d("touchmode", "ensureTouchModeLocally(" + inTouchMode + "), current "
                + "touch mode is " + mAttachInfo.mInTouchMode);

        if (mAttachInfo.mInTouchMode == inTouchMode) return false;

        mAttachInfo.mInTouchMode = inTouchMode;
        mAttachInfo.mTreeObserver.dispatchOnTouchModeChanged(inTouchMode);

        return (inTouchMode) ? enterTouchMode() : leaveTouchMode();
    }

    private boolean enterTouchMode() {
        if (mView != null && mView.hasFocus()) {
            // note: not relying on mFocusedView here because this could
            // be when the window is first being added, and mFocused isn't
            // set yet.
            final View focused = mView.findFocus();
            if (focused != null && !focused.isFocusableInTouchMode()) {
                final ViewGroup ancestorToTakeFocus = findAncestorToTakeFocusInTouchMode(focused);
                if (ancestorToTakeFocus != null) {
                    // there is an ancestor that wants focus after its
                    // descendants that is focusable in touch mode.. give it
                    // focus
                    return ancestorToTakeFocus.requestFocus();
                } else {
                    // There's nothing to focus. Clear and propagate through the
                    // hierarchy, but don't attempt to place new focus.
                    focused.clearFocusInternal(null, true, false);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Find an ancestor of focused that wants focus after its descendants and is
     * focusable in touch mode.
     * @param focused The currently focused view.
     * @return An appropriate view, or null if no such view exists.
     */
    private static ViewGroup findAncestorToTakeFocusInTouchMode(View focused) {
        ViewParent parent = focused.getParent();
        while (parent instanceof ViewGroup) {
            final ViewGroup vgParent = (ViewGroup) parent;
            if (vgParent.getDescendantFocusability() == ViewGroup.FOCUS_AFTER_DESCENDANTS
                    && vgParent.isFocusableInTouchMode()) {
                return vgParent;
            }
            if (vgParent.isRootNamespace()) {
                return null;
            } else {
                parent = vgParent.getParent();
            }
        }
        return null;
    }

    private boolean leaveTouchMode() {
        if (mView != null) {
            if (mView.hasFocus()) {
                View focusedView = mView.findFocus();
                if (!(focusedView instanceof ViewGroup)) {
                    // some view has focus, let it keep it
                    return false;
                } else if (((ViewGroup) focusedView).getDescendantFocusability() !=
                        ViewGroup.FOCUS_AFTER_DESCENDANTS) {
                    // some view group has focus, and doesn't prefer its children
                    // over itself for focus, so let them keep it.
                    return false;
                }
            }

            // find the best view to give focus to in this brave new non-touch-mode
            // world
            return mView.restoreDefaultFocus();
        }
        return false;
    }

    /**
     * Base class for implementing a stage in the chain of responsibility
     * for processing input events.
     * <p>
     * Events are delivered to the stage by the {@link #deliver} method.  The stage
     * then has the choice of finishing the event or forwarding it to the next stage.
     * </p>
     */
    abstract class InputStage {
        private final InputStage mNext;

        protected static final int FORWARD = 0;
        protected static final int FINISH_HANDLED = 1;
        protected static final int FINISH_NOT_HANDLED = 2;

        /**
         * Creates an input stage.
         * @param next The next stage to which events should be forwarded.
         */
        public InputStage(InputStage next) {
            mNext = next;
        }

        /**
         * Delivers an event to be processed.
         */
        public final void deliver(QueuedInputEvent q) {
            if ((q.mFlags & QueuedInputEvent.FLAG_FINISHED) != 0) {
                forward(q);
            } else if (shouldDropInputEvent(q)) {
                finish(q, false);
            } else {
                apply(q, onProcess(q));
            }
        }

        /**
         * Marks the the input event as finished then forwards it to the next stage.
         */
        protected void finish(QueuedInputEvent q, boolean handled) {
            q.mFlags |= QueuedInputEvent.FLAG_FINISHED;
            if (handled) {
                q.mFlags |= QueuedInputEvent.FLAG_FINISHED_HANDLED;
            }
            forward(q);
        }

        /**
         * Forwards the event to the next stage.
         */
        protected void forward(QueuedInputEvent q) {
            onDeliverToNext(q);
        }

        /**
         * Applies a result code from {@link #onProcess} to the specified event.
         */
        protected void apply(QueuedInputEvent q, int result) {
            if (result == FORWARD) {
                forward(q);
            } else if (result == FINISH_HANDLED) {
                finish(q, true);
            } else if (result == FINISH_NOT_HANDLED) {
                finish(q, false);
            } else {
                throw new IllegalArgumentException("Invalid result: " + result);
            }
        }

        /**
         * Called when an event is ready to be processed.
         * @return A result code indicating how the event was handled.
         */
        protected int onProcess(QueuedInputEvent q) {
            return FORWARD;
        }

        /**
         * Called when an event is being delivered to the next stage.
         */
        protected void onDeliverToNext(QueuedInputEvent q) {
            if (DEBUG_INPUT_STAGES) {
                Log.v(mTag, "Done with " + getClass().getSimpleName() + ". " + q);
            }
            if (mNext != null) {
                mNext.deliver(q);
            } else {
                finishInputEvent(q);
            }
        }

        protected void onWindowFocusChanged(boolean hasWindowFocus) {
            if (mNext != null) {
                mNext.onWindowFocusChanged(hasWindowFocus);
            }
        }

        protected void onDetachedFromWindow() {
            if (mNext != null) {
                mNext.onDetachedFromWindow();
            }
        }

        protected boolean shouldDropInputEvent(QueuedInputEvent q) {
            if (mView == null || !mAdded) {
                Slog.w(mTag, "Dropping event due to root view being removed: " + q.mEvent);
                return true;
            } else if ((!mAttachInfo.mHasWindowFocus
                    && !q.mEvent.isFromSource(InputDevice.SOURCE_CLASS_POINTER)
                    && !isAutofillUiShowing()) || mStopped
                    || (mIsAmbientMode && !q.mEvent.isFromSource(InputDevice.SOURCE_CLASS_BUTTON))
                    || (mPausedForTransition && !isBack(q.mEvent))) {
                // This is a focus event and the window doesn't currently have input focus or
                // has stopped. This could be an event that came back from the previous stage
                // but the window has lost focus or stopped in the meantime.
                if (isTerminalInputEvent(q.mEvent)) {
                    // Don't drop terminal input events, however mark them as canceled.
                    q.mEvent.cancel();
                    Slog.w(mTag, "Cancelling event due to no window focus: " + q.mEvent);
                    return false;
                }

                // Drop non-terminal input events.
                Slog.w(mTag, "Dropping event due to no window focus: " + q.mEvent);
                return true;
            }
            return false;
        }

        void dump(String prefix, PrintWriter writer) {
            if (mNext != null) {
                mNext.dump(prefix, writer);
            }
        }

        private boolean isBack(InputEvent event) {
            if (event instanceof KeyEvent) {
                return ((KeyEvent) event).getKeyCode() == KeyEvent.KEYCODE_BACK;
            } else {
                return false;
            }
        }
    }

    /**
     * Base class for implementing an input pipeline stage that supports
     * asynchronous and out-of-order processing of input events.
     * <p>
     * In addition to what a normal input stage can do, an asynchronous
     * input stage may also defer an input event that has been delivered to it
     * and finish or forward it later.
     * </p>
     */
    abstract class AsyncInputStage extends InputStage {
        private final String mTraceCounter;

        private QueuedInputEvent mQueueHead;
        private QueuedInputEvent mQueueTail;
        private int mQueueLength;

        protected static final int DEFER = 3;

        /**
         * Creates an asynchronous input stage.
         * @param next The next stage to which events should be forwarded.
         * @param traceCounter The name of a counter to record the size of
         * the queue of pending events.
         */
        public AsyncInputStage(InputStage next, String traceCounter) {
            super(next);
            mTraceCounter = traceCounter;
        }

        /**
         * Marks the event as deferred, which is to say that it will be handled
         * asynchronously.  The caller is responsible for calling {@link #forward}
         * or {@link #finish} later when it is done handling the event.
         */
        protected void defer(QueuedInputEvent q) {
            q.mFlags |= QueuedInputEvent.FLAG_DEFERRED;
            enqueue(q);
        }

        @Override
        protected void forward(QueuedInputEvent q) {
            // Clear the deferred flag.
            q.mFlags &= ~QueuedInputEvent.FLAG_DEFERRED;

            // Fast path if the queue is empty.
            QueuedInputEvent curr = mQueueHead;
            if (curr == null) {
                super.forward(q);
                return;
            }

            // Determine whether the event must be serialized behind any others
            // before it can be delivered to the next stage.  This is done because
            // deferred events might be handled out of order by the stage.
            final int deviceId = q.mEvent.getDeviceId();
            QueuedInputEvent prev = null;
            boolean blocked = false;
            while (curr != null && curr != q) {
                if (!blocked && deviceId == curr.mEvent.getDeviceId()) {
                    blocked = true;
                }
                prev = curr;
                curr = curr.mNext;
            }

            // If the event is blocked, then leave it in the queue to be delivered later.
            // Note that the event might not yet be in the queue if it was not previously
            // deferred so we will enqueue it if needed.
            if (blocked) {
                if (curr == null) {
                    enqueue(q);
                }
                return;
            }

            // The event is not blocked.  Deliver it immediately.
            if (curr != null) {
                curr = curr.mNext;
                dequeue(q, prev);
            }
            super.forward(q);

            // Dequeuing this event may have unblocked successors.  Deliver them.
            while (curr != null) {
                if (deviceId == curr.mEvent.getDeviceId()) {
                    if ((curr.mFlags & QueuedInputEvent.FLAG_DEFERRED) != 0) {
                        break;
                    }
                    QueuedInputEvent next = curr.mNext;
                    dequeue(curr, prev);
                    super.forward(curr);
                    curr = next;
                } else {
                    prev = curr;
                    curr = curr.mNext;
                }
            }
        }

        @Override
        protected void apply(QueuedInputEvent q, int result) {
            if (result == DEFER) {
                defer(q);
            } else {
                super.apply(q, result);
            }
        }

        private void enqueue(QueuedInputEvent q) {
            if (mQueueTail == null) {
                mQueueHead = q;
                mQueueTail = q;
            } else {
                mQueueTail.mNext = q;
                mQueueTail = q;
            }

            mQueueLength += 1;
            Trace.traceCounter(Trace.TRACE_TAG_INPUT, mTraceCounter, mQueueLength);
        }

        private void dequeue(QueuedInputEvent q, QueuedInputEvent prev) {
            if (prev == null) {
                mQueueHead = q.mNext;
            } else {
                prev.mNext = q.mNext;
            }
            if (mQueueTail == q) {
                mQueueTail = prev;
            }
            q.mNext = null;

            mQueueLength -= 1;
            Trace.traceCounter(Trace.TRACE_TAG_INPUT, mTraceCounter, mQueueLength);
        }

        @Override
        void dump(String prefix, PrintWriter writer) {
            writer.print(prefix);
            writer.print(getClass().getName());
            writer.print(": mQueueLength=");
            writer.println(mQueueLength);

            super.dump(prefix, writer);
        }
    }

    /**
     * Delivers pre-ime input events to a native activity.
     * Does not support pointer events.
     */
    final class NativePreImeInputStage extends AsyncInputStage
            implements InputQueue.FinishedInputEventCallback {
        public NativePreImeInputStage(InputStage next, String traceCounter) {
            super(next, traceCounter);
        }

        @Override
        protected int onProcess(QueuedInputEvent q) {
            if (mInputQueue != null && q.mEvent instanceof KeyEvent) {
                mInputQueue.sendInputEvent(q.mEvent, q, true, this);
                return DEFER;
            }
            return FORWARD;
        }

        @Override
        public void onFinishedInputEvent(Object token, boolean handled) {
            QueuedInputEvent q = (QueuedInputEvent)token;
            if (handled) {
                finish(q, true);
                return;
            }
            forward(q);
        }
    }

    /**
     * Delivers pre-ime input events to the view hierarchy.
     * Does not support pointer events.
     */
    final class ViewPreImeInputStage extends InputStage {
        public ViewPreImeInputStage(InputStage next) {
            super(next);
        }

        @Override
        protected int onProcess(QueuedInputEvent q) {
            if (q.mEvent instanceof KeyEvent) {
                return processKeyEvent(q);
            }
            return FORWARD;
        }

        private int processKeyEvent(QueuedInputEvent q) {
            final KeyEvent event = (KeyEvent)q.mEvent;
            if (mView.dispatchKeyEventPreIme(event)) {
                return FINISH_HANDLED;
            }
            return FORWARD;
        }
    }

    /**
     * Delivers input events to the ime.
     * Does not support pointer events.
     */
    final class ImeInputStage extends AsyncInputStage
            implements InputMethodManager.FinishedInputEventCallback {
        public ImeInputStage(InputStage next, String traceCounter) {
            super(next, traceCounter);
        }

        @Override
        protected int onProcess(QueuedInputEvent q) {
            if (mLastWasImTarget && !isInLocalFocusMode()) {
                InputMethodManager imm = mContext.getSystemService(InputMethodManager.class);
                if (imm != null) {
                    final InputEvent event = q.mEvent;
                    if (DEBUG_IMF) Log.v(mTag, "Sending input event to IME: " + event);
                    int result = imm.dispatchInputEvent(event, q, this, mHandler);
                    if (result == InputMethodManager.DISPATCH_HANDLED) {
                        return FINISH_HANDLED;
                    } else if (result == InputMethodManager.DISPATCH_NOT_HANDLED) {
                        // The IME could not handle it, so skip along to the next InputStage
                        return FORWARD;
                    } else {
                        return DEFER; // callback will be invoked later
                    }
                }
            }
            return FORWARD;
        }

        @Override
        public void onFinishedInputEvent(Object token, boolean handled) {
            QueuedInputEvent q = (QueuedInputEvent)token;
            if (handled) {
                finish(q, true);
                return;
            }
            forward(q);
        }
    }

    /**
     * Performs early processing of post-ime input events.
     */
    final class EarlyPostImeInputStage extends InputStage {
        public EarlyPostImeInputStage(InputStage next) {
            super(next);
        }

        @Override
        protected int onProcess(QueuedInputEvent q) {
            if (q.mEvent instanceof KeyEvent) {
                return processKeyEvent(q);
            } else if (q.mEvent instanceof MotionEvent) {
                return processMotionEvent(q);
            }
            return FORWARD;
        }

        private int processKeyEvent(QueuedInputEvent q) {
            final KeyEvent event = (KeyEvent)q.mEvent;

            if (mAttachInfo.mTooltipHost != null) {
                mAttachInfo.mTooltipHost.handleTooltipKey(event);
            }

            // If the key's purpose is to exit touch mode then we consume it
            // and consider it handled.
            if (checkForLeavingTouchModeAndConsume(event)) {
                return FINISH_HANDLED;
            }

            // Make sure the fallback event policy sees all keys that will be
            // delivered to the view hierarchy.
            mFallbackEventHandler.preDispatchKeyEvent(event);
            return FORWARD;
        }

        private int processMotionEvent(QueuedInputEvent q) {
            final MotionEvent event = (MotionEvent) q.mEvent;

            if (event.isFromSource(InputDevice.SOURCE_CLASS_POINTER)) {
                return processPointerEvent(q);
            }

            // If the motion event is from an absolute position device, exit touch mode
            final int action = event.getActionMasked();
            if (action == MotionEvent.ACTION_DOWN || action == MotionEvent.ACTION_SCROLL) {
                if (event.isFromSource(InputDevice.SOURCE_CLASS_POSITION)) {
                    ensureTouchMode(false);
                }
            }
            return FORWARD;
        }

        private int processPointerEvent(QueuedInputEvent q) {
            final MotionEvent event = (MotionEvent)q.mEvent;

            // Translate the pointer event for compatibility, if needed.
            if (mTranslator != null) {
                mTranslator.translateEventInScreenToAppWindow(event);
            }

            // Enter touch mode on down or scroll, if it is coming from a touch screen device,
            // exit otherwise.
            final int action = event.getAction();
            if (action == MotionEvent.ACTION_DOWN || action == MotionEvent.ACTION_SCROLL) {
                ensureTouchMode(event.isFromSource(InputDevice.SOURCE_TOUCHSCREEN));
            }

            if (action == MotionEvent.ACTION_DOWN) {
                // Upon motion event within app window, close autofill ui.
                AutofillManager afm = getAutofillManager();
                if (afm != null) {
                    afm.requestHideFillUi();
                }
            }

            if (action == MotionEvent.ACTION_DOWN && mAttachInfo.mTooltipHost != null) {
                mAttachInfo.mTooltipHost.hideTooltip();
            }

            // Offset the scroll position.
            if (mCurScrollY != 0) {
                event.offsetLocation(0, mCurScrollY);
            }

            // Remember the touch position for possible drag-initiation.
            if (event.isTouchEvent()) {
                mLastTouchPoint.x = event.getRawX();
                mLastTouchPoint.y = event.getRawY();
                mLastTouchSource = event.getSource();
            }
            return FORWARD;
        }
    }

    /**
     * Delivers post-ime input events to a native activity.
     */
    final class NativePostImeInputStage extends AsyncInputStage
            implements InputQueue.FinishedInputEventCallback {
        public NativePostImeInputStage(InputStage next, String traceCounter) {
            super(next, traceCounter);
        }

        @Override
        protected int onProcess(QueuedInputEvent q) {
            if (mInputQueue != null) {
                mInputQueue.sendInputEvent(q.mEvent, q, false, this);
                return DEFER;
            }
            return FORWARD;
        }

        @Override
        public void onFinishedInputEvent(Object token, boolean handled) {
            QueuedInputEvent q = (QueuedInputEvent)token;
            if (handled) {
                finish(q, true);
                return;
            }
            forward(q);
        }
    }

    /**
     * Delivers post-ime input events to the view hierarchy.
     */
    final class ViewPostImeInputStage extends InputStage {
        public ViewPostImeInputStage(InputStage next) {
            super(next);
        }

        @Override
        protected int onProcess(QueuedInputEvent q) {
            if (q.mEvent instanceof KeyEvent) {
                return processKeyEvent(q);
            } else {
                final int source = q.mEvent.getSource();
                if ((source & InputDevice.SOURCE_CLASS_POINTER) != 0) {
                    return processPointerEvent(q);
                } else if ((source & InputDevice.SOURCE_CLASS_TRACKBALL) != 0) {
                    return processTrackballEvent(q);
                } else {
                    return processGenericMotionEvent(q);
                }
            }
        }

        @Override
        protected void onDeliverToNext(QueuedInputEvent q) {
            if (mUnbufferedInputDispatch
                    && q.mEvent instanceof MotionEvent
                    && ((MotionEvent)q.mEvent).isTouchEvent()
                    && isTerminalInputEvent(q.mEvent)) {
                mUnbufferedInputDispatch = false;
                scheduleConsumeBatchedInput();
            }
            super.onDeliverToNext(q);
        }

        private boolean performFocusNavigation(KeyEvent event) {
            int direction = 0;
            switch (event.getKeyCode()) {
                case KeyEvent.KEYCODE_DPAD_LEFT:
                    if (event.hasNoModifiers()) {
                        direction = View.FOCUS_LEFT;
                    }
                    break;
                case KeyEvent.KEYCODE_DPAD_RIGHT:
                    if (event.hasNoModifiers()) {
                        direction = View.FOCUS_RIGHT;
                    }
                    break;
                case KeyEvent.KEYCODE_DPAD_UP:
                    if (event.hasNoModifiers()) {
                        direction = View.FOCUS_UP;
                    }
                    break;
                case KeyEvent.KEYCODE_DPAD_DOWN:
                    if (event.hasNoModifiers()) {
                        direction = View.FOCUS_DOWN;
                    }
                    break;
                case KeyEvent.KEYCODE_TAB:
                    if (event.hasNoModifiers()) {
                        direction = View.FOCUS_FORWARD;
                    } else if (event.hasModifiers(KeyEvent.META_SHIFT_ON)) {
                        direction = View.FOCUS_BACKWARD;
                    }
                    break;
            }
            if (direction != 0) {
                View focused = mView.findFocus();
                if (focused != null) {
                    View v = focused.focusSearch(direction);
                    if (v != null && v != focused) {
                        // do the math the get the interesting rect
                        // of previous focused into the coord system of
                        // newly focused view
                        focused.getFocusedRect(mTempRect);
                        if (mView instanceof ViewGroup) {
                            ((ViewGroup) mView).offsetDescendantRectToMyCoords(
                                    focused, mTempRect);
                            ((ViewGroup) mView).offsetRectIntoDescendantCoords(
                                    v, mTempRect);
                        }
                        if (v.requestFocus(direction, mTempRect)) {
                            playSoundEffect(SoundEffectConstants
                                    .getContantForFocusDirection(direction));
                            return true;
                        }
                    }

                    // Give the focused view a last chance to handle the dpad key.
                    if (mView.dispatchUnhandledMove(focused, direction)) {
                        return true;
                    }
                } else {
                    if (mView.restoreDefaultFocus()) {
                        return true;
                    }
                }
            }
            return false;
        }

        private boolean performKeyboardGroupNavigation(int direction) {
            final View focused = mView.findFocus();
            if (focused == null && mView.restoreDefaultFocus()) {
                return true;
            }
            View cluster = focused == null ? keyboardNavigationClusterSearch(null, direction)
                    : focused.keyboardNavigationClusterSearch(null, direction);

            // Since requestFocus only takes "real" focus directions (and therefore also
            // restoreFocusInCluster), convert forward/backward focus into FOCUS_DOWN.
            int realDirection = direction;
            if (direction == View.FOCUS_FORWARD || direction == View.FOCUS_BACKWARD) {
                realDirection = View.FOCUS_DOWN;
            }

            if (cluster != null && cluster.isRootNamespace()) {
                // the default cluster. Try to find a non-clustered view to focus.
                if (cluster.restoreFocusNotInCluster()) {
                    playSoundEffect(SoundEffectConstants.getContantForFocusDirection(direction));
                    return true;
                }
                // otherwise skip to next actual cluster
                cluster = keyboardNavigationClusterSearch(null, direction);
            }

            if (cluster != null && cluster.restoreFocusInCluster(realDirection)) {
                playSoundEffect(SoundEffectConstants.getContantForFocusDirection(direction));
                return true;
            }

            return false;
        }

        private int processKeyEvent(QueuedInputEvent q) {
            final KeyEvent event = (KeyEvent)q.mEvent;

            if (mUnhandledKeyManager.preViewDispatch(event)) {
                return FINISH_HANDLED;
            }

            // Deliver the key to the view hierarchy.
            if (mView.dispatchKeyEvent(event)) {
                return FINISH_HANDLED;
            }

            if (shouldDropInputEvent(q)) {
                return FINISH_NOT_HANDLED;
            }

            // This dispatch is for windows that don't have a Window.Callback. Otherwise,
            // the Window.Callback usually will have already called this (see
            // DecorView.superDispatchKeyEvent) leaving this call a no-op.
            if (mUnhandledKeyManager.dispatch(mView, event)) {
                return FINISH_HANDLED;
            }

            int groupNavigationDirection = 0;

            if (event.getAction() == KeyEvent.ACTION_DOWN
                    && event.getKeyCode() == KeyEvent.KEYCODE_TAB) {
                if (KeyEvent.metaStateHasModifiers(event.getMetaState(), KeyEvent.META_META_ON)) {
                    groupNavigationDirection = View.FOCUS_FORWARD;
                } else if (KeyEvent.metaStateHasModifiers(event.getMetaState(),
                        KeyEvent.META_META_ON | KeyEvent.META_SHIFT_ON)) {
                    groupNavigationDirection = View.FOCUS_BACKWARD;
                }
            }

            // If a modifier is held, try to interpret the key as a shortcut.
            if (event.getAction() == KeyEvent.ACTION_DOWN
                    && !KeyEvent.metaStateHasNoModifiers(event.getMetaState())
                    && event.getRepeatCount() == 0
                    && !KeyEvent.isModifierKey(event.getKeyCode())
                    && groupNavigationDirection == 0) {
                if (mView.dispatchKeyShortcutEvent(event)) {
                    return FINISH_HANDLED;
                }
                if (shouldDropInputEvent(q)) {
                    return FINISH_NOT_HANDLED;
                }
            }

            // Apply the fallback event policy.
            if (mFallbackEventHandler.dispatchKeyEvent(event)) {
                return FINISH_HANDLED;
            }
            if (shouldDropInputEvent(q)) {
                return FINISH_NOT_HANDLED;
            }

            // Handle automatic focus changes.
            if (event.getAction() == KeyEvent.ACTION_DOWN) {
                if (groupNavigationDirection != 0) {
                    if (performKeyboardGroupNavigation(groupNavigationDirection)) {
                        return FINISH_HANDLED;
                    }
                } else {
                    if (performFocusNavigation(event)) {
                        return FINISH_HANDLED;
                    }
                }
            }
            return FORWARD;
        }

        private int processPointerEvent(QueuedInputEvent q) {
            final MotionEvent event = (MotionEvent)q.mEvent;

            if (event.getPointerCount() == 3 && isSwipeToScreenshotGestureActive()) {
                event.setAction(MotionEvent.ACTION_CANCEL);
            }

            mAttachInfo.mUnbufferedDispatchRequested = false;
            mAttachInfo.mHandlingPointerEvent = true;
            boolean handled = mView.dispatchPointerEvent(event);
            maybeUpdatePointerIcon(event);
            maybeUpdateTooltip(event);
            mAttachInfo.mHandlingPointerEvent = false;
            if (mAttachInfo.mUnbufferedDispatchRequested && !mUnbufferedInputDispatch) {
                mUnbufferedInputDispatch = true;
                if (mConsumeBatchedInputScheduled) {
                    scheduleConsumeBatchedInputImmediately();
                }
            }
            return handled ? FINISH_HANDLED : FORWARD;
        }

        private void maybeUpdatePointerIcon(MotionEvent event) {
            if (event.getPointerCount() == 1 && event.isFromSource(InputDevice.SOURCE_MOUSE)) {
                if (event.getActionMasked() == MotionEvent.ACTION_HOVER_ENTER
                        || event.getActionMasked() == MotionEvent.ACTION_HOVER_EXIT) {
                    // Other apps or the window manager may change the icon type outside of
                    // this app, therefore the icon type has to be reset on enter/exit event.
                    mPointerIconType = PointerIcon.TYPE_NOT_SPECIFIED;
                }

                if (event.getActionMasked() != MotionEvent.ACTION_HOVER_EXIT) {
                    if (!updatePointerIcon(event) &&
                            event.getActionMasked() == MotionEvent.ACTION_HOVER_MOVE) {
                        mPointerIconType = PointerIcon.TYPE_NOT_SPECIFIED;
                    }
                }
            }
        }

        private int processTrackballEvent(QueuedInputEvent q) {
            final MotionEvent event = (MotionEvent)q.mEvent;

            if (event.isFromSource(InputDevice.SOURCE_MOUSE_RELATIVE)) {
                if (!hasPointerCapture() || mView.dispatchCapturedPointerEvent(event)) {
                    return FINISH_HANDLED;
                }
            }

            if (mView.dispatchTrackballEvent(event)) {
                return FINISH_HANDLED;
            }
            return FORWARD;
        }

        private int processGenericMotionEvent(QueuedInputEvent q) {
            final MotionEvent event = (MotionEvent)q.mEvent;

            if (event.isFromSource(InputDevice.SOURCE_TOUCHPAD)) {
                if (hasPointerCapture() && mView.dispatchCapturedPointerEvent(event)) {
                    return FINISH_HANDLED;
                }
            }

            // Deliver the event to the view.
            if (mView.dispatchGenericMotionEvent(event)) {
                return FINISH_HANDLED;
            }
            return FORWARD;
        }
    }

    private void resetPointerIcon(MotionEvent event) {
        mPointerIconType = PointerIcon.TYPE_NOT_SPECIFIED;
        updatePointerIcon(event);
    }

    private boolean updatePointerIcon(MotionEvent event) {
        final int pointerIndex = 0;
        final float x = event.getX(pointerIndex);
        final float y = event.getY(pointerIndex);
        if (mView == null) {
            // E.g. click outside a popup to dismiss it
            Slog.d(mTag, "updatePointerIcon called after view was removed");
            return false;
        }
        if (x < 0 || x >= mView.getWidth() || y < 0 || y >= mView.getHeight()) {
            // E.g. when moving window divider with mouse
            return false;
        }
        final PointerIcon pointerIcon = mView.onResolvePointerIcon(event, pointerIndex);
        final int pointerType = (pointerIcon != null) ?
                pointerIcon.getType() : PointerIcon.TYPE_DEFAULT;

        if (mPointerIconType != pointerType) {
            mPointerIconType = pointerType;
            mCustomPointerIcon = null;
            if (mPointerIconType != PointerIcon.TYPE_CUSTOM) {
                InputManager.getInstance().setPointerIconType(pointerType);
                return true;
            }
        }
        if (mPointerIconType == PointerIcon.TYPE_CUSTOM &&
                !pointerIcon.equals(mCustomPointerIcon)) {
            mCustomPointerIcon = pointerIcon;
            InputManager.getInstance().setCustomPointerIcon(mCustomPointerIcon);
        }
        return true;
    }

    private void maybeUpdateTooltip(MotionEvent event) {
        if (event.getPointerCount() != 1) {
            return;
        }
        final int action = event.getActionMasked();
        if (action != MotionEvent.ACTION_HOVER_ENTER
                && action != MotionEvent.ACTION_HOVER_MOVE
                && action != MotionEvent.ACTION_HOVER_EXIT) {
            return;
        }
        AccessibilityManager manager = AccessibilityManager.getInstance(mContext);
        if (manager.isEnabled() && manager.isTouchExplorationEnabled()) {
            return;
        }
        if (mView == null) {
            Slog.d(mTag, "maybeUpdateTooltip called after view was removed");
            return;
        }
        mView.dispatchTooltipHoverEvent(event);
    }

    /**
     * Performs synthesis of new input events from unhandled input events.
     */
    final class SyntheticInputStage extends InputStage {
        private final SyntheticTrackballHandler mTrackball = new SyntheticTrackballHandler();
        private final SyntheticJoystickHandler mJoystick = new SyntheticJoystickHandler();
        private final SyntheticTouchNavigationHandler mTouchNavigation =
                new SyntheticTouchNavigationHandler();
        private final SyntheticKeyboardHandler mKeyboard = new SyntheticKeyboardHandler();

        public SyntheticInputStage() {
            super(null);
        }

        @Override
        protected int onProcess(QueuedInputEvent q) {
            q.mFlags |= QueuedInputEvent.FLAG_RESYNTHESIZED;
            if (q.mEvent instanceof MotionEvent) {
                final MotionEvent event = (MotionEvent)q.mEvent;
                final int source = event.getSource();
                if ((source & InputDevice.SOURCE_CLASS_TRACKBALL) != 0) {
                    mTrackball.process(event);
                    return FINISH_HANDLED;
                } else if ((source & InputDevice.SOURCE_CLASS_JOYSTICK) != 0) {
                    mJoystick.process(event);
                    return FINISH_HANDLED;
                } else if ((source & InputDevice.SOURCE_TOUCH_NAVIGATION)
                        == InputDevice.SOURCE_TOUCH_NAVIGATION) {
                    mTouchNavigation.process(event);
                    return FINISH_HANDLED;
                }
            } else if ((q.mFlags & QueuedInputEvent.FLAG_UNHANDLED) != 0) {
                mKeyboard.process((KeyEvent)q.mEvent);
                return FINISH_HANDLED;
            }

            return FORWARD;
        }

        @Override
        protected void onDeliverToNext(QueuedInputEvent q) {
            if ((q.mFlags & QueuedInputEvent.FLAG_RESYNTHESIZED) == 0) {
                // Cancel related synthetic events if any prior stage has handled the event.
                if (q.mEvent instanceof MotionEvent) {
                    final MotionEvent event = (MotionEvent)q.mEvent;
                    final int source = event.getSource();
                    if ((source & InputDevice.SOURCE_CLASS_TRACKBALL) != 0) {
                        mTrackball.cancel();
                    } else if ((source & InputDevice.SOURCE_CLASS_JOYSTICK) != 0) {
                        mJoystick.cancel();
                    } else if ((source & InputDevice.SOURCE_TOUCH_NAVIGATION)
                            == InputDevice.SOURCE_TOUCH_NAVIGATION) {
                        mTouchNavigation.cancel(event);
                    }
                }
            }
            super.onDeliverToNext(q);
        }

        @Override
        protected void onWindowFocusChanged(boolean hasWindowFocus) {
            if (!hasWindowFocus) {
                mJoystick.cancel();
            }
        }

        @Override
        protected void onDetachedFromWindow() {
            mJoystick.cancel();
        }
    }

    /**
     * Creates dpad events from unhandled trackball movements.
     */
    final class SyntheticTrackballHandler {
        private final TrackballAxis mX = new TrackballAxis();
        private final TrackballAxis mY = new TrackballAxis();
        private long mLastTime;

        public void process(MotionEvent event) {
            // Translate the trackball event into DPAD keys and try to deliver those.
            long curTime = SystemClock.uptimeMillis();
            if ((mLastTime + MAX_TRACKBALL_DELAY) < curTime) {
                // It has been too long since the last movement,
                // so restart at the beginning.
                mX.reset(0);
                mY.reset(0);
                mLastTime = curTime;
            }

            final int action = event.getAction();
            final int metaState = event.getMetaState();
            switch (action) {
                case MotionEvent.ACTION_DOWN:
                    mX.reset(2);
                    mY.reset(2);
                    enqueueInputEvent(new KeyEvent(curTime, curTime,
                            KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_DPAD_CENTER, 0, metaState,
                            KeyCharacterMap.VIRTUAL_KEYBOARD, 0, KeyEvent.FLAG_FALLBACK,
                            InputDevice.SOURCE_KEYBOARD));
                    break;
                case MotionEvent.ACTION_UP:
                    mX.reset(2);
                    mY.reset(2);
                    enqueueInputEvent(new KeyEvent(curTime, curTime,
                            KeyEvent.ACTION_UP, KeyEvent.KEYCODE_DPAD_CENTER, 0, metaState,
                            KeyCharacterMap.VIRTUAL_KEYBOARD, 0, KeyEvent.FLAG_FALLBACK,
                            InputDevice.SOURCE_KEYBOARD));
                    break;
            }

            if (DEBUG_TRACKBALL) Log.v(mTag, "TB X=" + mX.position + " step="
                    + mX.step + " dir=" + mX.dir + " acc=" + mX.acceleration
                    + " move=" + event.getX()
                    + " / Y=" + mY.position + " step="
                    + mY.step + " dir=" + mY.dir + " acc=" + mY.acceleration
                    + " move=" + event.getY());
            final float xOff = mX.collect(event.getX(), event.getEventTime(), "X");
            final float yOff = mY.collect(event.getY(), event.getEventTime(), "Y");

            // Generate DPAD events based on the trackball movement.
            // We pick the axis that has moved the most as the direction of
            // the DPAD.  When we generate DPAD events for one axis, then the
            // other axis is reset -- we don't want to perform DPAD jumps due
            // to slight movements in the trackball when making major movements
            // along the other axis.
            int keycode = 0;
            int movement = 0;
            float accel = 1;
            if (xOff > yOff) {
                movement = mX.generate();
                if (movement != 0) {
                    keycode = movement > 0 ? KeyEvent.KEYCODE_DPAD_RIGHT
                            : KeyEvent.KEYCODE_DPAD_LEFT;
                    accel = mX.acceleration;
                    mY.reset(2);
                }
            } else if (yOff > 0) {
                movement = mY.generate();
                if (movement != 0) {
                    keycode = movement > 0 ? KeyEvent.KEYCODE_DPAD_DOWN
                            : KeyEvent.KEYCODE_DPAD_UP;
                    accel = mY.acceleration;
                    mX.reset(2);
                }
            }

            if (keycode != 0) {
                if (movement < 0) movement = -movement;
                int accelMovement = (int)(movement * accel);
                if (DEBUG_TRACKBALL) Log.v(mTag, "Move: movement=" + movement
                        + " accelMovement=" + accelMovement
                        + " accel=" + accel);
                if (accelMovement > movement) {
                    if (DEBUG_TRACKBALL) Log.v(mTag, "Delivering fake DPAD: "
                            + keycode);
                    movement--;
                    int repeatCount = accelMovement - movement;
                    enqueueInputEvent(new KeyEvent(curTime, curTime,
                            KeyEvent.ACTION_MULTIPLE, keycode, repeatCount, metaState,
                            KeyCharacterMap.VIRTUAL_KEYBOARD, 0, KeyEvent.FLAG_FALLBACK,
                            InputDevice.SOURCE_KEYBOARD));
                }
                while (movement > 0) {
                    if (DEBUG_TRACKBALL) Log.v(mTag, "Delivering fake DPAD: "
                            + keycode);
                    movement--;
                    curTime = SystemClock.uptimeMillis();
                    enqueueInputEvent(new KeyEvent(curTime, curTime,
                            KeyEvent.ACTION_DOWN, keycode, 0, metaState,
                            KeyCharacterMap.VIRTUAL_KEYBOARD, 0, KeyEvent.FLAG_FALLBACK,
                            InputDevice.SOURCE_KEYBOARD));
                    enqueueInputEvent(new KeyEvent(curTime, curTime,
                            KeyEvent.ACTION_UP, keycode, 0, metaState,
                            KeyCharacterMap.VIRTUAL_KEYBOARD, 0, KeyEvent.FLAG_FALLBACK,
                            InputDevice.SOURCE_KEYBOARD));
                }
                mLastTime = curTime;
            }
        }

        public void cancel() {
            mLastTime = Integer.MIN_VALUE;

            // If we reach this, we consumed a trackball event.
            // Because we will not translate the trackball event into a key event,
            // touch mode will not exit, so we exit touch mode here.
            if (mView != null && mAdded) {
                ensureTouchMode(false);
            }
        }
    }

    /**
     * Maintains state information for a single trackball axis, generating
     * discrete (DPAD) movements based on raw trackball motion.
     */
    static final class TrackballAxis {
        /**
         * The maximum amount of acceleration we will apply.
         */
        static final float MAX_ACCELERATION = 20;

        /**
         * The maximum amount of time (in milliseconds) between events in order
         * for us to consider the user to be doing fast trackball movements,
         * and thus apply an acceleration.
         */
        static final long FAST_MOVE_TIME = 150;

        /**
         * Scaling factor to the time (in milliseconds) between events to how
         * much to multiple/divide the current acceleration.  When movement
         * is < FAST_MOVE_TIME this multiplies the acceleration; when >
         * FAST_MOVE_TIME it divides it.
         */
        static final float ACCEL_MOVE_SCALING_FACTOR = (1.0f/40);

        static final float FIRST_MOVEMENT_THRESHOLD = 0.5f;
        static final float SECOND_CUMULATIVE_MOVEMENT_THRESHOLD = 2.0f;
        static final float SUBSEQUENT_INCREMENTAL_MOVEMENT_THRESHOLD = 1.0f;

        float position;
        float acceleration = 1;
        long lastMoveTime = 0;
        int step;
        int dir;
        int nonAccelMovement;

        void reset(int _step) {
            position = 0;
            acceleration = 1;
            lastMoveTime = 0;
            step = _step;
            dir = 0;
        }

        /**
         * Add trackball movement into the state.  If the direction of movement
         * has been reversed, the state is reset before adding the
         * movement (so that you don't have to compensate for any previously
         * collected movement before see the result of the movement in the
         * new direction).
         *
         * @return Returns the absolute value of the amount of movement
         * collected so far.
         */
        float collect(float off, long time, String axis) {
            long normTime;
            if (off > 0) {
                normTime = (long)(off * FAST_MOVE_TIME);
                if (dir < 0) {
                    if (DEBUG_TRACKBALL) Log.v(TAG, axis + " reversed to positive!");
                    position = 0;
                    step = 0;
                    acceleration = 1;
                    lastMoveTime = 0;
                }
                dir = 1;
            } else if (off < 0) {
                normTime = (long)((-off) * FAST_MOVE_TIME);
                if (dir > 0) {
                    if (DEBUG_TRACKBALL) Log.v(TAG, axis + " reversed to negative!");
                    position = 0;
                    step = 0;
                    acceleration = 1;
                    lastMoveTime = 0;
                }
                dir = -1;
            } else {
                normTime = 0;
            }

            // The number of milliseconds between each movement that is
            // considered "normal" and will not result in any acceleration
            // or deceleration, scaled by the offset we have here.
            if (normTime > 0) {
                long delta = time - lastMoveTime;
                lastMoveTime = time;
                float acc = acceleration;
                if (delta < normTime) {
                    // The user is scrolling rapidly, so increase acceleration.
                    float scale = (normTime-delta) * ACCEL_MOVE_SCALING_FACTOR;
                    if (scale > 1) acc *= scale;
                    if (DEBUG_TRACKBALL) Log.v(TAG, axis + " accelerate: off="
                            + off + " normTime=" + normTime + " delta=" + delta
                            + " scale=" + scale + " acc=" + acc);
                    acceleration = acc < MAX_ACCELERATION ? acc : MAX_ACCELERATION;
                } else {
                    // The user is scrolling slowly, so decrease acceleration.
                    float scale = (delta-normTime) * ACCEL_MOVE_SCALING_FACTOR;
                    if (scale > 1) acc /= scale;
                    if (DEBUG_TRACKBALL) Log.v(TAG, axis + " deccelerate: off="
                            + off + " normTime=" + normTime + " delta=" + delta
                            + " scale=" + scale + " acc=" + acc);
                    acceleration = acc > 1 ? acc : 1;
                }
            }
            position += off;
            return Math.abs(position);
        }

        /**
         * Generate the number of discrete movement events appropriate for
         * the currently collected trackball movement.
         *
         * @return Returns the number of discrete movements, either positive
         * or negative, or 0 if there is not enough trackball movement yet
         * for a discrete movement.
         */
        int generate() {
            int movement = 0;
            nonAccelMovement = 0;
            do {
                final int dir = position >= 0 ? 1 : -1;
                switch (step) {
                    // If we are going to execute the first step, then we want
                    // to do this as soon as possible instead of waiting for
                    // a full movement, in order to make things look responsive.
                    case 0:
                        if (Math.abs(position) < FIRST_MOVEMENT_THRESHOLD) {
                            return movement;
                        }
                        movement += dir;
                        nonAccelMovement += dir;
                        step = 1;
                        break;
                    // If we have generated the first movement, then we need
                    // to wait for the second complete trackball motion before
                    // generating the second discrete movement.
                    case 1:
                        if (Math.abs(position) < SECOND_CUMULATIVE_MOVEMENT_THRESHOLD) {
                            return movement;
                        }
                        movement += dir;
                        nonAccelMovement += dir;
                        position -= SECOND_CUMULATIVE_MOVEMENT_THRESHOLD * dir;
                        step = 2;
                        break;
                    // After the first two, we generate discrete movements
                    // consistently with the trackball, applying an acceleration
                    // if the trackball is moving quickly.  This is a simple
                    // acceleration on top of what we already compute based
                    // on how quickly the wheel is being turned, to apply
                    // a longer increasing acceleration to continuous movement
                    // in one direction.
                    default:
                        if (Math.abs(position) < SUBSEQUENT_INCREMENTAL_MOVEMENT_THRESHOLD) {
                            return movement;
                        }
                        movement += dir;
                        position -= dir * SUBSEQUENT_INCREMENTAL_MOVEMENT_THRESHOLD;
                        float acc = acceleration;
                        acc *= 1.1f;
                        acceleration = acc < MAX_ACCELERATION ? acc : acceleration;
                        break;
                }
            } while (true);
        }
    }

    /**
     * Creates dpad events from unhandled joystick movements.
     */
    final class SyntheticJoystickHandler extends Handler {
        private final static int MSG_ENQUEUE_X_AXIS_KEY_REPEAT = 1;
        private final static int MSG_ENQUEUE_Y_AXIS_KEY_REPEAT = 2;

        private final JoystickAxesState mJoystickAxesState = new JoystickAxesState();
        private final SparseArray<KeyEvent> mDeviceKeyEvents = new SparseArray<>();

        public SyntheticJoystickHandler() {
            super(true);
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MSG_ENQUEUE_X_AXIS_KEY_REPEAT:
                case MSG_ENQUEUE_Y_AXIS_KEY_REPEAT: {
                    if (mAttachInfo.mHasWindowFocus) {
                        KeyEvent oldEvent = (KeyEvent) msg.obj;
                        KeyEvent e = KeyEvent.changeTimeRepeat(oldEvent,
                                SystemClock.uptimeMillis(), oldEvent.getRepeatCount() + 1);
                        enqueueInputEvent(e);
                        Message m = obtainMessage(msg.what, e);
                        m.setAsynchronous(true);
                        sendMessageDelayed(m, ViewConfiguration.getKeyRepeatDelay());
                    }
                } break;
            }
        }

        public void process(MotionEvent event) {
            switch(event.getActionMasked()) {
                case MotionEvent.ACTION_CANCEL:
                    cancel();
                    break;
                case MotionEvent.ACTION_MOVE:
                    update(event);
                    break;
                default:
                    Log.w(mTag, "Unexpected action: " + event.getActionMasked());
            }
        }

        private void cancel() {
            removeMessages(MSG_ENQUEUE_X_AXIS_KEY_REPEAT);
            removeMessages(MSG_ENQUEUE_Y_AXIS_KEY_REPEAT);
            for (int i = 0; i < mDeviceKeyEvents.size(); i++) {
                final KeyEvent keyEvent = mDeviceKeyEvents.valueAt(i);
                if (keyEvent != null) {
                    enqueueInputEvent(KeyEvent.changeTimeRepeat(keyEvent,
                            SystemClock.uptimeMillis(), 0));
                }
            }
            mDeviceKeyEvents.clear();
            mJoystickAxesState.resetState();
        }

        private void update(MotionEvent event) {
            final int historySize = event.getHistorySize();
            for (int h = 0; h < historySize; h++) {
                final long time = event.getHistoricalEventTime(h);
                mJoystickAxesState.updateStateForAxis(event, time, MotionEvent.AXIS_X,
                        event.getHistoricalAxisValue(MotionEvent.AXIS_X, 0, h));
                mJoystickAxesState.updateStateForAxis(event, time, MotionEvent.AXIS_Y,
                        event.getHistoricalAxisValue(MotionEvent.AXIS_Y, 0, h));
                mJoystickAxesState.updateStateForAxis(event, time, MotionEvent.AXIS_HAT_X,
                        event.getHistoricalAxisValue(MotionEvent.AXIS_HAT_X, 0, h));
                mJoystickAxesState.updateStateForAxis(event, time, MotionEvent.AXIS_HAT_Y,
                        event.getHistoricalAxisValue(MotionEvent.AXIS_HAT_Y, 0, h));
            }
            final long time = event.getEventTime();
            mJoystickAxesState.updateStateForAxis(event, time, MotionEvent.AXIS_X,
                    event.getAxisValue(MotionEvent.AXIS_X));
            mJoystickAxesState.updateStateForAxis(event, time, MotionEvent.AXIS_Y,
                    event.getAxisValue(MotionEvent.AXIS_Y));
            mJoystickAxesState.updateStateForAxis(event, time, MotionEvent.AXIS_HAT_X,
                    event.getAxisValue(MotionEvent.AXIS_HAT_X));
            mJoystickAxesState.updateStateForAxis(event, time, MotionEvent.AXIS_HAT_Y,
                    event.getAxisValue(MotionEvent.AXIS_HAT_Y));
        }

        final class JoystickAxesState {
            // State machine: from neutral state (no button press) can go into
            // button STATE_UP_OR_LEFT or STATE_DOWN_OR_RIGHT state, emitting an ACTION_DOWN event.
            // From STATE_UP_OR_LEFT or STATE_DOWN_OR_RIGHT state can go into neutral state,
            // emitting an ACTION_UP event.
            private static final int STATE_UP_OR_LEFT = -1;
            private static final int STATE_NEUTRAL = 0;
            private static final int STATE_DOWN_OR_RIGHT = 1;

            final int[] mAxisStatesHat = {STATE_NEUTRAL, STATE_NEUTRAL}; // {AXIS_HAT_X, AXIS_HAT_Y}
            final int[] mAxisStatesStick = {STATE_NEUTRAL, STATE_NEUTRAL}; // {AXIS_X, AXIS_Y}

            void resetState() {
                mAxisStatesHat[0] = STATE_NEUTRAL;
                mAxisStatesHat[1] = STATE_NEUTRAL;
                mAxisStatesStick[0] = STATE_NEUTRAL;
                mAxisStatesStick[1] = STATE_NEUTRAL;
            }

            void updateStateForAxis(MotionEvent event, long time, int axis, float value) {
                // Emit KeyEvent if necessary
                // axis can be AXIS_X, AXIS_Y, AXIS_HAT_X, AXIS_HAT_Y
                final int axisStateIndex;
                final int repeatMessage;
                if (isXAxis(axis)) {
                    axisStateIndex = 0;
                    repeatMessage = MSG_ENQUEUE_X_AXIS_KEY_REPEAT;
                } else if (isYAxis(axis)) {
                    axisStateIndex = 1;
                    repeatMessage = MSG_ENQUEUE_Y_AXIS_KEY_REPEAT;
                } else {
                    Log.e(mTag, "Unexpected axis " + axis + " in updateStateForAxis!");
                    return;
                }
                final int newState = joystickAxisValueToState(value);

                final int currentState;
                if (axis == MotionEvent.AXIS_X || axis == MotionEvent.AXIS_Y) {
                    currentState = mAxisStatesStick[axisStateIndex];
                } else {
                    currentState = mAxisStatesHat[axisStateIndex];
                }

                if (currentState == newState) {
                    return;
                }

                final int metaState = event.getMetaState();
                final int deviceId = event.getDeviceId();
                final int source = event.getSource();

                if (currentState == STATE_DOWN_OR_RIGHT || currentState == STATE_UP_OR_LEFT) {
                    // send a button release event
                    final int keyCode = joystickAxisAndStateToKeycode(axis, currentState);
                    if (keyCode != KeyEvent.KEYCODE_UNKNOWN) {
                        enqueueInputEvent(new KeyEvent(time, time, KeyEvent.ACTION_UP, keyCode,
                                0, metaState, deviceId, 0, KeyEvent.FLAG_FALLBACK, source));
                        // remove the corresponding pending UP event if focus lost/view detached
                        mDeviceKeyEvents.put(deviceId, null);
                    }
                    removeMessages(repeatMessage);
                }

                if (newState == STATE_DOWN_OR_RIGHT || newState == STATE_UP_OR_LEFT) {
                    // send a button down event
                    final int keyCode = joystickAxisAndStateToKeycode(axis, newState);
                    if (keyCode != KeyEvent.KEYCODE_UNKNOWN) {
                        KeyEvent keyEvent = new KeyEvent(time, time, KeyEvent.ACTION_DOWN, keyCode,
                                0, metaState, deviceId, 0, KeyEvent.FLAG_FALLBACK, source);
                        enqueueInputEvent(keyEvent);
                        Message m = obtainMessage(repeatMessage, keyEvent);
                        m.setAsynchronous(true);
                        sendMessageDelayed(m, ViewConfiguration.getKeyRepeatTimeout());
                        // store the corresponding ACTION_UP event so that it can be sent
                        // if focus is lost or root view is removed
                        mDeviceKeyEvents.put(deviceId,
                                new KeyEvent(time, time, KeyEvent.ACTION_UP, keyCode,
                                        0, metaState, deviceId, 0,
                                        KeyEvent.FLAG_FALLBACK | KeyEvent.FLAG_CANCELED,
                                        source));
                    }
                }
                if (axis == MotionEvent.AXIS_X || axis == MotionEvent.AXIS_Y) {
                    mAxisStatesStick[axisStateIndex] = newState;
                } else {
                    mAxisStatesHat[axisStateIndex] = newState;
                }
            }

            private boolean isXAxis(int axis) {
                return axis == MotionEvent.AXIS_X || axis == MotionEvent.AXIS_HAT_X;
            }
            private boolean isYAxis(int axis) {
                return axis == MotionEvent.AXIS_Y || axis == MotionEvent.AXIS_HAT_Y;
            }

            private int joystickAxisAndStateToKeycode(int axis, int state) {
                if (isXAxis(axis) && state == STATE_UP_OR_LEFT) {
                    return KeyEvent.KEYCODE_DPAD_LEFT;
                }
                if (isXAxis(axis) && state == STATE_DOWN_OR_RIGHT) {
                    return KeyEvent.KEYCODE_DPAD_RIGHT;
                }
                if (isYAxis(axis) && state == STATE_UP_OR_LEFT) {
                    return KeyEvent.KEYCODE_DPAD_UP;
                }
                if (isYAxis(axis) && state == STATE_DOWN_OR_RIGHT) {
                    return KeyEvent.KEYCODE_DPAD_DOWN;
                }
                Log.e(mTag, "Unknown axis " + axis + " or direction " + state);
                return KeyEvent.KEYCODE_UNKNOWN; // should never happen
            }

            private int joystickAxisValueToState(float value) {
                if (value >= 0.5f) {
                    return STATE_DOWN_OR_RIGHT;
                } else if (value <= -0.5f) {
                    return STATE_UP_OR_LEFT;
                } else {
                    return STATE_NEUTRAL;
                }
            }
        }
    }

    /**
     * Creates dpad events from unhandled touch navigation movements.
     */
    final class SyntheticTouchNavigationHandler extends Handler {
        private static final String LOCAL_TAG = "SyntheticTouchNavigationHandler";
        private static final boolean LOCAL_DEBUG = false;

        // Assumed nominal width and height in millimeters of a touch navigation pad,
        // if no resolution information is available from the input system.
        private static final float DEFAULT_WIDTH_MILLIMETERS = 48;
        private static final float DEFAULT_HEIGHT_MILLIMETERS = 48;

        /* TODO: These constants should eventually be moved to ViewConfiguration. */

        // The nominal distance traveled to move by one unit.
        private static final int TICK_DISTANCE_MILLIMETERS = 12;

        // Minimum and maximum fling velocity in ticks per second.
        // The minimum velocity should be set such that we perform enough ticks per
        // second that the fling appears to be fluid.  For example, if we set the minimum
        // to 2 ticks per second, then there may be up to half a second delay between the next
        // to last and last ticks which is noticeably discrete and jerky.  This value should
        // probably not be set to anything less than about 4.
        // If fling accuracy is a problem then consider tuning the tick distance instead.
        private static final float MIN_FLING_VELOCITY_TICKS_PER_SECOND = 6f;
        private static final float MAX_FLING_VELOCITY_TICKS_PER_SECOND = 24f;

        // Fling velocity decay factor applied after each new key is emitted.
        // This parameter controls the deceleration and overall duration of the fling.
        // The fling stops automatically when its velocity drops below the minimum
        // fling velocity defined above.
        private static final float FLING_TICK_DECAY = 0.8f;

        /* The input device that we are tracking. */

        private int mCurrentDeviceId = -1;
        private int mCurrentSource;
        private boolean mCurrentDeviceSupported;

        /* Configuration for the current input device. */

        // The scaled tick distance.  A movement of this amount should generally translate
        // into a single dpad event in a given direction.
        private float mConfigTickDistance;

        // The minimum and maximum scaled fling velocity.
        private float mConfigMinFlingVelocity;
        private float mConfigMaxFlingVelocity;

        /* Tracking state. */

        // The velocity tracker for detecting flings.
        private VelocityTracker mVelocityTracker;

        // The active pointer id, or -1 if none.
        private int mActivePointerId = -1;

        // Location where tracking started.
        private float mStartX;
        private float mStartY;

        // Most recently observed position.
        private float mLastX;
        private float mLastY;

        // Accumulated movement delta since the last direction key was sent.
        private float mAccumulatedX;
        private float mAccumulatedY;

        // Set to true if any movement was delivered to the app.
        // Implies that tap slop was exceeded.
        private boolean mConsumedMovement;

        // The most recently sent key down event.
        // The keycode remains set until the direction changes or a fling ends
        // so that repeated key events may be generated as required.
        private long mPendingKeyDownTime;
        private int mPendingKeyCode = KeyEvent.KEYCODE_UNKNOWN;
        private int mPendingKeyRepeatCount;
        private int mPendingKeyMetaState;

        // The current fling velocity while a fling is in progress.
        private boolean mFlinging;
        private float mFlingVelocity;

        public SyntheticTouchNavigationHandler() {
            super(true);
        }

        public void process(MotionEvent event) {
            // Update the current device information.
            final long time = event.getEventTime();
            final int deviceId = event.getDeviceId();
            final int source = event.getSource();
            if (mCurrentDeviceId != deviceId || mCurrentSource != source) {
                finishKeys(time);
                finishTracking(time);
                mCurrentDeviceId = deviceId;
                mCurrentSource = source;
                mCurrentDeviceSupported = false;
                InputDevice device = event.getDevice();
                if (device != null) {
                    // In order to support an input device, we must know certain
                    // characteristics about it, such as its size and resolution.
                    InputDevice.MotionRange xRange = device.getMotionRange(MotionEvent.AXIS_X);
                    InputDevice.MotionRange yRange = device.getMotionRange(MotionEvent.AXIS_Y);
                    if (xRange != null && yRange != null) {
                        mCurrentDeviceSupported = true;

                        // Infer the resolution if it not actually known.
                        float xRes = xRange.getResolution();
                        if (xRes <= 0) {
                            xRes = xRange.getRange() / DEFAULT_WIDTH_MILLIMETERS;
                        }
                        float yRes = yRange.getResolution();
                        if (yRes <= 0) {
                            yRes = yRange.getRange() / DEFAULT_HEIGHT_MILLIMETERS;
                        }
                        float nominalRes = (xRes + yRes) * 0.5f;

                        // Precompute all of the configuration thresholds we will need.
                        mConfigTickDistance = TICK_DISTANCE_MILLIMETERS * nominalRes;
                        mConfigMinFlingVelocity =
                                MIN_FLING_VELOCITY_TICKS_PER_SECOND * mConfigTickDistance;
                        mConfigMaxFlingVelocity =
                                MAX_FLING_VELOCITY_TICKS_PER_SECOND * mConfigTickDistance;

                        if (LOCAL_DEBUG) {
                            Log.d(LOCAL_TAG, "Configured device " + mCurrentDeviceId
                                    + " (" + Integer.toHexString(mCurrentSource) + "): "
                                    + ", mConfigTickDistance=" + mConfigTickDistance
                                    + ", mConfigMinFlingVelocity=" + mConfigMinFlingVelocity
                                    + ", mConfigMaxFlingVelocity=" + mConfigMaxFlingVelocity);
                        }
                    }
                }
            }
            if (!mCurrentDeviceSupported) {
                return;
            }

            // Handle the event.
            final int action = event.getActionMasked();
            switch (action) {
                case MotionEvent.ACTION_DOWN: {
                    boolean caughtFling = mFlinging;
                    finishKeys(time);
                    finishTracking(time);
                    mActivePointerId = event.getPointerId(0);
                    mVelocityTracker = VelocityTracker.obtain();
                    mVelocityTracker.addMovement(event);
                    mStartX = event.getX();
                    mStartY = event.getY();
                    mLastX = mStartX;
                    mLastY = mStartY;
                    mAccumulatedX = 0;
                    mAccumulatedY = 0;

                    // If we caught a fling, then pretend that the tap slop has already
                    // been exceeded to suppress taps whose only purpose is to stop the fling.
                    mConsumedMovement = caughtFling;
                    break;
                }

                case MotionEvent.ACTION_MOVE:
                case MotionEvent.ACTION_UP: {
                    if (mActivePointerId < 0) {
                        break;
                    }
                    final int index = event.findPointerIndex(mActivePointerId);
                    if (index < 0) {
                        finishKeys(time);
                        finishTracking(time);
                        break;
                    }

                    mVelocityTracker.addMovement(event);
                    final float x = event.getX(index);
                    final float y = event.getY(index);
                    mAccumulatedX += x - mLastX;
                    mAccumulatedY += y - mLastY;
                    mLastX = x;
                    mLastY = y;

                    // Consume any accumulated movement so far.
                    final int metaState = event.getMetaState();
                    consumeAccumulatedMovement(time, metaState);

                    // Detect taps and flings.
                    if (action == MotionEvent.ACTION_UP) {
                        if (mConsumedMovement && mPendingKeyCode != KeyEvent.KEYCODE_UNKNOWN) {
                            // It might be a fling.
                            mVelocityTracker.computeCurrentVelocity(1000, mConfigMaxFlingVelocity);
                            final float vx = mVelocityTracker.getXVelocity(mActivePointerId);
                            final float vy = mVelocityTracker.getYVelocity(mActivePointerId);
                            if (!startFling(time, vx, vy)) {
                                finishKeys(time);
                            }
                        }
                        finishTracking(time);
                    }
                    break;
                }

                case MotionEvent.ACTION_CANCEL: {
                    finishKeys(time);
                    finishTracking(time);
                    break;
                }
            }
        }

        public void cancel(MotionEvent event) {
            if (mCurrentDeviceId == event.getDeviceId()
                    && mCurrentSource == event.getSource()) {
                final long time = event.getEventTime();
                finishKeys(time);
                finishTracking(time);
            }
        }

        private void finishKeys(long time) {
            cancelFling();
            sendKeyUp(time);
        }

        private void finishTracking(long time) {
            if (mActivePointerId >= 0) {
                mActivePointerId = -1;
                mVelocityTracker.recycle();
                mVelocityTracker = null;
            }
        }

        private void consumeAccumulatedMovement(long time, int metaState) {
            final float absX = Math.abs(mAccumulatedX);
            final float absY = Math.abs(mAccumulatedY);
            if (absX >= absY) {
                if (absX >= mConfigTickDistance) {
                    mAccumulatedX = consumeAccumulatedMovement(time, metaState, mAccumulatedX,
                            KeyEvent.KEYCODE_DPAD_LEFT, KeyEvent.KEYCODE_DPAD_RIGHT);
                    mAccumulatedY = 0;
                    mConsumedMovement = true;
                }
            } else {
                if (absY >= mConfigTickDistance) {
                    mAccumulatedY = consumeAccumulatedMovement(time, metaState, mAccumulatedY,
                            KeyEvent.KEYCODE_DPAD_UP, KeyEvent.KEYCODE_DPAD_DOWN);
                    mAccumulatedX = 0;
                    mConsumedMovement = true;
                }
            }
        }

        private float consumeAccumulatedMovement(long time, int metaState,
                float accumulator, int negativeKeyCode, int positiveKeyCode) {
            while (accumulator <= -mConfigTickDistance) {
                sendKeyDownOrRepeat(time, negativeKeyCode, metaState);
                accumulator += mConfigTickDistance;
            }
            while (accumulator >= mConfigTickDistance) {
                sendKeyDownOrRepeat(time, positiveKeyCode, metaState);
                accumulator -= mConfigTickDistance;
            }
            return accumulator;
        }

        private void sendKeyDownOrRepeat(long time, int keyCode, int metaState) {
            if (mPendingKeyCode != keyCode) {
                sendKeyUp(time);
                mPendingKeyDownTime = time;
                mPendingKeyCode = keyCode;
                mPendingKeyRepeatCount = 0;
            } else {
                mPendingKeyRepeatCount += 1;
            }
            mPendingKeyMetaState = metaState;

            // Note: Normally we would pass FLAG_LONG_PRESS when the repeat count is 1
            // but it doesn't quite make sense when simulating the events in this way.
            if (LOCAL_DEBUG) {
                Log.d(LOCAL_TAG, "Sending key down: keyCode=" + mPendingKeyCode
                        + ", repeatCount=" + mPendingKeyRepeatCount
                        + ", metaState=" + Integer.toHexString(mPendingKeyMetaState));
            }
            enqueueInputEvent(new KeyEvent(mPendingKeyDownTime, time,
                    KeyEvent.ACTION_DOWN, mPendingKeyCode, mPendingKeyRepeatCount,
                    mPendingKeyMetaState, mCurrentDeviceId,
                    KeyEvent.FLAG_FALLBACK, mCurrentSource));
        }

        private void sendKeyUp(long time) {
            if (mPendingKeyCode != KeyEvent.KEYCODE_UNKNOWN) {
                if (LOCAL_DEBUG) {
                    Log.d(LOCAL_TAG, "Sending key up: keyCode=" + mPendingKeyCode
                            + ", metaState=" + Integer.toHexString(mPendingKeyMetaState));
                }
                enqueueInputEvent(new KeyEvent(mPendingKeyDownTime, time,
                        KeyEvent.ACTION_UP, mPendingKeyCode, 0, mPendingKeyMetaState,
                        mCurrentDeviceId, 0, KeyEvent.FLAG_FALLBACK,
                        mCurrentSource));
                mPendingKeyCode = KeyEvent.KEYCODE_UNKNOWN;
            }
        }

        private boolean startFling(long time, float vx, float vy) {
            if (LOCAL_DEBUG) {
                Log.d(LOCAL_TAG, "Considering fling: vx=" + vx + ", vy=" + vy
                        + ", min=" + mConfigMinFlingVelocity);
            }

            // Flings must be oriented in the same direction as the preceding movements.
            switch (mPendingKeyCode) {
                case KeyEvent.KEYCODE_DPAD_LEFT:
                    if (-vx >= mConfigMinFlingVelocity
                            && Math.abs(vy) < mConfigMinFlingVelocity) {
                        mFlingVelocity = -vx;
                        break;
                    }
                    return false;

                case KeyEvent.KEYCODE_DPAD_RIGHT:
                    if (vx >= mConfigMinFlingVelocity
                            && Math.abs(vy) < mConfigMinFlingVelocity) {
                        mFlingVelocity = vx;
                        break;
                    }
                    return false;

                case KeyEvent.KEYCODE_DPAD_UP:
                    if (-vy >= mConfigMinFlingVelocity
                            && Math.abs(vx) < mConfigMinFlingVelocity) {
                        mFlingVelocity = -vy;
                        break;
                    }
                    return false;

                case KeyEvent.KEYCODE_DPAD_DOWN:
                    if (vy >= mConfigMinFlingVelocity
                            && Math.abs(vx) < mConfigMinFlingVelocity) {
                        mFlingVelocity = vy;
                        break;
                    }
                    return false;
            }

            // Post the first fling event.
            mFlinging = postFling(time);
            return mFlinging;
        }

        private boolean postFling(long time) {
            // The idea here is to estimate the time when the pointer would have
            // traveled one tick distance unit given the current fling velocity.
            // This effect creates continuity of motion.
            if (mFlingVelocity >= mConfigMinFlingVelocity) {
                long delay = (long)(mConfigTickDistance / mFlingVelocity * 1000);
                postAtTime(mFlingRunnable, time + delay);
                if (LOCAL_DEBUG) {
                    Log.d(LOCAL_TAG, "Posted fling: velocity="
                            + mFlingVelocity + ", delay=" + delay
                            + ", keyCode=" + mPendingKeyCode);
                }
                return true;
            }
            return false;
        }

        private void cancelFling() {
            if (mFlinging) {
                removeCallbacks(mFlingRunnable);
                mFlinging = false;
            }
        }

        private final Runnable mFlingRunnable = new Runnable() {
            @Override
            public void run() {
                final long time = SystemClock.uptimeMillis();
                sendKeyDownOrRepeat(time, mPendingKeyCode, mPendingKeyMetaState);
                mFlingVelocity *= FLING_TICK_DECAY;
                if (!postFling(time)) {
                    mFlinging = false;
                    finishKeys(time);
                }
            }
        };
    }

    final class SyntheticKeyboardHandler {
        public void process(KeyEvent event) {
            if ((event.getFlags() & KeyEvent.FLAG_FALLBACK) != 0) {
                return;
            }

            final KeyCharacterMap kcm = event.getKeyCharacterMap();
            final int keyCode = event.getKeyCode();
            final int metaState = event.getMetaState();

            // Check for fallback actions specified by the key character map.
            KeyCharacterMap.FallbackAction fallbackAction =
                    kcm.getFallbackAction(keyCode, metaState);
            if (fallbackAction != null) {
                final int flags = event.getFlags() | KeyEvent.FLAG_FALLBACK;
                KeyEvent fallbackEvent = KeyEvent.obtain(
                        event.getDownTime(), event.getEventTime(),
                        event.getAction(), fallbackAction.keyCode,
                        event.getRepeatCount(), fallbackAction.metaState,
                        event.getDeviceId(), event.getScanCode(),
                        flags, event.getSource(), null);
                fallbackAction.recycle();
                enqueueInputEvent(fallbackEvent);
            }
        }
    }

    /**
     * Returns true if the key is used for keyboard navigation.
     * @param keyEvent The key event.
     * @return True if the key is used for keyboard navigation.
     */
    private static boolean isNavigationKey(KeyEvent keyEvent) {
        switch (keyEvent.getKeyCode()) {
        case KeyEvent.KEYCODE_DPAD_LEFT:
        case KeyEvent.KEYCODE_DPAD_RIGHT:
        case KeyEvent.KEYCODE_DPAD_UP:
        case KeyEvent.KEYCODE_DPAD_DOWN:
        case KeyEvent.KEYCODE_DPAD_CENTER:
        case KeyEvent.KEYCODE_PAGE_UP:
        case KeyEvent.KEYCODE_PAGE_DOWN:
        case KeyEvent.KEYCODE_MOVE_HOME:
        case KeyEvent.KEYCODE_MOVE_END:
        case KeyEvent.KEYCODE_TAB:
        case KeyEvent.KEYCODE_SPACE:
        case KeyEvent.KEYCODE_ENTER:
            return true;
        }
        return false;
    }

    /**
     * Returns true if the key is used for typing.
     * @param keyEvent The key event.
     * @return True if the key is used for typing.
     */
    private static boolean isTypingKey(KeyEvent keyEvent) {
        return keyEvent.getUnicodeChar() > 0;
    }

    /**
     * See if the key event means we should leave touch mode (and leave touch mode if so).
     * @param event The key event.
     * @return Whether this key event should be consumed (meaning the act of
     *   leaving touch mode alone is considered the event).
     */
    private boolean checkForLeavingTouchModeAndConsume(KeyEvent event) {
        // Only relevant in touch mode.
        if (!mAttachInfo.mInTouchMode) {
            return false;
        }

        // Only consider leaving touch mode on DOWN or MULTIPLE actions, never on UP.
        final int action = event.getAction();
        if (action != KeyEvent.ACTION_DOWN && action != KeyEvent.ACTION_MULTIPLE) {
            return false;
        }

        // Don't leave touch mode if the IME told us not to.
        if ((event.getFlags() & KeyEvent.FLAG_KEEP_TOUCH_MODE) != 0) {
            return false;
        }

        // If the key can be used for keyboard navigation then leave touch mode
        // and select a focused view if needed (in ensureTouchMode).
        // When a new focused view is selected, we consume the navigation key because
        // navigation doesn't make much sense unless a view already has focus so
        // the key's purpose is to set focus.
        if (isNavigationKey(event)) {
            return ensureTouchMode(false);
        }

        // If the key can be used for typing then leave touch mode
        // and select a focused view if needed (in ensureTouchMode).
        // Always allow the view to process the typing key.
        if (isTypingKey(event)) {
            ensureTouchMode(false);
            return false;
        }

        return false;
    }

    /* drag/drop */
    @UnsupportedAppUsage
    void setLocalDragState(Object obj) {
        mLocalDragState = obj;
    }

    private void handleDragEvent(DragEvent event) {
        // From the root, only drag start/end/location are dispatched.  entered/exited
        // are determined and dispatched by the viewgroup hierarchy, who then report
        // that back here for ultimate reporting back to the framework.
        if (mView != null && mAdded) {
            final int what = event.mAction;

            // Cache the drag description when the operation starts, then fill it in
            // on subsequent calls as a convenience
            if (what == DragEvent.ACTION_DRAG_STARTED) {
                mCurrentDragView = null;    // Start the current-recipient tracking
                mDragDescription = event.mClipDescription;
            } else {
                if (what == DragEvent.ACTION_DRAG_ENDED) {
                    mDragDescription = null;
                }
                event.mClipDescription = mDragDescription;
            }

            if (what == DragEvent.ACTION_DRAG_EXITED) {
                // A direct EXITED event means that the window manager knows we've just crossed
                // a window boundary, so the current drag target within this one must have
                // just been exited. Send the EXITED notification to the current drag view, if any.
                if (View.sCascadedDragDrop) {
                    mView.dispatchDragEnterExitInPreN(event);
                }
                setDragFocus(null, event);
            } else {
                // For events with a [screen] location, translate into window coordinates
                if ((what == DragEvent.ACTION_DRAG_LOCATION) || (what == DragEvent.ACTION_DROP)) {
                    mDragPoint.set(event.mX, event.mY);
                    if (mTranslator != null) {
                        mTranslator.translatePointInScreenToAppWindow(mDragPoint);
                    }

                    if (mCurScrollY != 0) {
                        mDragPoint.offset(0, mCurScrollY);
                    }

                    event.mX = mDragPoint.x;
                    event.mY = mDragPoint.y;
                }

                // Remember who the current drag target is pre-dispatch
                final View prevDragView = mCurrentDragView;

                if (what == DragEvent.ACTION_DROP && event.mClipData != null) {
                    event.mClipData.prepareToEnterProcess();
                }

                // Now dispatch the drag/drop event
                boolean result = mView.dispatchDragEvent(event);

                if (what == DragEvent.ACTION_DRAG_LOCATION && !event.mEventHandlerWasCalled) {
                    // If the LOCATION event wasn't delivered to any handler, no view now has a drag
                    // focus.
                    setDragFocus(null, event);
                }

                // If we changed apparent drag target, tell the OS about it
                if (prevDragView != mCurrentDragView) {
                    try {
                        if (prevDragView != null) {
                            mWindowSession.dragRecipientExited(mWindow);
                        }
                        if (mCurrentDragView != null) {
                            mWindowSession.dragRecipientEntered(mWindow);
                        }
                    } catch (RemoteException e) {
                        Slog.e(mTag, "Unable to note drag target change");
                    }
                }

                // Report the drop result when we're done
                if (what == DragEvent.ACTION_DROP) {
                    try {
                        Log.i(mTag, "Reporting drop result: " + result);
                        mWindowSession.reportDropResult(mWindow, result);
                    } catch (RemoteException e) {
                        Log.e(mTag, "Unable to report drop result");
                    }
                }

                // When the drag operation ends, reset drag-related state
                if (what == DragEvent.ACTION_DRAG_ENDED) {
                    mCurrentDragView = null;
                    setLocalDragState(null);
                    mAttachInfo.mDragToken = null;
                    if (mAttachInfo.mDragSurface != null) {
                        mAttachInfo.mDragSurface.release();
                        mAttachInfo.mDragSurface = null;
                    }
                }
            }
        }
        event.recycle();
    }

    public void handleDispatchSystemUiVisibilityChanged(SystemUiVisibilityInfo args) {
        if (mSeq != args.seq) {
            // The sequence has changed, so we need to update our value and make
            // sure to do a traversal afterward so the window manager is given our
            // most recent data.
            mSeq = args.seq;
            mAttachInfo.mForceReportNewAttributes = true;
            scheduleTraversals();
        }
        if (mView == null) return;
        if (args.localChanges != 0) {
            mView.updateLocalSystemUiVisibility(args.localValue, args.localChanges);
        }

        int visibility = args.globalVisibility&View.SYSTEM_UI_CLEARABLE_FLAGS;
        if (visibility != mAttachInfo.mGlobalSystemUiVisibility) {
            mAttachInfo.mGlobalSystemUiVisibility = visibility;
            mView.dispatchSystemUiVisibilityChanged(visibility);
        }
    }

    /**
     * Notify that the window title changed
     */
    public void onWindowTitleChanged() {
        mAttachInfo.mForceReportNewAttributes = true;
    }

    public void handleDispatchWindowShown() {
        mAttachInfo.mTreeObserver.dispatchOnWindowShown();
    }

    public void handleRequestKeyboardShortcuts(IResultReceiver receiver, int deviceId) {
        Bundle data = new Bundle();
        ArrayList<KeyboardShortcutGroup> list = new ArrayList<>();
        if (mView != null) {
            mView.requestKeyboardShortcuts(list, deviceId);
        }
        data.putParcelableArrayList(WindowManager.PARCEL_KEY_SHORTCUTS_ARRAY, list);
        try {
            receiver.send(0, data);
        } catch (RemoteException e) {
        }
    }

    @UnsupportedAppUsage
    public void getLastTouchPoint(Point outLocation) {
        outLocation.x = (int) mLastTouchPoint.x;
        outLocation.y = (int) mLastTouchPoint.y;
    }

    public int getLastTouchSource() {
        return mLastTouchSource;
    }

    public void setDragFocus(View newDragTarget, DragEvent event) {
        if (mCurrentDragView != newDragTarget && !View.sCascadedDragDrop) {
            // Send EXITED and ENTERED notifications to the old and new drag focus views.

            final float tx = event.mX;
            final float ty = event.mY;
            final int action = event.mAction;
            final ClipData td = event.mClipData;
            // Position should not be available for ACTION_DRAG_ENTERED and ACTION_DRAG_EXITED.
            event.mX = 0;
            event.mY = 0;
            event.mClipData = null;

            if (mCurrentDragView != null) {
                event.mAction = DragEvent.ACTION_DRAG_EXITED;
                mCurrentDragView.callDragEventHandler(event);
            }

            if (newDragTarget != null) {
                event.mAction = DragEvent.ACTION_DRAG_ENTERED;
                newDragTarget.callDragEventHandler(event);
            }

            event.mAction = action;
            event.mX = tx;
            event.mY = ty;
            event.mClipData = td;
        }

        mCurrentDragView = newDragTarget;
    }

    private AudioManager getAudioManager() {
        if (mView == null) {
            throw new IllegalStateException("getAudioManager called when there is no mView");
        }
        if (mAudioManager == null) {
            mAudioManager = (AudioManager) mView.getContext().getSystemService(Context.AUDIO_SERVICE);
        }
        return mAudioManager;
    }

    private @Nullable AutofillManager getAutofillManager() {
        if (mView instanceof ViewGroup) {
            ViewGroup decorView = (ViewGroup) mView;
            if (decorView.getChildCount() > 0) {
                // We cannot use decorView's Context for querying AutofillManager: DecorView's
                // context is based on Application Context, it would allocate a different
                // AutofillManager instance.
                return decorView.getChildAt(0).getContext()
                        .getSystemService(AutofillManager.class);
            }
        }
        return null;
    }

    private boolean isAutofillUiShowing() {
        AutofillManager afm = getAutofillManager();
        if (afm == null) {
            return false;
        }
        return afm.isAutofillUiShowing();
    }

    public AccessibilityInteractionController getAccessibilityInteractionController() {
        if (mView == null) {
            throw new IllegalStateException("getAccessibilityInteractionController"
                    + " called when there is no mView");
        }
        if (mAccessibilityInteractionController == null) {
            mAccessibilityInteractionController = new AccessibilityInteractionController(this);
        }
        return mAccessibilityInteractionController;
    }

    private int relayoutWindow(WindowManager.LayoutParams params, int viewVisibility,
            boolean insetsPending) throws RemoteException {

        float appScale = mAttachInfo.mApplicationScale;
        boolean restore = false;
        if (params != null && mTranslator != null) {
            restore = true;
            params.backup();
            mTranslator.translateWindowLayout(params);
        }

        if (params != null) {
            if (DBG) Log.d(mTag, "WindowLayout in layoutWindow:" + params);

            if (mOrigWindowType != params.type) {
                // For compatibility with old apps, don't crash here.
                if (mTargetSdkVersion < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
                    Slog.w(mTag, "Window type can not be changed after "
                            + "the window is added; ignoring change of " + mView);
                    params.type = mOrigWindowType;
                }
            }
        }

        long frameNumber = -1;
        if (mSurface.isValid()) {
            frameNumber = mSurface.getNextFrameNumber();
        }

        int relayoutResult = mWindowSession.relayout(mWindow, mSeq, params,
                (int) (mView.getMeasuredWidth() * appScale + 0.5f),
                (int) (mView.getMeasuredHeight() * appScale + 0.5f), viewVisibility,
                insetsPending ? WindowManagerGlobal.RELAYOUT_INSETS_PENDING : 0, frameNumber,
                mTmpFrame, mPendingOverscanInsets, mPendingContentInsets, mPendingVisibleInsets,
                mPendingStableInsets, mPendingOutsets, mPendingBackDropFrame, mPendingDisplayCutout,
                mPendingMergedConfiguration, mSurfaceControl, mTempInsets);
        if (mSurfaceControl.isValid()) {
            mSurface.copyFrom(mSurfaceControl);
        } else {
            destroySurface();
        }

        mPendingAlwaysConsumeSystemBars =
                (relayoutResult & WindowManagerGlobal.RELAYOUT_RES_CONSUME_ALWAYS_SYSTEM_BARS) != 0;

        if (restore) {
            params.restore();
        }

        if (mTranslator != null) {
            mTranslator.translateRectInScreenToAppWinFrame(mTmpFrame);
            mTranslator.translateRectInScreenToAppWindow(mPendingOverscanInsets);
            mTranslator.translateRectInScreenToAppWindow(mPendingContentInsets);
            mTranslator.translateRectInScreenToAppWindow(mPendingVisibleInsets);
            mTranslator.translateRectInScreenToAppWindow(mPendingStableInsets);
        }
        setFrame(mTmpFrame);
        mInsetsController.onStateChanged(mTempInsets);
        return relayoutResult;
    }

    private void setFrame(Rect frame) {
        mWinFrame.set(frame);
        mInsetsController.onFrameChanged(frame);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void playSoundEffect(int effectId) {
        checkThread();

        try {
            final AudioManager audioManager = getAudioManager();

            switch (effectId) {
                case SoundEffectConstants.CLICK:
                    audioManager.playSoundEffect(AudioManager.FX_KEY_CLICK);
                    return;
                case SoundEffectConstants.NAVIGATION_DOWN:
                    audioManager.playSoundEffect(AudioManager.FX_FOCUS_NAVIGATION_DOWN);
                    return;
                case SoundEffectConstants.NAVIGATION_LEFT:
                    audioManager.playSoundEffect(AudioManager.FX_FOCUS_NAVIGATION_LEFT);
                    return;
                case SoundEffectConstants.NAVIGATION_RIGHT:
                    audioManager.playSoundEffect(AudioManager.FX_FOCUS_NAVIGATION_RIGHT);
                    return;
                case SoundEffectConstants.NAVIGATION_UP:
                    audioManager.playSoundEffect(AudioManager.FX_FOCUS_NAVIGATION_UP);
                    return;
                default:
                    throw new IllegalArgumentException("unknown effect id " + effectId +
                            " not defined in " + SoundEffectConstants.class.getCanonicalName());
            }
        } catch (IllegalStateException e) {
            // Exception thrown by getAudioManager() when mView is null
            Log.e(mTag, "FATAL EXCEPTION when attempting to play sound effect: " + e);
            e.printStackTrace();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean performHapticFeedback(int effectId, boolean always) {
        try {
            return mWindowSession.performHapticFeedback(effectId, always);
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public View focusSearch(View focused, int direction) {
        checkThread();
        if (!(mView instanceof ViewGroup)) {
            return null;
        }
        return FocusFinder.getInstance().findNextFocus((ViewGroup) mView, focused, direction);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public View keyboardNavigationClusterSearch(View currentCluster,
            @FocusDirection int direction) {
        checkThread();
        return FocusFinder.getInstance().findNextKeyboardNavigationCluster(
                mView, currentCluster, direction);
    }

    public void debug() {
        mView.debug();
    }

    public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
        String innerPrefix = prefix + "  ";
        writer.print(prefix); writer.println("ViewRoot:");
        writer.print(innerPrefix); writer.print("mAdded="); writer.print(mAdded);
                writer.print(" mRemoved="); writer.println(mRemoved);
        writer.print(innerPrefix); writer.print("mConsumeBatchedInputScheduled=");
                writer.println(mConsumeBatchedInputScheduled);
        writer.print(innerPrefix); writer.print("mConsumeBatchedInputImmediatelyScheduled=");
                writer.println(mConsumeBatchedInputImmediatelyScheduled);
        writer.print(innerPrefix); writer.print("mPendingInputEventCount=");
                writer.println(mPendingInputEventCount);
        writer.print(innerPrefix); writer.print("mProcessInputEventsScheduled=");
                writer.println(mProcessInputEventsScheduled);
        writer.print(innerPrefix); writer.print("mTraversalScheduled=");
                writer.print(mTraversalScheduled);
        writer.print(innerPrefix); writer.print("mIsAmbientMode=");
                writer.print(mIsAmbientMode);
        if (mTraversalScheduled) {
            writer.print(" (barrier="); writer.print(mTraversalBarrier); writer.println(")");
        } else {
            writer.println();
        }
        mFirstInputStage.dump(innerPrefix, writer);

        mChoreographer.dump(prefix, writer);

        mInsetsController.dump(prefix, writer);

        writer.print(prefix); writer.println("View Hierarchy:");
        dumpViewHierarchy(innerPrefix, writer, mView);
    }

    private void dumpViewHierarchy(String prefix, PrintWriter writer, View view) {
        writer.print(prefix);
        if (view == null) {
            writer.println("null");
            return;
        }
        writer.println(view.toString());
        if (!(view instanceof ViewGroup)) {
            return;
        }
        ViewGroup grp = (ViewGroup)view;
        final int N = grp.getChildCount();
        if (N <= 0) {
            return;
        }
        prefix = prefix + "  ";
        for (int i=0; i<N; i++) {
            dumpViewHierarchy(prefix, writer, grp.getChildAt(i));
        }
    }

    public void dumpGfxInfo(int[] info) {
        info[0] = info[1] = 0;
        if (mView != null) {
            getGfxInfo(mView, info);
        }
    }

    private static void getGfxInfo(View view, int[] info) {
        RenderNode renderNode = view.mRenderNode;
        info[0]++;
        if (renderNode != null) {
            info[1] += (int) renderNode.computeApproximateMemoryUsage();
        }

        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;

            int count = group.getChildCount();
            for (int i = 0; i < count; i++) {
                getGfxInfo(group.getChildAt(i), info);
            }
        }
    }

    /**
     * @param immediate True, do now if not in traversal. False, put on queue and do later.
     * @return True, request has been queued. False, request has been completed.
     */
    boolean die(boolean immediate) {
        // Make sure we do execute immediately if we are in the middle of a traversal or the damage
        // done by dispatchDetachedFromWindow will cause havoc on return.
        if (immediate && !mIsInTraversal) {
            doDie();
            return false;
        }

        if (!mIsDrawing) {
            destroyHardwareRenderer();
        } else {
            Log.e(mTag, "Attempting to destroy the window while drawing!\n" +
                    "  window=" + this + ", title=" + mWindowAttributes.getTitle());
        }
        mHandler.sendEmptyMessage(MSG_DIE);
        return true;
    }

    void doDie() {
        checkThread();
        if (LOCAL_LOGV) Log.v(mTag, "DIE in " + this + " of " + mSurface);
        synchronized (this) {
            if (mRemoved) {
                return;
            }
            mRemoved = true;
            if (mAdded) {
                dispatchDetachedFromWindow();
            } else {
                Log.w(mTag, "add view failed and remove related objects");

                mAccessibilityManager.removeAccessibilityStateChangeListener(
                        mAccessibilityInteractionConnectionManager);
                mAccessibilityManager.removeHighTextContrastStateChangeListener(
                        mHighContrastTextManager);
                mDisplayManager.unregisterDisplayListener(mDisplayListener);
            }

            if (mAdded && !mFirst) {
                destroyHardwareRenderer();

                if (mView != null) {
                    int viewVisibility = mView.getVisibility();
                    boolean viewVisibilityChanged = mViewVisibility != viewVisibility;
                    if (mWindowAttributesChanged || viewVisibilityChanged) {
                        // If layout params have been changed, first give them
                        // to the window manager to make sure it has the correct
                        // animation info.
                        try {
                            if ((relayoutWindow(mWindowAttributes, viewVisibility, false)
                                    & WindowManagerGlobal.RELAYOUT_RES_FIRST_TIME) != 0) {
                                mWindowSession.finishDrawing(mWindow);
                            }
                        } catch (RemoteException e) {
                        }
                    }

                    destroySurface();
                }
            }

            mAdded = false;
        }
        WindowManagerGlobal.getInstance().doRemoveView(this);
    }

    public void requestUpdateConfiguration(Configuration config) {
        Message msg = mHandler.obtainMessage(MSG_UPDATE_CONFIGURATION, config);
        mHandler.sendMessage(msg);
    }

    public void loadSystemProperties() {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                // Profiling
                mProfileRendering = SystemProperties.getBoolean(PROPERTY_PROFILE_RENDERING, false);
                profileRendering(mAttachInfo.mHasWindowFocus);

                // Hardware rendering
                if (mAttachInfo.mThreadedRenderer != null) {
                    if (mAttachInfo.mThreadedRenderer.loadSystemProperties()) {
                        invalidate();
                    }
                }

                // Layout debugging
                boolean layout = DisplayProperties.debug_layout().orElse(false);
                if (layout != mAttachInfo.mDebugLayout) {
                    mAttachInfo.mDebugLayout = layout;
                    if (!mHandler.hasMessages(MSG_INVALIDATE_WORLD)) {
                        mHandler.sendEmptyMessageDelayed(MSG_INVALIDATE_WORLD, 200);
                    }
                }
            }
        });
    }

    private void destroyHardwareRenderer() {
        ThreadedRenderer hardwareRenderer = mAttachInfo.mThreadedRenderer;

        if (hardwareRenderer != null) {
            if (mView != null) {
                hardwareRenderer.destroyHardwareResources(mView);
            }
            hardwareRenderer.destroy();
            hardwareRenderer.setRequested(false);

            mAttachInfo.mThreadedRenderer = null;
            mAttachInfo.mHardwareAccelerated = false;
        }
    }

    @UnsupportedAppUsage
    private void dispatchResized(Rect frame, Rect overscanInsets, Rect contentInsets,
            Rect visibleInsets, Rect stableInsets, Rect outsets, boolean reportDraw,
            MergedConfiguration mergedConfiguration, Rect backDropFrame, boolean forceLayout,
            boolean alwaysConsumeSystemBars, int displayId,
            DisplayCutout.ParcelableWrapper displayCutout) {
        if (DEBUG_LAYOUT) Log.v(mTag, "Resizing " + this + ": frame=" + frame.toShortString()
                + " contentInsets=" + contentInsets.toShortString()
                + " visibleInsets=" + visibleInsets.toShortString()
                + " reportDraw=" + reportDraw
                + " backDropFrame=" + backDropFrame);

        // Tell all listeners that we are resizing the window so that the chrome can get
        // updated as fast as possible on a separate thread,
        if (mDragResizing && mUseMTRenderer) {
            boolean fullscreen = frame.equals(backDropFrame);
            synchronized (mWindowCallbacks) {
                for (int i = mWindowCallbacks.size() - 1; i >= 0; i--) {
                    mWindowCallbacks.get(i).onWindowSizeIsChanging(backDropFrame, fullscreen,
                            visibleInsets, stableInsets);
                }
            }
        }

        Message msg = mHandler.obtainMessage(reportDraw ? MSG_RESIZED_REPORT : MSG_RESIZED);
        if (mTranslator != null) {
            mTranslator.translateRectInScreenToAppWindow(frame);
            mTranslator.translateRectInScreenToAppWindow(overscanInsets);
            mTranslator.translateRectInScreenToAppWindow(contentInsets);
            mTranslator.translateRectInScreenToAppWindow(visibleInsets);
        }
        SomeArgs args = SomeArgs.obtain();
        final boolean sameProcessCall = (Binder.getCallingPid() == android.os.Process.myPid());
        args.arg1 = sameProcessCall ? new Rect(frame) : frame;
        args.arg2 = sameProcessCall ? new Rect(contentInsets) : contentInsets;
        args.arg3 = sameProcessCall ? new Rect(visibleInsets) : visibleInsets;
        args.arg4 = sameProcessCall && mergedConfiguration != null
                ? new MergedConfiguration(mergedConfiguration) : mergedConfiguration;
        args.arg5 = sameProcessCall ? new Rect(overscanInsets) : overscanInsets;
        args.arg6 = sameProcessCall ? new Rect(stableInsets) : stableInsets;
        args.arg7 = sameProcessCall ? new Rect(outsets) : outsets;
        args.arg8 = sameProcessCall ? new Rect(backDropFrame) : backDropFrame;
        args.arg9 = displayCutout.get(); // DisplayCutout is immutable.
        args.argi1 = forceLayout ? 1 : 0;
        args.argi2 = alwaysConsumeSystemBars ? 1 : 0;
        args.argi3 = displayId;
        msg.obj = args;
        mHandler.sendMessage(msg);
    }

    private void dispatchInsetsChanged(InsetsState insetsState) {
        mHandler.obtainMessage(MSG_INSETS_CHANGED, insetsState).sendToTarget();
    }

    private void dispatchInsetsControlChanged(InsetsState insetsState,
            InsetsSourceControl[] activeControls) {
        SomeArgs args = SomeArgs.obtain();
        args.arg1 = insetsState;
        args.arg2 = activeControls;
        mHandler.obtainMessage(MSG_INSETS_CONTROL_CHANGED, args).sendToTarget();
    }

    public void dispatchMoved(int newX, int newY) {
        if (DEBUG_LAYOUT) Log.v(mTag, "Window moved " + this + ": newX=" + newX + " newY=" + newY);
        if (mTranslator != null) {
            PointF point = new PointF(newX, newY);
            mTranslator.translatePointInScreenToAppWindow(point);
            newX = (int) (point.x + 0.5);
            newY = (int) (point.y + 0.5);
        }
        Message msg = mHandler.obtainMessage(MSG_WINDOW_MOVED, newX, newY);
        mHandler.sendMessage(msg);
    }

    /**
     * Represents a pending input event that is waiting in a queue.
     *
     * Input events are processed in serial order by the timestamp specified by
     * {@link InputEvent#getEventTimeNano()}.  In general, the input dispatcher delivers
     * one input event to the application at a time and waits for the application
     * to finish handling it before delivering the next one.
     *
     * However, because the application or IME can synthesize and inject multiple
     * key events at a time without going through the input dispatcher, we end up
     * needing a queue on the application's side.
     */
    private static final class QueuedInputEvent {
        public static final int FLAG_DELIVER_POST_IME = 1 << 0;
        public static final int FLAG_DEFERRED = 1 << 1;
        public static final int FLAG_FINISHED = 1 << 2;
        public static final int FLAG_FINISHED_HANDLED = 1 << 3;
        public static final int FLAG_RESYNTHESIZED = 1 << 4;
        public static final int FLAG_UNHANDLED = 1 << 5;
        public static final int FLAG_MODIFIED_FOR_COMPATIBILITY = 1 << 6;

        public QueuedInputEvent mNext;

        public InputEvent mEvent;
        public InputEventReceiver mReceiver;
        public int mFlags;

        public boolean shouldSkipIme() {
            if ((mFlags & FLAG_DELIVER_POST_IME) != 0) {
                return true;
            }
            return mEvent instanceof MotionEvent
                    && (mEvent.isFromSource(InputDevice.SOURCE_CLASS_POINTER)
                        || mEvent.isFromSource(InputDevice.SOURCE_ROTARY_ENCODER));
        }

        public boolean shouldSendToSynthesizer() {
            if ((mFlags & FLAG_UNHANDLED) != 0) {
                return true;
            }

            return false;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("QueuedInputEvent{flags=");
            boolean hasPrevious = false;
            hasPrevious = flagToString("DELIVER_POST_IME", FLAG_DELIVER_POST_IME, hasPrevious, sb);
            hasPrevious = flagToString("DEFERRED", FLAG_DEFERRED, hasPrevious, sb);
            hasPrevious = flagToString("FINISHED", FLAG_FINISHED, hasPrevious, sb);
            hasPrevious = flagToString("FINISHED_HANDLED", FLAG_FINISHED_HANDLED, hasPrevious, sb);
            hasPrevious = flagToString("RESYNTHESIZED", FLAG_RESYNTHESIZED, hasPrevious, sb);
            hasPrevious = flagToString("UNHANDLED", FLAG_UNHANDLED, hasPrevious, sb);
            if (!hasPrevious) {
                sb.append("0");
            }
            sb.append(", hasNextQueuedEvent=" + (mEvent != null ? "true" : "false"));
            sb.append(", hasInputEventReceiver=" + (mReceiver != null ? "true" : "false"));
            sb.append(", mEvent=" + mEvent + "}");
            return sb.toString();
        }

        private boolean flagToString(String name, int flag,
                boolean hasPrevious, StringBuilder sb) {
            if ((mFlags & flag) != 0) {
                if (hasPrevious) {
                    sb.append("|");
                }
                sb.append(name);
                return true;
            }
            return hasPrevious;
        }
    }

    private QueuedInputEvent obtainQueuedInputEvent(InputEvent event,
            InputEventReceiver receiver, int flags) {
        QueuedInputEvent q = mQueuedInputEventPool;
        if (q != null) {
            mQueuedInputEventPoolSize -= 1;
            mQueuedInputEventPool = q.mNext;
            q.mNext = null;
        } else {
            q = new QueuedInputEvent();
        }

        q.mEvent = event;
        q.mReceiver = receiver;
        q.mFlags = flags;
        return q;
    }

    private void recycleQueuedInputEvent(QueuedInputEvent q) {
        q.mEvent = null;
        q.mReceiver = null;

        if (mQueuedInputEventPoolSize < MAX_QUEUED_INPUT_EVENT_POOL_SIZE) {
            mQueuedInputEventPoolSize += 1;
            q.mNext = mQueuedInputEventPool;
            mQueuedInputEventPool = q;
        }
    }

    @UnsupportedAppUsage
    void enqueueInputEvent(InputEvent event) {
        enqueueInputEvent(event, null, 0, false);
    }

    @UnsupportedAppUsage
    void enqueueInputEvent(InputEvent event,
            InputEventReceiver receiver, int flags, boolean processImmediately) {
        QueuedInputEvent q = obtainQueuedInputEvent(event, receiver, flags);

        // Always enqueue the input event in order, regardless of its time stamp.
        // We do this because the application or the IME may inject key events
        // in response to touch events and we want to ensure that the injected keys
        // are processed in the order they were received and we cannot trust that
        // the time stamp of injected events are monotonic.
        QueuedInputEvent last = mPendingInputEventTail;
        if (last == null) {
            mPendingInputEventHead = q;
            mPendingInputEventTail = q;
        } else {
            last.mNext = q;
            mPendingInputEventTail = q;
        }
        mPendingInputEventCount += 1;
        Trace.traceCounter(Trace.TRACE_TAG_INPUT, mPendingInputEventQueueLengthCounterName,
                mPendingInputEventCount);

        if (processImmediately) {
            doProcessInputEvents();
        } else {
            scheduleProcessInputEvents();
        }
    }

    private void scheduleProcessInputEvents() {
        if (!mProcessInputEventsScheduled) {
            mProcessInputEventsScheduled = true;
            Message msg = mHandler.obtainMessage(MSG_PROCESS_INPUT_EVENTS);
            msg.setAsynchronous(true);
            mHandler.sendMessage(msg);
        }
    }

    void doProcessInputEvents() {
        // Deliver all pending input events in the queue.
        while (mPendingInputEventHead != null) {
            QueuedInputEvent q = mPendingInputEventHead;
            mPendingInputEventHead = q.mNext;
            if (mPendingInputEventHead == null) {
                mPendingInputEventTail = null;
            }
            q.mNext = null;

            mPendingInputEventCount -= 1;
            Trace.traceCounter(Trace.TRACE_TAG_INPUT, mPendingInputEventQueueLengthCounterName,
                    mPendingInputEventCount);

            long eventTime = q.mEvent.getEventTimeNano();
            long oldestEventTime = eventTime;
            if (q.mEvent instanceof MotionEvent) {
                MotionEvent me = (MotionEvent)q.mEvent;
                if (me.getHistorySize() > 0) {
                    oldestEventTime = me.getHistoricalEventTimeNano(0);
                }
            }
            mChoreographer.mFrameInfo.updateInputEventTime(eventTime, oldestEventTime);

            deliverInputEvent(q);
        }

        // We are done processing all input events that we can process right now
        // so we can clear the pending flag immediately.
        if (mProcessInputEventsScheduled) {
            mProcessInputEventsScheduled = false;
            mHandler.removeMessages(MSG_PROCESS_INPUT_EVENTS);
        }
    }

    private void deliverInputEvent(QueuedInputEvent q) {
        Trace.asyncTraceBegin(Trace.TRACE_TAG_VIEW, "deliverInputEvent",
                q.mEvent.getSequenceNumber());
        if (mInputEventConsistencyVerifier != null) {
            mInputEventConsistencyVerifier.onInputEvent(q.mEvent, 0);
        }

        InputStage stage;
        if (q.shouldSendToSynthesizer()) {
            stage = mSyntheticInputStage;
        } else {
            stage = q.shouldSkipIme() ? mFirstPostImeInputStage : mFirstInputStage;
        }

        if (q.mEvent instanceof KeyEvent) {
            mUnhandledKeyManager.preDispatch((KeyEvent) q.mEvent);
        }

        if (stage != null) {
            handleWindowFocusChanged();
            stage.deliver(q);
        } else {
            finishInputEvent(q);
        }
    }

    private void finishInputEvent(QueuedInputEvent q) {
        Trace.asyncTraceEnd(Trace.TRACE_TAG_VIEW, "deliverInputEvent",
                q.mEvent.getSequenceNumber());

        if (q.mReceiver != null) {
            boolean handled = (q.mFlags & QueuedInputEvent.FLAG_FINISHED_HANDLED) != 0;
            boolean modified = (q.mFlags & QueuedInputEvent.FLAG_MODIFIED_FOR_COMPATIBILITY) != 0;
            if (modified) {
                Trace.traceBegin(Trace.TRACE_TAG_VIEW, "processInputEventBeforeFinish");
                InputEvent processedEvent;
                try {
                    processedEvent =
                            mInputCompatProcessor.processInputEventBeforeFinish(q.mEvent);
                } finally {
                    Trace.traceEnd(Trace.TRACE_TAG_VIEW);
                }
                if (processedEvent != null) {
                    q.mReceiver.finishInputEvent(processedEvent, handled);
                }
            } else {
                q.mReceiver.finishInputEvent(q.mEvent, handled);
            }
        } else {
            q.mEvent.recycleIfNeededAfterDispatch();
        }

        recycleQueuedInputEvent(q);
    }

    static boolean isTerminalInputEvent(InputEvent event) {
        if (event instanceof KeyEvent) {
            final KeyEvent keyEvent = (KeyEvent)event;
            return keyEvent.getAction() == KeyEvent.ACTION_UP;
        } else {
            final MotionEvent motionEvent = (MotionEvent)event;
            final int action = motionEvent.getAction();
            return action == MotionEvent.ACTION_UP
                    || action == MotionEvent.ACTION_CANCEL
                    || action == MotionEvent.ACTION_HOVER_EXIT;
        }
    }

    void scheduleConsumeBatchedInput() {
        if (!mConsumeBatchedInputScheduled) {
            mConsumeBatchedInputScheduled = true;
            mChoreographer.postCallback(Choreographer.CALLBACK_INPUT,
                    mConsumedBatchedInputRunnable, null);
        }
    }

    void unscheduleConsumeBatchedInput() {
        if (mConsumeBatchedInputScheduled) {
            mConsumeBatchedInputScheduled = false;
            mChoreographer.removeCallbacks(Choreographer.CALLBACK_INPUT,
                    mConsumedBatchedInputRunnable, null);
        }
    }

    void scheduleConsumeBatchedInputImmediately() {
        if (!mConsumeBatchedInputImmediatelyScheduled) {
            unscheduleConsumeBatchedInput();
            mConsumeBatchedInputImmediatelyScheduled = true;
            mHandler.post(mConsumeBatchedInputImmediatelyRunnable);
        }
    }

    void doConsumeBatchedInput(long frameTimeNanos) {
        if (mConsumeBatchedInputScheduled) {
            mConsumeBatchedInputScheduled = false;
            if (mInputEventReceiver != null) {
                if (mInputEventReceiver.consumeBatchedInputEvents(frameTimeNanos)
                        && frameTimeNanos != -1) {
                    // If we consumed a batch here, we want to go ahead and schedule the
                    // consumption of batched input events on the next frame. Otherwise, we would
                    // wait until we have more input events pending and might get starved by other
                    // things occurring in the process. If the frame time is -1, however, then
                    // we're in a non-batching mode, so there's no need to schedule this.
                    scheduleConsumeBatchedInput();
                }
            }
            doProcessInputEvents();
        }
    }

    final class TraversalRunnable implements Runnable {
        @Override
        public void run() {
            doTraversal();
        }
    }
    final TraversalRunnable mTraversalRunnable = new TraversalRunnable();

    final class WindowInputEventReceiver extends InputEventReceiver {
        public WindowInputEventReceiver(InputChannel inputChannel, Looper looper) {
            super(inputChannel, looper);
        }

        @Override
        public void onInputEvent(InputEvent event) {
            Trace.traceBegin(Trace.TRACE_TAG_VIEW, "processInputEventForCompatibility");
            List<InputEvent> processedEvents;
            try {
                processedEvents =
                    mInputCompatProcessor.processInputEventForCompatibility(event);
            } finally {
                Trace.traceEnd(Trace.TRACE_TAG_VIEW);
            }
            if (processedEvents != null) {
                if (processedEvents.isEmpty()) {
                    // InputEvent consumed by mInputCompatProcessor
                    finishInputEvent(event, true);
                } else {
                    for (int i = 0; i < processedEvents.size(); i++) {
                        enqueueInputEvent(
                                processedEvents.get(i), this,
                                QueuedInputEvent.FLAG_MODIFIED_FOR_COMPATIBILITY, true);
                    }
                }
            } else {
                enqueueInputEvent(event, this, 0, true);
            }
        }

        @Override
        public void onBatchedInputEventPending() {
            if (mUnbufferedInputDispatch) {
                super.onBatchedInputEventPending();
            } else {
                scheduleConsumeBatchedInput();
            }
        }

        @Override
        public void dispose() {
            unscheduleConsumeBatchedInput();
            super.dispose();
        }
    }
    WindowInputEventReceiver mInputEventReceiver;

    final class ConsumeBatchedInputRunnable implements Runnable {
        @Override
        public void run() {
            doConsumeBatchedInput(mChoreographer.getFrameTimeNanos());
        }
    }
    final ConsumeBatchedInputRunnable mConsumedBatchedInputRunnable =
            new ConsumeBatchedInputRunnable();
    boolean mConsumeBatchedInputScheduled;

    final class ConsumeBatchedInputImmediatelyRunnable implements Runnable {
        @Override
        public void run() {
            doConsumeBatchedInput(-1);
        }
    }
    final ConsumeBatchedInputImmediatelyRunnable mConsumeBatchedInputImmediatelyRunnable =
            new ConsumeBatchedInputImmediatelyRunnable();
    boolean mConsumeBatchedInputImmediatelyScheduled;

    final class InvalidateOnAnimationRunnable implements Runnable {
        private boolean mPosted;
        private final ArrayList<View> mViews = new ArrayList<View>();
        private final ArrayList<AttachInfo.InvalidateInfo> mViewRects =
                new ArrayList<AttachInfo.InvalidateInfo>();
        private View[] mTempViews;
        private AttachInfo.InvalidateInfo[] mTempViewRects;

        public void addView(View view) {
            synchronized (this) {
                mViews.add(view);
                postIfNeededLocked();
            }
        }

        public void addViewRect(AttachInfo.InvalidateInfo info) {
            synchronized (this) {
                mViewRects.add(info);
                postIfNeededLocked();
            }
        }

        public void removeView(View view) {
            synchronized (this) {
                mViews.remove(view);

                for (int i = mViewRects.size(); i-- > 0; ) {
                    AttachInfo.InvalidateInfo info = mViewRects.get(i);
                    if (info.target == view) {
                        mViewRects.remove(i);
                        info.recycle();
                    }
                }

                if (mPosted && mViews.isEmpty() && mViewRects.isEmpty()) {
                    mChoreographer.removeCallbacks(Choreographer.CALLBACK_ANIMATION, this, null);
                    mPosted = false;
                }
            }
        }

        @Override
        public void run() {
            final int viewCount;
            final int viewRectCount;
            synchronized (this) {
                mPosted = false;

                viewCount = mViews.size();
                if (viewCount != 0) {
                    mTempViews = mViews.toArray(mTempViews != null
                            ? mTempViews : new View[viewCount]);
                    mViews.clear();
                }

                viewRectCount = mViewRects.size();
                if (viewRectCount != 0) {
                    mTempViewRects = mViewRects.toArray(mTempViewRects != null
                            ? mTempViewRects : new AttachInfo.InvalidateInfo[viewRectCount]);
                    mViewRects.clear();
                }
            }

            for (int i = 0; i < viewCount; i++) {
                mTempViews[i].invalidate();
                mTempViews[i] = null;
            }

            for (int i = 0; i < viewRectCount; i++) {
                final View.AttachInfo.InvalidateInfo info = mTempViewRects[i];
                info.target.invalidate(info.left, info.top, info.right, info.bottom);
                info.recycle();
            }
        }

        private void postIfNeededLocked() {
            if (!mPosted) {
                mChoreographer.postCallback(Choreographer.CALLBACK_ANIMATION, this, null);
                mPosted = true;
            }
        }
    }
    final InvalidateOnAnimationRunnable mInvalidateOnAnimationRunnable =
            new InvalidateOnAnimationRunnable();

    public void dispatchInvalidateDelayed(View view, long delayMilliseconds) {
        Message msg = mHandler.obtainMessage(MSG_INVALIDATE, view);
        mHandler.sendMessageDelayed(msg, delayMilliseconds);
    }

    public void dispatchInvalidateRectDelayed(AttachInfo.InvalidateInfo info,
            long delayMilliseconds) {
        final Message msg = mHandler.obtainMessage(MSG_INVALIDATE_RECT, info);
        mHandler.sendMessageDelayed(msg, delayMilliseconds);
    }

    public void dispatchInvalidateOnAnimation(View view) {
        mInvalidateOnAnimationRunnable.addView(view);
    }

    public void dispatchInvalidateRectOnAnimation(AttachInfo.InvalidateInfo info) {
        mInvalidateOnAnimationRunnable.addViewRect(info);
    }

    @UnsupportedAppUsage
    public void cancelInvalidate(View view) {
        mHandler.removeMessages(MSG_INVALIDATE, view);
        // fixme: might leak the AttachInfo.InvalidateInfo objects instead of returning
        // them to the pool
        mHandler.removeMessages(MSG_INVALIDATE_RECT, view);
        mInvalidateOnAnimationRunnable.removeView(view);
    }

    @UnsupportedAppUsage
    public void dispatchInputEvent(InputEvent event) {
        dispatchInputEvent(event, null);
    }

    @UnsupportedAppUsage
    public void dispatchInputEvent(InputEvent event, InputEventReceiver receiver) {
        SomeArgs args = SomeArgs.obtain();
        args.arg1 = event;
        args.arg2 = receiver;
        Message msg = mHandler.obtainMessage(MSG_DISPATCH_INPUT_EVENT, args);
        msg.setAsynchronous(true);
        mHandler.sendMessage(msg);
    }

    public void synthesizeInputEvent(InputEvent event) {
        Message msg = mHandler.obtainMessage(MSG_SYNTHESIZE_INPUT_EVENT, event);
        msg.setAsynchronous(true);
        mHandler.sendMessage(msg);
    }

    @UnsupportedAppUsage
    public void dispatchKeyFromIme(KeyEvent event) {
        Message msg = mHandler.obtainMessage(MSG_DISPATCH_KEY_FROM_IME, event);
        msg.setAsynchronous(true);
        mHandler.sendMessage(msg);
    }

    public void dispatchKeyFromAutofill(KeyEvent event) {
        Message msg = mHandler.obtainMessage(MSG_DISPATCH_KEY_FROM_AUTOFILL, event);
        msg.setAsynchronous(true);
        mHandler.sendMessage(msg);
    }

    /**
     * Reinject unhandled {@link InputEvent}s in order to synthesize fallbacks events.
     *
     * Note that it is the responsibility of the caller of this API to recycle the InputEvent it
     * passes in.
     */
    @UnsupportedAppUsage
    public void dispatchUnhandledInputEvent(InputEvent event) {
        if (event instanceof MotionEvent) {
            event = MotionEvent.obtain((MotionEvent) event);
        }
        synthesizeInputEvent(event);
    }

    public void dispatchAppVisibility(boolean visible) {
        Message msg = mHandler.obtainMessage(MSG_DISPATCH_APP_VISIBILITY);
        msg.arg1 = visible ? 1 : 0;
        mHandler.sendMessage(msg);
    }

    public void dispatchGetNewSurface() {
        Message msg = mHandler.obtainMessage(MSG_DISPATCH_GET_NEW_SURFACE);
        mHandler.sendMessage(msg);
    }

    /**
     * Dispatch the offset changed.
     *
     * @param offset the offset of this view in the parent window.
     */
    public void dispatchLocationInParentDisplayChanged(Point offset) {
        Message msg =
                mHandler.obtainMessage(MSG_LOCATION_IN_PARENT_DISPLAY_CHANGED, offset.x, offset.y);
        mHandler.sendMessage(msg);
    }

    public void windowFocusChanged(boolean hasFocus, boolean inTouchMode) {
        synchronized (this) {
            mWindowFocusChanged = true;
            mUpcomingWindowFocus = hasFocus;
            mUpcomingInTouchMode = inTouchMode;
        }
        Message msg = Message.obtain();
        msg.what = MSG_WINDOW_FOCUS_CHANGED;
        mHandler.sendMessage(msg);
    }

    public void dispatchWindowShown() {
        mHandler.sendEmptyMessage(MSG_DISPATCH_WINDOW_SHOWN);
    }

    public void dispatchCloseSystemDialogs(String reason) {
        Message msg = Message.obtain();
        msg.what = MSG_CLOSE_SYSTEM_DIALOGS;
        msg.obj = reason;
        mHandler.sendMessage(msg);
    }

    public void dispatchDragEvent(DragEvent event) {
        final int what;
        if (event.getAction() == DragEvent.ACTION_DRAG_LOCATION) {
            what = MSG_DISPATCH_DRAG_LOCATION_EVENT;
            mHandler.removeMessages(what);
        } else {
            what = MSG_DISPATCH_DRAG_EVENT;
        }
        Message msg = mHandler.obtainMessage(what, event);
        mHandler.sendMessage(msg);
    }

    public void updatePointerIcon(float x, float y) {
        final int what = MSG_UPDATE_POINTER_ICON;
        mHandler.removeMessages(what);
        final long now = SystemClock.uptimeMillis();
        final MotionEvent event = MotionEvent.obtain(
                0, now, MotionEvent.ACTION_HOVER_MOVE, x, y, 0);
        Message msg = mHandler.obtainMessage(what, event);
        mHandler.sendMessage(msg);
    }

    public void dispatchSystemUiVisibilityChanged(int seq, int globalVisibility,
            int localValue, int localChanges) {
        SystemUiVisibilityInfo args = new SystemUiVisibilityInfo();
        args.seq = seq;
        args.globalVisibility = globalVisibility;
        args.localValue = localValue;
        args.localChanges = localChanges;
        mHandler.sendMessage(mHandler.obtainMessage(MSG_DISPATCH_SYSTEM_UI_VISIBILITY, args));
    }

    public void dispatchCheckFocus() {
        if (!mHandler.hasMessages(MSG_CHECK_FOCUS)) {
            // This will result in a call to checkFocus() below.
            mHandler.sendEmptyMessage(MSG_CHECK_FOCUS);
        }
    }

    public void dispatchRequestKeyboardShortcuts(IResultReceiver receiver, int deviceId) {
        mHandler.obtainMessage(
                MSG_REQUEST_KEYBOARD_SHORTCUTS, deviceId, 0, receiver).sendToTarget();
    }

    public void dispatchPointerCaptureChanged(boolean on) {
        final int what = MSG_POINTER_CAPTURE_CHANGED;
        mHandler.removeMessages(what);
        Message msg = mHandler.obtainMessage(what);
        msg.arg1 = on ? 1 : 0;
        mHandler.sendMessage(msg);
    }

    /**
     * Post a callback to send a
     * {@link AccessibilityEvent#TYPE_WINDOW_CONTENT_CHANGED} event.
     * This event is send at most once every
     * {@link ViewConfiguration#getSendRecurringAccessibilityEventsInterval()}.
     */
    private void postSendWindowContentChangedCallback(View source, int changeType) {
        if (mSendWindowContentChangedAccessibilityEvent == null) {
            mSendWindowContentChangedAccessibilityEvent =
                new SendWindowContentChangedAccessibilityEvent();
        }
        mSendWindowContentChangedAccessibilityEvent.runOrPost(source, changeType);
    }

    /**
     * Remove a posted callback to send a
     * {@link AccessibilityEvent#TYPE_WINDOW_CONTENT_CHANGED} event.
     */
    private void removeSendWindowContentChangedCallback() {
        if (mSendWindowContentChangedAccessibilityEvent != null) {
            mHandler.removeCallbacks(mSendWindowContentChangedAccessibilityEvent);
        }
    }

    @Override
    public boolean showContextMenuForChild(View originalView) {
        return false;
    }

    @Override
    public boolean showContextMenuForChild(View originalView, float x, float y) {
        return false;
    }

    @Override
    public ActionMode startActionModeForChild(View originalView, ActionMode.Callback callback) {
        return null;
    }

    @Override
    public ActionMode startActionModeForChild(
            View originalView, ActionMode.Callback callback, int type) {
        return null;
    }

    @Override
    public void createContextMenu(ContextMenu menu) {
    }

    @Override
    public void childDrawableStateChanged(View child) {
    }

    @Override
    public boolean requestSendAccessibilityEvent(View child, AccessibilityEvent event) {
        if (mView == null || mStopped || mPausedForTransition) {
            return false;
        }

        // Immediately flush pending content changed event (if any) to preserve event order
        if (event.getEventType() != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
                && mSendWindowContentChangedAccessibilityEvent != null
                && mSendWindowContentChangedAccessibilityEvent.mSource != null) {
            mSendWindowContentChangedAccessibilityEvent.removeCallbacksAndRun();
        }

        // Intercept accessibility focus events fired by virtual nodes to keep
        // track of accessibility focus position in such nodes.
        final int eventType = event.getEventType();
        final View source = getSourceForAccessibilityEvent(event);
        switch (eventType) {
            case AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED: {
                if (source != null) {
                    AccessibilityNodeProvider provider = source.getAccessibilityNodeProvider();
                    if (provider != null) {
                        final int virtualNodeId = AccessibilityNodeInfo.getVirtualDescendantId(
                                event.getSourceNodeId());
                        final AccessibilityNodeInfo node;
                        node = provider.createAccessibilityNodeInfo(virtualNodeId);
                        setAccessibilityFocus(source, node);
                    }
                }
            } break;
            case AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUS_CLEARED: {
                if (source != null && source.getAccessibilityNodeProvider() != null) {
                    setAccessibilityFocus(null, null);
                }
            } break;


            case AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED: {
                handleWindowContentChangedEvent(event);
            } break;
        }
        mAccessibilityManager.sendAccessibilityEvent(event);
        return true;
    }

    private View getSourceForAccessibilityEvent(AccessibilityEvent event) {
        final long sourceNodeId = event.getSourceNodeId();
        final int accessibilityViewId = AccessibilityNodeInfo.getAccessibilityViewId(
                sourceNodeId);
        return AccessibilityNodeIdManager.getInstance().findView(accessibilityViewId);
    }

    /**
     * Updates the focused virtual view, when necessary, in response to a
     * content changed event.
     * <p>
     * This is necessary to get updated bounds after a position change.
     *
     * @param event an accessibility event of type
     *              {@link AccessibilityEvent#TYPE_WINDOW_CONTENT_CHANGED}
     */
    private void handleWindowContentChangedEvent(AccessibilityEvent event) {
        final View focusedHost = mAccessibilityFocusedHost;
        if (focusedHost == null || mAccessibilityFocusedVirtualView == null) {
            // No virtual view focused, nothing to do here.
            return;
        }

        final AccessibilityNodeProvider provider = focusedHost.getAccessibilityNodeProvider();
        if (provider == null) {
            // Error state: virtual view with no provider. Clear focus.
            mAccessibilityFocusedHost = null;
            mAccessibilityFocusedVirtualView = null;
            focusedHost.clearAccessibilityFocusNoCallbacks(0);
            return;
        }

        // We only care about change types that may affect the bounds of the
        // focused virtual view.
        final int changes = event.getContentChangeTypes();
        if ((changes & AccessibilityEvent.CONTENT_CHANGE_TYPE_SUBTREE) == 0
                && changes != AccessibilityEvent.CONTENT_CHANGE_TYPE_UNDEFINED) {
            return;
        }

        final long eventSourceNodeId = event.getSourceNodeId();
        final int changedViewId = AccessibilityNodeInfo.getAccessibilityViewId(eventSourceNodeId);

        // Search up the tree for subtree containment.
        boolean hostInSubtree = false;
        View root = mAccessibilityFocusedHost;
        while (root != null && !hostInSubtree) {
            if (changedViewId == root.getAccessibilityViewId()) {
                hostInSubtree = true;
            } else {
                final ViewParent parent = root.getParent();
                if (parent instanceof View) {
                    root = (View) parent;
                } else {
                    root = null;
                }
            }
        }

        // We care only about changes in subtrees containing the host view.
        if (!hostInSubtree) {
            return;
        }

        final long focusedSourceNodeId = mAccessibilityFocusedVirtualView.getSourceNodeId();
        int focusedChildId = AccessibilityNodeInfo.getVirtualDescendantId(focusedSourceNodeId);

        // Refresh the node for the focused virtual view.
        final Rect oldBounds = mTempRect;
        mAccessibilityFocusedVirtualView.getBoundsInScreen(oldBounds);
        mAccessibilityFocusedVirtualView = provider.createAccessibilityNodeInfo(focusedChildId);
        if (mAccessibilityFocusedVirtualView == null) {
            // Error state: The node no longer exists. Clear focus.
            mAccessibilityFocusedHost = null;
            focusedHost.clearAccessibilityFocusNoCallbacks(0);

            // This will probably fail, but try to keep the provider's internal
            // state consistent by clearing focus.
            provider.performAction(focusedChildId,
                    AccessibilityAction.ACTION_CLEAR_ACCESSIBILITY_FOCUS.getId(), null);
            invalidateRectOnScreen(oldBounds);
        } else {
            // The node was refreshed, invalidate bounds if necessary.
            final Rect newBounds = mAccessibilityFocusedVirtualView.getBoundsInScreen();
            if (!oldBounds.equals(newBounds)) {
                oldBounds.union(newBounds);
                invalidateRectOnScreen(oldBounds);
            }
        }
    }

    @Override
    public void notifySubtreeAccessibilityStateChanged(View child, View source, int changeType) {
        postSendWindowContentChangedCallback(Preconditions.checkNotNull(source), changeType);
    }

    @Override
    public boolean canResolveLayoutDirection() {
        return true;
    }

    @Override
    public boolean isLayoutDirectionResolved() {
        return true;
    }

    @Override
    public int getLayoutDirection() {
        return View.LAYOUT_DIRECTION_RESOLVED_DEFAULT;
    }

    @Override
    public boolean canResolveTextDirection() {
        return true;
    }

    @Override
    public boolean isTextDirectionResolved() {
        return true;
    }

    @Override
    public int getTextDirection() {
        return View.TEXT_DIRECTION_RESOLVED_DEFAULT;
    }

    @Override
    public boolean canResolveTextAlignment() {
        return true;
    }

    @Override
    public boolean isTextAlignmentResolved() {
        return true;
    }

    @Override
    public int getTextAlignment() {
        return View.TEXT_ALIGNMENT_RESOLVED_DEFAULT;
    }

    private View getCommonPredecessor(View first, View second) {
        if (mTempHashSet == null) {
            mTempHashSet = new HashSet<View>();
        }
        HashSet<View> seen = mTempHashSet;
        seen.clear();
        View firstCurrent = first;
        while (firstCurrent != null) {
            seen.add(firstCurrent);
            ViewParent firstCurrentParent = firstCurrent.mParent;
            if (firstCurrentParent instanceof View) {
                firstCurrent = (View) firstCurrentParent;
            } else {
                firstCurrent = null;
            }
        }
        View secondCurrent = second;
        while (secondCurrent != null) {
            if (seen.contains(secondCurrent)) {
                seen.clear();
                return secondCurrent;
            }
            ViewParent secondCurrentParent = secondCurrent.mParent;
            if (secondCurrentParent instanceof View) {
                secondCurrent = (View) secondCurrentParent;
            } else {
                secondCurrent = null;
            }
        }
        seen.clear();
        return null;
    }

    void checkThread() {
        if (mThread != Thread.currentThread()) {
            throw new CalledFromWrongThreadException(
                    "Only the original thread that created a view hierarchy can touch its views.");
        }
    }

    @Override
    public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
        // ViewAncestor never intercepts touch event, so this can be a no-op
    }

    @Override
    public boolean requestChildRectangleOnScreen(View child, Rect rectangle, boolean immediate) {
        if (rectangle == null) {
            return scrollToRectOrFocus(null, immediate);
        }
        rectangle.offset(child.getLeft() - child.getScrollX(),
                child.getTop() - child.getScrollY());
        final boolean scrolled = scrollToRectOrFocus(rectangle, immediate);
        mTempRect.set(rectangle);
        mTempRect.offset(0, -mCurScrollY);
        mTempRect.offset(mAttachInfo.mWindowLeft, mAttachInfo.mWindowTop);
        try {
            mWindowSession.onRectangleOnScreenRequested(mWindow, mTempRect);
        } catch (RemoteException re) {
            /* ignore */
        }
        return scrolled;
    }

    @Override
    public void childHasTransientStateChanged(View child, boolean hasTransientState) {
        // Do nothing.
    }

    @Override
    public boolean onStartNestedScroll(View child, View target, int nestedScrollAxes) {
        return false;
    }

    @Override
    public void onStopNestedScroll(View target) {
    }

    @Override
    public void onNestedScrollAccepted(View child, View target, int nestedScrollAxes) {
    }

    @Override
    public void onNestedScroll(View target, int dxConsumed, int dyConsumed,
            int dxUnconsumed, int dyUnconsumed) {
    }

    @Override
    public void onNestedPreScroll(View target, int dx, int dy, int[] consumed) {
    }

    @Override
    public boolean onNestedFling(View target, float velocityX, float velocityY, boolean consumed) {
        return false;
    }

    @Override
    public boolean onNestedPreFling(View target, float velocityX, float velocityY) {
        return false;
    }

    @Override
    public boolean onNestedPrePerformAccessibilityAction(View target, int action, Bundle args) {
        return false;
    }


    private void reportNextDraw() {
        if (mReportNextDraw == false) {
            drawPending();
        }
        mReportNextDraw = true;
    }

    /**
     * Force the window to report its next draw.
     * <p>
     * This method is only supposed to be used to speed up the interaction from SystemUI and window
     * manager when waiting for the first frame to be drawn when turning on the screen. DO NOT USE
     * unless you fully understand this interaction.
     * @hide
     */
    public void setReportNextDraw() {
        reportNextDraw();
        invalidate();
    }

    void changeCanvasOpacity(boolean opaque) {
        Log.d(mTag, "changeCanvasOpacity: opaque=" + opaque);
        opaque = opaque & ((mView.mPrivateFlags & View.PFLAG_REQUEST_TRANSPARENT_REGIONS) == 0);
        if (mAttachInfo.mThreadedRenderer != null) {
            mAttachInfo.mThreadedRenderer.setOpaque(opaque);
        }
    }

    /**
     * Dispatches a KeyEvent to all registered key fallback handlers.
     *
     * @param event
     * @return {@code true} if the event was handled, {@code false} otherwise.
     */
    public boolean dispatchUnhandledKeyEvent(KeyEvent event) {
        return mUnhandledKeyManager.dispatch(mView, event);
    }

    class TakenSurfaceHolder extends BaseSurfaceHolder {
        @Override
        public boolean onAllowLockCanvas() {
            return mDrawingAllowed;
        }

        @Override
        public void onRelayoutContainer() {
            // Not currently interesting -- from changing between fixed and layout size.
        }

        @Override
        public void setFormat(int format) {
            ((RootViewSurfaceTaker)mView).setSurfaceFormat(format);
        }

        @Override
        public void setType(int type) {
            ((RootViewSurfaceTaker)mView).setSurfaceType(type);
        }

        @Override
        public void onUpdateSurface() {
            // We take care of format and type changes on our own.
            throw new IllegalStateException("Shouldn't be here");
        }

        @Override
        public boolean isCreating() {
            return mIsCreating;
        }

        @Override
        public void setFixedSize(int width, int height) {
            throw new UnsupportedOperationException(
                    "Currently only support sizing from layout");
        }

        @Override
        public void setKeepScreenOn(boolean screenOn) {
            ((RootViewSurfaceTaker)mView).setSurfaceKeepScreenOn(screenOn);
        }
    }

    static class W extends IWindow.Stub {
        private final WeakReference<ViewRootImpl> mViewAncestor;
        private final IWindowSession mWindowSession;

        W(ViewRootImpl viewAncestor) {
            mViewAncestor = new WeakReference<ViewRootImpl>(viewAncestor);
            mWindowSession = viewAncestor.mWindowSession;
        }

        @Override
        public void resized(Rect frame, Rect overscanInsets, Rect contentInsets,
                Rect visibleInsets, Rect stableInsets, Rect outsets, boolean reportDraw,
                MergedConfiguration mergedConfiguration, Rect backDropFrame, boolean forceLayout,
                boolean alwaysConsumeSystemBars, int displayId,
                DisplayCutout.ParcelableWrapper displayCutout) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchResized(frame, overscanInsets, contentInsets,
                        visibleInsets, stableInsets, outsets, reportDraw, mergedConfiguration,
                        backDropFrame, forceLayout, alwaysConsumeSystemBars, displayId,
                        displayCutout);
            }
        }

        @Override
        public void locationInParentDisplayChanged(Point offset) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchLocationInParentDisplayChanged(offset);
            }
        }

        @Override
        public void insetsChanged(InsetsState insetsState) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchInsetsChanged(insetsState);
            }
        }

        @Override
        public void insetsControlChanged(InsetsState insetsState,
                InsetsSourceControl[] activeControls) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchInsetsControlChanged(insetsState, activeControls);
            }
        }

        @Override
        public void moved(int newX, int newY) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchMoved(newX, newY);
            }
        }

        @Override
        public void dispatchAppVisibility(boolean visible) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchAppVisibility(visible);
            }
        }

        @Override
        public void dispatchGetNewSurface() {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchGetNewSurface();
            }
        }

        @Override
        public void windowFocusChanged(boolean hasFocus, boolean inTouchMode) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.windowFocusChanged(hasFocus, inTouchMode);
            }
        }

        private static int checkCallingPermission(String permission) {
            try {
                return ActivityManager.getService().checkPermission(
                        permission, Binder.getCallingPid(), Binder.getCallingUid());
            } catch (RemoteException e) {
                return PackageManager.PERMISSION_DENIED;
            }
        }

        @Override
        public void executeCommand(String command, String parameters, ParcelFileDescriptor out) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                final View view = viewAncestor.mView;
                if (view != null) {
                    if (checkCallingPermission(Manifest.permission.DUMP) !=
                            PackageManager.PERMISSION_GRANTED) {
                        throw new SecurityException("Insufficient permissions to invoke"
                                + " executeCommand() from pid=" + Binder.getCallingPid()
                                + ", uid=" + Binder.getCallingUid());
                    }

                    OutputStream clientStream = null;
                    try {
                        clientStream = new ParcelFileDescriptor.AutoCloseOutputStream(out);
                        ViewDebug.dispatchCommand(view, command, parameters, clientStream);
                    } catch (IOException e) {
                        e.printStackTrace();
                    } finally {
                        if (clientStream != null) {
                            try {
                                clientStream.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
        }

        @Override
        public void closeSystemDialogs(String reason) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchCloseSystemDialogs(reason);
            }
        }

        @Override
        public void dispatchWallpaperOffsets(float x, float y, float xStep, float yStep,
                boolean sync) {
            if (sync) {
                try {
                    mWindowSession.wallpaperOffsetsComplete(asBinder());
                } catch (RemoteException e) {
                }
            }
        }

        @Override
        public void dispatchWallpaperCommand(String action, int x, int y,
                int z, Bundle extras, boolean sync) {
            if (sync) {
                try {
                    mWindowSession.wallpaperCommandComplete(asBinder(), null);
                } catch (RemoteException e) {
                }
            }
        }

        /* Drag/drop */
        @Override
        public void dispatchDragEvent(DragEvent event) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchDragEvent(event);
            }
        }

        @Override
        public void updatePointerIcon(float x, float y) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.updatePointerIcon(x, y);
            }
        }

        @Override
        public void dispatchSystemUiVisibilityChanged(int seq, int globalVisibility,
                int localValue, int localChanges) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchSystemUiVisibilityChanged(seq, globalVisibility,
                        localValue, localChanges);
            }
        }

        @Override
        public void dispatchWindowShown() {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchWindowShown();
            }
        }

        @Override
        public void requestAppKeyboardShortcuts(IResultReceiver receiver, int deviceId) {
            ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchRequestKeyboardShortcuts(receiver, deviceId);
            }
        }

        @Override
        public void dispatchPointerCaptureChanged(boolean hasCapture) {
            final ViewRootImpl viewAncestor = mViewAncestor.get();
            if (viewAncestor != null) {
                viewAncestor.dispatchPointerCaptureChanged(hasCapture);
            }
        }

    }

    public static final class CalledFromWrongThreadException extends AndroidRuntimeException {
        @UnsupportedAppUsage
        public CalledFromWrongThreadException(String msg) {
            super(msg);
        }
    }

    static HandlerActionQueue getRunQueue() {
        HandlerActionQueue rq = sRunQueues.get();
        if (rq != null) {
            return rq;
        }
        rq = new HandlerActionQueue();
        sRunQueues.set(rq);
        return rq;
    }

    /**
     * Start a drag resizing which will inform all listeners that a window resize is taking place.
     */
    private void startDragResizing(Rect initialBounds, boolean fullscreen, Rect systemInsets,
            Rect stableInsets, int resizeMode) {
        if (!mDragResizing) {
            mDragResizing = true;
            if (mUseMTRenderer) {
                for (int i = mWindowCallbacks.size() - 1; i >= 0; i--) {
                    mWindowCallbacks.get(i).onWindowDragResizeStart(
                            initialBounds, fullscreen, systemInsets, stableInsets, resizeMode);
                }
            }
            mFullRedrawNeeded = true;
        }
    }

    /**
     * End a drag resize which will inform all listeners that a window resize has ended.
     */
    private void endDragResizing() {
        if (mDragResizing) {
            mDragResizing = false;
            if (mUseMTRenderer) {
                for (int i = mWindowCallbacks.size() - 1; i >= 0; i--) {
                    mWindowCallbacks.get(i).onWindowDragResizeEnd();
                }
            }
            mFullRedrawNeeded = true;
        }
    }

    private boolean updateContentDrawBounds() {
        boolean updated = false;
        if (mUseMTRenderer) {
            for (int i = mWindowCallbacks.size() - 1; i >= 0; i--) {
                updated |=
                        mWindowCallbacks.get(i).onContentDrawn(mWindowAttributes.surfaceInsets.left,
                                mWindowAttributes.surfaceInsets.top, mWidth, mHeight);
            }
        }
        return updated | (mDragResizing && mReportNextDraw);
    }

    private void requestDrawWindow() {
        if (!mUseMTRenderer) {
            return;
        }
        mWindowDrawCountDown = new CountDownLatch(mWindowCallbacks.size());
        for (int i = mWindowCallbacks.size() - 1; i >= 0; i--) {
            mWindowCallbacks.get(i).onRequestDraw(mReportNextDraw);
        }
    }

    /**
     * Tells this instance that its corresponding activity has just relaunched. In this case, we
     * need to force a relayout of the window to make sure we get the correct bounds from window
     * manager.
     */
    public void reportActivityRelaunched() {
        mActivityRelaunched = true;
    }

    public SurfaceControl getSurfaceControl() {
        return mSurfaceControl;
    }

    /**
     * Class for managing the accessibility interaction connection
     * based on the global accessibility state.
     */
    final class AccessibilityInteractionConnectionManager
            implements AccessibilityStateChangeListener {
        @Override
        public void onAccessibilityStateChanged(boolean enabled) {
            if (enabled) {
                ensureConnection();
                if (mAttachInfo.mHasWindowFocus && (mView != null)) {
                    mView.sendAccessibilityEvent(AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED);
                    View focusedView = mView.findFocus();
                    if (focusedView != null && focusedView != mView) {
                        focusedView.sendAccessibilityEvent(AccessibilityEvent.TYPE_VIEW_FOCUSED);
                    }
                }
            } else {
                ensureNoConnection();
                mHandler.obtainMessage(MSG_CLEAR_ACCESSIBILITY_FOCUS_HOST).sendToTarget();
            }
        }

        public void ensureConnection() {
            final boolean registered = mAttachInfo.mAccessibilityWindowId
                    != AccessibilityWindowInfo.UNDEFINED_WINDOW_ID;
            if (!registered) {
                mAttachInfo.mAccessibilityWindowId =
                        mAccessibilityManager.addAccessibilityInteractionConnection(mWindow,
                                mContext.getPackageName(),
                                new AccessibilityInteractionConnection(ViewRootImpl.this));
            }
        }

        public void ensureNoConnection() {
            final boolean registered = mAttachInfo.mAccessibilityWindowId
                    != AccessibilityWindowInfo.UNDEFINED_WINDOW_ID;
            if (registered) {
                mAttachInfo.mAccessibilityWindowId = AccessibilityWindowInfo.UNDEFINED_WINDOW_ID;
                mAccessibilityManager.removeAccessibilityInteractionConnection(mWindow);
            }
        }
    }

    final class HighContrastTextManager implements HighTextContrastChangeListener {
        HighContrastTextManager() {
            ThreadedRenderer.setHighContrastText(mAccessibilityManager.isHighTextContrastEnabled());
        }
        @Override
        public void onHighTextContrastStateChanged(boolean enabled) {
            ThreadedRenderer.setHighContrastText(enabled);

            // Destroy Displaylists so they can be recreated with high contrast recordings
            destroyHardwareResources();

            // Schedule redraw, which will rerecord + redraw all text
            invalidate();
        }
    }

    /**
     * This class is an interface this ViewAncestor provides to the
     * AccessibilityManagerService to the latter can interact with
     * the view hierarchy in this ViewAncestor.
     */
    static final class AccessibilityInteractionConnection
            extends IAccessibilityInteractionConnection.Stub {
        private final WeakReference<ViewRootImpl> mViewRootImpl;

        AccessibilityInteractionConnection(ViewRootImpl viewRootImpl) {
            mViewRootImpl = new WeakReference<ViewRootImpl>(viewRootImpl);
        }

        @Override
        public void findAccessibilityNodeInfoByAccessibilityId(long accessibilityNodeId,
                Region interactiveRegion, int interactionId,
                IAccessibilityInteractionConnectionCallback callback, int flags,
                int interrogatingPid, long interrogatingTid, MagnificationSpec spec, Bundle args) {
            ViewRootImpl viewRootImpl = mViewRootImpl.get();
            if (viewRootImpl != null && viewRootImpl.mView != null) {
                viewRootImpl.getAccessibilityInteractionController()
                    .findAccessibilityNodeInfoByAccessibilityIdClientThread(accessibilityNodeId,
                            interactiveRegion, interactionId, callback, flags, interrogatingPid,
                            interrogatingTid, spec, args);
            } else {
                // We cannot make the call and notify the caller so it does not wait.
                try {
                    callback.setFindAccessibilityNodeInfosResult(null, interactionId);
                } catch (RemoteException re) {
                    /* best effort - ignore */
                }
            }
        }

        @Override
        public void performAccessibilityAction(long accessibilityNodeId, int action,
                Bundle arguments, int interactionId,
                IAccessibilityInteractionConnectionCallback callback, int flags,
                int interrogatingPid, long interrogatingTid) {
            ViewRootImpl viewRootImpl = mViewRootImpl.get();
            if (viewRootImpl != null && viewRootImpl.mView != null) {
                viewRootImpl.getAccessibilityInteractionController()
                    .performAccessibilityActionClientThread(accessibilityNodeId, action, arguments,
                            interactionId, callback, flags, interrogatingPid, interrogatingTid);
            } else {
                // We cannot make the call and notify the caller so it does not wait.
                try {
                    callback.setPerformAccessibilityActionResult(false, interactionId);
                } catch (RemoteException re) {
                    /* best effort - ignore */
                }
            }
        }

        @Override
        public void findAccessibilityNodeInfosByViewId(long accessibilityNodeId,
                String viewId, Region interactiveRegion, int interactionId,
                IAccessibilityInteractionConnectionCallback callback, int flags,
                int interrogatingPid, long interrogatingTid, MagnificationSpec spec) {
            ViewRootImpl viewRootImpl = mViewRootImpl.get();
            if (viewRootImpl != null && viewRootImpl.mView != null) {
                viewRootImpl.getAccessibilityInteractionController()
                    .findAccessibilityNodeInfosByViewIdClientThread(accessibilityNodeId,
                            viewId, interactiveRegion, interactionId, callback, flags,
                            interrogatingPid, interrogatingTid, spec);
            } else {
                // We cannot make the call and notify the caller so it does not wait.
                try {
                    callback.setFindAccessibilityNodeInfoResult(null, interactionId);
                } catch (RemoteException re) {
                    /* best effort - ignore */
                }
            }
        }

        @Override
        public void findAccessibilityNodeInfosByText(long accessibilityNodeId, String text,
                Region interactiveRegion, int interactionId,
                IAccessibilityInteractionConnectionCallback callback, int flags,
                int interrogatingPid, long interrogatingTid, MagnificationSpec spec) {
            ViewRootImpl viewRootImpl = mViewRootImpl.get();
            if (viewRootImpl != null && viewRootImpl.mView != null) {
                viewRootImpl.getAccessibilityInteractionController()
                    .findAccessibilityNodeInfosByTextClientThread(accessibilityNodeId, text,
                            interactiveRegion, interactionId, callback, flags, interrogatingPid,
                            interrogatingTid, spec);
            } else {
                // We cannot make the call and notify the caller so it does not wait.
                try {
                    callback.setFindAccessibilityNodeInfosResult(null, interactionId);
                } catch (RemoteException re) {
                    /* best effort - ignore */
                }
            }
        }

        @Override
        public void findFocus(long accessibilityNodeId, int focusType, Region interactiveRegion,
                int interactionId, IAccessibilityInteractionConnectionCallback callback, int flags,
                int interrogatingPid, long interrogatingTid, MagnificationSpec spec) {
            ViewRootImpl viewRootImpl = mViewRootImpl.get();
            if (viewRootImpl != null && viewRootImpl.mView != null) {
                viewRootImpl.getAccessibilityInteractionController()
                    .findFocusClientThread(accessibilityNodeId, focusType, interactiveRegion,
                            interactionId, callback, flags, interrogatingPid, interrogatingTid,
                            spec);
            } else {
                // We cannot make the call and notify the caller so it does not wait.
                try {
                    callback.setFindAccessibilityNodeInfoResult(null, interactionId);
                } catch (RemoteException re) {
                    /* best effort - ignore */
                }
            }
        }

        @Override
        public void focusSearch(long accessibilityNodeId, int direction, Region interactiveRegion,
                int interactionId, IAccessibilityInteractionConnectionCallback callback, int flags,
                int interrogatingPid, long interrogatingTid, MagnificationSpec spec) {
            ViewRootImpl viewRootImpl = mViewRootImpl.get();
            if (viewRootImpl != null && viewRootImpl.mView != null) {
                viewRootImpl.getAccessibilityInteractionController()
                    .focusSearchClientThread(accessibilityNodeId, direction, interactiveRegion,
                            interactionId, callback, flags, interrogatingPid, interrogatingTid,
                            spec);
            } else {
                // We cannot make the call and notify the caller so it does not wait.
                try {
                    callback.setFindAccessibilityNodeInfoResult(null, interactionId);
                } catch (RemoteException re) {
                    /* best effort - ignore */
                }
            }
        }

        @Override
        public void clearAccessibilityFocus() {
            ViewRootImpl viewRootImpl = mViewRootImpl.get();
            if (viewRootImpl != null && viewRootImpl.mView != null) {
                viewRootImpl.getAccessibilityInteractionController()
                        .clearAccessibilityFocusClientThread();
            }
        }

        @Override
        public void notifyOutsideTouch() {
            ViewRootImpl viewRootImpl = mViewRootImpl.get();
            if (viewRootImpl != null && viewRootImpl.mView != null) {
                viewRootImpl.getAccessibilityInteractionController()
                        .notifyOutsideTouchClientThread();
            }
        }
    }

    private class SendWindowContentChangedAccessibilityEvent implements Runnable {
        private int mChangeTypes = 0;

        public View mSource;
        public long mLastEventTimeMillis;
        /**
         * Override for {@link AccessibilityEvent#originStackTrace} to provide the stack trace
         * of the original {@link #runOrPost} call instead of one for sending the delayed event
         * from a looper.
         */
        public StackTraceElement[] mOrigin;

        @Override
        public void run() {
            // Protect against re-entrant code and attempt to do the right thing in the case that
            // we're multithreaded.
            View source = mSource;
            mSource = null;
            if (source == null) {
                Log.e(TAG, "Accessibility content change has no source");
                return;
            }
            // The accessibility may be turned off while we were waiting so check again.
            if (AccessibilityManager.getInstance(mContext).isEnabled()) {
                mLastEventTimeMillis = SystemClock.uptimeMillis();
                AccessibilityEvent event = AccessibilityEvent.obtain();
                event.setEventType(AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED);
                event.setContentChangeTypes(mChangeTypes);
                if (AccessibilityEvent.DEBUG_ORIGIN) event.originStackTrace = mOrigin;
                source.sendAccessibilityEventUnchecked(event);
            } else {
                mLastEventTimeMillis = 0;
            }
            // In any case reset to initial state.
            source.resetSubtreeAccessibilityStateChanged();
            mChangeTypes = 0;
            if (AccessibilityEvent.DEBUG_ORIGIN) mOrigin = null;
        }

        public void runOrPost(View source, int changeType) {
            if (mHandler.getLooper() != Looper.myLooper()) {
                CalledFromWrongThreadException e = new CalledFromWrongThreadException("Only the "
                        + "original thread that created a view hierarchy can touch its views.");
                // TODO: Throw the exception
                Log.e(TAG, "Accessibility content change on non-UI thread. Future Android "
                        + "versions will throw an exception.", e);
                // Attempt to recover. This code does not eliminate the thread safety issue, but
                // it should force any issues to happen near the above log.
                mHandler.removeCallbacks(this);
                if (mSource != null) {
                    // Dispatch whatever was pending. It's still possible that the runnable started
                    // just before we removed the callbacks, and bad things will happen, but at
                    // least they should happen very close to the logged error.
                    run();
                }
            }
            if (mSource != null) {
                // If there is no common predecessor, then mSource points to
                // a removed view, hence in this case always prefer the source.
                View predecessor = getCommonPredecessor(mSource, source);
                if (predecessor != null) {
                    predecessor = predecessor.getSelfOrParentImportantForA11y();
                }
                mSource = (predecessor != null) ? predecessor : source;
                mChangeTypes |= changeType;
                return;
            }
            mSource = source;
            mChangeTypes = changeType;
            if (AccessibilityEvent.DEBUG_ORIGIN) {
                mOrigin = Thread.currentThread().getStackTrace();
            }
            final long timeSinceLastMillis = SystemClock.uptimeMillis() - mLastEventTimeMillis;
            final long minEventIntevalMillis =
                    ViewConfiguration.getSendRecurringAccessibilityEventsInterval();
            if (timeSinceLastMillis >= minEventIntevalMillis) {
                removeCallbacksAndRun();
            } else {
                mHandler.postDelayed(this, minEventIntevalMillis - timeSinceLastMillis);
            }
        }

        public void removeCallbacksAndRun() {
            mHandler.removeCallbacks(this);
            run();
        }
    }

    private static class UnhandledKeyManager {
        // This is used to ensure that unhandled events are only dispatched once. We attempt
        // to dispatch more than once in order to achieve a certain order. Specifically, if we
        // are in an Activity or Dialog (and have a Window.Callback), the unhandled events should
        // be dispatched after the view hierarchy, but before the Callback. However, if we aren't
        // in an activity, we still want unhandled keys to be dispatched.
        private boolean mDispatched = true;

        // Keeps track of which Views have unhandled key focus for which keys. This doesn't
        // include modifiers.
        private final SparseArray<WeakReference<View>> mCapturedKeys = new SparseArray<>();

        // The current receiver. This value is transient and used between the pre-dispatch and
        // pre-view phase to ensure that other input-stages don't interfere with tracking.
        private WeakReference<View> mCurrentReceiver = null;

        boolean dispatch(View root, KeyEvent event) {
            if (mDispatched) {
                return false;
            }
            View consumer;
            try {
                Trace.traceBegin(Trace.TRACE_TAG_VIEW, "UnhandledKeyEvent dispatch");
                mDispatched = true;

                consumer = root.dispatchUnhandledKeyEvent(event);

                // If an unhandled listener handles one, then keep track of it so that the
                // consuming view is first to receive its repeats and release as well.
                if (event.getAction() == KeyEvent.ACTION_DOWN) {
                    int keycode = event.getKeyCode();
                    if (consumer != null && !KeyEvent.isModifierKey(keycode)) {
                        mCapturedKeys.put(keycode, new WeakReference<>(consumer));
                    }
                }
            } finally {
                Trace.traceEnd(Trace.TRACE_TAG_VIEW);
            }
            return consumer != null;
        }

        /**
         * Called before the event gets dispatched to anything
         */
        void preDispatch(KeyEvent event) {
            // Always clean-up 'up' events since it's possible for earlier dispatch stages to
            // consume them without consuming the corresponding 'down' event.
            mCurrentReceiver = null;
            if (event.getAction() == KeyEvent.ACTION_UP) {
                int idx = mCapturedKeys.indexOfKey(event.getKeyCode());
                if (idx >= 0) {
                    mCurrentReceiver = mCapturedKeys.valueAt(idx);
                    mCapturedKeys.removeAt(idx);
                }
            }
        }

        /**
         * Called before the event gets dispatched to the view hierarchy
         * @return {@code true} if an unhandled handler has focus and consumed the event
         */
        boolean preViewDispatch(KeyEvent event) {
            mDispatched = false;
            if (mCurrentReceiver == null) {
                mCurrentReceiver = mCapturedKeys.get(event.getKeyCode());
            }
            if (mCurrentReceiver != null) {
                View target = mCurrentReceiver.get();
                if (event.getAction() == KeyEvent.ACTION_UP) {
                    mCurrentReceiver = null;
                }
                if (target != null && target.isAttachedToWindow()) {
                    target.onUnhandledKeyEvent(event);
                }
                // consume anyways so that we don't feed uncaptured key events to other views
                return true;
            }
            return false;
        }
    }

    private boolean isSwipeToScreenshotGestureActive() {
        try {
            return ActivityManager.getService().isSwipeToScreenshotGestureActive();
        } catch (RemoteException e) {
            return false;
        }
    }
}
