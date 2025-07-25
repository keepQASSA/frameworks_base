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

package com.android.server.job;

import static com.android.server.job.JobSchedulerService.sElapsedRealtimeClock;

import android.app.ActivityManager;
import android.app.job.IJobCallback;
import android.app.job.IJobService;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobWorkItem;
import android.app.usage.UsageStatsManagerInternal;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.UserHandle;
import android.os.WorkSource;
import android.util.EventLog;
import android.util.Slog;
import android.util.TimeUtils;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.app.IBatteryStats;
import com.android.server.EventLogTags;
import com.android.server.LocalServices;
import com.android.server.job.controllers.JobStatus;

/**
 * Handles client binding and lifecycle of a job. Jobs execute one at a time on an instance of this
 * class.
 *
 * There are two important interactions into this class from the
 * {@link com.android.server.job.JobSchedulerService}. To execute a job and to cancel a job.
 * - Execution of a new job is handled by the {@link #mAvailable}. This bit is flipped once when a
 * job lands, and again when it is complete.
 * - Cancelling is trickier, because there are also interactions from the client. It's possible
 * the {@link com.android.server.job.JobServiceContext.JobServiceHandler} tries to process a
 * {@link #doCancelLocked} after the client has already finished. This is handled by having
 * {@link com.android.server.job.JobServiceContext.JobServiceHandler#handleCancelLocked} check whether
 * the context is still valid.
 * To mitigate this, we avoid sending duplicate onStopJob()
 * calls to the client after they've specified jobFinished().
 */
public final class JobServiceContext implements ServiceConnection {
    private static final boolean DEBUG = JobSchedulerService.DEBUG;
    private static final boolean DEBUG_STANDBY = JobSchedulerService.DEBUG_STANDBY;

    private static final String TAG = "JobServiceContext";
    /** Amount of time a job is allowed to execute for before being considered timed-out. */
    public static final long EXECUTING_TIMESLICE_MILLIS = 10 * 60 * 1000;  // 10mins.
    /** Amount of time the JobScheduler waits for the initial service launch+bind. */
    private static final long OP_BIND_TIMEOUT_MILLIS = 18 * 1000;
    /** Amount of time the JobScheduler will wait for a response from an app for a message. */
    private static final long OP_TIMEOUT_MILLIS = 8 * 1000;

    private static final String[] VERB_STRINGS = {
            "VERB_BINDING", "VERB_STARTING", "VERB_EXECUTING", "VERB_STOPPING", "VERB_FINISHED"
    };

    // States that a job occupies while interacting with the client.
    static final int VERB_BINDING = 0;
    static final int VERB_STARTING = 1;
    static final int VERB_EXECUTING = 2;
    static final int VERB_STOPPING = 3;
    static final int VERB_FINISHED = 4;

    // Messages that result from interactions with the client service.
    /** System timed out waiting for a response. */
    private static final int MSG_TIMEOUT = 0;

    public static final int NO_PREFERRED_UID = -1;

    private final Handler mCallbackHandler;
    /** Make callbacks to {@link JobSchedulerService} to inform on job completion status. */
    private final JobCompletedListener mCompletedListener;
    /** Used for service binding, etc. */
    private final Context mContext;
    private final Object mLock;
    private final IBatteryStats mBatteryStats;
    private final JobPackageTracker mJobPackageTracker;
    private PowerManager.WakeLock mWakeLock;

    // Execution state.
    private JobParameters mParams;
    @VisibleForTesting
    int mVerb;
    private boolean mCancelled;

    /**
     * All the information maintained about the job currently being executed.
     *
     * Any reads (dereferences) not done from the handler thread must be synchronized on
     * {@link #mLock}.
     * Writes can only be done from the handler thread, or {@link #executeRunnableJob(JobStatus)}.
     */
    private JobStatus mRunningJob;
    private JobCallback mRunningCallback;
    /** Used to store next job to run when current job is to be preempted. */
    private int mPreferredUid;
    IJobService service;

    /**
     * Whether this context is free. This is set to false at the start of execution, and reset to
     * true when execution is complete.
     */
    @GuardedBy("mLock")
    private boolean mAvailable;
    /** Track start time. */
    private long mExecutionStartTimeElapsed;
    /** Track when job will timeout. */
    private long mTimeoutElapsed;

    // Debugging: reason this job was last stopped.
    public String mStoppedReason;

    // Debugging: time this job was last stopped.
    public long mStoppedTime;

    final class JobCallback extends IJobCallback.Stub {
        public String mStoppedReason;
        public long mStoppedTime;

        @Override
        public void acknowledgeStartMessage(int jobId, boolean ongoing) {
            doAcknowledgeStartMessage(this, jobId, ongoing);
        }

        @Override
        public void acknowledgeStopMessage(int jobId, boolean reschedule) {
            doAcknowledgeStopMessage(this, jobId, reschedule);
        }

        @Override
        public JobWorkItem dequeueWork(int jobId) {
            return doDequeueWork(this, jobId);
        }

        @Override
        public boolean completeWork(int jobId, int workId) {
            return doCompleteWork(this, jobId, workId);
        }

        @Override
        public void jobFinished(int jobId, boolean reschedule) {
            doJobFinished(this, jobId, reschedule);
        }
    }

    JobServiceContext(JobSchedulerService service, IBatteryStats batteryStats,
            JobPackageTracker tracker, Looper looper) {
        this(service.getContext(), service.getLock(), batteryStats, tracker, service, looper);
    }

    @VisibleForTesting
    JobServiceContext(Context context, Object lock, IBatteryStats batteryStats,
            JobPackageTracker tracker, JobCompletedListener completedListener, Looper looper) {
        mContext = context;
        mLock = lock;
        mBatteryStats = batteryStats;
        mJobPackageTracker = tracker;
        mCallbackHandler = new JobServiceHandler(looper);
        mCompletedListener = completedListener;
        mAvailable = true;
        mVerb = VERB_FINISHED;
        mPreferredUid = NO_PREFERRED_UID;
    }

    /**
     * Give a job to this context for execution. Callers must first check {@link #getRunningJobLocked()}
     * and ensure it is null to make sure this is a valid context.
     * @param job The status of the job that we are going to run.
     * @return True if the job is valid and is running. False if the job cannot be executed.
     */
    boolean executeRunnableJob(JobStatus job) {
        synchronized (mLock) {
            if (!mAvailable) {
                Slog.e(TAG, "Starting new runnable but context is unavailable > Error.");
                return false;
            }

            mPreferredUid = NO_PREFERRED_UID;

            mRunningJob = job;
            mRunningCallback = new JobCallback();
            final boolean isDeadlineExpired =
                    job.hasDeadlineConstraint() &&
                            (job.getLatestRunTimeElapsed() < sElapsedRealtimeClock.millis());
            Uri[] triggeredUris = null;
            if (job.changedUris != null) {
                triggeredUris = new Uri[job.changedUris.size()];
                job.changedUris.toArray(triggeredUris);
            }
            String[] triggeredAuthorities = null;
            if (job.changedAuthorities != null) {
                triggeredAuthorities = new String[job.changedAuthorities.size()];
                job.changedAuthorities.toArray(triggeredAuthorities);
            }
            final JobInfo ji = job.getJob();
            mParams = new JobParameters(mRunningCallback, job.getJobId(), ji.getExtras(),
                    ji.getTransientExtras(), ji.getClipData(), ji.getClipGrantFlags(),
                    isDeadlineExpired, triggeredUris, triggeredAuthorities, job.network);
            mExecutionStartTimeElapsed = sElapsedRealtimeClock.millis();

            final long whenDeferred = job.getWhenStandbyDeferred();
            if (whenDeferred > 0) {
                final long deferral = mExecutionStartTimeElapsed - whenDeferred;
                EventLog.writeEvent(EventLogTags.JOB_DEFERRED_EXECUTION, deferral);
                if (DEBUG_STANDBY) {
                    StringBuilder sb = new StringBuilder(128);
                    sb.append("Starting job deferred for standby by ");
                    TimeUtils.formatDuration(deferral, sb);
                    sb.append(" ms : ");
                    sb.append(job.toShortString());
                    Slog.v(TAG, sb.toString());
                }
            }

            // Once we'e begun executing a job, we by definition no longer care whether
            // it was inflated from disk with not-yet-coherent delay/deadline bounds.
            job.clearPersistedUtcTimes();

            mVerb = VERB_BINDING;
            scheduleOpTimeOutLocked();
            final Intent intent = new Intent().setComponent(job.getServiceComponent());
            boolean binding = false;
            try {
                binding = mContext.bindServiceAsUser(intent, this,
                        Context.BIND_AUTO_CREATE | Context.BIND_NOT_FOREGROUND
                        | Context.BIND_NOT_PERCEPTIBLE | Context.BIND_DENY_ACTIVITY_STARTS,
                        UserHandle.of(job.getUserId()));
            } catch (SecurityException e) {
                // Some permission policy, for example INTERACT_ACROSS_USERS and
                // android:singleUser, can result in a SecurityException being thrown from
                // bindServiceAsUser().  If this happens, catch it and fail gracefully.
                Slog.w(TAG, "Job service " + job.getServiceComponent().getShortClassName()
                        + " cannot be executed: " + e.getMessage());
                binding = false;
            }
            if (!binding) {
                if (DEBUG) {
                    Slog.d(TAG, job.getServiceComponent().getShortClassName() + " unavailable.");
                }
                mContext.unbindService(this);
                mRunningJob = null;
                mRunningCallback = null;
                mParams = null;
                mExecutionStartTimeElapsed = 0L;
                mVerb = VERB_FINISHED;
                removeOpTimeOutLocked();
                return false;
            }
            mJobPackageTracker.noteActive(job);
            try {
                mBatteryStats.noteJobStart(job.getBatteryName(), job.getSourceUid(),
                        job.getStandbyBucket(), job.getJobId());
            } catch (RemoteException e) {
                // Whatever.
            }
            final String jobPackage = job.getSourcePackageName();
            final int jobUserId = job.getSourceUserId();
            UsageStatsManagerInternal usageStats =
                    LocalServices.getService(UsageStatsManagerInternal.class);
            usageStats.setLastJobRunTime(jobPackage, jobUserId, mExecutionStartTimeElapsed);
            JobSchedulerInternal jobScheduler =
                    LocalServices.getService(JobSchedulerInternal.class);
            jobScheduler.noteJobStart(jobPackage, jobUserId);
            mAvailable = false;
            mStoppedReason = null;
            mStoppedTime = 0;
            return true;
        }
    }

    /**
     * Used externally to query the running job. Will return null if there is no job running.
     */
    JobStatus getRunningJobLocked() {
        return mRunningJob;
    }

    /**
     * Used only for debugging. Will return <code>"&lt;null&gt;"</code> if there is no job running.
     */
    private String getRunningJobNameLocked() {
        return mRunningJob != null ? mRunningJob.toShortString() : "<null>";
    }

    /** Called externally when a job that was scheduled for execution should be cancelled. */
    @GuardedBy("mLock")
    void cancelExecutingJobLocked(int reason, String debugReason) {
        doCancelLocked(reason, debugReason);
    }

    @GuardedBy("mLock")
    void preemptExecutingJobLocked() {
        doCancelLocked(JobParameters.REASON_PREEMPT, "cancelled due to preemption");
    }

    int getPreferredUid() {
        return mPreferredUid;
    }

    void clearPreferredUid() {
        mPreferredUid = NO_PREFERRED_UID;
    }

    long getExecutionStartTimeElapsed() {
        return mExecutionStartTimeElapsed;
    }

    long getTimeoutElapsed() {
        return mTimeoutElapsed;
    }

    @GuardedBy("mLock")
    boolean timeoutIfExecutingLocked(String pkgName, int userId, boolean matchJobId, int jobId,
            String reason) {
        final JobStatus executing = getRunningJobLocked();
        if (executing != null && (userId == UserHandle.USER_ALL || userId == executing.getUserId())
                && (pkgName == null || pkgName.equals(executing.getSourcePackageName()))
                && (!matchJobId || jobId == executing.getJobId())) {
            if (mVerb == VERB_EXECUTING) {
                mParams.setStopReason(JobParameters.REASON_TIMEOUT, reason);
                sendStopMessageLocked("force timeout from shell");
                return true;
            }
        }
        return false;
    }

    void doJobFinished(JobCallback cb, int jobId, boolean reschedule) {
        doCallback(cb, reschedule, "app called jobFinished");
    }

    void doAcknowledgeStopMessage(JobCallback cb, int jobId, boolean reschedule) {
        doCallback(cb, reschedule, null);
    }

    void doAcknowledgeStartMessage(JobCallback cb, int jobId, boolean ongoing) {
        doCallback(cb, ongoing, "finished start");
    }

    JobWorkItem doDequeueWork(JobCallback cb, int jobId) {
        final long ident = Binder.clearCallingIdentity();
        try {
            synchronized (mLock) {
                assertCallerLocked(cb);
                if (mVerb == VERB_STOPPING || mVerb == VERB_FINISHED) {
                    // This job is either all done, or on its way out.  Either way, it
                    // should not dispatch any more work.  We will pick up any remaining
                    // work the next time we start the job again.
                    return null;
                }
                final JobWorkItem work = mRunningJob.dequeueWorkLocked();
                if (work == null && !mRunningJob.hasExecutingWorkLocked()) {
                    // This will finish the job.
                    doCallbackLocked(false, "last work dequeued");
                }
                return work;
            }
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    boolean doCompleteWork(JobCallback cb, int jobId, int workId) {
        final long ident = Binder.clearCallingIdentity();
        try {
            synchronized (mLock) {
                assertCallerLocked(cb);
                return mRunningJob.completeWorkLocked(ActivityManager.getService(), workId);
            }
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    /**
     * We acquire/release a wakelock on onServiceConnected/unbindService. This mirrors the work
     * we intend to send to the client - we stop sending work when the service is unbound so until
     * then we keep the wakelock.
     * @param name The concrete component name of the service that has been connected.
     * @param service The IBinder of the Service's communication channel,
     */
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        JobStatus runningJob;
        synchronized (mLock) {
            // This isn't strictly necessary b/c the JobServiceHandler is running on the main
            // looper and at this point we can't get any binder callbacks from the client. Better
            // safe than sorry.
            runningJob = mRunningJob;

            if (runningJob == null || !name.equals(runningJob.getServiceComponent())) {
                closeAndCleanupJobLocked(true /* needsReschedule */,
                        "connected for different component");
                return;
            }
            this.service = IJobService.Stub.asInterface(service);
            final PowerManager pm =
                    (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
            PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                    runningJob.getTag());
            wl.setWorkSource(deriveWorkSource(runningJob));
            wl.setReferenceCounted(false);
            wl.acquire();

            // We use a new wakelock instance per job.  In rare cases there is a race between
            // teardown following job completion/cancellation and new job service spin-up
            // such that if we simply assign mWakeLock to be the new instance, we orphan
            // the currently-live lock instead of cleanly replacing it.  Watch for this and
            // explicitly fast-forward the release if we're in that situation.
            if (mWakeLock != null) {
                Slog.w(TAG, "Bound new job " + runningJob + " but live wakelock " + mWakeLock
                        + " tag=" + mWakeLock.getTag());
                mWakeLock.release();
            }
            mWakeLock = wl;
            doServiceBoundLocked();
        }
    }

    private WorkSource deriveWorkSource(JobStatus runningJob) {
        final int jobUid = runningJob.getSourceUid();
        if (WorkSource.isChainedBatteryAttributionEnabled(mContext)) {
            WorkSource workSource = new WorkSource();
            workSource.createWorkChain()
                    .addNode(jobUid, null)
                    .addNode(android.os.Process.SYSTEM_UID, "JobScheduler");
            return workSource;
        } else {
            return new WorkSource(jobUid);
        }
    }

    /** If the client service crashes we reschedule this job and clean up. */
    @Override
    public void onServiceDisconnected(ComponentName name) {
        synchronized (mLock) {
            closeAndCleanupJobLocked(true /* needsReschedule */, "unexpectedly disconnected");
        }
    }

    /**
     * This class is reused across different clients, and passes itself in as a callback. Check
     * whether the client exercising the callback is the client we expect.
     * @return True if the binder calling is coming from the client we expect.
     */
    private boolean verifyCallerLocked(JobCallback cb) {
        if (mRunningCallback != cb) {
            if (DEBUG) {
                Slog.d(TAG, "Stale callback received, ignoring.");
            }
            return false;
        }
        return true;
    }

    private void assertCallerLocked(JobCallback cb) {
        if (!verifyCallerLocked(cb)) {
            StringBuilder sb = new StringBuilder(128);
            sb.append("Caller no longer running");
            if (cb.mStoppedReason != null) {
                sb.append(", last stopped ");
                TimeUtils.formatDuration(sElapsedRealtimeClock.millis() - cb.mStoppedTime, sb);
                sb.append(" because: ");
                sb.append(cb.mStoppedReason);
            }
            throw new SecurityException(sb.toString());
        }
    }

    /**
     * Scheduling of async messages (basically timeouts at this point).
     */
    private class JobServiceHandler extends Handler {
        JobServiceHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message message) {
            switch (message.what) {
                case MSG_TIMEOUT:
                    synchronized (mLock) {
                        if (message.obj == mRunningCallback) {
                            handleOpTimeoutLocked();
                        } else {
                            JobCallback jc = (JobCallback)message.obj;
                            StringBuilder sb = new StringBuilder(128);
                            sb.append("Ignoring timeout of no longer active job");
                            if (jc.mStoppedReason != null) {
                                sb.append(", stopped ");
                                TimeUtils.formatDuration(sElapsedRealtimeClock.millis()
                                        - jc.mStoppedTime, sb);
                                sb.append(" because: ");
                                sb.append(jc.mStoppedReason);
                            }
                            Slog.w(TAG, sb.toString());
                        }
                    }
                    break;
                default:
                    Slog.e(TAG, "Unrecognised message: " + message);
            }
        }
    }

    @GuardedBy("mLock")
    void doServiceBoundLocked() {
        removeOpTimeOutLocked();
        handleServiceBoundLocked();
    }

    void doCallback(JobCallback cb, boolean reschedule, String reason) {
        final long ident = Binder.clearCallingIdentity();
        try {
            synchronized (mLock) {
                if (!verifyCallerLocked(cb)) {
                    return;
                }
                doCallbackLocked(reschedule, reason);
            }
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    @GuardedBy("mLock")
    void doCallbackLocked(boolean reschedule, String reason) {
        if (DEBUG) {
            Slog.d(TAG, "doCallback of : " + mRunningJob
                    + " v:" + VERB_STRINGS[mVerb]);
        }
        removeOpTimeOutLocked();

        if (mVerb == VERB_STARTING) {
            handleStartedLocked(reschedule);
        } else if (mVerb == VERB_EXECUTING ||
                mVerb == VERB_STOPPING) {
            handleFinishedLocked(reschedule, reason);
        } else {
            if (DEBUG) {
                Slog.d(TAG, "Unrecognised callback: " + mRunningJob);
            }
        }
    }

    @GuardedBy("mLock")
    void doCancelLocked(int arg1, String debugReason) {
        if (mVerb == VERB_FINISHED) {
            if (DEBUG) {
                Slog.d(TAG,
                        "Trying to process cancel for torn-down context, ignoring.");
            }
            return;
        }
        mParams.setStopReason(arg1, debugReason);
        if (arg1 == JobParameters.REASON_PREEMPT) {
            mPreferredUid = mRunningJob != null ? mRunningJob.getUid() :
                    NO_PREFERRED_UID;
        }
        handleCancelLocked(debugReason);
    }

    /** Start the job on the service. */
    @GuardedBy("mLock")
    private void handleServiceBoundLocked() {
        if (DEBUG) {
            Slog.d(TAG, "handleServiceBound for " + getRunningJobNameLocked());
        }
        if (mVerb != VERB_BINDING) {
            Slog.e(TAG, "Sending onStartJob for a job that isn't pending. "
                    + VERB_STRINGS[mVerb]);
            closeAndCleanupJobLocked(false /* reschedule */, "started job not pending");
            return;
        }
        if (mCancelled) {
            if (DEBUG) {
                Slog.d(TAG, "Job cancelled while waiting for bind to complete. "
                        + mRunningJob);
            }
            closeAndCleanupJobLocked(true /* reschedule */, "cancelled while waiting for bind");
            return;
        }
        try {
            mVerb = VERB_STARTING;
            scheduleOpTimeOutLocked();
            service.startJob(mParams);
        } catch (Exception e) {
            // We catch 'Exception' because client-app malice or bugs might induce a wide
            // range of possible exception-throw outcomes from startJob() and its handling
            // of the client's ParcelableBundle extras.
            Slog.e(TAG, "Error sending onStart message to '" +
                    mRunningJob.getServiceComponent().getShortClassName() + "' ", e);
        }
    }

    /**
     * State behaviours.
     * VERB_STARTING   -> Successful start, change job to VERB_EXECUTING and post timeout.
     *     _PENDING    -> Error
     *     _EXECUTING  -> Error
     *     _STOPPING   -> Error
     */
    @GuardedBy("mLock")
    private void handleStartedLocked(boolean workOngoing) {
        switch (mVerb) {
            case VERB_STARTING:
                mVerb = VERB_EXECUTING;
                if (!workOngoing) {
                    // Job is finished already so fast-forward to handleFinished.
                    handleFinishedLocked(false, "onStartJob returned false");
                    return;
                }
                if (mCancelled) {
                    if (DEBUG) {
                        Slog.d(TAG, "Job cancelled while waiting for onStartJob to complete.");
                    }
                    // Cancelled *while* waiting for acknowledgeStartMessage from client.
                    handleCancelLocked(null);
                    return;
                }
                scheduleOpTimeOutLocked();
                break;
            default:
                Slog.e(TAG, "Handling started job but job wasn't starting! Was "
                        + VERB_STRINGS[mVerb] + ".");
                return;
        }
    }

    /**
     * VERB_EXECUTING  -> Client called jobFinished(), clean up and notify done.
     *     _STOPPING   -> Successful finish, clean up and notify done.
     *     _STARTING   -> Error
     *     _PENDING    -> Error
     */
    @GuardedBy("mLock")
    private void handleFinishedLocked(boolean reschedule, String reason) {
        switch (mVerb) {
            case VERB_EXECUTING:
            case VERB_STOPPING:
                closeAndCleanupJobLocked(reschedule, reason);
                break;
            default:
                Slog.e(TAG, "Got an execution complete message for a job that wasn't being" +
                        "executed. Was " + VERB_STRINGS[mVerb] + ".");
        }
    }

    /**
     * A job can be in various states when a cancel request comes in:
     * VERB_BINDING    -> Cancelled before bind completed. Mark as cancelled and wait for
     *                    {@link #onServiceConnected(android.content.ComponentName, android.os.IBinder)}
     *     _STARTING   -> Mark as cancelled and wait for
     *                    {@link JobServiceContext#doAcknowledgeStartMessage}
     *     _EXECUTING  -> call {@link #sendStopMessageLocked}}, but only if there are no callbacks
     *                      in the message queue.
     *     _ENDING     -> No point in doing anything here, so we ignore.
     */
    @GuardedBy("mLock")
    private void handleCancelLocked(String reason) {
        if (JobSchedulerService.DEBUG) {
            Slog.d(TAG, "Handling cancel for: " + mRunningJob.getJobId() + " "
                    + VERB_STRINGS[mVerb]);
        }
        switch (mVerb) {
            case VERB_BINDING:
            case VERB_STARTING:
                mCancelled = true;
                applyStoppedReasonLocked(reason);
                break;
            case VERB_EXECUTING:
                sendStopMessageLocked(reason);
                break;
            case VERB_STOPPING:
                // Nada.
                break;
            default:
                Slog.e(TAG, "Cancelling a job without a valid verb: " + mVerb);
                break;
        }
    }

    /** Process MSG_TIMEOUT here. */
    @GuardedBy("mLock")
    private void handleOpTimeoutLocked() {
        switch (mVerb) {
            case VERB_BINDING:
                Slog.w(TAG, "Time-out while trying to bind " + getRunningJobNameLocked()
                        + ", dropping.");
                closeAndCleanupJobLocked(false /* needsReschedule */, "timed out while binding");
                break;
            case VERB_STARTING:
                // Client unresponsive - wedged or failed to respond in time. We don't really
                // know what happened so let's log it and notify the JobScheduler
                // FINISHED/NO-RETRY.
                Slog.w(TAG, "No response from client for onStartJob "
                        + getRunningJobNameLocked());
                closeAndCleanupJobLocked(false /* needsReschedule */, "timed out while starting");
                break;
            case VERB_STOPPING:
                // At least we got somewhere, so fail but ask the JobScheduler to reschedule.
                Slog.w(TAG, "No response from client for onStopJob "
                        + getRunningJobNameLocked());
                closeAndCleanupJobLocked(true /* needsReschedule */, "timed out while stopping");
                break;
            case VERB_EXECUTING:
                // Not an error - client ran out of time.
                Slog.i(TAG, "Client timed out while executing (no jobFinished received), " +
                        "sending onStop: " + getRunningJobNameLocked());
                mParams.setStopReason(JobParameters.REASON_TIMEOUT, "client timed out");
                sendStopMessageLocked("timeout while executing");
                break;
            default:
                Slog.e(TAG, "Handling timeout for an invalid job state: "
                        + getRunningJobNameLocked() + ", dropping.");
                closeAndCleanupJobLocked(false /* needsReschedule */, "invalid timeout");
        }
    }

    /**
     * Already running, need to stop. Will switch {@link #mVerb} from VERB_EXECUTING ->
     * VERB_STOPPING.
     */
    @GuardedBy("mLock")
    private void sendStopMessageLocked(String reason) {
        removeOpTimeOutLocked();
        if (mVerb != VERB_EXECUTING) {
            Slog.e(TAG, "Sending onStopJob for a job that isn't started. " + mRunningJob);
            closeAndCleanupJobLocked(false /* reschedule */, reason);
            return;
        }
        try {
            applyStoppedReasonLocked(reason);
            mVerb = VERB_STOPPING;
            scheduleOpTimeOutLocked();
            service.stopJob(mParams);
        } catch (RemoteException e) {
            Slog.e(TAG, "Error sending onStopJob to client.", e);
            // The job's host app apparently crashed during the job, so we should reschedule.
            closeAndCleanupJobLocked(true /* reschedule */, "host crashed when trying to stop");
        }
    }

    /**
     * The provided job has finished, either by calling
     * {@link android.app.job.JobService#jobFinished(android.app.job.JobParameters, boolean)}
     * or from acknowledging the stop message we sent. Either way, we're done tracking it and
     * we want to clean up internally.
     */
    @GuardedBy("mLock")
    private void closeAndCleanupJobLocked(boolean reschedule, String reason) {
        final JobStatus completedJob;
        if (mVerb == VERB_FINISHED) {
            return;
        }
        applyStoppedReasonLocked(reason);
        completedJob = mRunningJob;
        mJobPackageTracker.noteInactive(completedJob, mParams.getStopReason(), reason);
        try {
            mBatteryStats.noteJobFinish(mRunningJob.getBatteryName(),
                    mRunningJob.getSourceUid(), mParams.getStopReason(),
                    mRunningJob.getStandbyBucket(), mRunningJob.getJobId());
        } catch (RemoteException e) {
            // Whatever.
        }
        if (mWakeLock != null) {
            mWakeLock.release();
        }
        mContext.unbindService(JobServiceContext.this);
        mWakeLock = null;
        mRunningJob = null;
        mRunningCallback = null;
        mParams = null;
        mVerb = VERB_FINISHED;
        mCancelled = false;
        service = null;
        mAvailable = true;
        removeOpTimeOutLocked();
        mCompletedListener.onJobCompletedLocked(completedJob, reschedule);
    }

    private void applyStoppedReasonLocked(String reason) {
        if (reason != null && mStoppedReason == null) {
            mStoppedReason = reason;
            mStoppedTime = sElapsedRealtimeClock.millis();
            if (mRunningCallback != null) {
                mRunningCallback.mStoppedReason = mStoppedReason;
                mRunningCallback.mStoppedTime = mStoppedTime;
            }
        }
    }

    /**
     * Called when sending a message to the client, over whose execution we have no control. If
     * we haven't received a response in a certain amount of time, we want to give up and carry
     * on with life.
     */
    private void scheduleOpTimeOutLocked() {
        removeOpTimeOutLocked();

        final long timeoutMillis;
        switch (mVerb) {
            case VERB_EXECUTING:
                timeoutMillis = EXECUTING_TIMESLICE_MILLIS;
                break;

            case VERB_BINDING:
                timeoutMillis = OP_BIND_TIMEOUT_MILLIS;
                break;

            default:
                timeoutMillis = OP_TIMEOUT_MILLIS;
                break;
        }
        if (DEBUG) {
            Slog.d(TAG, "Scheduling time out for '" +
                    mRunningJob.getServiceComponent().getShortClassName() + "' jId: " +
                    mParams.getJobId() + ", in " + (timeoutMillis / 1000) + " s");
        }
        Message m = mCallbackHandler.obtainMessage(MSG_TIMEOUT, mRunningCallback);
        mCallbackHandler.sendMessageDelayed(m, timeoutMillis);
        mTimeoutElapsed = sElapsedRealtimeClock.millis() + timeoutMillis;
    }


    private void removeOpTimeOutLocked() {
        mCallbackHandler.removeMessages(MSG_TIMEOUT);
    }
}
