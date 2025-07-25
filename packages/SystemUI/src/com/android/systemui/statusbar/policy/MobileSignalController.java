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
package com.android.systemui.statusbar.policy;

import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.database.ContentObserver;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.UserHandle;
import android.provider.Settings;
import android.provider.Settings.Global;
import android.telephony.NetworkRegistrationInfo;
import android.telephony.ims.ImsMmTelManager;
import android.telephony.ims.ImsReasonInfo;
import android.telephony.ims.feature.MmTelFeature;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.SignalStrength;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.text.Html;
import android.text.TextUtils;
import android.util.Log;
import android.util.SparseArray;

import com.android.ims.ImsException;
import com.android.ims.ImsManager;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.telephony.TelephonyIntents;
import com.android.internal.telephony.cdma.EriInfo;
import com.android.settingslib.Utils;
import com.android.settingslib.graph.SignalDrawable;
import com.android.settingslib.net.SignalStrengthUtil;
import com.android.systemui.Dependency;
import com.android.systemui.R;
import com.android.systemui.statusbar.policy.NetworkController.IconState;
import com.android.systemui.statusbar.policy.NetworkController.SignalCallback;
import com.android.systemui.statusbar.policy.NetworkControllerImpl.Config;
import com.android.systemui.statusbar.policy.NetworkControllerImpl.SubscriptionDefaults;
import com.android.systemui.tuner.TunerService;

import java.io.PrintWriter;
import java.util.BitSet;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class MobileSignalController extends SignalController<
        MobileSignalController.MobileState, MobileSignalController.MobileIconGroup> implements TunerService.Tunable {

    // The message to display Nr5G icon gracfully by CarrierConfig timeout
    private static final int MSG_DISPLAY_GRACE = 1;

    private final TelephonyManager mPhone;
    private final SubscriptionDefaults mDefaults;
    private final String mNetworkNameDefault;
    private final String mNetworkNameSeparator;
    private final ContentObserver mObserver;
    @VisibleForTesting
    final PhoneStateListener mPhoneStateListener;
    // Save entire info for logging, we only use the id.
    final SubscriptionInfo mSubscriptionInfo;

    // @VisibleForDemoMode
    final SparseArray<MobileIconGroup> mNetworkToIconLookup;

    // Since some pieces of the phone state are interdependent we store it locally,
    // this could potentially become part of MobileState for simplification/complication
    // of code.
    private int mDataNetType = TelephonyManager.NETWORK_TYPE_UNKNOWN;
    private int mDataState = TelephonyManager.DATA_DISCONNECTED;
    private ServiceState mServiceState;
    private SignalStrength mSignalStrength;
    private MobileIconGroup mDefaultIcons;
    private Config mConfig;
    private final Handler mDisplayGraceHandler;
    @VisibleForTesting
    boolean mInflateSignalStrengths = false;
    @VisibleForTesting
    boolean mIsShowingIconGracefully = false;
    // Some specific carriers have 5GE network which is special LTE CA network.
    private static final int NETWORK_TYPE_LTE_CA_5GE = TelephonyManager.MAX_NETWORK_TYPE + 1;

    // 4G instead of LTE
    private boolean mShow4gForLte;

    private ImsManager mImsManager;
    private ImsManager.Connector mImsManagerConnector;
    private int mCallState = TelephonyManager.CALL_STATE_IDLE;

    private int mVoLTEicon = 0;
    private boolean mRoamingIconAllowed;
    private boolean mDataDisabledIcon;
    private int mVoWIFIicon = 0;
    private boolean mOverride;

    public static final String VOLTE_ICON_STYLE =
            "system:" + Settings.System.VOLTE_ICON_STYLE;
    public static final String ROAMING_INDICATOR_ICON =
            "system:" + Settings.System.ROAMING_INDICATOR_ICON;
    public static final String DATA_DISABLED_ICON =
            "system:" + Settings.System.DATA_DISABLED_ICON;
    public static final String SHOW_FOURG_ICON =
            "system:" + Settings.System.SHOW_FOURG_ICON;
    public static final String VOWIFI_ICON_STYLE =
            "system:" + Settings.System.VOWIFI_ICON_STYLE;
    public static final String VOLTE_VOWIFI_OVERRIDE =
            "system:" + Settings.System.VOLTE_VOWIFI_OVERRIDE;

    // TODO: Reduce number of vars passed in, if we have the NetworkController, probably don't
    // need listener lists anymore.
    public MobileSignalController(Context context, Config config, boolean hasMobileData,
            TelephonyManager phone, CallbackHandler callbackHandler,
            NetworkControllerImpl networkController, SubscriptionInfo info,
            SubscriptionDefaults defaults, Looper receiverLooper) {
        super("MobileSignalController(" + info.getSubscriptionId() + ")", context,
                NetworkCapabilities.TRANSPORT_CELLULAR, callbackHandler,
                networkController);
        mNetworkToIconLookup = new SparseArray<>();
        mConfig = config;
        mPhone = phone;
        mDefaults = defaults;
        mSubscriptionInfo = info;
        mPhoneStateListener = new MobilePhoneStateListener(receiverLooper);
        mNetworkNameSeparator = getStringIfExists(R.string.status_bar_network_name_separator)
                .toString();
        mNetworkNameDefault = getStringIfExists(
                com.android.internal.R.string.lockscreen_carrier_default).toString();

        mapIconSets();

        String networkName = info.getCarrierName() != null ? info.getCarrierName().toString()
                : mNetworkNameDefault;
        mLastState.networkName = mCurrentState.networkName = networkName;
        mLastState.networkNameData = mCurrentState.networkNameData = networkName;
        mLastState.enabled = mCurrentState.enabled = hasMobileData;
        mLastState.iconGroup = mCurrentState.iconGroup = mDefaultIcons;
        // Get initial data sim state.
        updateDataSim();

        int phoneId = mSubscriptionInfo.getSimSlotIndex();
        mImsManagerConnector = new ImsManager.Connector(mContext, phoneId,
                new ImsManager.Connector.Listener() {
                    @Override
                    public void connectionReady(ImsManager manager) throws ImsException {
                        Log.d(mTag, "ImsManager: connection ready.");
                        mImsManager = manager;
                        setListeners();
                    }

                    @Override
                    public void connectionUnavailable() {
                        Log.d(mTag, "ImsManager: connection unavailable.");
                        removeListeners();
                    }
        });


        mObserver = new ContentObserver(new Handler(receiverLooper)) {
            @Override
            public void onChange(boolean selfChange) {
                updateTelephony();
            }
        };

        mDisplayGraceHandler = new Handler(receiverLooper) {
            @Override
            public void handleMessage(Message msg) {
                if (msg.what == MSG_DISPLAY_GRACE) {
                    mIsShowingIconGracefully = false;
                    updateTelephony();
                }
            }
        };

        Dependency.get(TunerService.class).addTunable(this, VOLTE_ICON_STYLE);
        Dependency.get(TunerService.class).addTunable(this, ROAMING_INDICATOR_ICON);
        Dependency.get(TunerService.class).addTunable(this, DATA_DISABLED_ICON);
        Dependency.get(TunerService.class).addTunable(this, SHOW_FOURG_ICON);
        Dependency.get(TunerService.class).addTunable(this, VOWIFI_ICON_STYLE);
        Dependency.get(TunerService.class).addTunable(this, VOLTE_VOWIFI_OVERRIDE);
    }

    @Override
    public void onTuningChanged(String key, String newValue) {
        switch (key) {
            case VOLTE_ICON_STYLE:
                mVoLTEicon =
                    TunerService.parseInteger(newValue, 0);
                notifyListeners();
                break;
            case ROAMING_INDICATOR_ICON:
                mRoamingIconAllowed =
                    TunerService.parseIntegerSwitch(newValue, true);
                updateTelephony();
                break;
            case DATA_DISABLED_ICON:
                mDataDisabledIcon =
                    TunerService.parseIntegerSwitch(newValue, true);
                updateTelephony();
                break;
            case SHOW_FOURG_ICON:
                mShow4gForLte =
                    TunerService.parseIntegerSwitch(newValue, false);
                mapIconSets();
                updateTelephony();
                break;
            case VOWIFI_ICON_STYLE:
                mVoWIFIicon =
                    TunerService.parseInteger(newValue, 0);
                notifyListeners();
                break;
            case VOLTE_VOWIFI_OVERRIDE:
                mOverride =
                    TunerService.parseIntegerSwitch(newValue, true);
                notifyListeners();
                break;
            default:
                break;
        }
   }

    public void setConfiguration(Config config) {
        mConfig = config;
        updateInflateSignalStrength();
        mapIconSets();
        updateTelephony();
    }

    public void setAirplaneMode(boolean airplaneMode) {
        mCurrentState.airplaneMode = airplaneMode;
        notifyListenersIfNecessary();
    }

    public void setUserSetupComplete(boolean userSetup) {
        mCurrentState.userSetup = userSetup;
        notifyListenersIfNecessary();
    }

    @Override
    public void updateConnectivity(BitSet connectedTransports, BitSet validatedTransports) {
        boolean isValidated = validatedTransports.get(mTransportType);
        mCurrentState.isDefault = connectedTransports.get(mTransportType);
        // Only show this as not having connectivity if we are default.
        mCurrentState.inetCondition = (isValidated || !mCurrentState.isDefault) ? 1 : 0;
        notifyListenersIfNecessary();
    }

    public void setCarrierNetworkChangeMode(boolean carrierNetworkChangeMode) {
        mCurrentState.carrierNetworkChangeMode = carrierNetworkChangeMode;
        updateTelephony();
    }

    /**
     * Start listening for phone state changes.
     */
    public void registerListener() {
        mPhone.listen(mPhoneStateListener,
                PhoneStateListener.LISTEN_SERVICE_STATE
                        | PhoneStateListener.LISTEN_SIGNAL_STRENGTHS
                        | PhoneStateListener.LISTEN_CALL_STATE
                        | PhoneStateListener.LISTEN_DATA_CONNECTION_STATE
                        | PhoneStateListener.LISTEN_DATA_ACTIVITY
                        | PhoneStateListener.LISTEN_CARRIER_NETWORK_CHANGE
                        | PhoneStateListener.LISTEN_ACTIVE_DATA_SUBSCRIPTION_ID_CHANGE);
        mContext.getContentResolver().registerContentObserver(Global.getUriFor(Global.MOBILE_DATA),
                true, mObserver);
        mContext.getContentResolver().registerContentObserver(Global.getUriFor(
                Global.MOBILE_DATA + mSubscriptionInfo.getSubscriptionId()),
                true, mObserver);
        mContext.registerReceiver(mVolteSwitchObserver,
                new IntentFilter("org.codeaurora.intent.action.ACTION_ENHANCE_4G_SWITCH"));
        mImsManagerConnector.connect();
    }

    /**
     * Stop listening for phone state changes.
     */
    public void unregisterListener() {
        mPhone.listen(mPhoneStateListener, 0);
        mContext.getContentResolver().unregisterContentObserver(mObserver);
        mContext.unregisterReceiver(mVolteSwitchObserver);
        mImsManagerConnector.disconnect();
    }

    /**
     * Produce a mapping of data network types to icon groups for simple and quick use in
     * updateTelephony.
     */
    private void mapIconSets() {
        mNetworkToIconLookup.clear();

        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_EVDO_0, TelephonyIcons.THREE_G);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_EVDO_A, TelephonyIcons.THREE_G);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_EVDO_B, TelephonyIcons.THREE_G);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_EHRPD, TelephonyIcons.THREE_G);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_UMTS, TelephonyIcons.THREE_G);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_TD_SCDMA, TelephonyIcons.THREE_G);

        if (!mConfig.showAtLeast3G) {
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_UNKNOWN,
                    TelephonyIcons.UNKNOWN);
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_EDGE, TelephonyIcons.E);
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_CDMA, TelephonyIcons.ONE_X);
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_1xRTT, TelephonyIcons.ONE_X);

            mDefaultIcons = TelephonyIcons.G;
        } else {
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_UNKNOWN,
                    TelephonyIcons.THREE_G);
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_EDGE,
                    TelephonyIcons.THREE_G);
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_CDMA,
                    TelephonyIcons.THREE_G);
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_1xRTT,
                    TelephonyIcons.THREE_G);
            mDefaultIcons = TelephonyIcons.THREE_G;
        }

        MobileIconGroup hGroup = TelephonyIcons.THREE_G;
        MobileIconGroup hPlusGroup = TelephonyIcons.THREE_G;
        if (mConfig.show4gFor3g) {
            hGroup = TelephonyIcons.FOUR_G;
            hPlusGroup = TelephonyIcons.FOUR_G;
        } else if (mConfig.hspaDataDistinguishable) {
            hGroup = TelephonyIcons.H;
            hPlusGroup = TelephonyIcons.H_PLUS;
        }

        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_HSDPA, hGroup);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_HSUPA, hGroup);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_HSPA, hGroup);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_HSPAP, hPlusGroup);

        if (mShow4gForLte) {
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_LTE, TelephonyIcons.FOUR_G);
            if (mConfig.hideLtePlus) {
                mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_LTE_CA,
                        TelephonyIcons.FOUR_G);
            } else {
                mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_LTE_CA,
                        TelephonyIcons.FOUR_G_PLUS);
            }
        } else {
            mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_LTE, TelephonyIcons.LTE);
            if (mConfig.hideLtePlus) {
                mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_LTE_CA,
                        TelephonyIcons.LTE);
            } else {
                mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_LTE_CA,
                        TelephonyIcons.LTE_PLUS);
            }
        }
        mNetworkToIconLookup.put(NETWORK_TYPE_LTE_CA_5GE,
                TelephonyIcons.LTE_CA_5G_E);
        mNetworkToIconLookup.put(TelephonyManager.NETWORK_TYPE_IWLAN, TelephonyIcons.WFC);
    }

    private void updateInflateSignalStrength() {
        mInflateSignalStrengths = SignalStrengthUtil.shouldInflateSignalStrength(mContext,
                mSubscriptionInfo.getSubscriptionId());
    }

    private int getNumLevels() {
        if (mInflateSignalStrengths) {
            return SignalStrength.NUM_SIGNAL_STRENGTH_BINS + 1;
        }
        return SignalStrength.NUM_SIGNAL_STRENGTH_BINS;
    }

    @Override
    public int getCurrentIconId() {
        if (mCurrentState.iconGroup == TelephonyIcons.CARRIER_NETWORK_CHANGE) {
            return SignalDrawable.getCarrierChangeState(getNumLevels());
        } else if (mCurrentState.connected) {
            int level = mCurrentState.level;
            if (mInflateSignalStrengths) {
                level++;
            }
            boolean dataDisabled = mCurrentState.userSetup
                    && (mCurrentState.iconGroup == TelephonyIcons.DATA_DISABLED
                    || (mCurrentState.iconGroup == TelephonyIcons.NOT_DEFAULT_DATA));
            boolean noInternet = mCurrentState.inetCondition == 0;
            boolean cutOut = dataDisabled || noInternet;
            return SignalDrawable.getState(level, getNumLevels(), cutOut);
        } else if (mCurrentState.enabled) {
            return SignalDrawable.getEmptyState(getNumLevels());
        } else {
            return 0;
        }
    }

    @Override
    public int getQsCurrentIconId() {
        return getCurrentIconId();
    }

    private int getVolteVowifiResId() {
        int resId = 0;

        if (mOverride && mConfig.showVowifiIcon && mVoWIFIicon > 0 && isVowifiAvailable()) {
            if (!isCallIdle()) {
                resId = R.drawable.ic_vowifi_calling;
            } else {
                switch (mVoWIFIicon) {
                    case 1:
                    default:
                        resId = R.drawable.ic_vowifi;
                        break;
                    case 2:
                        resId = R.drawable.ic_vowifi_oneplus;
                        break;
                    case 3:
                        resId = R.drawable.ic_vowifi_moto;
                        break;
                    case 4:
                        resId = R.drawable.ic_vowifi_asus;
                        break;
                    case 5:
                        resId = R.drawable.ic_vowifi_emui;
                        break;
                }
            }
        } else if (mImsManager != null && mConfig.showVolteIcon && mVoLTEicon > 0 && isVolteAvailable()) {
            switch (mVoLTEicon) {
                case 1:
                default:
                    resId = R.drawable.ic_volte1;
                    break;
                case 2:
                    resId = R.drawable.ic_volte2;
                    break;
                case 3:
                    resId = R.drawable.ic_volte3;
                    break;
                case 4:
                    resId = R.drawable.ic_volte4;
                    break;
                case 5:
                    resId = R.drawable.ic_volte5;
                    break;
                case 6:
                    resId = R.drawable.ic_volte6;
                    break;
                case 7:
                    resId = R.drawable.ic_volte7;
                    break;
                case 8:
                    resId = R.drawable.ic_volte8; // EMUI icon
                    break;
            }
        }
        return resId;
    }

    private void setListeners() {
        if (mImsManager == null) {
            Log.e(mTag, "setListeners mImsManager is null");
            return;
        }

        try {
            mImsManager.addCapabilitiesCallback(mCapabilityCallback);
            mImsManager.addRegistrationCallback(mImsRegistrationCallback);
            Log.d(mTag, "addCapabilitiesCallback " + mCapabilityCallback + " into " + mImsManager);
            Log.d(mTag, "addRegistrationCallback " + mImsRegistrationCallback
                    + " into " + mImsManager);
        } catch (ImsException e) {
            Log.d(mTag, "unable to addCapabilitiesCallback callback.");
        }
        queryImsState();
    }

    private void queryImsState() {
        TelephonyManager tm = mPhone.createForSubscriptionId(mSubscriptionInfo.getSubscriptionId());
        mCurrentState.voiceCapable = tm.isVolteAvailable();
        mCurrentState.videoCapable = tm.isVideoTelephonyAvailable();
        mCurrentState.imsRegistered = mPhone.isImsRegistered(mSubscriptionInfo.getSubscriptionId());
        if (DEBUG) {
            Log.d(mTag, "queryImsState tm=" + tm + " phone=" + mPhone
                    + " voiceCapable=" + mCurrentState.voiceCapable
                    + " videoCapable=" + mCurrentState.videoCapable
                    + " imsResitered=" + mCurrentState.imsRegistered);
        }
        notifyListenersIfNecessary();
    }

    private void removeListeners() {
        if (mImsManager == null) {
            Log.e(mTag, "removeListeners mImsManager is null");
            return;
        }

        try {
            mImsManager.removeCapabilitiesCallback(mCapabilityCallback);
            mImsManager.removeRegistrationListener(mImsRegistrationCallback);
            Log.d(mTag, "removeCapabilitiesCallback " + mCapabilityCallback
                    + " from " + mImsManager);
            Log.d(mTag, "removeRegistrationCallback " + mImsRegistrationCallback
                    + " from " + mImsManager);
        } catch (ImsException e) {
            Log.d(mTag, "unable to remove callback.");
        }
    }

    @Override
    public void notifyListeners(SignalCallback callback) {
        MobileIconGroup icons = getIcons();

        String contentDescription = getStringIfExists(getContentDescription()).toString();
        CharSequence dataContentDescriptionHtml = getStringIfExists(icons.mDataContentDescription);

        //TODO: Hacky
        // The data content description can sometimes be shown in a text view and might come to us
        // as HTML. Strip any styling here so that listeners don't have to care
        CharSequence dataContentDescription = Html.fromHtml(
                dataContentDescriptionHtml.toString(), 0).toString();
        if (mCurrentState.inetCondition == 0) {
            dataContentDescription = mContext.getString(R.string.data_connection_no_internet);
        }
        final boolean dataDisabled = (mCurrentState.iconGroup == TelephonyIcons.DATA_DISABLED
                || (mCurrentState.iconGroup == TelephonyIcons.NOT_DEFAULT_DATA))
                && mCurrentState.userSetup;

        // Show icon in QS when we are connected or data is disabled.
        boolean showDataIcon = mCurrentState.dataConnected || dataDisabled;
        IconState statusIcon = new IconState(mCurrentState.enabled && !mCurrentState.airplaneMode,
                getCurrentIconId(), contentDescription);

        int qsTypeIcon = 0;
        IconState qsIcon = null;
        CharSequence description = null;
        // Only send data sim callbacks to QS.
        if (mCurrentState.dataSim) {
            qsTypeIcon = (showDataIcon || mConfig.alwaysShowDataRatIcon) ? icons.mQsDataType : 0;
            qsIcon = new IconState(mCurrentState.enabled
                    && !mCurrentState.isEmergency, getQsCurrentIconId(), contentDescription);
            description = mCurrentState.isEmergency ? null : mCurrentState.networkName;
        }
        boolean activityIn = mCurrentState.dataConnected
                && !mCurrentState.carrierNetworkChangeMode
                && mCurrentState.activityIn;
        boolean activityOut = mCurrentState.dataConnected
                && !mCurrentState.carrierNetworkChangeMode
                && mCurrentState.activityOut;
        showDataIcon &= mCurrentState.isDefault || dataDisabled;
        int typeIcon = (showDataIcon || mConfig.alwaysShowDataRatIcon) ? icons.mDataType : 0;
        int voltewifiIcon = getVolteVowifiResId();

        MobileIconGroup vowifiIconGroup = getVowifiIconGroup();
        if (mConfig.showVowifiIcon && vowifiIconGroup != null) {
            typeIcon = vowifiIconGroup.mDataType;
            statusIcon = new IconState(true,
                    mCurrentState.enabled && !mCurrentState.airplaneMode? statusIcon.icon : 0,
                    statusIcon.contentDescription);
        }

        callback.setMobileDataIndicators(statusIcon, qsIcon, typeIcon, qsTypeIcon,
                activityIn, activityOut, voltewifiIcon, dataContentDescription, dataContentDescriptionHtml,
                description, icons.mIsWide, mSubscriptionInfo.getSubscriptionId(),
                mCurrentState.roaming);
    }

    @Override
    protected MobileState cleanState() {
        return new MobileState();
    }

    private boolean isCdma() {
        return (mSignalStrength != null) && !mSignalStrength.isGsm();
    }

    public boolean isEmergencyOnly() {
        return (mServiceState != null && mServiceState.isEmergencyOnly());
    }

    private boolean isRoaming() {
        // During a carrier change, roaming indications need to be supressed.
        if (isCarrierNetworkChangeActive()) {
            return false;
        }
        if (isCdma() && mServiceState != null) {
            final int iconMode = mServiceState.getCdmaEriIconMode();
            return mServiceState.getCdmaEriIconIndex() != EriInfo.ROAMING_INDICATOR_OFF
                    && (iconMode == EriInfo.ROAMING_ICON_MODE_NORMAL
                    || iconMode == EriInfo.ROAMING_ICON_MODE_FLASH);
        } else {
            return mServiceState != null && mServiceState.getRoaming();
        }
    }

    private boolean isCarrierNetworkChangeActive() {
        return mCurrentState.carrierNetworkChangeMode;
    }

    public void handleBroadcast(Intent intent) {
        String action = intent.getAction();
        if (action.equals(TelephonyIntents.SPN_STRINGS_UPDATED_ACTION)) {
            updateNetworkName(intent.getBooleanExtra(TelephonyIntents.EXTRA_SHOW_SPN, false),
                    intent.getStringExtra(TelephonyIntents.EXTRA_SPN),
                    intent.getStringExtra(TelephonyIntents.EXTRA_DATA_SPN),
                    intent.getBooleanExtra(TelephonyIntents.EXTRA_SHOW_PLMN, false),
                    intent.getStringExtra(TelephonyIntents.EXTRA_PLMN));
            notifyListenersIfNecessary();
        } else if (action.equals(TelephonyIntents.ACTION_DEFAULT_DATA_SUBSCRIPTION_CHANGED)) {
            updateDataSim();
            notifyListenersIfNecessary();
        }
    }

    private void updateDataSim() {
        int activeDataSubId = mDefaults.getActiveDataSubId();
        if (SubscriptionManager.isValidSubscriptionId(activeDataSubId)) {
            mCurrentState.dataSim = activeDataSubId == mSubscriptionInfo.getSubscriptionId();
        } else {
            // There doesn't seem to be a data sim selected, however if
            // there isn't a MobileSignalController with dataSim set, then
            // QS won't get any callbacks and will be blank.  Instead
            // lets just assume we are the data sim (which will basically
            // show one at random) in QS until one is selected.  The user
            // should pick one soon after, so we shouldn't be in this state
            // for long.
            mCurrentState.dataSim = true;
        }
    }

    private boolean isCarrierSpecificDataIcon() {
        if (mConfig.patternOfCarrierSpecificDataIcon == null
                || mConfig.patternOfCarrierSpecificDataIcon.length() == 0) {
            return false;
        }

        Pattern stringPattern = Pattern.compile(mConfig.patternOfCarrierSpecificDataIcon);
        String[] operatorNames = new String[]{mServiceState.getOperatorAlphaLongRaw(),
                mServiceState.getOperatorAlphaShortRaw()};
        for (String opName : operatorNames) {
            if (!TextUtils.isEmpty(opName)) {
                Matcher matcher = stringPattern.matcher(opName);
                if (matcher.find()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Updates the network's name based on incoming spn and plmn.
     */
    void updateNetworkName(boolean showSpn, String spn, String dataSpn,
            boolean showPlmn, String plmn) {
        if (CHATTY) {
            Log.d("CarrierLabel", "updateNetworkName showSpn=" + showSpn
                    + " spn=" + spn + " dataSpn=" + dataSpn
                    + " showPlmn=" + showPlmn + " plmn=" + plmn);
        }
        StringBuilder str = new StringBuilder();
        StringBuilder strData = new StringBuilder();
        if (showPlmn && plmn != null) {
            str.append(plmn);
            strData.append(plmn);
        }
        if (showSpn && spn != null) {
            if (str.length() != 0) {
                str.append(mNetworkNameSeparator);
            }
            str.append(spn);
        }
        if (str.length() != 0) {
            mCurrentState.networkName = str.toString();
        } else {
            mCurrentState.networkName = mNetworkNameDefault;
        }
        if (showSpn && dataSpn != null) {
            if (strData.length() != 0) {
                strData.append(mNetworkNameSeparator);
            }
            strData.append(dataSpn);
        }
        if (strData.length() != 0) {
            mCurrentState.networkNameData = strData.toString();
        } else {
            mCurrentState.networkNameData = mNetworkNameDefault;
        }
    }

    /**
     * Updates the current state based on mServiceState, mSignalStrength, mDataNetType,
     * mDataState, and mSimState.  It should be called any time one of these is updated.
     * This will call listeners if necessary.
     */
    private final void updateTelephony() {
        if (DEBUG) {
            Log.d(mTag, "updateTelephonySignalStrength: hasService=" +
                    Utils.isInService(mServiceState) + " ss=" + mSignalStrength);
        }
        checkDefaultData();
        mCurrentState.connected = Utils.isInService(mServiceState)
                && mSignalStrength != null;
        if (mCurrentState.connected) {
            if (!mSignalStrength.isGsm() && mConfig.alwaysShowCdmaRssi) {
                mCurrentState.level = mSignalStrength.getCdmaLevel();
            } else {
                mCurrentState.level = mSignalStrength.getLevel();
            }
        }

        // When the device is camped on a 5G Non-Standalone network, the data network type is still
        // LTE. In this case, we first check which 5G icon should be shown.
        MobileIconGroup nr5GIconGroup = getNr5GIconGroup();
        if (mConfig.nrIconDisplayGracePeriodMs > 0) {
            nr5GIconGroup = adjustNr5GIconGroupByDisplayGraceTime(nr5GIconGroup);
        }

        if (nr5GIconGroup != null) {
            mCurrentState.iconGroup = nr5GIconGroup;
        } else if (mNetworkToIconLookup.indexOfKey(mDataNetType) >= 0) {
            mCurrentState.iconGroup = mNetworkToIconLookup.get(mDataNetType);
        } else {
            mCurrentState.iconGroup = mDefaultIcons;
        }
        mCurrentState.dataConnected = mCurrentState.connected
                && mDataState == TelephonyManager.DATA_CONNECTED;

        mCurrentState.roaming = isRoaming() && mRoamingIconAllowed;
        if (isCarrierNetworkChangeActive()) {
            mCurrentState.iconGroup = TelephonyIcons.CARRIER_NETWORK_CHANGE;
        } else if (isDataDisabled() && mDataDisabledIcon) {
            if (mSubscriptionInfo.getSubscriptionId()
                    != mDefaults.getDefaultDataSubId()) {
                mCurrentState.iconGroup = TelephonyIcons.NOT_DEFAULT_DATA;
            } else {
                mCurrentState.iconGroup = TelephonyIcons.DATA_DISABLED;
            }
        }
        if (isEmergencyOnly() != mCurrentState.isEmergency) {
            mCurrentState.isEmergency = isEmergencyOnly();
            mNetworkController.recalculateEmergency();
        }
        // Fill in the network name if we think we have it.
        if (mCurrentState.networkName.equals(mNetworkNameDefault) && mServiceState != null
                && !TextUtils.isEmpty(mServiceState.getOperatorAlphaShort())) {
            mCurrentState.networkName = mServiceState.getOperatorAlphaShort();
        }
        // If this is the data subscription, update the currentState data name
        if (mCurrentState.networkNameData.equals(mNetworkNameDefault) && mServiceState != null
                && mCurrentState.dataSim
                && !TextUtils.isEmpty(mServiceState.getDataOperatorAlphaShort())) {
            mCurrentState.networkNameData = mServiceState.getDataOperatorAlphaShort();
        }

        notifyListenersIfNecessary();
    }

    /**
     * If we are controlling the NOT_DEFAULT_DATA icon, check the status of the other one
     */
    private void checkDefaultData() {
        if (mCurrentState.iconGroup != TelephonyIcons.NOT_DEFAULT_DATA) {
            mCurrentState.defaultDataOff = false;
            return;
        }

        mCurrentState.defaultDataOff = mNetworkController.isDataControllerDisabled();
    }

    void onMobileDataChanged() {
        checkDefaultData();
        notifyListenersIfNecessary();
    }

    private MobileIconGroup getNr5GIconGroup() {
        if (mServiceState == null) return null;

        int nrState = mServiceState.getNrState();
        if (nrState == NetworkRegistrationInfo.NR_STATE_CONNECTED) {
            // Check if the NR 5G is using millimeter wave and the icon is config.
            if (mServiceState.getNrFrequencyRange() == ServiceState.FREQUENCY_RANGE_MMWAVE) {
                if (mConfig.nr5GIconMap.containsKey(Config.NR_CONNECTED_MMWAVE)) {
                    return mConfig.nr5GIconMap.get(Config.NR_CONNECTED_MMWAVE);
                }
            }

            // If NR 5G is not using millimeter wave or there is no icon for millimeter wave, we
            // check the normal 5G icon.
            if (mConfig.nr5GIconMap.containsKey(Config.NR_CONNECTED)) {
                return mConfig.nr5GIconMap.get(Config.NR_CONNECTED);
            }
        } else if (nrState == NetworkRegistrationInfo.NR_STATE_NOT_RESTRICTED) {
            if (mCurrentState.activityDormant) {
                if (mConfig.nr5GIconMap.containsKey(Config.NR_NOT_RESTRICTED_RRC_IDLE)) {
                    return mConfig.nr5GIconMap.get(Config.NR_NOT_RESTRICTED_RRC_IDLE);
                }
            } else {
                if (mConfig.nr5GIconMap.containsKey(Config.NR_NOT_RESTRICTED_RRC_CON)) {
                    return mConfig.nr5GIconMap.get(Config.NR_NOT_RESTRICTED_RRC_CON);
                }
            }
        } else if (nrState == NetworkRegistrationInfo.NR_STATE_RESTRICTED) {
            if (mConfig.nr5GIconMap.containsKey(Config.NR_RESTRICTED)) {
                return mConfig.nr5GIconMap.get(Config.NR_RESTRICTED);
            }
        }

        return null;
    }

    /**
     * The function to adjust MobileIconGroup depend on CarrierConfig's time
     * nextIconGroup == null imply next state could be 2G/3G/4G/4G+
     * nextIconGroup != null imply next state will be 5G/5G+
     * Flag : mIsShowingIconGracefully
     * ---------------------------------------------------------------------------------
     * |   Last state   |  Current state  | Flag |       Action                        |
     * ---------------------------------------------------------------------------------
     * |     5G/5G+     | 2G/3G/4G/4G+    | true | return previous IconGroup           |
     * |     5G/5G+     |     5G/5G+      | true | Bypass                              |
     * |  2G/3G/4G/4G+  |     5G/5G+      | true | Bypass                              |
     * |  2G/3G/4G/4G+  | 2G/3G/4G/4G+    | true | Bypass                              |
     * |  SS.connected  | SS.disconnect   |  T|F | Reset timer                         |
     * |NETWORK_TYPE_LTE|!NETWORK_TYPE_LTE|  T|F | Reset timer                         |
     * |     5G/5G+     | 2G/3G/4G/4G+    | false| Bypass                              |
     * |     5G/5G+     |     5G/5G+      | false| Bypass                              |
     * |  2G/3G/4G/4G+  |     5G/5G+      | false| SendMessageDelay(time), flag->true  |
     * |  2G/3G/4G/4G+  | 2G/3G/4G/4G+    | false| Bypass                              |
     * ---------------------------------------------------------------------------------
     */
    private MobileIconGroup adjustNr5GIconGroupByDisplayGraceTime(
            MobileIconGroup candidateIconGroup) {
        if (mIsShowingIconGracefully && candidateIconGroup == null) {
            candidateIconGroup = (MobileIconGroup) mCurrentState.iconGroup;
        } else if (!mIsShowingIconGracefully && candidateIconGroup != null
                && mLastState.iconGroup != candidateIconGroup) {
            mDisplayGraceHandler.sendMessageDelayed(
                    mDisplayGraceHandler.obtainMessage(MSG_DISPLAY_GRACE),
                    mConfig.nrIconDisplayGracePeriodMs);
            mIsShowingIconGracefully = true;
        } else if (!mCurrentState.connected || mDataState == TelephonyManager.DATA_DISCONNECTED
                || candidateIconGroup == null) {
            mDisplayGraceHandler.removeMessages(MSG_DISPLAY_GRACE);
            mIsShowingIconGracefully = false;
            candidateIconGroup = null;
        }

        return candidateIconGroup;
    }

    boolean isDataDisabled() {
        return !mPhone.isDataCapable();
    }

    @VisibleForTesting
    void setActivity(int activity) {
        mCurrentState.activityIn = activity == TelephonyManager.DATA_ACTIVITY_INOUT
                || activity == TelephonyManager.DATA_ACTIVITY_IN;
        mCurrentState.activityOut = activity == TelephonyManager.DATA_ACTIVITY_INOUT
                || activity == TelephonyManager.DATA_ACTIVITY_OUT;
        mCurrentState.activityDormant = activity == TelephonyManager.DATA_ACTIVITY_DORMANT;

        notifyListenersIfNecessary();
    }

    private boolean isCallIdle() {
        return mCallState == TelephonyManager.CALL_STATE_IDLE;
    }

    private boolean isVolteAvailable() {
        return (mCurrentState.voiceCapable || mCurrentState.videoCapable) &&  mCurrentState.imsRegistered;
    }

    private boolean isVowifiAvailable() {
        return isVolteAvailable()
                && mServiceState.getDataNetworkType() == TelephonyManager.NETWORK_TYPE_IWLAN;
    }

    private MobileIconGroup getVowifiIconGroup() {
        if (mVoWIFIicon == 0 || mOverride) return null;

        if (isVowifiAvailable() && !isCallIdle()) {
            return TelephonyIcons.VOWIFI_CALLING;
        } else if (isVowifiAvailable()) {
            switch (mVoWIFIicon) {
                case 1:
                default:
                    return TelephonyIcons.VOWIFI;
                // OOS
                case 2:
                    return TelephonyIcons.VOWIFI_ONEPLUS;
                // Motorola
                case 3:
                    return TelephonyIcons.VOWIFI_MOTO;
                // ASUS
                case 4:
                    return TelephonyIcons.VOWIFI_ASUS;
                // EMUI (Huawei P10)
                case 5:
                    return TelephonyIcons.VOWIFI_EMUI;
            }
        } else {
            return null;
        }
    }

    @Override
    public void dump(PrintWriter pw) {
        super.dump(pw);
        pw.println("  mSubscription=" + mSubscriptionInfo + ",");
        pw.println("  mServiceState=" + mServiceState + ",");
        pw.println("  mSignalStrength=" + mSignalStrength + ",");
        pw.println("  mDataState=" + mDataState + ",");
        pw.println("  mDataNetType=" + mDataNetType + ",");
        pw.println("  mInflateSignalStrengths=" + mInflateSignalStrengths + ",");
        pw.println("  isDataDisabled=" + isDataDisabled() + ",");
        pw.println("  mIsShowingIconGracefully=" + mIsShowingIconGracefully + ",");
    }

    class MobilePhoneStateListener extends PhoneStateListener {
        public MobilePhoneStateListener(Looper looper) {
            super(looper);
        }

        @Override
        public void onSignalStrengthsChanged(SignalStrength signalStrength) {
            if (DEBUG) {
                Log.d(mTag, "onSignalStrengthsChanged signalStrength=" + signalStrength +
                        ((signalStrength == null) ? "" : (" level=" + signalStrength.getLevel())));
            }
            mSignalStrength = signalStrength;
            updateTelephony();
        }

        @Override
        public void onServiceStateChanged(ServiceState state) {
            if (DEBUG) {
                Log.d(mTag, "onServiceStateChanged voiceState=" + state.getVoiceRegState()
                        + " dataState=" + state.getDataRegState());
            }
            mServiceState = state;
            if (mServiceState != null) {
                updateDataNetType(mServiceState.getDataNetworkType());
            }
            updateTelephony();
        }

        @Override
        public void onDataConnectionStateChanged(int state, int networkType) {
            if (DEBUG) {
                Log.d(mTag, "onDataConnectionStateChanged: state=" + state
                        + " type=" + networkType);
            }
            mDataState = state;
            updateDataNetType(networkType);
            updateTelephony();
        }

        private void updateDataNetType(int networkType) {
            mDataNetType = networkType;
            if (mDataNetType == TelephonyManager.NETWORK_TYPE_LTE) {
                if (isCarrierSpecificDataIcon()) {
                    mDataNetType = NETWORK_TYPE_LTE_CA_5GE;
                } else if (mServiceState != null && mServiceState.isUsingCarrierAggregation()) {
                    mDataNetType = TelephonyManager.NETWORK_TYPE_LTE_CA;
                }
            }
        }

        @Override
        public void onDataActivity(int direction) {
            if (DEBUG) {
                Log.d(mTag, "onDataActivity: direction=" + direction);
            }
            setActivity(direction);
        }

        @Override
        public void onCarrierNetworkChange(boolean active) {
            if (DEBUG) {
                Log.d(mTag, "onCarrierNetworkChange: active=" + active);
            }
            mCurrentState.carrierNetworkChangeMode = active;

            updateTelephony();
        }

        @Override
        public void onActiveDataSubscriptionIdChanged(int subId) {
            if (DEBUG) Log.d(mTag, "onActiveDataSubscriptionIdChanged: subId=" + subId);
            updateDataSim();
            updateTelephony();
        }

        @Override
        public void onCallStateChanged(int state, String phoneNumber) {
            if (DEBUG) {
                Log.d(mTag, "onCallStateChanged: state=" + state);
            }
            mCallState = state;
            updateTelephony();
        }
    };

    private ImsMmTelManager.CapabilityCallback mCapabilityCallback = new ImsMmTelManager.CapabilityCallback() {
        @Override
        public void onCapabilitiesStatusChanged(MmTelFeature.MmTelCapabilities config) {
            mCurrentState.voiceCapable =
                    config.isCapable(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VOICE);
            mCurrentState.videoCapable =
                    config.isCapable(MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_VIDEO);
            Log.d(mTag, "onCapabilitiesStatusChanged isVoiceCapable=" + mCurrentState.voiceCapable
                    + " isVideoCapable=" + mCurrentState.videoCapable);
            notifyListenersIfNecessary();
        }
    };

    private final ImsMmTelManager.RegistrationCallback mImsRegistrationCallback =
            new ImsMmTelManager.RegistrationCallback() {
                @Override
                public void onRegistered(int imsTransportType) {
                    Log.d(mTag, "onRegistered imsTransportType=" + imsTransportType);
                    mCurrentState.imsRegistered = true;
                    notifyListenersIfNecessary();
                }

                @Override
                public void onRegistering(int imsTransportType) {
                    Log.d(mTag, "onRegistering imsTransportType=" + imsTransportType);
                    mCurrentState.imsRegistered = false;
                    notifyListenersIfNecessary();
                }

                @Override
                public void onUnregistered(ImsReasonInfo info) {
                    Log.d(mTag, "onDeregistered imsReasonInfo=" + info);
                    mCurrentState.imsRegistered = false;
                    notifyListenersIfNecessary();
                }
    };

    private final BroadcastReceiver mVolteSwitchObserver = new BroadcastReceiver() {
        public void onReceive(Context context, Intent intent) {
            Log.d(mTag, "action=" + intent.getAction());
            if ( mConfig.showVolteIcon ) {
                notifyListeners();
            }
        }
    };

    static class MobileIconGroup extends SignalController.IconGroup {
        final int mDataContentDescription; // mContentDescriptionDataType
        final int mDataType;
        final boolean mIsWide;
        final int mQsDataType;

        public MobileIconGroup(String name, int[][] sbIcons, int[][] qsIcons, int[] contentDesc,
                int sbNullState, int qsNullState, int sbDiscState, int qsDiscState,
                int discContentDesc, int dataContentDesc, int dataType, boolean isWide) {
            super(name, sbIcons, qsIcons, contentDesc, sbNullState, qsNullState, sbDiscState,
                    qsDiscState, discContentDesc);
            mDataContentDescription = dataContentDesc;
            mDataType = dataType;
            mIsWide = isWide;
            mQsDataType = dataType; // TODO: remove this field
        }
    }

    static class MobileState extends SignalController.State {
        String networkName;
        String networkNameData;
        boolean dataSim;
        boolean dataConnected;
        boolean isEmergency;
        boolean airplaneMode;
        boolean carrierNetworkChangeMode;
        boolean isDefault;
        boolean userSetup;
        boolean roaming;
        boolean defaultDataOff;  // Tracks the on/off state of the defaultDataSubscription
        boolean imsRegistered;
        boolean voiceCapable;
        boolean videoCapable;

        @Override
        public void copyFrom(State s) {
            super.copyFrom(s);
            MobileState state = (MobileState) s;
            dataSim = state.dataSim;
            networkName = state.networkName;
            networkNameData = state.networkNameData;
            dataConnected = state.dataConnected;
            isDefault = state.isDefault;
            isEmergency = state.isEmergency;
            airplaneMode = state.airplaneMode;
            carrierNetworkChangeMode = state.carrierNetworkChangeMode;
            userSetup = state.userSetup;
            roaming = state.roaming;
            defaultDataOff = state.defaultDataOff;
            imsRegistered = state.imsRegistered;
            voiceCapable = state.voiceCapable;
            videoCapable = state.videoCapable;
        }

        @Override
        protected void toString(StringBuilder builder) {
            super.toString(builder);
            builder.append(',');
            builder.append("dataSim=").append(dataSim).append(',');
            builder.append("networkName=").append(networkName).append(',');
            builder.append("networkNameData=").append(networkNameData).append(',');
            builder.append("dataConnected=").append(dataConnected).append(',');
            builder.append("roaming=").append(roaming).append(',');
            builder.append("isDefault=").append(isDefault).append(',');
            builder.append("isEmergency=").append(isEmergency).append(',');
            builder.append("airplaneMode=").append(airplaneMode).append(',');
            builder.append("carrierNetworkChangeMode=").append(carrierNetworkChangeMode)
                    .append(',');
            builder.append("userSetup=").append(userSetup).append(',');
            builder.append("defaultDataOff=").append(defaultDataOff);
            builder.append("imsRegistered=").append(imsRegistered).append(',');
            builder.append("voiceCapable=").append(voiceCapable).append(',');
            builder.append("videoCapable=").append(videoCapable);
        }

        @Override
        public boolean equals(Object o) {
            return super.equals(o)
                    && Objects.equals(((MobileState) o).networkName, networkName)
                    && Objects.equals(((MobileState) o).networkNameData, networkNameData)
                    && ((MobileState) o).dataSim == dataSim
                    && ((MobileState) o).dataConnected == dataConnected
                    && ((MobileState) o).isEmergency == isEmergency
                    && ((MobileState) o).airplaneMode == airplaneMode
                    && ((MobileState) o).carrierNetworkChangeMode == carrierNetworkChangeMode
                    && ((MobileState) o).userSetup == userSetup
                    && ((MobileState) o).isDefault == isDefault
                    && ((MobileState) o).roaming == roaming
                    && ((MobileState) o).defaultDataOff == defaultDataOff
                    && ((MobileState) o).imsRegistered == imsRegistered
                    && ((MobileState) o).voiceCapable == voiceCapable
                    && ((MobileState) o).videoCapable == videoCapable;
        }
    }
}
