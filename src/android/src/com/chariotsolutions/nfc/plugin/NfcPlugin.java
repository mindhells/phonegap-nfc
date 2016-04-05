package com.chariotsolutions.nfc.plugin;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

// using wildcard imports so we can support Cordova 3.x
import org.apache.cordova.*; // Cordova 3.x

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.graphics.Bitmap;
import android.net.Uri;
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Base64;
import android.util.Log;

import com.dnielectura.jj2000.J2kStreamDecoder;

import es.gob.jmulticard.jse.provider.MrtdKeyStoreImpl;

import java.security.KeyStoreSpi;
import java.security.Security;
import java.util.Vector;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import de.tsenger.androsmex.data.CANSpecDO;
import de.tsenger.androsmex.data.CANSpecDOStore;
import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import de.tsenger.androsmex.mrtd.EF_COM;
import de.tsenger.androsmex.pace.PaceException;
import es.gob.jmulticard.card.dnie.FakeX509Certificate;
import es.gob.jmulticard.jse.provider.DnieKeyStore;
import es.gob.jmulticard.jse.provider.DnieProvider;
import es.gob.jmulticard.jse.provider.MrtdKeyStoreImpl;

import es.gob.jmulticard.jse.provider.MrtdPrivateKey;
import es.gob.jmulticard.jse.smartcardio.SmartCardMRTDConnection;
import es.gob.jmulticard.ui.passwordcallback.DNIeDialogManager;
import es.inteco.labs.net.DNIeCaCertsManager;

public class NfcPlugin extends CordovaPlugin implements NfcAdapter.OnNdefPushCompleteCallback, NfcAdapter.ReaderCallback {
    private static final String REGISTER_MIME_TYPE = "registerMimeType";
    private static final String REMOVE_MIME_TYPE = "removeMimeType";
    private static final String REGISTER_NDEF = "registerNdef";
    private static final String REMOVE_NDEF = "removeNdef";
    private static final String REGISTER_NDEF_FORMATABLE = "registerNdefFormatable";
    private static final String REGISTER_DEFAULT_TAG = "registerTag";
    private static final String REMOVE_DEFAULT_TAG = "removeTag";
    private static final String WRITE_TAG = "writeTag";
    private static final String MAKE_READ_ONLY = "makeReadOnly";
    private static final String ERASE_TAG = "eraseTag";
    private static final String SHARE_TAG = "shareTag";
    private static final String UNSHARE_TAG = "unshareTag";
    private static final String HANDOVER = "handover"; // Android Beam
    private static final String STOP_HANDOVER = "stopHandover";
    private static final String ENABLED = "enabled";
    private static final String INIT = "init";
    private static final String SHOW_SETTINGS = "showSettings";

    private static final String GET_CANS = "getCans";
    private static final String ADD_CAN = "addCan";
    private static final String DELETE_CAN = "deleteCan";

    private static final String NDEF = "ndef";
    private static final String NDEF_MIME = "ndef-mime";
    private static final String NDEF_FORMATABLE = "ndef-formatable";
    private static final String TAG_DEFAULT = "tag";

    private static final String STATUS_NFC_OK = "NFC_OK";
    private static final String STATUS_NO_NFC = "NO_NFC";
    private static final String STATUS_NFC_DISABLED = "NFC_DISABLED";
    private static final String STATUS_NDEF_PUSH_DISABLED = "NDEF_PUSH_DISABLED";

    private static final String TAG = "NfcPlugin";
    private final List<IntentFilter> intentFilters = new ArrayList<IntentFilter>();
    private final ArrayList<String[]> techLists = new ArrayList<String[]>();

    private NdefMessage p2pMessage = null;
    private PendingIntent pendingIntent = null;

    private Intent savedIntent = null;

    private CallbackContext shareTagCallback;
    private CallbackContext handoverCallback;

    private CANSpecDO selectedCan;

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {

        Log.d(TAG, "execute " + action);

        // showSettings can be called if NFC is disabled
        // might want to skip this if NO_NFC
        if (action.equalsIgnoreCase(SHOW_SETTINGS)) {
            showSettings(callbackContext);
            return true;
        }

        if (!getNfcStatus().equals(STATUS_NFC_OK)) {
            callbackContext.error(getNfcStatus());
            return true; // short circuit
        }

        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

        if (action.equalsIgnoreCase(INIT)) {
            //init(callbackContext);
            nfcAdapter.setNdefPushMessage(null, getActivity());
            nfcAdapter.setNdefPushMessageCallback(null, getActivity());
            callbackContext.success();
        }

        if (action.equals(REGISTER_DEFAULT_TAG)) {
            selectedCan = null;
            String newCode = data.getString(0);
            CANSpecDOStore cansDO = new CANSpecDOStore(getActivity());
            Vector<CANSpecDO> cans = cansDO.getAll();
            for (CANSpecDO can: cans){
                if (can.getCanNumber().equals(newCode)){
                    selectedCan = can;
                    break;
                }
            }
            if (selectedCan == null)
                selectedCan = new CANSpecDO(newCode, "", "");
            Bundle options = new Bundle();
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 10000); //10 seconds
            nfcAdapter.enableReaderMode(
                    getActivity(),
                    this,
                    NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                    options);
            callbackContext.success();
        }  else if (action.equals(REMOVE_DEFAULT_TAG)) {
            nfcAdapter.disableReaderMode(getActivity());
            callbackContext.success();
        }

        if (action.equals(GET_CANS)){
            CANSpecDOStore cansDO = new CANSpecDOStore(getActivity());
            Vector<CANSpecDO> cans = cansDO.getAll();
            JSONArray result = new JSONArray();
            for (CANSpecDO can: cans){
                JSONObject jcan = new JSONObject();
                jcan.put("number", can.getCanNumber());
                jcan.put("name", can.getUserName());
                jcan.put("id", can.getUserNif());
                result.put(jcan);
            }
            callbackContext.success(result);
        } else if (action.equals(ADD_CAN)){
            String newCode = data.getString(0);
            CANSpecDOStore cansDO = new CANSpecDOStore(getActivity());
            CANSpecDO newCan = new CANSpecDO(newCode, "", "");
            cansDO.save(newCan);
            callbackContext.success();
        } else if (action.equals(DELETE_CAN)) {
            String newCode = data.getString(0);
            CANSpecDOStore cansDO = new CANSpecDOStore(getActivity());
            CANSpecDO newCan = new CANSpecDO(newCode, "", "");
            cansDO.delete(newCan);
            callbackContext.success();
        }



        /*
        createPendingIntent();

        if (action.equalsIgnoreCase(REGISTER_MIME_TYPE)) {
            registerMimeType(data, callbackContext);

        } else if (action.equalsIgnoreCase(REMOVE_MIME_TYPE)) {
          removeMimeType(data, callbackContext);

        } else if (action.equalsIgnoreCase(REGISTER_NDEF)) {
          registerNdef(callbackContext);

        } else if (action.equalsIgnoreCase(REMOVE_NDEF)) {
          removeNdef(callbackContext);

        } else if (action.equalsIgnoreCase(REGISTER_NDEF_FORMATABLE)) {
            registerNdefFormatable(callbackContext);

        }  else if (action.equals(REGISTER_DEFAULT_TAG)) {
          registerDefaultTag(callbackContext);

        }  else if (action.equals(REMOVE_DEFAULT_TAG)) {
          removeDefaultTag(callbackContext);

        } else if (action.equalsIgnoreCase(WRITE_TAG)) {
            writeTag(data, callbackContext);

        } else if (action.equalsIgnoreCase(MAKE_READ_ONLY)) {
            makeReadOnly(callbackContext);

        } else if (action.equalsIgnoreCase(ERASE_TAG)) {
            eraseTag(callbackContext);

        } else if (action.equalsIgnoreCase(SHARE_TAG)) {
            shareTag(data, callbackContext);

        } else if (action.equalsIgnoreCase(UNSHARE_TAG)) {
            unshareTag(callbackContext);

        } else if (action.equalsIgnoreCase(HANDOVER)) {
            handover(data, callbackContext);

        } else if (action.equalsIgnoreCase(STOP_HANDOVER)) {
            stopHandover(callbackContext);

        } else if (action.equalsIgnoreCase(INIT)) {
            init(callbackContext);

        } else if (action.equalsIgnoreCase(ENABLED)) {
            // status is checked before every call
            // if code made it here, NFC is enabled
            callbackContext.success(STATUS_NFC_OK);

        } else {
            // invalid action
            return false;
        }
        */

        return true;
    }

    private String getNfcStatus() {
        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());
        if (nfcAdapter == null) {
            return STATUS_NO_NFC;
        } else if (!nfcAdapter.isEnabled()) {
            return STATUS_NFC_DISABLED;
        } else {
            return STATUS_NFC_OK;
        }
    }

    private void registerDefaultTag(CallbackContext callbackContext) {
      addTagFilter();
      callbackContext.success();
  }

    private void removeDefaultTag(CallbackContext callbackContext) {
      removeTagFilter();
      callbackContext.success();
  }

    private void registerNdefFormatable(CallbackContext callbackContext) {
        addTechList(new String[]{NdefFormatable.class.getName()});
        callbackContext.success();
    }

    private void registerNdef(CallbackContext callbackContext) {
      addTechList(new String[]{Ndef.class.getName()});
      callbackContext.success();
  }

    private void removeNdef(CallbackContext callbackContext) {
      removeTechList(new String[]{Ndef.class.getName()});
      callbackContext.success();
  }

    private void unshareTag(CallbackContext callbackContext) {
        p2pMessage = null;
        stopNdefPush();
        shareTagCallback = null;
        callbackContext.success();
    }

    private void init(CallbackContext callbackContext) {
        Log.d(TAG, "Enabling plugin " + getIntent());

        startNfc();
        if (!recycledIntent()) {
            parseMessage();
        }
        callbackContext.success();
    }

    private void removeMimeType(JSONArray data, CallbackContext callbackContext) throws JSONException {
        String mimeType = "";
        try {
            mimeType = data.getString(0);
            /*boolean removed =*/ removeIntentFilter(mimeType);
            callbackContext.success();
        } catch (MalformedMimeTypeException e) {
            callbackContext.error("Invalid MIME Type " + mimeType);
        }
    }

    private void registerMimeType(JSONArray data, CallbackContext callbackContext) throws JSONException {
        String mimeType = "";
        try {
            mimeType = data.getString(0);
            intentFilters.add(createIntentFilter(mimeType));
            callbackContext.success();
        } catch (MalformedMimeTypeException e) {
            callbackContext.error("Invalid MIME Type " + mimeType);
        }
    }

    // Cheating and writing an empty record. We may actually be able to erase some tag types.
    private void eraseTag(CallbackContext callbackContext) throws JSONException {
        Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        NdefRecord[] records = {
            new NdefRecord(NdefRecord.TNF_EMPTY, new byte[0], new byte[0], new byte[0])
        };
        writeNdefMessage(new NdefMessage(records), tag, callbackContext);
    }

    private void writeTag(JSONArray data, CallbackContext callbackContext) throws JSONException {
        if (getIntent() == null) {  // TODO remove this and handle LostTag
            callbackContext.error("Failed to write tag, received null intent");
        }

        Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        NdefRecord[] records = Util.jsonToNdefRecords(data.getString(0));
        writeNdefMessage(new NdefMessage(records), tag, callbackContext);
    }

    private void writeNdefMessage(final NdefMessage message, final Tag tag, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                try {
                    Ndef ndef = Ndef.get(tag);
                    if (ndef != null) {
                        ndef.connect();

                        if (ndef.isWritable()) {
                            int size = message.toByteArray().length;
                            if (ndef.getMaxSize() < size) {
                                callbackContext.error("Tag capacity is " + ndef.getMaxSize() +
                                        " bytes, message is " + size + " bytes.");
                            } else {
                                ndef.writeNdefMessage(message);
                                callbackContext.success();
                            }
                        } else {
                            callbackContext.error("Tag is read only");
                        }
                        ndef.close();
                    } else {
                        NdefFormatable formatable = NdefFormatable.get(tag);
                        if (formatable != null) {
                            formatable.connect();
                            formatable.format(message);
                            callbackContext.success();
                            formatable.close();
                        } else {
                            callbackContext.error("Tag doesn't support NDEF");
                        }
                    }
                } catch (FormatException e) {
                    callbackContext.error(e.getMessage());
                } catch (TagLostException e) {
                    callbackContext.error(e.getMessage());
                } catch (IOException e) {
                    callbackContext.error(e.getMessage());
                }
            }
        });
    }

    private void makeReadOnly(final CallbackContext callbackContext) throws JSONException {

        if (getIntent() == null) { // Lost Tag
            callbackContext.error("Failed to make tag read only, received null intent");
            return;
        }

        final Tag tag = savedIntent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (tag == null) {
            callbackContext.error("Failed to make tag read only, tag is null");
            return;
        }

        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                boolean success = false;
                String message = "Could not make tag read only";

                Ndef ndef = Ndef.get(tag);

                try {
                    if (ndef != null) {

                        ndef.connect();

                        if (!ndef.isWritable()) {
                            message = "Tag is not writable";
                        } else if (ndef.canMakeReadOnly()) {
                            success = ndef.makeReadOnly();
                        } else {
                            message = "Tag can not be made read only";
                        }

                    } else {
                        message = "Tag is not NDEF";
                    }

                } catch (IOException e) {
                    Log.e(TAG, "Failed to make tag read only", e);
                    if (e.getMessage() != null) {
                        message = e.getMessage();
                    } else {
                        message = e.toString();
                    }
                }

                if (success) {
                    callbackContext.success();
                } else {
                    callbackContext.error(message);
                }
            }
        });
    }

    private void shareTag(JSONArray data, CallbackContext callbackContext) throws JSONException {
        NdefRecord[] records = Util.jsonToNdefRecords(data.getString(0));
        this.p2pMessage = new NdefMessage(records);

        startNdefPush(callbackContext);
    }

    // setBeamPushUris
    // Every Uri you provide must have either scheme 'file' or scheme 'content'.
    // Note that this takes priority over setNdefPush
    //
    // See http://developer.android.com/reference/android/nfc/NfcAdapter.html#setBeamPushUris(android.net.Uri[],%20android.app.Activity)
    private void handover(JSONArray data, CallbackContext callbackContext) throws JSONException {

        Uri[] uri = new Uri[data.length()];

        for (int i = 0; i < data.length(); i++) {
            uri[i] = Uri.parse(data.getString(i));
        }

        startNdefBeam(callbackContext, uri);
    }

    private void stopHandover(CallbackContext callbackContext) throws JSONException {
        stopNdefBeam();
        handoverCallback = null;
        callbackContext.success();
    }

    private void showSettings(CallbackContext callbackContext) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.JELLY_BEAN) {
            Intent intent = new Intent(android.provider.Settings.ACTION_NFC_SETTINGS);
            getActivity().startActivity(intent);
        } else {
            Intent intent = new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS);
            getActivity().startActivity(intent);
        }
        callbackContext.success();
    }

    private void createPendingIntent() {
        if (pendingIntent == null) {
            Activity activity = getActivity();
            Intent intent = new Intent(activity, activity.getClass());
            intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            pendingIntent = PendingIntent.getActivity(activity, 0, intent, 0);
        }
    }

    private void addTechList(String[] list) {
      this.addTechFilter();
      this.addToTechList(list);
    }

    private void removeTechList(String[] list) {
      this.removeTechFilter();
      this.removeFromTechList(list);
    }

    private void addTechFilter() {
      intentFilters.add(new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED));
    }

    private boolean removeTechFilter() {
      boolean removed = false;
      Iterator<IntentFilter> iter = intentFilters.iterator();
      while (iter.hasNext()) {
        IntentFilter intentFilter = iter.next();
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intentFilter.getAction(0))) {
          intentFilters.remove(intentFilter);
          removed = true;
        }
      }
      return removed;
    }

    private void addTagFilter() {
      intentFilters.add(new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED));
  }

    private boolean removeTagFilter() {
      boolean removed = false;
      Iterator<IntentFilter> iter = intentFilters.iterator();
      while (iter.hasNext()) {
        IntentFilter intentFilter = iter.next();
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(intentFilter.getAction(0))) {
          intentFilters.remove(intentFilter);
          removed = true;
        }
      }
      return removed;
  }

    private void startNfc() {
        createPendingIntent(); // onResume can call startNfc before execute

        getActivity().runOnUiThread(new Runnable() {
            public void run() {
                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter != null && !getActivity().isFinishing()) {
                    try {
                        nfcAdapter.enableForegroundDispatch(getActivity(), getPendingIntent(), getIntentFilters(), getTechLists());

                        if (p2pMessage != null) {
                            nfcAdapter.setNdefPushMessage(p2pMessage, getActivity());
                        }
                    } catch (IllegalStateException e) {
                        // issue 110 - user exits app with home button while nfc is initializing
                        Log.w(TAG, "Illegal State Exception starting NFC. Assuming application is terminating.");
                    }

                }
            }
        });
    }

    private void stopNfc() {
        Log.d(TAG, "stopNfc");
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter != null) {
                    try {
                        nfcAdapter.disableForegroundDispatch(getActivity());
                    } catch (IllegalStateException e) {
                        // issue 125 - user exits app with back button while nfc
                        Log.w(TAG, "Illegal State Exception stopping NFC. Assuming application is terminating.");
                    }
                }
            }
        });
    }

    private void startNdefBeam(final CallbackContext callbackContext, final Uri[] uris) {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter == null) {
                    callbackContext.error(STATUS_NO_NFC);
                } else if (!nfcAdapter.isNdefPushEnabled()) {
                    callbackContext.error(STATUS_NDEF_PUSH_DISABLED);
                } else {
                    nfcAdapter.setOnNdefPushCompleteCallback(NfcPlugin.this, getActivity());
                    try {
                        nfcAdapter.setBeamPushUris(uris, getActivity());

                        PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
                        result.setKeepCallback(true);
                        handoverCallback = callbackContext;
                        callbackContext.sendPluginResult(result);

                    } catch (IllegalArgumentException e) {
                        callbackContext.error(e.getMessage());
                    }
                }
            }
        });
    }

    private void startNdefPush(final CallbackContext callbackContext) {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter == null) {
                    callbackContext.error(STATUS_NO_NFC);
                } else if (!nfcAdapter.isNdefPushEnabled()) {
                    callbackContext.error(STATUS_NDEF_PUSH_DISABLED);
                } else {
                    nfcAdapter.setNdefPushMessage(p2pMessage, getActivity());
                    nfcAdapter.setOnNdefPushCompleteCallback(NfcPlugin.this, getActivity());

                    PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
                    result.setKeepCallback(true);
                    shareTagCallback = callbackContext;
                    callbackContext.sendPluginResult(result);
                }
            }
        });
    }

    private void stopNdefPush() {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter != null) {
                    nfcAdapter.setNdefPushMessage(null, getActivity());
                }

            }
        });
    }

    private void stopNdefBeam() {
        getActivity().runOnUiThread(new Runnable() {
            public void run() {

                NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(getActivity());

                if (nfcAdapter != null) {
                    nfcAdapter.setBeamPushUris(null, getActivity());
                }

            }
        });
    }

    private void addToTechList(String[] techs) {
      techLists.add(techs);
  }

    private void removeFromTechList(String[] techs) {
      techLists.remove(techs);
  }

    private boolean removeIntentFilter(String mimeType) throws MalformedMimeTypeException {
      boolean removed = false;
      Iterator<IntentFilter> iter = intentFilters.iterator();
      while (iter.hasNext()) {
        IntentFilter intentFilter = iter.next();
        String mt = intentFilter.getDataType(0);
        if (mimeType.equals(mt)) {
          intentFilters.remove(intentFilter);
          removed = true;
        }
      }
      return removed;
    }

    private IntentFilter createIntentFilter(String mimeType) throws MalformedMimeTypeException {
        IntentFilter intentFilter = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        intentFilter.addDataType(mimeType);
        return intentFilter;
    }

    private PendingIntent getPendingIntent() {
        return pendingIntent;
    }

    private IntentFilter[] getIntentFilters() {
        return intentFilters.toArray(new IntentFilter[intentFilters.size()]);
    }

    private String[][] getTechLists() {
        //noinspection ToArrayCallWithZeroLengthArrayArgument
        return techLists.toArray(new String[0][0]);
    }

    void parseMessage() {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                Log.d(TAG, "parseMessage " + getIntent());
                Intent intent = getIntent();
                String action = intent.getAction();
                Log.d(TAG, "action " + action);
                if (action == null) {
                    return;
                }

                Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                Parcelable[] messages = intent.getParcelableArrayExtra((NfcAdapter.EXTRA_NDEF_MESSAGES));

                if (action.equals(NfcAdapter.ACTION_NDEF_DISCOVERED)) {
                    Ndef ndef = Ndef.get(tag);
                    fireNdefEvent(NDEF_MIME, ndef, messages);

                } else if (action.equals(NfcAdapter.ACTION_TECH_DISCOVERED)) {
                    for (String tagTech : tag.getTechList()) {
                        Log.d(TAG, tagTech);
                        if (tagTech.equals(NdefFormatable.class.getName())) {
                            fireNdefFormatableEvent(tag);
                        } else if (tagTech.equals(Ndef.class.getName())) { //
                            Ndef ndef = Ndef.get(tag);
                            fireNdefEvent(NDEF, ndef, messages);
                        }
                    }
                }

                if (action.equals(NfcAdapter.ACTION_TAG_DISCOVERED)) {
                    fireTagEvent(tag);
                }

                setIntent(new Intent());
            }
        });
    }

    private void fireNdefEvent(String type, Ndef ndef, Parcelable[] messages) {

        JSONObject jsonObject = buildNdefJSON(ndef, messages);
        String tag = jsonObject.toString();

        String command = MessageFormat.format(javaScriptEventTemplate, type, tag);
        Log.v(TAG, command);
        this.webView.sendJavascript(command);

    }

    private void fireNdefFormatableEvent (Tag tag) {

        String command = MessageFormat.format(javaScriptEventTemplate, NDEF_FORMATABLE, Util.tagToJSON(tag));
        Log.v(TAG, command);
        this.webView.sendJavascript(command);
    }

    private void fireTagEvent (Tag tag) {

        String command = MessageFormat.format(javaScriptEventTemplate, TAG_DEFAULT, Util.tagToJSON(tag));
        Log.v(TAG, command);
        this.webView.sendJavascript(command);
    }

    JSONObject buildNdefJSON(Ndef ndef, Parcelable[] messages) {

        JSONObject json = Util.ndefToJSON(ndef);

        // ndef is null for peer-to-peer
        // ndef and messages are null for ndef format-able
        if (ndef == null && messages != null) {

            try {

                if (messages.length > 0) {
                    NdefMessage message = (NdefMessage) messages[0];
                    json.put("ndefMessage", Util.messageToJSON(message));
                    // guessing type, would prefer a more definitive way to determine type
                    json.put("type", "NDEF Push Protocol");
                }

                if (messages.length > 1) {
                    Log.wtf(TAG, "Expected one ndefMessage but found " + messages.length);
                }

            } catch (JSONException e) {
                // shouldn't happen
                Log.e(Util.TAG, "Failed to convert ndefMessage into json", e);
            }
        }
        return json;
    }

    private boolean recycledIntent() { // TODO this is a kludge, find real solution

        int flags = getIntent().getFlags();
        if ((flags & Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) == Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) {
            Log.i(TAG, "Launched from history, killing recycled intent");
            setIntent(new Intent());
            return true;
        }
        return false;
    }

    /*
    @Override
    public void onPause(boolean multitasking) {
        Log.d(TAG, "onPause " + getIntent());
        super.onPause(multitasking);
        if (multitasking) {
            // nfc can't run in background
            stopNfc();
        }
    }

    @Override
    public void onResume(boolean multitasking) {
        Log.d(TAG, "onResume " + getIntent());
        super.onResume(multitasking);
        startNfc();
    }

    @Override
    public void onNewIntent(Intent intent) {
        Log.d(TAG, "onNewIntent " + intent);
        super.onNewIntent(intent);
        setIntent(intent);
        savedIntent = intent;
        parseMessage();
    }
    */

    private Activity getActivity() {
        return this.cordova.getActivity();
    }

    private Intent getIntent() {
        return getActivity().getIntent();
    }

    private void setIntent(Intent intent) {
        getActivity().setIntent(intent);
    }

    String javaScriptEventTemplate =
        "var e = document.createEvent(''Events'');\n" +
        "e.initEvent(''{0}'');\n" +
        "e.tag = {1};\n" +
        "document.dispatchEvent(e);";

    @Override
    public void onNdefPushComplete(NfcEvent event) {

        // handover (beam) take precedence over share tag (ndef push)
        if (handoverCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, "Beamed Message to Peer");
            result.setKeepCallback(true);
            handoverCallback.sendPluginResult(result);
        } else if (shareTagCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, "Shared Message with Peer");
            result.setKeepCallback(true);
            shareTagCallback.sendPluginResult(result);
        }

    }

    private static final String AUTH_CERT_ALIAS = "CertAutenticacion"; //$NON-NLS-1$

    @Override
    public void onTagDiscovered(Tag tag) {
        System.setProperty("es.gob.jmulticard.fastmode", "true");

        CANSpecDOStore cansDO = new CANSpecDOStore(getActivity());

        final DnieProvider p = new DnieProvider();
        p.setProviderTag(tag);
        p.setProviderCan(selectedCan.getCanNumber());
        Security.insertProviderAt(p, 1);


        KeyStoreSpi ksSpi = new MrtdKeyStoreImpl();
        DnieKeyStore m_ksUserMrtd = new DnieKeyStore(ksSpi, p, "MRTD");

        try {
            m_ksUserMrtd.load(null, null);
            DG1_Dnie m_dg1 = null; //datos
            DG2 m_dg2 = null; //foto
            DG7 m_dg7 = null; //firma
            DG11 m_dg11 = null; //datos extendidos
            EF_COM m_efcom = m_ksUserMrtd.getEFCOM();
            byte[] tagList = m_efcom.getTagList();
            for(int idx=0;idx<tagList.length;idx++) {
                switch (tagList[idx]){
                    case 0x61:
                        m_dg1 = m_ksUserMrtd.getDatagroup1();
                        break;
                    case 0x75:
                        m_dg2 = m_ksUserMrtd.getDatagroup2();
                        break;
                    case 0x67:
                        m_dg7 = m_ksUserMrtd.getDatagroup7();
                        break;
                    case 0x6B:
                        m_dg11 = m_ksUserMrtd.getDatagroup11();
                        break;
                }
            }


            final JSONObject json = new JSONObject();
            if (m_dg1 != null){
                json.put("name", m_dg1.getName());
                json.put("surname", m_dg1.getSurname());
                json.put("id", m_dg1.getDocNumber());
                json.put("type", m_dg1.getDocType());
                json.put("sex", m_dg1.getSex());
                json.put("birth", m_dg1.getDateOfBirth());
                json.put("nation", m_dg1.getNationality());
                json.put("opt", m_dg1.getOptData());
                json.put("expiry", m_dg1.getDateOfExpiry());
                json.put("issuer", m_dg1.getIssuer());
            }
            if (m_dg11 != null){
                json.put("m11_id", m_dg11.getPersonalNumber());
                //json.put("m11_birth", m_dg11.getDateOfBirth()); raises an error
                //json.put("m11_name", m_dg11.getName());
                //json.put("m11_icao", m_dg11.getIcaoName());
                json.put("m11_address", m_dg11.getAddress(0));
                //json.put("m11_address1", m_dg11.getAddress(1));
                //json.put("m11_address2", m_dg11.getAddress(2));
                //json.put("m11_address3", m_dg11.getAddress(3));
                json.put("m11_brith_place", m_dg11.getBirthPlace());
                //json.put("m11_brith", m_dg11.getDateOfBirth()); raises an error
                //json.put("m11_brith2", m_dg11.getBirthDate());
                //json.put("m11_title", m_dg11.getTitle());
                //json.put("m11_summary", m_dg11.getSummary());
                //json.put("m11_profession", m_dg11.getProfession());
                //json.put("m11_custody", m_dg11.getCustodyInfo());
                //json.put("m11_other", m_dg11.getOtherInfo());
                //json.put("m11_phone", m_dg11.getPhone());
            }

            //todo: update CanDO
            if (m_dg2 != null){
                byte [] imagen = m_dg2.getImageBytes();
                J2kStreamDecoder j2k = new J2kStreamDecoder();
                ByteArrayInputStream bis = new ByteArrayInputStream(imagen);
                Bitmap loadedImage = j2k.decode(bis);
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                loadedImage.compress(Bitmap.CompressFormat.PNG, 50, byteArrayOutputStream);
                byte[] byteArray = byteArrayOutputStream .toByteArray();
                String encoded = Base64.encodeToString(byteArray, Base64.DEFAULT);

                json.put("photo", "data:image/png;base64," + encoded);
            }

            if (m_dg7 != null){
                byte [] imagen = m_dg7.getImageBytes();
                J2kStreamDecoder j2k = new J2kStreamDecoder();
                ByteArrayInputStream bis = new ByteArrayInputStream(imagen);
                Bitmap loadedImage = j2k.decode(bis);
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                loadedImage.compress(Bitmap.CompressFormat.PNG, 50, byteArrayOutputStream);
                byte[] byteArray = byteArrayOutputStream .toByteArray();
                String encoded = Base64.encodeToString(byteArray, Base64.DEFAULT);

                json.put("signature", "data:image/png;base64," + encoded);
            }

            webView.getView().post(new Runnable() {
                @Override
                public void run() {

                    String command = MessageFormat.format(javaScriptEventTemplate, TAG_DEFAULT, json);
                    webView.loadUrl("javascript:" + command);
                }
            });


        } catch (Exception e) {

            final JSONObject ejson = new JSONObject();
            try{
                ejson.put("error", "Error al leer los datos de la tarjeta");
            }catch (Exception se){}

            webView.getView().post(new Runnable() {
                @Override
                public void run() {

                    String command = MessageFormat.format(javaScriptEventTemplate, TAG_DEFAULT, ejson);
                    webView.loadUrl("javascript:" + command);
                }
            });

        }



    }


}
