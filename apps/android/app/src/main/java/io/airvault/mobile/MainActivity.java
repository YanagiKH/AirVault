package io.airvault.mobile;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.json.JSONArray;

import java.util.ArrayList;
import java.util.List;

public final class MainActivity extends Activity implements MobileTransferController.Listener, SecureDiscovery.Listener {
    private static final int PICK_FILES = 201;
    private static final int PICK_FOLDER = 202;
    private static final int SCANDIT_QR_SCAN = 203;
    private final List<Uri> selectedFiles = new ArrayList<>();
    private final List<SecureDiscovery.DiscoveredDevice> nearbyDevices = new ArrayList<>();
    private PeerStore peers;
    private CryptoEngine.Identity identity;
    private MobileTransferController transfers;
    private SecureDiscovery discovery;
    private Spinner peerSpinner;
    private Spinner nearbySpinner;
    private TextView fileSummary;
    private TextView peerList;
    private TextView discoveryStatus;
    private TextView relayStatus;
    private TextView activity;
    private ProgressBar progress;
    private String pendingAuthorizationTransfer;
    private String pendingFolderTransfer;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(Color.rgb(8, 20, 33));
        getWindow().setNavigationBarColor(Color.rgb(8, 20, 33));
        try {
            identity = new IdentityStore(this).loadOrCreate();
            peers = new PeerStore(this);
            String relayUrl = getPreferences(MODE_PRIVATE).getString("relay_url", "wss://relay.example.airvault.invalid");
            try {
                transfers = new MobileTransferController(this, relayUrl, identity, peers, this);
            } catch (IllegalArgumentException invalidSavedRelay) {
                relayUrl = "wss://relay.example.airvault.invalid";
                getPreferences(MODE_PRIVATE).edit().remove("relay_url").apply();
                transfers = new MobileTransferController(this, relayUrl, identity, peers, this);
            }
            setContentView(buildInterface(relayUrl));
            transfers.connect();
            discovery = new SecureDiscovery(this, identity, this);
            discovery.start();
        } catch (Exception error) {
            new AlertDialog.Builder(this)
                    .setTitle("AirVault could not start")
                    .setMessage("The protected device identity or saved device list could not be loaded. Android security storage may be unavailable.")
                    .setPositiveButton("Close", (_dialog, _which) -> finish())
                    .setCancelable(false)
                    .show();
        }
    }

    @Override protected void onDestroy() {
        if (discovery != null) discovery.stop();
        if (transfers != null) transfers.disconnect();
        super.onDestroy();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == SCANDIT_QR_SCAN) {
            if (resultCode == RESULT_OK && data != null && pendingAuthorizationTransfer != null) {
                String payload = data.getStringExtra(ScanditQrScanActivity.EXTRA_QR_PAYLOAD);
                if (payload != null) authorizePendingTransfer(payload);
            } else if (data != null && data.getStringExtra("error") != null) {
                toast(data.getStringExtra("error") + "; using the compatibility scanner");
                startZxingQrScanner();
            }
            return;
        }
        IntentResult scan = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (scan != null && scan.getContents() != null) {
            authorizePendingTransfer(scan.getContents());
            return;
        }
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_FILES && resultCode == RESULT_OK && data != null) {
            selectedFiles.clear();
            if (data.getClipData() != null) {
                for (int i = 0; i < data.getClipData().getItemCount(); i++) {
                    Uri uri = data.getClipData().getItemAt(i).getUri();
                    takeReadPermission(uri);
                    selectedFiles.add(uri);
                }
            } else if (data.getData() != null) {
                takeReadPermission(data.getData());
                selectedFiles.add(data.getData());
            }
            fileSummary.setText(selectedFiles.isEmpty() ? "No files selected" : selectedFiles.size() + " file(s) ready for security scan");
        } else if (requestCode == PICK_FOLDER && resultCode == RESULT_OK && data != null && data.getData() != null && pendingFolderTransfer != null) {
            try {
                getContentResolver().takePersistableUriPermission(data.getData(), Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            } catch (SecurityException ignored) {
                // Some document providers grant only a transient permission.
            }
            transfers.approveIncoming(pendingFolderTransfer, data.getData());
            pendingFolderTransfer = null;
        }
    }

    private View buildInterface(String relayUrl) {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.rgb(7, 17, 30));
        LinearLayout root = column();
        root.setPadding(dp(18), dp(18), dp(18), dp(40));
        scroll.addView(root);

        LinearLayout heading = row();
        TextView brand = text("AirVault", 26, Color.WHITE);
        brand.setTypeface(null, android.graphics.Typeface.BOLD);
        relayStatus = badge("offline");
        heading.addView(brand, new LinearLayout.LayoutParams(0, dp(52), 1));
        heading.addView(relayStatus);
        root.addView(heading);
        root.addView(text("Private transfer, verified end to end", 13, Color.rgb(139, 160, 186)));

        LinearLayout identityCard = card();
        identityCard.addView(label("THIS DEVICE"));
        identityCard.addView(text(identity.deviceId, 18, Color.rgb(196, 233, 255)));
        Button copy = button("Copy device ID", false);
        copy.setOnClickListener(_view -> {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("AirVault device ID", identity.deviceId));
            toast("Device ID copied");
        });
        identityCard.addView(copy);
        root.addView(identityCard);

        LinearLayout content = getResources().getConfiguration().smallestScreenWidthDp >= 700 ? row() : column();
        LinearLayout sendCard = card();
        sendCard.addView(sectionTitle("1  Select and send files"));
        Button choose = button("Choose multiple files", false);
        choose.setOnClickListener(_view -> chooseFiles());
        fileSummary = text("No files selected", 13, Color.rgb(139, 160, 186));
        peerSpinner = new Spinner(this);
        peerSpinner.setBackgroundColor(Color.rgb(19, 38, 59));
        sendCard.addView(choose);
        sendCard.addView(fileSummary);
        sendCard.addView(peerSpinner, match(dp(52)));
        Button send = button("Create secure transfer", true);
        send.setOnClickListener(_view -> {
            int position = peerSpinner.getSelectedItemPosition();
            List<PeerStore.Peer> available = peers.all();
            if (selectedFiles.isEmpty() || position <= 0 || position > available.size()) {
                toast("Choose files and a saved destination");
                return;
            }
            transfers.beginSend(selectedFiles, available.get(position - 1).deviceId);
        });
        sendCard.addView(send);

        LinearLayout peersCard = card();
        peersCard.addView(sectionTitle("2  Saved devices"));
        EditText idInput = input("AV-XXXXX-XXXXX-XXXXX-XXXXX");
        EditText nameInput = input("Device name");
        Button add = button("Save device", false);
        Button remove = button("Remove selected device", false);
        peerList = text("", 12, Color.rgb(173, 192, 213));
        add.setOnClickListener(_view -> {
            try {
                if (idInput.getText().toString().equalsIgnoreCase(identity.deviceId)) throw new IllegalArgumentException("This is your own device ID");
                peers.save(idInput.getText().toString(), nameInput.getText().toString());
                idInput.setText("");
                nameInput.setText("");
                refreshPeers();
            } catch (Exception error) {
                toast(error.getMessage());
            }
        });
        remove.setOnClickListener(_view -> {
            int position = peerSpinner.getSelectedItemPosition();
            List<PeerStore.Peer> available = peers.all();
            if (position <= 0 || position > available.size()) {
                toast("Choose a saved device to remove");
                return;
            }
            peers.remove(available.get(position - 1).deviceId);
            refreshPeers();
            toast("Device removed");
        });
        peersCard.addView(idInput);
        peersCard.addView(nameInput);
        peersCard.addView(add);
        peersCard.addView(remove);
        peersCard.addView(peerList);
        refreshPeers();

        LinearLayout discoveryCard = card();
        discoveryCard.addView(sectionTitle("3  Secure nearby discovery"));
        discoveryCard.addView(text("Signed local beacons help you find nearby AirVault devices. Nothing is saved until you choose it.", 12, Color.rgb(139, 160, 186)));
        nearbySpinner = new Spinner(this);
        nearbySpinner.setBackgroundColor(Color.rgb(19, 38, 59));
        discoveryStatus = text("Searching the local network…", 12, Color.rgb(173, 192, 213));
        Button saveNearby = button("Save selected nearby device", false);
        saveNearby.setOnClickListener(_view -> saveSelectedNearbyDevice());
        discoveryCard.addView(nearbySpinner, match(dp(52)));
        discoveryCard.addView(saveNearby);
        discoveryCard.addView(discoveryStatus);
        refreshNearbyDevices();

        if (content.getOrientation() == LinearLayout.HORIZONTAL) {
            content.addView(sendCard, weighted());
            content.addView(peersCard, weighted());
        } else {
            content.addView(sendCard);
            content.addView(peersCard);
        }
        root.addView(content);
        root.addView(discoveryCard);

        LinearLayout activityCard = card();
        activityCard.addView(label("TRANSFER ACTIVITY"));
        activity = text("No active transfers", 14, Color.WHITE);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        activityCard.addView(activity);
        activityCard.addView(progress, match(dp(12)));
        root.addView(activityCard);

        LinearLayout settingsCard = card();
        settingsCard.addView(sectionTitle("Relay settings"));
        EditText relayInput = input("wss://relay.example.com");
        relayInput.setText(relayUrl);
        Button apply = button("Apply encrypted relay", false);
        apply.setOnClickListener(_view -> {
            try {
                String value = relayInput.getText().toString().trim();
                transfers.updateRelay(value);
                getPreferences(MODE_PRIVATE).edit().putString("relay_url", value).apply();
            } catch (Exception error) {
                toast(error.getMessage());
            }
        });
        settingsCard.addView(relayInput);
        settingsCard.addView(apply);
        settingsCard.addView(text("Android requires wss://. Relay servers can route ciphertext but cannot read file contents or filenames.", 12, Color.rgb(139, 160, 186)));
        root.addView(settingsCard);
        return scroll;
    }

    private void chooseFiles() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .setType("*/*")
                .putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, PICK_FILES);
    }

    private void chooseFolder(String transferId) {
        pendingFolderTransfer = transferId;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, PICK_FOLDER);
    }

    private void refreshPeers() {
        if (peerSpinner == null || peerList == null) return;
        List<String> labels = new ArrayList<>();
        labels.add("Choose a saved device");
        StringBuilder details = new StringBuilder();
        for (PeerStore.Peer peer : peers.all()) {
            labels.add(peer.name + " · " + peer.deviceId.substring(peer.deviceId.length() - 11));
            details.append(peer.name).append("\n").append(peer.deviceId)
                    .append(peer.verifiedAt > 0 ? "  · Verified\n\n" : "  · Awaiting first PIN verification\n\n");
        }
        peerSpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels));
        peerList.setText(details.length() == 0 ? "No saved devices yet." : details.toString().trim());
    }

    @Override public void onRelayStatus(String status) {
        runOnUiThread(() -> relayStatus.setText(status));
    }

    @Override public void onIncomingOffer(String transferId, String senderName) {
        runOnUiThread(() -> {
            pendingAuthorizationTransfer = transferId;
            EditText pin = input("6-digit PIN");
            pin.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
            LinearLayout body = column();
            body.setPadding(dp(18), 0, dp(18), 0);
            body.addView(text(senderName + " wants to send files. Enter the sender's PIN or scan the AirVault QR code.", 14, Color.DKGRAY));
            body.addView(pin);
            new AlertDialog.Builder(this)
                    .setTitle("Authorize incoming transfer")
                    .setView(body)
                    .setPositiveButton("Verify", (_dialog, _which) -> transfers.acceptIncoming(transferId, pin.getText().toString()))
                    .setNeutralButton("Scan QR", (_dialog, _which) -> startQrScanner())
                    .setNegativeButton("Decline", (_dialog, _which) -> transfers.rejectIncoming(transferId))
                    .show();
        });
    }

    @Override public void onManifestReview(String transferId, JSONArray manifest, long totalBytes, int executableWarnings) {
        runOnUiThread(() -> {
            if (transferId.equals(pendingAuthorizationTransfer)) pendingAuthorizationTransfer = null;
            StringBuilder files = new StringBuilder();
            try {
                for (int i = 0; i < manifest.length(); i++) {
                    files.append("• ").append(manifest.getJSONObject(i).getString("name"))
                            .append("  (").append(formatBytes(manifest.getJSONObject(i).getLong("size"))).append(")\n");
                }
            } catch (Exception ignored) {
                files.append("Manifest display unavailable");
            }
            String warning = executableWarnings > 0 ? "\nWarning: " + executableWarnings + " potentially executable file(s)." : "";
            new AlertDialog.Builder(this)
                    .setTitle("Security preflight passed")
                    .setMessage(files + "\nTotal: " + formatBytes(totalBytes) + warning + "\n\nAccept and choose a download folder?")
                    .setPositiveButton("Accept", (_dialog, _which) -> chooseFolder(transferId))
                    .setNegativeButton("Decline", (_dialog, _which) -> transfers.rejectIncoming(transferId))
                    .show();
        });
    }

    @Override public void onAuthorizationReady(String transferId, String pin, String qrPayload) {
        runOnUiThread(() -> {
            ImageView qr = new ImageView(this);
            qr.setImageBitmap(qrBitmap(qrPayload, 650));
            LinearLayout body = column();
            TextView code = text(pin.substring(0, 3) + " " + pin.substring(3), 36, Color.BLACK);
            code.setGravity(Gravity.CENTER);
            body.addView(code);
            body.addView(qr, match(dp(280)));
            body.addView(text("The receiver must enter this PIN or scan this QR code before any encrypted file data is sent.", 13, Color.DKGRAY));
            new AlertDialog.Builder(this).setTitle("One-time transfer authorization").setView(body).setPositiveButton("Done", null).show();
        });
    }

    @Override public void onProgress(String transferId, String message, int percent) {
        runOnUiThread(() -> {
            activity.setText(message);
            progress.setProgress(percent);
        });
    }

    @Override public void onComplete(String transferId, String message) {
        runOnUiThread(() -> {
            activity.setText(message);
            progress.setProgress(100);
            toast(message);
        });
    }

    @Override public void onError(String safeMessage) {
        runOnUiThread(() -> toast(safeMessage));
    }

    @Override public void onDiscovered(SecureDiscovery.DiscoveredDevice device) {
        runOnUiThread(() -> {
            for (int index = 0; index < nearbyDevices.size(); index++) {
                SecureDiscovery.DiscoveredDevice existing = nearbyDevices.get(index);
                if (existing.deviceId.equals(device.deviceId)) {
                    if (existing.publicKey.equals(device.publicKey)) nearbyDevices.set(index, device);
                    refreshNearbyDevices();
                    return;
                }
            }
            nearbyDevices.add(device);
            refreshNearbyDevices();
        });
    }

    @Override public void onDiscoveryWarning(String message) {
        runOnUiThread(() -> {
            if (discoveryStatus != null && nearbyDevices.isEmpty()) discoveryStatus.setText(message);
        });
    }

    private void refreshNearbyDevices() {
        if (nearbySpinner == null || discoveryStatus == null) return;
        List<String> labels = new ArrayList<>();
        labels.add("Choose a nearby device");
        for (SecureDiscovery.DiscoveredDevice device : nearbyDevices) {
            labels.add(device.deviceId);
        }
        nearbySpinner.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels));
        discoveryStatus.setText(nearbyDevices.isEmpty()
                ? "Searching the local network…"
                : nearbyDevices.size() + " valid signed nearby device(s) found");
    }

    private void saveSelectedNearbyDevice() {
        int position = nearbySpinner == null ? 0 : nearbySpinner.getSelectedItemPosition();
        if (position <= 0 || position > nearbyDevices.size()) {
            toast("Choose a nearby device to save");
            return;
        }
        SecureDiscovery.DiscoveredDevice device = nearbyDevices.get(position - 1);
        try {
            peers.save(device.deviceId, "Nearby " + device.deviceId.substring(device.deviceId.length() - 5));
            peers.pin(device.deviceId, device.publicKey);
            refreshPeers();
            toast("Nearby device saved with its signed identity key");
        } catch (Exception error) {
            toast(error.getMessage());
        }
    }

    private void startQrScanner() {
        if (ScanditQrScanActivity.isConfigured()) {
            startActivityForResult(new Intent(this, ScanditQrScanActivity.class), SCANDIT_QR_SCAN);
        } else {
            startZxingQrScanner();
        }
    }

    private void startZxingQrScanner() {
        new IntentIntegrator(this)
                .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
                .setPrompt("Scan the sender's AirVault QR code")
                .setBeepEnabled(false)
                .initiateScan();
    }

    private void authorizePendingTransfer(String authorization) {
        if (pendingAuthorizationTransfer == null) {
            toast("The transfer authorization request has expired");
            return;
        }
        transfers.acceptIncoming(pendingAuthorizationTransfer, authorization);
    }

    private LinearLayout card() {
        LinearLayout card = column();
        card.setPadding(dp(18), dp(18), dp(18), dp(18));
        card.setBackgroundColor(Color.rgb(13, 27, 45));
        LinearLayout.LayoutParams params = match(ViewGroup.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(14), 0, 0);
        card.setLayoutParams(params);
        return card;
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER_VERTICAL);
        return layout;
    }

    private LinearLayout row() {
        LinearLayout layout = column();
        layout.setOrientation(LinearLayout.HORIZONTAL);
        return layout;
    }

    private TextView text(String value, int sp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setPadding(0, dp(6), 0, dp(6));
        return view;
    }

    private TextView label(String value) {
        TextView label = text(value, 11, Color.rgb(73, 217, 232));
        label.setLetterSpacing(.12f);
        return label;
    }

    private TextView sectionTitle(String value) {
        TextView title = text(value, 18, Color.WHITE);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        return title;
    }

    private TextView badge(String value) {
        TextView badge = text(value, 12, Color.rgb(143, 246, 195));
        badge.setPadding(dp(12), dp(7), dp(12), dp(7));
        badge.setBackgroundColor(Color.rgb(18, 60, 52));
        return badge;
    }

    private EditText input(String hint) {
        EditText input = new EditText(this);
        input.setHint(hint);
        input.setTextColor(Color.WHITE);
        input.setHintTextColor(Color.rgb(120, 143, 168));
        input.setSingleLine(true);
        input.setBackgroundColor(Color.rgb(19, 38, 59));
        input.setPadding(dp(12), dp(10), dp(12), dp(10));
        LinearLayout.LayoutParams params = match(dp(52));
        params.setMargins(0, dp(8), 0, 0);
        input.setLayoutParams(params);
        return input;
    }

    private Button button(String value, boolean primary) {
        Button button = new Button(this);
        button.setText(value);
        button.setAllCaps(false);
        button.setTextColor(primary ? Color.rgb(6, 16, 28) : Color.WHITE);
        button.setBackgroundColor(primary ? Color.rgb(73, 217, 232) : Color.rgb(19, 38, 59));
        LinearLayout.LayoutParams params = match(dp(52));
        params.setMargins(0, dp(9), 0, 0);
        button.setLayoutParams(params);
        return button;
    }

    private LinearLayout.LayoutParams match(int height) {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, height);
    }

    private LinearLayout.LayoutParams weighted() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        params.setMargins(dp(5), 0, dp(5), 0);
        return params;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void takeReadPermission(Uri uri) {
        try {
            getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (SecurityException ignored) {
            // The URI remains valid for the current activity when persistence is unsupported.
        }
    }

    private Bitmap qrBitmap(String value, int size) {
        try {
            BitMatrix matrix = new MultiFormatWriter().encode(value, BarcodeFormat.QR_CODE, size, size);
            Bitmap bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565);
            for (int y = 0; y < size; y++) for (int x = 0; x < size; x++) bitmap.setPixel(x, y, matrix.get(x, y) ? Color.BLACK : Color.WHITE);
            return bitmap;
        } catch (Exception error) {
            return Bitmap.createBitmap(1, 1, Bitmap.Config.RGB_565);
        }
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        String[] units = { "KiB", "MiB", "GiB", "TiB" };
        double value = bytes / 1024.0;
        int unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return String.format(java.util.Locale.US, value >= 10 ? "%.1f %s" : "%.2f %s", value, units[unit]);
    }

    private void toast(String message) {
        Toast.makeText(this, message == null ? "Operation failed" : message, Toast.LENGTH_LONG).show();
    }
}
