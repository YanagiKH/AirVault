package io.airvault.mobile;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;

import com.scandit.datacapture.barcode.capture.BarcodeCapture;
import com.scandit.datacapture.barcode.capture.BarcodeCaptureListener;
import com.scandit.datacapture.barcode.capture.BarcodeCaptureSession;
import com.scandit.datacapture.barcode.capture.BarcodeCaptureSettings;
import com.scandit.datacapture.barcode.data.Barcode;
import com.scandit.datacapture.barcode.data.Symbology;
import com.scandit.datacapture.barcode.ui.overlay.BarcodeCaptureOverlay;
import com.scandit.datacapture.core.capture.DataCaptureContext;
import com.scandit.datacapture.core.data.FrameData;
import com.scandit.datacapture.core.source.Camera;
import com.scandit.datacapture.core.source.FrameSourceState;
import com.scandit.datacapture.core.ui.DataCaptureView;
import com.scandit.datacapture.core.ui.viewfinder.RectangularViewfinder;
import com.scandit.datacapture.core.ui.viewfinder.RectangularViewfinderStyle;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

/** Scans only AirVault authorization QR codes with Scandit Barcode Capture. */
public final class ScanditQrScanActivity extends Activity implements BarcodeCaptureListener {
    public static final String EXTRA_QR_PAYLOAD = "io.airvault.mobile.QR_PAYLOAD";
    private static final int CAMERA_PERMISSION = 310;

    private DataCaptureContext dataCaptureContext;
    private BarcodeCapture barcodeCapture;
    private Camera camera;

    static boolean isConfigured() {
        return !licenseKey().isEmpty();
    }

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (!isConfigured()) {
            finishWithError("Scandit is not configured for this build");
            return;
        }
        try {
            initializeScanner();
        } catch (RuntimeException error) {
            finishWithError("The secure QR scanner could not start");
        }
    }

    private void initializeScanner() {
        dataCaptureContext = DataCaptureContext.forLicenseKey(licenseKey());
        camera = Camera.getDefaultCamera(BarcodeCapture.createRecommendedCameraSettings());
        if (camera == null) throw new IllegalStateException("No camera is available");
        dataCaptureContext.setFrameSource(camera);

        BarcodeCaptureSettings settings = new BarcodeCaptureSettings();
        settings.enableSymbologies(Collections.singleton(Symbology.QR));
        barcodeCapture = BarcodeCapture.forDataCaptureContext(dataCaptureContext, settings);
        barcodeCapture.addListener(this);

        DataCaptureView captureView = DataCaptureView.newInstance(this, dataCaptureContext);
        BarcodeCaptureOverlay overlay = BarcodeCaptureOverlay.newInstance(barcodeCapture, captureView);
        overlay.setViewfinder(new RectangularViewfinder(RectangularViewfinderStyle.SQUARE));

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.BLACK);
        root.addView(captureView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        TextView prompt = new TextView(this);
        prompt.setText("Scan the sender's AirVault authorization QR code");
        prompt.setTextColor(Color.WHITE);
        prompt.setTextSize(16);
        prompt.setGravity(Gravity.CENTER);
        prompt.setBackgroundColor(Color.argb(190, 7, 17, 30));
        prompt.setPadding(dp(18), dp(14), dp(18), dp(14));
        FrameLayout.LayoutParams promptParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP);
        promptParams.setMargins(dp(12), dp(12), dp(12), 0);
        root.addView(prompt, promptParams);

        Button cancel = new Button(this);
        cancel.setText("Cancel");
        cancel.setAllCaps(false);
        cancel.setOnClickListener(_view -> finish());
        FrameLayout.LayoutParams cancelParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(54), Gravity.BOTTOM);
        cancelParams.setMargins(dp(18), 0, dp(18), dp(24));
        root.addView(cancel, cancelParams);
        setContentView(root);
    }

    @Override protected void onResume() {
        super.onResume();
        if (barcodeCapture == null) return;
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            resumeScanner();
        } else {
            requestPermissions(new String[] { Manifest.permission.CAMERA }, CAMERA_PERMISSION);
        }
    }

    @Override protected void onPause() {
        pauseScanner();
        super.onPause();
    }

    @Override protected void onDestroy() {
        if (barcodeCapture != null) barcodeCapture.removeListener(this);
        if (dataCaptureContext != null) dataCaptureContext.removeCurrentMode();
        super.onDestroy();
    }

    @Override public void onRequestPermissionsResult(
            int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != CAMERA_PERMISSION) return;
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            resumeScanner();
        } else {
            Toast.makeText(this, "Camera permission is required to scan the QR code", Toast.LENGTH_LONG).show();
            finish();
        }
    }

    @Override public void onBarcodeScanned(
            @NonNull BarcodeCapture capture,
            @NonNull BarcodeCaptureSession session,
            @NonNull FrameData data) {
        Barcode barcode = session.getNewlyRecognizedBarcode();
        if (barcode == null) return;
        capture.setEnabled(false);
        String payload = barcode.getData();
        runOnUiThread(() -> {
            if (payload == null || !payload.startsWith("airvault://accept?")) {
                Toast.makeText(this, "This is not an AirVault authorization QR code", Toast.LENGTH_SHORT).show();
                capture.setEnabled(true);
                return;
            }
            Intent result = new Intent().putExtra(EXTRA_QR_PAYLOAD, payload);
            setResult(RESULT_OK, result);
            finish();
        });
    }

    @Override public void onSessionUpdated(
            @NonNull BarcodeCapture capture,
            @NonNull BarcodeCaptureSession session,
            @NonNull FrameData data) {}

    @Override public void onObservationStarted(@NonNull BarcodeCapture capture) {}

    @Override public void onObservationStopped(@NonNull BarcodeCapture capture) {}

    private void resumeScanner() {
        if (barcodeCapture == null || camera == null) return;
        barcodeCapture.setEnabled(true);
        camera.switchToDesiredState(FrameSourceState.ON, null);
    }

    private void pauseScanner() {
        if (barcodeCapture != null) barcodeCapture.setEnabled(false);
        if (camera != null) camera.switchToDesiredState(FrameSourceState.OFF, null);
    }

    private void finishWithError(String message) {
        setResult(RESULT_CANCELED, new Intent().putExtra("error", message));
        finish();
    }

    private static String licenseKey() {
        try {
            byte[] decoded = android.util.Base64.decode(
                    BuildConfig.SCANDIT_LICENSE_KEY_BASE64, android.util.Base64.DEFAULT);
            return new String(decoded, StandardCharsets.UTF_8).trim();
        } catch (IllegalArgumentException error) {
            return "";
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
