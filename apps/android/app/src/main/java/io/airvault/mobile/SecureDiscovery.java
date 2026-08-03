package io.airvault.mobile;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.util.Base64;

import org.json.JSONObject;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Signed, replay-resistant local discovery compatible with the desktop client. */
public final class SecureDiscovery {
    public interface Listener {
        void onDiscovered(DiscoveredDevice device);
        void onDiscoveryWarning(String message);
    }

    public static final class DiscoveredDevice {
        public final String deviceId;
        public final String publicKey;

        DiscoveredDevice(String deviceId, String publicKey) {
            this.deviceId = deviceId;
            this.publicKey = publicKey;
        }
    }

    private static final String GROUP = "239.255.77.77";
    private static final int PORT = 53545;
    private static final int MAX_BEACON_BYTES = 8192;
    private static final int MAX_SEEN_BEACONS = 4096;
    private static final int MAX_BEACONS_PER_SECOND = 256;
    private static final long CLOCK_SKEW_MILLIS = 5 * 60_000L;
    private static final long BROADCAST_INTERVAL_MILLIS = 15_000L;

    private final Context context;
    private final CryptoEngine.Identity identity;
    private final Listener listener;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "airvault-secure-discovery");
        thread.setDaemon(true);
        return thread;
    });
    private final Map<String, Long> seen = new HashMap<>();
    private volatile boolean running;
    private volatile MulticastSocket socket;
    private WifiManager.MulticastLock multicastLock;

    public SecureDiscovery(Context context, CryptoEngine.Identity identity, Listener listener) {
        this.context = context.getApplicationContext();
        this.identity = identity;
        this.listener = listener;
    }

    public synchronized void start() {
        if (running) return;
        running = true;
        acquireMulticastLock();
        worker.execute(this::runLoop);
    }

    public synchronized void stop() {
        running = false;
        MulticastSocket active = socket;
        if (active != null) active.close();
        socket = null;
        worker.shutdownNow();
        if (multicastLock != null && multicastLock.isHeld()) multicastLock.release();
        multicastLock = null;
    }

    private void runLoop() {
        try (MulticastSocket active = new MulticastSocket(null)) {
            socket = active;
            active.setReuseAddress(true);
            active.bind(new InetSocketAddress(PORT));
            active.setSoTimeout(1_000);
            active.setTimeToLive(1);
            InetAddress group = InetAddress.getByName(GROUP);
            active.joinGroup(group);
            long nextBroadcast = 0;
            long windowStarted = System.currentTimeMillis();
            int windowCount = 0;
            byte[] buffer = new byte[MAX_BEACON_BYTES + 1];

            while (running) {
                long now = System.currentTimeMillis();
                if (now >= nextBroadcast) {
                    broadcast(active, group);
                    nextBroadcast = now + BROADCAST_INTERVAL_MILLIS;
                }
                if (now - windowStarted >= 1_000) {
                    windowStarted = now;
                    windowCount = 0;
                }
                try {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    active.receive(packet);
                    windowCount++;
                    if (windowCount > MAX_BEACONS_PER_SECOND || packet.getLength() > MAX_BEACON_BYTES) continue;
                    String payload = new String(packet.getData(), packet.getOffset(), packet.getLength(), StandardCharsets.UTF_8);
                    DiscoveredDevice device = parseBeacon(payload, identity.deviceId, now);
                    if (device == null || isReplay(payload, now)) continue;
                    listener.onDiscovered(device);
                } catch (SocketTimeoutException ignored) {
                    // The timeout lets stop() terminate this loop promptly.
                } catch (Exception ignored) {
                    // Untrusted multicast packets are ignored without affecting the application.
                }
            }
        } catch (Exception error) {
            if (running) listener.onDiscoveryWarning("Nearby device discovery is unavailable on this network");
        } finally {
            socket = null;
        }
    }

    private void broadcast(MulticastSocket active, InetAddress group) {
        try {
            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            JSONObject unsigned = new JSONObject()
                    .put("version", 1)
                    .put("type", "airvault-discovery")
                    .put("deviceId", identity.deviceId)
                    .put("publicKey", identity.publicKeyPem)
                    .put("timestamp", System.currentTimeMillis())
                    .put("nonce", Base64.encodeToString(nonce,
                            Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING));
            JSONObject beacon = new JSONObject(unsigned.toString())
                    .put("signature", CryptoEngine.sign(identity.privateKeyPem, CryptoEngine.canonical(unsigned)));
            byte[] bytes = beacon.toString().getBytes(StandardCharsets.UTF_8);
            if (bytes.length > MAX_BEACON_BYTES) return;
            active.send(new DatagramPacket(bytes, bytes.length, group, PORT));
        } catch (Exception error) {
            listener.onDiscoveryWarning("This device could not publish its signed discovery beacon");
        }
    }

    static DiscoveredDevice parseBeacon(String payload, String ownDeviceId, long now) throws Exception {
        JSONObject beacon = new JSONObject(payload);
        if (beacon.getInt("version") != 1 || !"airvault-discovery".equals(beacon.getString("type"))) return null;
        String deviceId = beacon.getString("deviceId");
        if (deviceId.equals(ownDeviceId)) return null;
        String publicKey = beacon.getString("publicKey");
        long timestamp = beacon.getLong("timestamp");
        String nonce = beacon.getString("nonce");
        if (timestamp < now - CLOCK_SKEW_MILLIS || timestamp > now + CLOCK_SKEW_MILLIS
                || !nonce.matches("^[A-Za-z0-9_-]{16}$")) return null;
        if (!deviceId.equals(CryptoEngine.deviceIdFromPublicKey(publicKey))) return null;
        JSONObject unsigned = new JSONObject();
        Iterator<String> keys = beacon.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!"signature".equals(key)) unsigned.put(key, beacon.get(key));
        }
        if (!CryptoEngine.verify(publicKey, CryptoEngine.canonical(unsigned), beacon.getString("signature"))) return null;
        return new DiscoveredDevice(deviceId, publicKey);
    }

    private boolean isReplay(String payload, long now) {
        try {
            JSONObject beacon = new JSONObject(payload);
            String key = beacon.getString("deviceId") + ":" + beacon.getString("nonce");
            Iterator<Map.Entry<String, Long>> iterator = seen.entrySet().iterator();
            while (iterator.hasNext()) if (iterator.next().getValue() < now) iterator.remove();
            if (seen.containsKey(key) || seen.size() >= MAX_SEEN_BEACONS) return true;
            seen.put(key, now + CLOCK_SKEW_MILLIS);
            return false;
        } catch (Exception error) {
            return true;
        }
    }

    private void acquireMulticastLock() {
        try {
            WifiManager wifi = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            if (wifi == null) return;
            multicastLock = wifi.createMulticastLock("airvault-secure-discovery");
            multicastLock.setReferenceCounted(false);
            multicastLock.acquire();
        } catch (RuntimeException error) {
            multicastLock = null;
        }
    }
}
