package io.airvault.mobile;

import org.json.JSONObject;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;

public final class RelayClient {
    public interface Listener {
        void onStatus(String status);
        void onRouted(String from, String transferId, JSONObject payload);
        void onError(String safeMessage);
    }

    private static final Dns PUBLIC_ONLY_DNS = hostname -> {
        List<InetAddress> addresses = Dns.SYSTEM.lookup(hostname);
        for (InetAddress address : addresses) {
            if (!isPublicInternetAddress(address)) {
                throw new UnknownHostException("Relay resolved to a non-public network address");
            }
        }
        return addresses;
    };

    private final OkHttpClient client = new OkHttpClient.Builder()
            .dns(PUBLIC_ONLY_DNS)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .pingInterval(30, TimeUnit.SECONDS)
            .build();
    private final CryptoEngine.Identity identity;
    private final Listener listener;
    private WebSocket socket;
    private String url;

    public RelayClient(String url, CryptoEngine.Identity identity, Listener listener) {
        this.url = requireSecureUrl(url);
        this.identity = identity;
        this.listener = listener;
    }

    public synchronized void connect() {
        disconnect();
        listener.onStatus("connecting");
        socket = client.newWebSocket(new Request.Builder().url(url).build(), new WebSocketListener() {
            @Override public void onOpen(WebSocket webSocket, Response response) {
                try {
                    byte[] nonce = new byte[18];
                    new SecureRandom().nextBytes(nonce);
                    JSONObject registration = new JSONObject()
                            .put("version", 1)
                            .put("deviceId", identity.deviceId)
                            .put("publicKey", identity.publicKeyPem)
                            .put("timestamp", System.currentTimeMillis())
                            .put("nonce", android.util.Base64.encodeToString(nonce,
                                    android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP | android.util.Base64.NO_PADDING));
                    JSONObject message = new JSONObject(registration.toString())
                            .put("type", "register")
                            .put("signature", CryptoEngine.sign(identity.privateKeyPem, CryptoEngine.canonical(registration)));
                    webSocket.send(message.toString());
                } catch (Exception error) {
                    listener.onError("Device authentication failed");
                    webSocket.close(1008, "authentication_failed");
                }
            }

            @Override public void onMessage(WebSocket webSocket, String text) {
                if (text.length() > 2 * 1024 * 1024) {
                    webSocket.close(1009, "message_too_large");
                    return;
                }
                try {
                    JSONObject message = new JSONObject(text);
                    String type = message.getString("type");
                    if ("registered".equals(type)) listener.onStatus("connected");
                    else if ("routed".equals(type)) listener.onRouted(
                            message.getString("from"), message.getString("transferId"), message.getJSONObject("payload"));
                    else if ("error".equals(type)) listener.onError("Relay rejected a protocol message");
                } catch (Exception ignored) {
                    listener.onError("Invalid relay response");
                }
            }

            @Override public void onClosed(WebSocket webSocket, int code, String reason) {
                listener.onStatus("disconnected");
            }

            @Override public void onFailure(WebSocket webSocket, Throwable throwable, Response response) {
                listener.onStatus("offline");
            }
        });
    }

    public synchronized void route(String to, String transferId, JSONObject payload) {
        try {
            if (socket != null && socket.queueSize() > 32L * 1024 * 1024) {
                throw new IllegalStateException("Relay connection is congested; transfer stopped safely");
            }
            if (socket == null || !socket.send(new JSONObject()
                    .put("type", "route")
                    .put("to", to)
                    .put("transferId", transferId)
                    .put("payload", payload).toString())) {
                throw new IllegalStateException("Relay is offline");
            }
        } catch (org.json.JSONException error) {
            throw new IllegalArgumentException("Invalid relay message", error);
        }
    }

    public synchronized void updateUrl(String value) {
        url = requireSecureUrl(value);
        connect();
    }

    public synchronized void disconnect() {
        if (socket != null) socket.close(1000, "client_shutdown");
        socket = null;
    }

    static String requireSecureUrl(String value) {
        if (value == null) throw new IllegalArgumentException("Relay URL is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) throw new IllegalArgumentException("Relay URL is required");

        URI uri;
        try {
            uri = URI.create(trimmed);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("Relay URL is invalid", error);
        }
        if (uri.isOpaque() || !"wss".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("Android relays must use wss://");
        }
        if (uri.getUserInfo() != null) throw new IllegalArgumentException("Relay URL must not include user info");
        if (uri.getFragment() != null) throw new IllegalArgumentException("Relay URL must not include a fragment");

        String host = uri.getHost();
        if (host == null || host.trim().isEmpty()) throw new IllegalArgumentException("Relay URL host is required");
        String normalizedHost = host.toLowerCase(Locale.US);
        if (normalizedHost.equals("localhost")
                || normalizedHost.endsWith(".localhost")
                || normalizedHost.endsWith(".local")) {
            throw new IllegalArgumentException("Relay URL must use a public host");
        }
        return uri.normalize().toASCIIString();
    }

    static boolean isPublicInternetAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }

        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = bytes[0] & 0xff;
            int second = bytes[1] & 0xff;
            if (first == 0 || first == 10 || first == 127 || first >= 224) return false;
            if (first == 100 && second >= 64 && second <= 127) return false;
            if (first == 169 && second == 254) return false;
            if (first == 172 && second >= 16 && second <= 31) return false;
            if (first == 192 && (second == 0 || second == 168)) return false;
            if (first == 198 && (second == 18 || second == 19)) return false;
            return !(first == 198 && second == 51 && (bytes[2] & 0xff) == 100)
                    && !(first == 203 && second == 0 && (bytes[2] & 0xff) == 113);
        }

        int first = bytes[0] & 0xff;
        int second = bytes[1] & 0xff;
        if ((first & 0xfe) == 0xfc) return false;
        return !(first == 0x20 && second == 0x01
                && (bytes[2] & 0xff) == 0x0d && (bytes[3] & 0xff) == 0xb8);
    }
}
