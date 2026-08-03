package io.airvault.mobile;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class PeerStore {
    public static final class Peer {
        public final String deviceId;
        public String name;
        public String publicKey;
        public long verifiedAt;

        Peer(String deviceId, String name, String publicKey, long verifiedAt) {
            this.deviceId = deviceId;
            this.name = name;
            this.publicKey = publicKey;
            this.verifiedAt = verifiedAt;
        }
    }

    private final SharedPreferences preferences;
    private final List<Peer> peers = new ArrayList<>();

    public PeerStore(Context context) {
        preferences = context.getSharedPreferences("airvault.peers.v1", Context.MODE_PRIVATE);
        load();
    }

    public synchronized List<Peer> all() {
        return new ArrayList<>(peers);
    }

    public synchronized Peer find(String deviceId) {
        for (Peer peer : peers) if (peer.deviceId.equals(deviceId)) return peer;
        return null;
    }

    public synchronized void save(String deviceId, String name) {
        String id = deviceId.trim().toUpperCase(Locale.US);
        if (!id.matches("^AV-[A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}$")) throw new IllegalArgumentException("Invalid AirVault device ID");
        String cleanName = name.replaceAll("[\\p{Cntrl}<>]", "").trim();
        if (cleanName.isEmpty()) cleanName = "Device " + id.substring(id.length() - 5);
        Peer peer = find(id);
        if (peer == null) peers.add(new Peer(id, cleanName.substring(0, Math.min(64, cleanName.length())), null, 0));
        else peer.name = cleanName.substring(0, Math.min(64, cleanName.length()));
        persist();
    }

    public synchronized void pin(String deviceId, String publicKey) throws Exception {
        Peer peer = find(deviceId);
        if (peer == null) throw new SecurityException("Device is not saved");
        if (!CryptoEngine.deviceIdFromPublicKey(publicKey).equals(deviceId)) throw new SecurityException("Identity fingerprint mismatch");
        if (peer.publicKey != null && !peer.publicKey.equals(publicKey)) throw new SecurityException("Saved device identity changed");
        peer.publicKey = publicKey;
        if (peer.verifiedAt == 0) peer.verifiedAt = System.currentTimeMillis();
        persist();
    }

    public synchronized void remove(String deviceId) {
        peers.removeIf(peer -> peer.deviceId.equals(deviceId));
        persist();
    }

    private void load() {
        try {
            JSONArray array = new JSONArray(preferences.getString("peers", "[]"));
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.getJSONObject(i);
                peers.add(new Peer(item.getString("deviceId"), item.getString("name"),
                        item.optString("publicKey", null), item.optLong("verifiedAt", 0)));
            }
        } catch (Exception error) {
            peers.clear();
            throw new IllegalStateException("Saved peer identities failed integrity validation", error);
        }
    }

    private void persist() {
        JSONArray array = new JSONArray();
        for (Peer peer : peers) {
            try {
                JSONObject item = new JSONObject()
                        .put("deviceId", peer.deviceId)
                        .put("name", peer.name)
                        .put("verifiedAt", peer.verifiedAt);
                if (peer.publicKey != null) item.put("publicKey", peer.publicKey);
                array.put(item);
            } catch (Exception impossible) {
                throw new IllegalStateException(impossible);
            }
        }
        preferences.edit().putString("peers", array.toString()).apply();
    }
}
