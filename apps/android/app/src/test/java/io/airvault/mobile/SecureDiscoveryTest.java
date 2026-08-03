package io.airvault.mobile;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.json.JSONObject;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureDiscoveryTest {
    @Test public void acceptsSignedFreshBeaconAndRejectsForgery() throws Exception {
        CryptoEngine.Identity remote = CryptoEngine.createIdentity();
        CryptoEngine.Identity local = CryptoEngine.createIdentity();
        long now = System.currentTimeMillis();
        JSONObject beacon = beacon(remote, now);

        SecureDiscovery.DiscoveredDevice discovered =
                SecureDiscovery.parseBeacon(beacon.toString(), local.deviceId, now);
        assertEquals(remote.deviceId, discovered.deviceId);
        assertEquals(remote.publicKeyPem, discovered.publicKey);

        beacon.put("deviceId", local.deviceId);
        assertNull(SecureDiscovery.parseBeacon(beacon.toString(), local.deviceId, now));
    }

    @Test public void rejectsStaleAndTamperedBeacon() throws Exception {
        CryptoEngine.Identity remote = CryptoEngine.createIdentity();
        CryptoEngine.Identity local = CryptoEngine.createIdentity();
        long now = System.currentTimeMillis();
        JSONObject stale = beacon(remote, now - 600_000L);
        assertNull(SecureDiscovery.parseBeacon(stale.toString(), local.deviceId, now));
        JSONObject overflowTimestamp = beacon(remote, Long.MIN_VALUE);
        assertNull(SecureDiscovery.parseBeacon(overflowTimestamp.toString(), local.deviceId, now));

        JSONObject tampered = beacon(remote, now);
        tampered.put("timestamp", now - 1);
        assertNull(SecureDiscovery.parseBeacon(tampered.toString(), local.deviceId, now));
    }

    private static JSONObject beacon(CryptoEngine.Identity identity, long timestamp) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        JSONObject unsigned = new JSONObject()
                .put("version", 1)
                .put("type", "airvault-discovery")
                .put("deviceId", identity.deviceId)
                .put("publicKey", identity.publicKeyPem)
                .put("timestamp", timestamp)
                .put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(nonce));
        return new JSONObject(unsigned.toString())
                .put("signature", CryptoEngine.sign(identity.privateKeyPem, CryptoEngine.canonical(unsigned)));
    }
}
