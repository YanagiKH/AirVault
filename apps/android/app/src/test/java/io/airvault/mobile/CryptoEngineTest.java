package io.airvault.mobile;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public final class CryptoEngineTest {
    private static JSONArray manifest() throws Exception {
        return new JSONArray().put(new JSONObject()
                .put("name", "report.txt")
                .put("relativePath", "report.txt")
                .put("size", 5)
                .put("sha256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .put("mimeType", "text/plain"));
    }

    @Test public void pinHandshakeDerivesMatchingAuthenticatedSession() throws Exception {
        CryptoEngine.Identity sender = CryptoEngine.createIdentity();
        CryptoEngine.Identity receiver = CryptoEngine.createIdentity();
        CryptoEngine.OfferBundle offer = CryptoEngine.createOffer(sender, receiver.deviceId, manifest());
        CryptoEngine.AcceptBundle accepted = CryptoEngine.acceptOffer(offer.offer, receiver, offer.pin);
        byte[] senderSession = CryptoEngine.completeAccept(offer, accepted.accept, null);

        assertArrayEquals(senderSession, accepted.sessionMaterial);
        byte[] plaintext = "hello".getBytes(StandardCharsets.UTF_8);
        JSONObject packet = CryptoEngine.encrypt(senderSession, offer.offer.getString("transferId"), "file:0", 0, plaintext);
        assertArrayEquals(plaintext, CryptoEngine.decrypt(
                accepted.sessionMaterial, offer.offer.getString("transferId"), "file:0", 0, packet));
    }

    @Test public void qrHandshakeAndIdentityFingerprintAreStable() throws Exception {
        CryptoEngine.Identity sender = CryptoEngine.createIdentity();
        CryptoEngine.Identity receiver = CryptoEngine.createIdentity();
        CryptoEngine.OfferBundle offer = CryptoEngine.createOffer(sender, receiver.deviceId, manifest());
        CryptoEngine.AcceptBundle accepted = CryptoEngine.acceptOffer(offer.offer, receiver, offer.qrSecret);

        assertEquals(sender.deviceId, CryptoEngine.deviceIdFromPublicKey(sender.publicKeyPem));
        assertEquals("qr", accepted.accept.getString("authorizationMethod"));
        assertTrue(offer.qrPayload.startsWith("airvault://accept?v=1&transfer="));
    }

    @Test public void wrongPinAndTamperedCiphertextFailClosed() throws Exception {
        CryptoEngine.Identity sender = CryptoEngine.createIdentity();
        CryptoEngine.Identity receiver = CryptoEngine.createIdentity();
        CryptoEngine.OfferBundle offer = CryptoEngine.createOffer(sender, receiver.deviceId, manifest());
        assertThrows(GeneralSecurityException.class,
                () -> CryptoEngine.acceptOffer(offer.offer, receiver, "000000".equals(offer.pin) ? "000001" : "000000"));

        CryptoEngine.AcceptBundle accepted = CryptoEngine.acceptOffer(offer.offer, receiver, offer.pin);
        JSONObject packet = CryptoEngine.encrypt(accepted.sessionMaterial, offer.offer.getString("transferId"), "control", 0,
                "ready".getBytes(StandardCharsets.UTF_8));
        String ciphertext = packet.getString("ciphertext");
        char replacement = ciphertext.charAt(0) == 'A' ? 'B' : 'A';
        packet.put("ciphertext", replacement + ciphertext.substring(1));
        assertThrows(GeneralSecurityException.class, () -> CryptoEngine.decrypt(
                accepted.sessionMaterial, offer.offer.getString("transferId"), "control", 0, packet));
    }

    @Test public void canonicalJsonIncludesPrototypeNamedProperties() throws Exception {
        JSONObject value = new JSONObject("{\"__proto__\":{\"polluted\":true},\"safe\":1}");
        String canonical = CryptoEngine.canonical(value);
        assertEquals("{\"__proto__\":{\"polluted\":true},\"safe\":1}", canonical);
        assertFalse(canonical.isEmpty());
    }

    @Test public void androidCryptoMatchesDesktopEd25519PemVector() throws Exception {
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MCowBQYDK2VwAyEAlh0fZ1Xz522Hb/Dyba55CUl16iCPFhGBB+ALkP+9scs=\n"
                + "-----END PUBLIC KEY-----\n";
        String message = "{\"platform\":\"desktop\",\"version\":1}";
        String signature = "iFQgxZ5XBaCEnQBMLP_HB6R4ojKUHvaL2WyWv-qOcKnEKXbL6kQgBXs1VXd_Kn8eARkpJYIzJp0rys-4ttNuCA";

        assertEquals("AV-BZ2AN-6DHIE-TKE2H-RLNJS", CryptoEngine.deviceIdFromPublicKey(publicKey));
        assertTrue(CryptoEngine.verify(publicKey, message, signature));
    }
}
