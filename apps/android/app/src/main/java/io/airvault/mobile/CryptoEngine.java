package io.airvault.mobile;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CryptoEngine {
    public static final int PROTOCOL_VERSION = 1;
    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoEngine() {}

    public static final class Identity {
        public final String deviceId;
        public final String publicKeyPem;
        public final String privateKeyPem;

        Identity(String deviceId, String publicKeyPem, String privateKeyPem) {
            this.deviceId = deviceId;
            this.publicKeyPem = publicKeyPem;
            this.privateKeyPem = privateKeyPem;
        }
    }

    public static final class OfferBundle {
        public final JSONObject offer;
        public final String pin;
        public final String qrSecret;
        public final String qrPayload;
        public final String ephemeralPrivateKeyPem;
        public final JSONArray manifest;

        OfferBundle(JSONObject offer, String pin, String qrSecret, String qrPayload, String ephemeralPrivateKeyPem, JSONArray manifest) {
            this.offer = offer;
            this.pin = pin;
            this.qrSecret = qrSecret;
            this.qrPayload = qrPayload;
            this.ephemeralPrivateKeyPem = ephemeralPrivateKeyPem;
            this.manifest = manifest;
        }
    }

    public static final class AcceptBundle {
        public final JSONObject accept;
        public final byte[] sessionMaterial;

        AcceptBundle(JSONObject accept, byte[] sessionMaterial) {
            this.accept = accept;
            this.sessionMaterial = sessionMaterial;
        }
    }

    public static Identity createIdentity() throws GeneralSecurityException {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String publicPem = pem("PUBLIC KEY", pair.getPublic().getEncoded());
        return new Identity(deviceIdFromPublicKey(publicPem), publicPem, pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
    }

    public static String deviceIdFromPublicKey(String publicKeyPem) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(readPem(publicKeyPem));
        String fingerprint = base32(digest).substring(0, 20);
        return String.format(Locale.US, "AV-%s-%s-%s-%s",
                fingerprint.substring(0, 5), fingerprint.substring(5, 10),
                fingerprint.substring(10, 15), fingerprint.substring(15, 20));
    }

    public static OfferBundle createOffer(Identity identity, String receiverId, JSONArray manifest)
            throws GeneralSecurityException, JSONException {
        String normalizedReceiver = receiverId.trim().toUpperCase(Locale.US);
        if (!normalizedReceiver.matches("^AV-[A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}$")) throw new GeneralSecurityException("Invalid AirVault device ID");
        KeyPair ephemeral = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        long now = System.currentTimeMillis();
        String pin = String.format(Locale.US, "%06d", RANDOM.nextInt(1_000_000));
        String qrSecret = randomBase64Url(32);
        JSONObject core = new JSONObject()
                .put("version", PROTOCOL_VERSION)
                .put("transferId", randomBase64Url(18))
                .put("senderId", identity.deviceId)
                .put("receiverId", normalizedReceiver)
                .put("senderIdentityPublicKey", identity.publicKeyPem)
                .put("senderEphemeralPublicKey", pem("PUBLIC KEY", ephemeral.getPublic().getEncoded()))
                .put("challenge", randomBase64Url(24))
                .put("manifestDigest", hex(MessageDigest.getInstance("SHA-256").digest(canonical(manifest).getBytes(StandardCharsets.UTF_8))))
                .put("createdAt", now)
                .put("expiresAt", now + 600_000L);
        String transcript = canonical(core);
        JSONObject unsigned = copy(core)
                .put("pinCommitment", hmacBase64Url(pin, "airvault:pin:" + transcript))
                .put("qrCommitment", hmacBase64Url(qrSecret, "airvault:qr:" + transcript));
        JSONObject offer = copy(unsigned).put("signature", sign(identity.privateKeyPem, canonical(unsigned)));
        String qr = "airvault://accept?v=1&transfer=" + offer.getString("transferId") + "&secret=" + qrSecret;
        return new OfferBundle(offer, pin, qrSecret, qr, pem("PRIVATE KEY", ephemeral.getPrivate().getEncoded()), manifest);
    }

    public static void verifyOffer(JSONObject offer, String expectedReceiverId) throws GeneralSecurityException, JSONException {
        if (offer.getInt("version") != PROTOCOL_VERSION) throw new GeneralSecurityException("Unsupported protocol version");
        if (!expectedReceiverId.equals(offer.getString("receiverId"))) throw new GeneralSecurityException("Offer targets another device");
        String publicKey = offer.getString("senderIdentityPublicKey");
        if (!deviceIdFromPublicKey(publicKey).equals(offer.getString("senderId"))) throw new GeneralSecurityException("Identity fingerprint mismatch");
        long now = System.currentTimeMillis();
        long createdAt = offer.getLong("createdAt");
        long expiresAt = offer.getLong("expiresAt");
        if (expiresAt < now || createdAt > now + 300_000L || expiresAt < createdAt || expiresAt - createdAt > 1_800_000L) {
            throw new GeneralSecurityException("Offer expired or has an invalid lifetime");
        }
        JSONObject unsigned = copyWithout(offer, "signature");
        if (!verify(publicKey, canonical(unsigned), offer.getString("signature"))) throw new GeneralSecurityException("Invalid offer signature");
    }

    public static byte[] deriveSessionKey(String localPrivatePem, String remotePublicPem, JSONObject offer, String authorization)
            throws GeneralSecurityException, JSONException {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(privateKey("X25519", localPrivatePem));
        agreement.doPhase(publicKey("X25519", remotePublicPem), true);
        byte[] shared = agreement.generateSecret();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update("AirVault/v1/session\0".getBytes(StandardCharsets.UTF_8));
        digest.update(canonical(copyWithout(offer, "signature")).getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
        digest.update(authorization.getBytes(StandardCharsets.UTF_8));
        byte[] salt = digest.digest();
        byte[] key = hkdfSha256(shared, salt, offer.getString("transferId").getBytes(StandardCharsets.UTF_8), 64);
        java.util.Arrays.fill(shared, (byte) 0);
        return key;
    }

    public static AcceptBundle acceptOffer(JSONObject offer, Identity receiver, String authorization)
            throws GeneralSecurityException, JSONException {
        verifyOffer(offer, receiver.deviceId);
        JSONObject core = copyWithout(copyWithout(copyWithout(offer, "pinCommitment"), "qrCommitment"), "signature");
        String transcript = canonical(core);
        String method;
        if (authorization.matches("^\\d{6}$") && constantTimeEquals(
                hmacBase64Url(authorization, "airvault:pin:" + transcript), offer.getString("pinCommitment"))) {
            method = "pin";
        } else if (constantTimeEquals(
                hmacBase64Url(authorization, "airvault:qr:" + transcript), offer.getString("qrCommitment"))) {
            method = "qr";
        } else {
            throw new GeneralSecurityException("Incorrect PIN or QR authorization");
        }
        KeyPair ephemeral = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        String ephemeralPublic = pem("PUBLIC KEY", ephemeral.getPublic().getEncoded());
        JSONObject proofObject = new JSONObject()
                .put("offer", copyWithout(offer, "signature"))
                .put("receiverEphemeralPublicKey", ephemeralPublic);
        JSONObject unsigned = new JSONObject()
                .put("version", PROTOCOL_VERSION)
                .put("transferId", offer.getString("transferId"))
                .put("receiverId", receiver.deviceId)
                .put("receiverIdentityPublicKey", receiver.publicKeyPem)
                .put("receiverEphemeralPublicKey", ephemeralPublic)
                .put("authorizationMethod", method)
                .put("authorizationProof", hmacBase64Url(authorization, "airvault:accept:" + canonical(proofObject)))
                .put("acceptedAt", System.currentTimeMillis());
        JSONObject accept = copy(unsigned).put("signature", sign(receiver.privateKeyPem, canonical(unsigned)));
        byte[] session = deriveSessionKey(
                pem("PRIVATE KEY", ephemeral.getPrivate().getEncoded()),
                offer.getString("senderEphemeralPublicKey"), offer, authorization);
        return new AcceptBundle(accept, session);
    }

    public static byte[] completeAccept(OfferBundle outgoing, JSONObject accept, String pinnedPublicKey)
            throws GeneralSecurityException, JSONException {
        if (accept.getInt("version") != PROTOCOL_VERSION
                || !outgoing.offer.getString("transferId").equals(accept.getString("transferId"))
                || !outgoing.offer.getString("receiverId").equals(accept.getString("receiverId"))) {
            throw new GeneralSecurityException("Accept does not match the transfer");
        }
        String receiverPublicKey = accept.getString("receiverIdentityPublicKey");
        if (!deviceIdFromPublicKey(receiverPublicKey).equals(accept.getString("receiverId"))) {
            throw new GeneralSecurityException("Receiver identity mismatch");
        }
        if (pinnedPublicKey != null && !pinnedPublicKey.equals(receiverPublicKey)) {
            throw new GeneralSecurityException("Saved receiver identity key changed");
        }
        if (!verify(receiverPublicKey, canonical(copyWithout(accept, "signature")), accept.getString("signature"))) {
            throw new GeneralSecurityException("Invalid receiver signature");
        }
        if (Math.abs(System.currentTimeMillis() - accept.getLong("acceptedAt")) > 300_000L) {
            throw new GeneralSecurityException("Stale receiver response");
        }
        String authorizationMethod = accept.getString("authorizationMethod");
        if (!"pin".equals(authorizationMethod) && !"qr".equals(authorizationMethod)) {
            throw new GeneralSecurityException("Invalid authorization method");
        }
        String authorization = "pin".equals(authorizationMethod) ? outgoing.pin : outgoing.qrSecret;
        JSONObject proofObject = new JSONObject()
                .put("offer", copyWithout(outgoing.offer, "signature"))
                .put("receiverEphemeralPublicKey", accept.getString("receiverEphemeralPublicKey"));
        String proof = hmacBase64Url(authorization, "airvault:accept:" + canonical(proofObject));
        if (!constantTimeEquals(proof, accept.getString("authorizationProof"))) {
            throw new GeneralSecurityException("Invalid receiver authorization proof");
        }
        return deriveSessionKey(outgoing.ephemeralPrivateKeyPem, accept.getString("receiverEphemeralPublicKey"), outgoing.offer, authorization);
    }

    public static JSONObject encrypt(byte[] sessionMaterial, String transferId, String purpose, long index, byte[] plaintext)
            throws GeneralSecurityException, JSONException {
        byte[] encryptionKey = java.util.Arrays.copyOfRange(sessionMaterial, 0, 32);
        byte[] confirmationKey = java.util.Arrays.copyOfRange(sessionMaterial, 32, 64);
        String aadText = canonical(new JSONObject().put("version", 1).put("transferId", transferId).put("purpose", purpose).put("index", index));
        byte[] nonce = java.util.Arrays.copyOf(hmac(confirmationKey, aadText.getBytes(StandardCharsets.UTF_8)), 12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aadText.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedAndTag = cipher.doFinal(plaintext);
        int ciphertextLength = encryptedAndTag.length - 16;
        return new JSONObject()
                .put("nonce", base64Url(nonce))
                .put("ciphertext", base64Url(java.util.Arrays.copyOf(encryptedAndTag, ciphertextLength)))
                .put("tag", base64Url(java.util.Arrays.copyOfRange(encryptedAndTag, ciphertextLength, encryptedAndTag.length)));
    }

    public static byte[] decrypt(byte[] sessionMaterial, String transferId, String purpose, long index, JSONObject packet)
            throws GeneralSecurityException, JSONException {
        byte[] encryptionKey = java.util.Arrays.copyOfRange(sessionMaterial, 0, 32);
        byte[] confirmationKey = java.util.Arrays.copyOfRange(sessionMaterial, 32, 64);
        String aadText = canonical(new JSONObject().put("version", 1).put("transferId", transferId).put("purpose", purpose).put("index", index));
        byte[] expectedNonce = java.util.Arrays.copyOf(hmac(confirmationKey, aadText.getBytes(StandardCharsets.UTF_8)), 12);
        byte[] actualNonce = Base64.getUrlDecoder().decode(packet.getString("nonce"));
        if (!MessageDigest.isEqual(expectedNonce, actualNonce)) throw new GeneralSecurityException("Invalid packet nonce");
        byte[] ciphertext = Base64.getUrlDecoder().decode(packet.getString("ciphertext"));
        byte[] tag = Base64.getUrlDecoder().decode(packet.getString("tag"));
        byte[] encryptedAndTag = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, encryptedAndTag, 0, ciphertext.length);
        System.arraycopy(tag, 0, encryptedAndTag, ciphertext.length, tag.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(128, actualNonce));
        cipher.updateAAD(aadText.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(encryptedAndTag);
    }

    public static String canonical(Object value) throws JSONException {
        if (value == JSONObject.NULL || value == null) return "null";
        if (value instanceof Boolean || value instanceof Number) return String.valueOf(value);
        if (value instanceof String) return JSONObject.quote((String) value);
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            List<String> items = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) items.add(canonical(array.get(i)));
            return "[" + String.join(",", items) + "]";
        }
        if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value;
            List<String> keys = new ArrayList<>();
            Iterator<String> iterator = object.keys();
            while (iterator.hasNext()) keys.add(iterator.next());
            Collections.sort(keys);
            List<String> fields = new ArrayList<>();
            for (String key : keys) fields.add(JSONObject.quote(key) + ":" + canonical(object.get(key)));
            return "{" + String.join(",", fields) + "}";
        }
        throw new JSONException("Unsupported canonical JSON value");
    }

    public static String sign(String privatePem, String message) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey("Ed25519", privatePem));
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        return base64Url(signature.sign());
    }

    public static boolean verify(String publicPem, String message, String encodedSignature) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey("Ed25519", publicPem));
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getUrlDecoder().decode(encodedSignature));
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws GeneralSecurityException {
        byte[] prk = hmac(salt, ikm);
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        for (int counter = 1; offset < length; counter++) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            int amount = Math.min(previous.length, length - offset);
            System.arraycopy(previous, 0, output, offset, amount);
            offset += amount;
        }
        java.util.Arrays.fill(prk, (byte) 0);
        return output;
    }

    private static byte[] hmac(byte[] key, byte[] value) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(value);
    }

    private static String hmacBase64Url(String key, String value) throws GeneralSecurityException {
        return base64Url(hmac(key.getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8)));
    }

    private static boolean constantTimeEquals(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    private static JSONObject copy(JSONObject value) throws JSONException {
        return new JSONObject(value.toString());
    }

    private static JSONObject copyWithout(JSONObject value, String excluded) throws JSONException {
        JSONObject result = new JSONObject();
        Iterator<String> keys = value.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!excluded.equals(key)) result.put(key, value.get(key));
        }
        return result;
    }

    private static PrivateKey privateKey(String algorithm, String pem) throws GeneralSecurityException {
        return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(readPem(pem)));
    }

    private static PublicKey publicKey(String algorithm, String pem) throws GeneralSecurityException {
        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(readPem(pem)));
    }

    private static byte[] readPem(String pem) {
        String encoded = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(encoded);
    }

    private static String pem(String type, byte[] encoded) {
        return "-----BEGIN " + type + "-----\n" + Base64.getEncoder().encodeToString(encoded) + "\n-----END " + type + "-----\n";
    }

    private static String randomBase64Url(int count) {
        byte[] bytes = new byte[count];
        RANDOM.nextBytes(bytes);
        return base64Url(bytes);
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String base32(byte[] input) {
        StringBuilder output = new StringBuilder();
        int bits = 0;
        int value = 0;
        for (byte item : input) {
            value = (value << 8) | (item & 0xff);
            bits += 8;
            while (bits >= 5) {
                output.append(BASE32[(value >>> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) output.append(BASE32[(value << (5 - bits)) & 31]);
        return output.toString();
    }

    private static String hex(byte[] bytes) {
        StringBuilder output = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) output.append(String.format(Locale.US, "%02x", value));
        return output.toString();
    }
}
