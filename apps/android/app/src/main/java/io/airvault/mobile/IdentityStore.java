package io.airvault.mobile;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class IdentityStore {
    private static final String PREFS = "airvault.identity.v1";
    private static final String KEY_ALIAS = "airvault.identity.wrap.v1";
    private static final String VALUE = "protected_identity";
    private final SharedPreferences preferences;

    public IdentityStore(Context context) {
        preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public CryptoEngine.Identity loadOrCreate() throws Exception {
        String stored = preferences.getString(VALUE, null);
        if (stored != null) return decode(stored);
        CryptoEngine.Identity identity = CryptoEngine.createIdentity();
        preferences.edit().putString(VALUE, encode(identity)).apply();
        return identity;
    }

    private String encode(CryptoEngine.Identity identity) throws Exception {
        JSONObject json = new JSONObject()
                .put("deviceId", identity.deviceId)
                .put("publicKeyPem", identity.publicKeyPem)
                .put("privateKeyPem", identity.privateKeyPem);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey());
        byte[] encrypted = cipher.doFinal(json.toString().getBytes(StandardCharsets.UTF_8));
        JSONObject envelope = new JSONObject()
                .put("iv", Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP))
                .put("ciphertext", Base64.encodeToString(encrypted, Base64.NO_WRAP));
        return envelope.toString();
    }

    private CryptoEngine.Identity decode(String stored) throws Exception {
        JSONObject envelope = new JSONObject(stored);
        byte[] iv = Base64.decode(envelope.getString("iv"), Base64.DEFAULT);
        byte[] encrypted = Base64.decode(envelope.getString("ciphertext"), Base64.DEFAULT);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), new GCMParameterSpec(128, iv));
        JSONObject json = new JSONObject(new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8));
        CryptoEngine.Identity identity = new CryptoEngine.Identity(
                json.getString("deviceId"), json.getString("publicKeyPem"), json.getString("privateKeyPem"));
        if (!identity.deviceId.equals(CryptoEngine.deviceIdFromPublicKey(identity.publicKeyPem))) {
            throw new SecurityException("Stored AirVault identity failed integrity verification");
        }
        return identity;
    }

    private SecretKey wrappingKey() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(KEY_ALIAS)) return ((KeyStore.SecretKeyEntry) store.getEntry(KEY_ALIAS, null)).getSecretKey();
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }
}
