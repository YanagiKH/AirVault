package io.airvault.mobile;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.List;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;

public final class FileSafetyScanner {
    private static final Set<String> EXECUTABLE = new HashSet<>(Arrays.asList(
            "apk", "bat", "cmd", "com", "cpl", "dll", "exe", "hta", "jar", "js", "lnk",
            "msi", "ps1", "reg", "scr", "sh", "sys", "vbs", "wsf"));

    private FileSafetyScanner() {}

    public static JSONArray createManifest(ContentResolver resolver, List<Uri> uris) throws Exception {
        if (uris.isEmpty() || uris.size() > 256) throw new SecurityException("Select between 1 and 256 files");
        JSONArray manifest = new JSONArray();
        Set<String> names = new HashSet<>();
        long total = 0;
        for (Uri uri : uris) {
            String name = null;
            long size = -1;
            try (Cursor cursor = resolver.query(uri, new String[] { OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE }, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    int sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE);
                    if (nameIndex >= 0) name = cursor.getString(nameIndex);
                    if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) size = cursor.getLong(sizeIndex);
                }
            }
            if (name == null || name.trim().isEmpty() || name.contains("/") || name.contains("\\") || name.contains("\0")) {
                throw new SecurityException("Unsafe filename");
            }
            String normalized = name.toLowerCase(Locale.US);
            if (!names.add(normalized)) throw new SecurityException("Duplicate filename: " + name);
            String extension = normalized.contains(".") ? normalized.substring(normalized.lastIndexOf('.') + 1) : "";
            boolean executableWarning = EXECUTABLE.contains(extension);
            String hash;
            long counted = 0;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = resolver.openInputStream(uri)) {
                if (input == null) throw new SecurityException("Cannot open " + name);
                byte[] buffer = new byte[256 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                    counted += read;
                    if (counted > 100L * 1024 * 1024 * 1024) throw new SecurityException("File is too large");
                }
            }
            if (size < 0) size = counted;
            if (size != counted) throw new SecurityException("File changed while it was scanned: " + name);
            total += size;
            if (total > 100L * 1024 * 1024 * 1024) throw new SecurityException("Transfer exceeds 100 GiB");
            manifest.put(new JSONObject()
                    .put("name", name)
                    .put("relativePath", name)
                    .put("size", size)
                    .put("sha256", hex(digest.digest()))
                    .put("mimeType", resolver.getType(uri) == null ? "application/octet-stream" : resolver.getType(uri))
                    .put("executableWarning", executableWarning));
        }
        return manifest;
    }

    public static void validateReceivedManifest(JSONArray manifest) throws Exception {
        if (manifest.length() == 0 || manifest.length() > 256) throw new SecurityException("Invalid file count");
        Set<String> names = new HashSet<>();
        long total = 0;
        for (int i = 0; i < manifest.length(); i++) {
            JSONObject file = manifest.getJSONObject(i);
            String name = file.getString("name");
            String relative = file.getString("relativePath");
            long size = file.getLong("size");
            if (name.trim().isEmpty() || name.contains("/") || name.contains("\\") || !relative.equals(name)) throw new SecurityException("Unsafe received path");
            if (!names.add(name.toLowerCase(Locale.US))) throw new SecurityException("Duplicate received filename");
            if (size < 0 || !file.getString("sha256").matches("^[a-fA-F0-9]{64}$")) throw new SecurityException("Invalid received metadata");
            total += size;
            if (total > 100L * 1024 * 1024 * 1024) throw new SecurityException("Transfer exceeds 100 GiB");
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format(Locale.US, "%02x", value));
        return result.toString();
    }
}
