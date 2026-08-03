package io.airvault.mobile;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.util.Base64;

import androidx.documentfile.provider.DocumentFile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MobileTransferController implements RelayClient.Listener {
    public interface Listener {
        void onRelayStatus(String status);
        void onIncomingOffer(String transferId, String senderName);
        void onManifestReview(String transferId, JSONArray manifest, long totalBytes, int executableWarnings);
        void onAuthorizationReady(String transferId, String pin, String qrPayload);
        void onProgress(String transferId, String message, int percent);
        void onComplete(String transferId, String message);
        void onError(String safeMessage);
    }

    private static final int CHUNK_BYTES = 256 * 1024;
    private static final int MAX_ACTIVE_TRANSFERS = 64;
    private final ContentResolver resolver;
    private final Context context;
    private final CryptoEngine.Identity identity;
    private final PeerStore peers;
    private final Listener listener;
    private final RelayClient relay;
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Map<String, Outgoing> outgoing = new HashMap<>();
    private final Map<String, Incoming> incoming = new HashMap<>();

    private static final class Outgoing {
        final List<Uri> uris;
        final CryptoEngine.OfferBundle bundle;
        byte[] session;
        boolean streaming;

        Outgoing(List<Uri> uris, CryptoEngine.OfferBundle bundle) {
            this.uris = uris;
            this.bundle = bundle;
        }
    }

    private static final class Incoming {
        final JSONObject offer;
        final String senderId;
        int failedAttempts;
        byte[] session;
        JSONArray manifest;
        DocumentFile destination;
        final Map<Integer, ReceivedFile> files = new HashMap<>();

        Incoming(JSONObject offer, String senderId) {
            this.offer = offer;
            this.senderId = senderId;
        }
    }

    private static final class ReceivedFile {
        final DocumentFile document;
        final OutputStream output;
        final MessageDigest digest;
        final long expectedBytes;
        final String expectedDigest;
        final String finalName;
        long receivedBytes;
        long nextChunk;

        ReceivedFile(DocumentFile document, OutputStream output, long expectedBytes, String expectedDigest, String finalName) throws Exception {
            this.document = document;
            this.output = output;
            this.expectedBytes = expectedBytes;
            this.expectedDigest = expectedDigest;
            this.finalName = finalName;
            this.digest = MessageDigest.getInstance("SHA-256");
        }
    }

    public MobileTransferController(
            Context context,
            String relayUrl,
            CryptoEngine.Identity identity,
            PeerStore peers,
            Listener listener) {
        this.context = context.getApplicationContext();
        this.resolver = context.getContentResolver();
        this.identity = identity;
        this.peers = peers;
        this.listener = listener;
        this.relay = new RelayClient(relayUrl, identity, this);
    }

    public void connect() {
        relay.connect();
    }

    public void disconnect() {
        relay.disconnect();
        io.shutdownNow();
    }

    public void updateRelay(String url) {
        relay.updateUrl(url);
    }

    public void beginSend(List<Uri> uris, String receiverId) {
        io.execute(() -> {
            try {
                pruneExpired();
                PeerStore.Peer peer = peers.find(receiverId);
                if (peer == null) throw new SecurityException("Choose a saved device");
                JSONArray manifest = FileSafetyScanner.createManifest(resolver, uris);
                CryptoEngine.OfferBundle bundle = CryptoEngine.createOffer(identity, receiverId, manifest);
                synchronized (outgoing) {
                    if (outgoing.size() >= MAX_ACTIVE_TRANSFERS) throw new SecurityException("Too many active outgoing transfers");
                    outgoing.put(bundle.offer.getString("transferId"), new Outgoing(new ArrayList<>(uris), bundle));
                }
                relay.route(receiverId, bundle.offer.getString("transferId"),
                        new JSONObject().put("kind", "offer").put("offer", bundle.offer));
                listener.onAuthorizationReady(bundle.offer.getString("transferId"), bundle.pin, bundle.qrPayload);
            } catch (Exception error) {
                listener.onError(safe(error));
            }
        });
    }

    public void acceptIncoming(String transferId, String authorization) {
        io.execute(() -> {
            try {
                Incoming record = incoming.get(transferId);
                if (record == null) throw new SecurityException("Transfer offer expired");
                if (record.failedAttempts >= 5) throw new SecurityException("Too many incorrect attempts");
                String secret = authorization.trim();
                if (secret.startsWith("airvault://")) {
                    Uri link = Uri.parse(secret);
                    if (!"accept".equals(link.getHost()) || !transferId.equals(link.getQueryParameter("transfer"))) {
                        throw new SecurityException("QR code does not match this transfer");
                    }
                    secret = link.getQueryParameter("secret");
                }
                try {
                    CryptoEngine.AcceptBundle accepted = CryptoEngine.acceptOffer(record.offer, identity, secret);
                    record.session = accepted.sessionMaterial;
                    peers.pin(record.senderId, record.offer.getString("senderIdentityPublicKey"));
                    relay.route(record.senderId, transferId,
                            new JSONObject().put("kind", "accept").put("accept", accepted.accept));
                    listener.onProgress(transferId, "Authorization verified; scanning encrypted manifest", 0);
                } catch (Exception error) {
                    record.failedAttempts++;
                    throw error;
                }
            } catch (Exception error) {
                listener.onError(safe(error));
            }
        });
    }

    public void approveIncoming(String transferId, Uri treeUri) {
        io.execute(() -> {
            try {
                Incoming record = incoming.get(transferId);
                if (record == null || record.session == null || record.manifest == null) throw new SecurityException("Manifest is not ready");
                DocumentFile destination = DocumentFile.fromTreeUri(context, treeUri);
                if (destination == null || !destination.canWrite()) throw new SecurityException("Selected folder is not writable");
                record.destination = destination;
                JSONObject packet = CryptoEngine.encrypt(record.session, transferId, "control", 0,
                        new JSONObject().put("action", "ready").toString().getBytes(StandardCharsets.UTF_8));
                relay.route(record.senderId, transferId, packetEnvelope("control", 0, packet, -1));
                listener.onProgress(transferId, "Receiving encrypted file data", 1);
            } catch (Exception error) {
                listener.onError(safe(error));
            }
        });
    }

    public void rejectIncoming(String transferId) {
        io.execute(() -> {
            Incoming record = incoming.remove(transferId);
            if (record != null) {
                cleanupIncoming(record);
                try {
                    relay.route(record.senderId, transferId, new JSONObject().put("kind", "reject"));
                } catch (Exception error) {
                    listener.onError("The rejection could not be delivered");
                }
            }
        });
    }

    @Override public void onStatus(String status) {
        listener.onRelayStatus(status);
    }

    @Override public void onRouted(String from, String transferId, JSONObject payload) {
        io.execute(() -> {
            try {
                String kind = payload.getString("kind");
                if ("offer".equals(kind)) receiveOffer(from, transferId, payload.getJSONObject("offer"));
                else if ("accept".equals(kind)) receiveAccept(from, transferId, payload.getJSONObject("accept"));
                else if ("reject".equals(kind)) {
                    outgoing.remove(transferId);
                    listener.onError("The receiving device declined the transfer");
                } else if ("packet".equals(kind)) receivePacket(from, transferId, payload);
            } catch (Exception error) {
                failTransfer(transferId, from);
                listener.onError(safe(error));
            }
        });
    }

    @Override public void onError(String safeMessage) {
        listener.onError(safeMessage);
    }

    private void receiveOffer(String from, String transferId, JSONObject offer) throws Exception {
        pruneExpired();
        if (incoming.containsKey(transferId)) return;
        if (incoming.size() >= MAX_ACTIVE_TRANSFERS) throw new SecurityException("Too many active incoming transfers");
        PeerStore.Peer peer = peers.find(from);
        if (peer == null) throw new SecurityException("Blocked transfer from an unsaved device");
        CryptoEngine.verifyOffer(offer, identity.deviceId);
        if (!from.equals(offer.getString("senderId")) || !transferId.equals(offer.getString("transferId"))) {
            throw new SecurityException("Transfer routing identity mismatch");
        }
        if (peer.publicKey != null && !peer.publicKey.equals(offer.getString("senderIdentityPublicKey"))) {
            throw new SecurityException("Saved sender identity changed");
        }
        incoming.put(transferId, new Incoming(offer, from));
        listener.onIncomingOffer(transferId, peer.name);
    }

    private void receiveAccept(String from, String transferId, JSONObject accept) throws Exception {
        Outgoing record = outgoing.get(transferId);
        if (record == null || !from.equals(record.bundle.offer.getString("receiverId"))) throw new SecurityException("Unexpected transfer acceptance");
        PeerStore.Peer peer = peers.find(from);
        record.session = CryptoEngine.completeAccept(record.bundle, accept, peer == null ? null : peer.publicKey);
        peers.pin(from, accept.getString("receiverIdentityPublicKey"));
        JSONObject encrypted = CryptoEngine.encrypt(record.session, transferId, "manifest", 0,
                CryptoEngine.canonical(record.bundle.manifest).getBytes(StandardCharsets.UTF_8));
        relay.route(from, transferId, packetEnvelope("manifest", 0, encrypted, -1));
    }

    private void receivePacket(String from, String transferId, JSONObject payload) throws Exception {
        String purpose = payload.getString("purpose");
        long index = payload.getLong("index");
        JSONObject packet = payload.getJSONObject("packet");
        Outgoing send = outgoing.get(transferId);
        if (send != null && send.session != null && from.equals(send.bundle.offer.getString("receiverId"))
                && "control".equals(purpose) && index == 0) {
            JSONObject control = new JSONObject(new String(
                    CryptoEngine.decrypt(send.session, transferId, purpose, index, packet), StandardCharsets.UTF_8));
            if (!"ready".equals(control.getString("action")) || send.streaming) throw new SecurityException("Invalid ready message");
            send.streaming = true;
            streamOutgoing(transferId, send);
            return;
        }

        Incoming receive = incoming.get(transferId);
        if (receive == null || receive.session == null || !from.equals(receive.senderId)) throw new SecurityException("Unknown encrypted session");
        if ("manifest".equals(purpose) && index == 0) {
            byte[] plaintext = CryptoEngine.decrypt(receive.session, transferId, purpose, index, packet);
            JSONArray manifest = new JSONArray(new String(plaintext, StandardCharsets.UTF_8));
            String digest = hex(MessageDigest.getInstance("SHA-256").digest(CryptoEngine.canonical(manifest).getBytes(StandardCharsets.UTF_8)));
            if (!digest.equals(receive.offer.getString("manifestDigest"))) throw new SecurityException("Manifest commitment mismatch");
            FileSafetyScanner.validateReceivedManifest(manifest);
            receive.manifest = manifest;
            long total = 0;
            int warnings = 0;
            for (int i = 0; i < manifest.length(); i++) {
                total += manifest.getJSONObject(i).getLong("size");
                if (manifest.getJSONObject(i).optBoolean("executableWarning", false)) warnings++;
            }
            listener.onManifestReview(transferId, manifest, total, warnings);
        } else if (purpose.startsWith("file:")) {
            receiveChunk(transferId, receive, payload);
        } else if ("control".equals(purpose) && index == 1) {
            JSONObject control = new JSONObject(new String(
                    CryptoEngine.decrypt(receive.session, transferId, purpose, index, packet), StandardCharsets.UTF_8));
            if (!"complete".equals(control.getString("action"))) throw new SecurityException("Invalid completion message");
            finalizeIncoming(transferId, receive);
        }
    }

    private void streamOutgoing(String transferId, Outgoing record) throws Exception {
        long total = 0;
        for (int i = 0; i < record.bundle.manifest.length(); i++) total += record.bundle.manifest.getJSONObject(i).getLong("size");
        long completed = 0;
        for (int fileIndex = 0; fileIndex < record.uris.size(); fileIndex++) {
            long chunkIndex = 0;
            try (InputStream input = resolver.openInputStream(record.uris.get(fileIndex))) {
                if (input == null) throw new SecurityException("A selected file is no longer available");
                byte[] buffer = new byte[CHUNK_BYTES];
                int read;
                boolean sent = false;
                while ((read = input.read(buffer)) != -1) {
                    byte[] chunk = java.util.Arrays.copyOf(buffer, read);
                    JSONObject packet = CryptoEngine.encrypt(record.session, transferId, "file:" + fileIndex, chunkIndex, chunk);
                    relay.route(record.bundle.offer.getString("receiverId"), transferId,
                            packetEnvelope("file:" + fileIndex, chunkIndex, packet, fileIndex));
                    sent = true;
                    chunkIndex++;
                    completed += read;
                    listener.onProgress(transferId, "Sending encrypted file data", total == 0 ? 100 : (int) Math.min(99, completed * 100 / total));
                }
                if (!sent) {
                    JSONObject packet = CryptoEngine.encrypt(record.session, transferId, "file:" + fileIndex, 0, new byte[0]);
                    relay.route(record.bundle.offer.getString("receiverId"), transferId,
                            packetEnvelope("file:" + fileIndex, 0, packet, fileIndex));
                }
            }
        }
        JSONObject complete = CryptoEngine.encrypt(record.session, transferId, "control", 1,
                new JSONObject().put("action", "complete").toString().getBytes(StandardCharsets.UTF_8));
        relay.route(record.bundle.offer.getString("receiverId"), transferId, packetEnvelope("control", 1, complete, -1));
        outgoing.remove(transferId);
        if (record.session != null) java.util.Arrays.fill(record.session, (byte) 0);
        listener.onComplete(transferId, "Files sent securely");
    }

    private void receiveChunk(String transferId, Incoming record, JSONObject payload) throws Exception {
        if (record.manifest == null || record.destination == null) throw new SecurityException("File data arrived before approval");
        int fileIndex = payload.getInt("fileIndex");
        long chunkIndex = payload.getLong("index");
        JSONObject manifestFile = record.manifest.getJSONObject(fileIndex);
        ReceivedFile target = record.files.get(fileIndex);
        if (target == null) {
            String finalName = manifestFile.getString("name");
            String temporaryName = finalName + "." + transferId.substring(0, 6) + ".airvault-part";
            DocumentFile document = record.destination.createFile("application/octet-stream", temporaryName);
            if (document == null) throw new SecurityException("Cannot create destination file");
            OutputStream output = resolver.openOutputStream(document.getUri(), "w");
            if (output == null) throw new SecurityException("Cannot open destination file");
            target = new ReceivedFile(document, output, manifestFile.getLong("size"), manifestFile.getString("sha256"), finalName);
            record.files.put(fileIndex, target);
        }
        if (chunkIndex != target.nextChunk) throw new SecurityException("Out-of-order or replayed file chunk");
        byte[] plaintext = CryptoEngine.decrypt(record.session, transferId, "file:" + fileIndex, chunkIndex, payload.getJSONObject("packet"));
        target.receivedBytes += plaintext.length;
        if (target.receivedBytes > target.expectedBytes) throw new SecurityException("Received file exceeds declared size");
        target.output.write(plaintext);
        target.digest.update(plaintext);
        target.nextChunk++;
    }

    private void finalizeIncoming(String transferId, Incoming record) throws Exception {
        if (record.manifest == null || record.files.size() != record.manifest.length()) throw new SecurityException("Missing file data");
        List<DocumentFile> finalized = new ArrayList<>();
        try {
            for (int i = 0; i < record.manifest.length(); i++) {
                ReceivedFile file = record.files.get(i);
                if (file == null || file.receivedBytes != file.expectedBytes) throw new SecurityException("File size verification failed");
                file.output.flush();
                file.output.close();
                if (!hex(file.digest.digest()).equals(file.expectedDigest)) {
                    throw new SecurityException("SHA-256 integrity verification failed");
                }
                String destinationName = file.finalName + " (" + transferId.substring(0, 6) + ")";
                if (record.destination == null || record.destination.findFile(destinationName) != null) {
                    throw new SecurityException("A destination file already exists");
                }
                if (!file.document.renameTo(destinationName)) throw new SecurityException("Could not finalize the received file");
                finalized.add(file.document);
            }
        } catch (Exception error) {
            for (DocumentFile file : finalized) try { file.delete(); } catch (Exception ignored) { }
            throw error;
        }
        incoming.remove(transferId);
        if (record.session != null) java.util.Arrays.fill(record.session, (byte) 0);
        listener.onComplete(transferId, "Files received and cryptographically verified");
    }

    private static JSONObject packetEnvelope(String purpose, long index, JSONObject packet, int fileIndex) throws Exception {
        JSONObject envelope = new JSONObject().put("kind", "packet").put("purpose", purpose).put("index", index).put("packet", packet);
        if (fileIndex >= 0) envelope.put("fileIndex", fileIndex);
        return envelope;
    }

    private void pruneExpired() {
        long now = System.currentTimeMillis();
        incoming.entrySet().removeIf(entry -> {
            try {
                if (entry.getValue().destination == null && entry.getValue().offer.getLong("expiresAt") < now) {
                    cleanupIncoming(entry.getValue());
                    return true;
                }
            } catch (Exception ignored) {
                cleanupIncoming(entry.getValue());
                return true;
            }
            return false;
        });
        outgoing.entrySet().removeIf(entry -> {
            try {
                return !entry.getValue().streaming && entry.getValue().bundle.offer.getLong("expiresAt") < now;
            } catch (Exception ignored) {
                return true;
            }
        });
    }

    private void failTransfer(String transferId, String from) {
        Outgoing send = outgoing.get(transferId);
        try {
            if (send != null && from.equals(send.bundle.offer.getString("receiverId"))) outgoing.remove(transferId);
        } catch (Exception ignored) { }
        Incoming record = incoming.get(transferId);
        if (record != null && from.equals(record.senderId)) {
            incoming.remove(transferId);
            cleanupIncoming(record);
        }
    }

    private static void cleanupIncoming(Incoming record) {
        for (ReceivedFile file : record.files.values()) {
            try { file.output.close(); } catch (Exception ignored) { }
            try { file.document.delete(); } catch (Exception ignored) { }
        }
        record.files.clear();
        if (record.session != null) java.util.Arrays.fill(record.session, (byte) 0);
    }

    private static String safe(Exception error) {
        if (error instanceof SecurityException || error instanceof IllegalArgumentException || error instanceof IllegalStateException) {
            return error.getMessage() == null ? "Security validation failed" : error.getMessage();
        }
        return "The secure transfer could not be completed";
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format(java.util.Locale.US, "%02x", value));
        return result.toString();
    }
}
