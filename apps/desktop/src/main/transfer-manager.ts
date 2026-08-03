import { EventEmitter } from "node:events";
import { createReadStream } from "node:fs";
import { link, mkdir, open, rm, unlink, type FileHandle } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import {
  acceptTransferOffer,
  canonicalJson,
  CHUNK_BYTES,
  completeTransferAccept,
  createTransferOffer,
  decryptPacket,
  encryptPacket,
  scanManifest,
  sha256,
  verifyTransferOffer,
  type EncryptedPacket,
  type FileManifestEntry,
  type IncomingAcceptState,
  type OutgoingOfferState,
  type SessionKeys,
  type TransferAccept,
  type TransferOffer,
} from "@airvault/protocol";
import { AirVaultStore } from "./store";
import { buildManifest, sha256File } from "./scanner";
import { RelayClient, type RoutedMessage } from "./relay-client";
import { scanDownloadedFiles } from "./malware-scan";

interface OutgoingRecord {
  paths: string[];
  state: OutgoingOfferState;
  session?: SessionKeys;
  streaming: boolean;
}

interface IncomingRecord {
  offer: TransferOffer;
  from: string;
  failedAttempts: number;
  accepted?: IncomingAcceptState;
  manifest?: FileManifestEntry[];
  destination?: string;
  temporaryDirectory?: string;
  files: Map<number, { handle: FileHandle; temporaryPath: string; finalPath: string; nextChunk: number; receivedBytes: number }>;
}

type PacketPayload = { kind: "packet"; purpose: string; index: number; packet: EncryptedPacket; fileIndex?: number; last?: boolean };
const MAX_ACTIVE_TRANSFERS = 64;

export class TransferManager extends EventEmitter {
  private readonly outgoing = new Map<string, OutgoingRecord>();
  private readonly incoming = new Map<string, IncomingRecord>();
  private routedQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly store: AirVaultStore,
    private readonly relay: RelayClient,
  ) {
    super();
    relay.on("routed", (message: RoutedMessage) => {
      this.routedQueue = this.routedQueue
        .then(() => this.handleRouted(message))
        .catch((error: unknown) => this.emitFailure(message.transferId, error));
    });
  }

  async beginSend(paths: string[], receiverId: string): Promise<{ transferId: string; pin: string; qrPayload: string; files: FileManifestEntry[] }> {
    this.pruneExpired();
    if (this.outgoing.size >= MAX_ACTIVE_TRANSFERS) throw new Error("Too many active outgoing transfers");
    const peer = this.store.findPeer(receiverId);
    if (!peer) throw new Error("Select a saved device");
    const manifest = await buildManifest(paths);
    const state = createTransferOffer(this.store.identity, peer.deviceId, manifest);
    this.outgoing.set(state.offer.transferId, { paths: [...paths], state, streaming: false });
    this.relay.route(peer.deviceId, state.offer.transferId, { kind: "offer", offer: state.offer });
    this.emit("progress", { transferId: state.offer.transferId, direction: "send", status: "Awaiting PIN or QR authorization", percent: 0 });
    return { transferId: state.offer.transferId, pin: state.pin, qrPayload: state.qrPayload, files: manifest };
  }

  async acceptIncoming(transferId: string, authorization: string): Promise<void> {
    const record = this.incoming.get(transferId);
    if (!record) throw new Error("Transfer offer was not found or has expired");
    if (record.failedAttempts >= 5) throw new Error("Too many incorrect attempts; ask the sender to create a new transfer");
    let secret = authorization.trim();
    if (secret.startsWith("airvault://")) {
      const url = new URL(secret);
      if (url.hostname !== "accept" || url.searchParams.get("transfer") !== transferId) throw new Error("QR code does not match this transfer");
      secret = url.searchParams.get("secret") ?? "";
    }
    try {
      const accepted = acceptTransferOffer(record.offer, this.store.identity, secret);
      record.accepted = accepted;
      await this.store.pinPeerIdentity(record.from, record.offer.senderIdentityPublicKey);
      this.relay.route(record.from, transferId, { kind: "accept", accept: accepted.accept });
      this.emit("progress", { transferId, direction: "receive", status: "Authorization verified; scanning transfer manifest", percent: 0 });
    } catch (error) {
      record.failedAttempts += 1;
      throw error;
    }
  }

  async approveIncoming(transferId: string, destination: string): Promise<void> {
    const record = this.incoming.get(transferId);
    if (!record?.accepted || !record.manifest) throw new Error("The transfer manifest has not been verified");
    const root = resolve(destination);
    await mkdir(root, { recursive: true });
    record.destination = root;
    record.temporaryDirectory = join(root, `.airvault-${transferId.slice(0, 8)}-${randomBytes(5).toString("hex")}`);
    await mkdir(record.temporaryDirectory, { recursive: false, mode: 0o700 });
    const packet = encryptPacket(record.accepted.session, "control", 0, Buffer.from(canonicalJson({ action: "ready" })));
    this.relay.route(record.from, transferId, { kind: "packet", purpose: "control", index: 0, packet });
    this.emit("progress", { transferId, direction: "receive", status: "Receiving encrypted file data", percent: 1 });
  }

  rejectIncoming(transferId: string): void {
    const record = this.incoming.get(transferId);
    if (!record) return;
    this.wipeIncoming(record);
    this.incoming.delete(transferId);
    this.relay.route(record.from, transferId, { kind: "reject" });
  }

  private async handleRouted(message: RoutedMessage): Promise<void> {
    const kind = message.payload.kind;
    if (kind === "offer") return this.receiveOffer(message);
    if (kind === "accept") return this.receiveAccept(message);
    if (kind === "reject") {
      const rejected = this.outgoing.get(message.transferId);
      this.wipeOutgoing(rejected);
      this.outgoing.delete(message.transferId);
      this.emitFailure(message.transferId, new Error("The receiving device declined the transfer"));
      return;
    }
    if (kind === "packet") return this.receivePacket(message, message.payload as unknown as PacketPayload);
  }

  private async receiveOffer(message: RoutedMessage): Promise<void> {
    this.pruneExpired();
    if (this.incoming.has(message.transferId)) return;
    if (this.incoming.size >= MAX_ACTIVE_TRANSFERS) throw new Error("Too many active incoming transfers");
    const peer = this.store.findPeer(message.from);
    if (!peer) throw new Error("Blocked transfer offer from an unsaved device");
    const offer = message.payload.offer as TransferOffer;
    verifyTransferOffer(offer, this.store.identity.deviceId);
    if (offer.transferId !== message.transferId || offer.senderId !== message.from) throw new Error("Transfer routing identity mismatch");
    if (peer.identityPublicKey && peer.identityPublicKey !== offer.senderIdentityPublicKey) throw new Error("SECURITY ALERT: sender identity key changed");
    this.incoming.set(message.transferId, { offer, from: message.from, failedAttempts: 0, files: new Map() });
    this.emit("offer", { transferId: message.transferId, senderId: message.from, senderName: peer.name, expiresAt: offer.expiresAt });
  }

  private async receiveAccept(message: RoutedMessage): Promise<void> {
    const record = this.outgoing.get(message.transferId);
    if (!record || message.from !== record.state.offer.receiverId) throw new Error("Unexpected transfer acceptance");
    const accept = message.payload.accept as TransferAccept;
    const peer = this.store.findPeer(message.from);
    record.session = completeTransferAccept(record.state, accept, peer?.identityPublicKey);
    await this.store.pinPeerIdentity(message.from, accept.receiverIdentityPublicKey);
    const manifestPacket = encryptPacket(record.session, "manifest", 0, Buffer.from(canonicalJson(record.state.manifests)));
    this.relay.route(message.from, message.transferId, { kind: "packet", purpose: "manifest", index: 0, packet: manifestPacket });
  }

  private async receivePacket(message: RoutedMessage, payload: PacketPayload): Promise<void> {
    if (!payload.packet || typeof payload.purpose !== "string" || !Number.isSafeInteger(payload.index)) throw new Error("Malformed encrypted packet");
    const outgoing = this.outgoing.get(message.transferId);
    if (outgoing?.session && message.from === outgoing.state.offer.receiverId && payload.purpose === "control" && payload.index === 0) {
      const control = JSON.parse(decryptPacket(outgoing.session, "control", 0, payload.packet).toString()) as { action?: string };
      if (control.action !== "ready" || outgoing.streaming) throw new Error("Invalid or duplicate receiver-ready message");
      outgoing.streaming = true;
      await this.streamOutgoing(message.transferId, outgoing);
      return;
    }

    const incoming = this.incoming.get(message.transferId);
    if (!incoming?.accepted || message.from !== incoming.from) throw new Error("Encrypted packet has no authorized transfer session");
    if (payload.purpose === "manifest" && payload.index === 0) {
      const plaintext = decryptPacket(incoming.accepted.session, "manifest", 0, payload.packet);
      const manifest = JSON.parse(plaintext.toString()) as FileManifestEntry[];
      if (sha256(canonicalJson(manifest)) !== incoming.offer.manifestDigest) throw new Error("Manifest commitment mismatch");
      const scan = scanManifest(manifest);
      if (!scan.safe) throw new Error(`Security scan blocked the manifest: ${scan.findings.map((item) => item.reason).join(", ")}`);
      incoming.manifest = manifest;
      this.emit("review", { transferId: message.transferId, senderId: message.from, files: manifest, scan });
      return;
    }
    if (payload.purpose.startsWith("file:") && payload.fileIndex !== undefined) {
      await this.receiveFileChunk(message.transferId, incoming, payload);
      return;
    }
    if (payload.purpose === "control" && payload.index === 1) {
      const control = JSON.parse(decryptPacket(incoming.accepted.session, "control", 1, payload.packet).toString()) as { action?: string };
      if (control.action !== "complete") throw new Error("Invalid completion packet");
      await this.finalizeIncoming(message.transferId, incoming);
    }
  }

  private async streamOutgoing(transferId: string, record: OutgoingRecord): Promise<void> {
    const session = record.session;
    if (!session) throw new Error("Transfer session was not established");
    let completedBytes = 0;
    const totalBytes = record.state.manifests.reduce((sum, file) => sum + file.size, 0);
    for (let fileIndex = 0; fileIndex < record.paths.length; fileIndex += 1) {
      let chunkIndex = 0;
      let sentChunk = false;
      for await (const raw of createReadStream(record.paths[fileIndex]!, { highWaterMark: CHUNK_BYTES })) {
        const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
        const packet = encryptPacket(session, `file:${fileIndex}`, chunkIndex, chunk);
        this.relay.route(record.state.offer.receiverId, transferId, { kind: "packet", purpose: `file:${fileIndex}`, fileIndex, index: chunkIndex, packet });
        chunkIndex += 1;
        sentChunk = true;
        completedBytes += chunk.length;
        this.emit("progress", { transferId, direction: "send", status: "Sending encrypted file data", percent: totalBytes ? Math.round(completedBytes / totalBytes * 100) : 100 });
        await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 2));
      }
      if (!sentChunk) {
        const packet = encryptPacket(session, `file:${fileIndex}`, 0, Buffer.alloc(0));
        this.relay.route(record.state.offer.receiverId, transferId, { kind: "packet", purpose: `file:${fileIndex}`, fileIndex, index: 0, packet });
      }
    }
    const complete = encryptPacket(session, "control", 1, Buffer.from(canonicalJson({ action: "complete" })));
    this.relay.route(record.state.offer.receiverId, transferId, { kind: "packet", purpose: "control", index: 1, packet: complete });
    this.wipeOutgoing(record);
    this.outgoing.delete(transferId);
    this.emit("complete", { transferId, direction: "send", message: "Files sent securely" });
  }

  private async receiveFileChunk(transferId: string, record: IncomingRecord, payload: PacketPayload): Promise<void> {
    if (!record.manifest || !record.destination || !record.temporaryDirectory || payload.fileIndex === undefined) throw new Error("File data arrived before receiver approval");
    const manifest = record.manifest[payload.fileIndex];
    if (!manifest || payload.purpose !== `file:${payload.fileIndex}`) throw new Error("Invalid file index");
    let target = record.files.get(payload.fileIndex);
    if (!target) {
      const safeName = basename(manifest.name);
      const finalPath = uniqueDestination(record.destination, safeName, transferId);
      const temporaryPath = join(record.temporaryDirectory, `${payload.fileIndex}.part`);
      target = { handle: await open(temporaryPath, "wx", 0o600), temporaryPath, finalPath, nextChunk: 0, receivedBytes: 0 };
      record.files.set(payload.fileIndex, target);
    }
    if (payload.index !== target.nextChunk) throw new Error("Out-of-order or replayed file chunk");
    const plaintext = decryptPacket(record.accepted!.session, payload.purpose, payload.index, payload.packet);
    target.receivedBytes += plaintext.length;
    if (target.receivedBytes > manifest.size) throw new Error("Received file exceeds its declared size");
    await target.handle.write(plaintext);
    target.nextChunk += 1;
    const received = [...record.files.values()].reduce((sum, file) => sum + file.receivedBytes, 0);
    const total = record.manifest.reduce((sum, file) => sum + file.size, 0);
    this.emit("progress", { transferId, direction: "receive", status: "Receiving encrypted file data", percent: Math.min(99, total ? Math.round(received / total * 100) : 99) });
  }

  private async finalizeIncoming(transferId: string, record: IncomingRecord): Promise<void> {
    if (!record.manifest || !record.temporaryDirectory) throw new Error("Transfer was not approved");
    const temporaryPaths: string[] = [];
    for (let index = 0; index < record.manifest.length; index += 1) {
      const target = record.files.get(index);
      if (!target) throw new Error(`Missing file data for ${record.manifest[index]!.name}`);
      if (target.receivedBytes !== record.manifest[index]!.size) throw new Error(`File size verification failed for ${record.manifest[index]!.name}`);
      await target.handle.sync();
      await target.handle.close();
      const digest = await sha256File(target.temporaryPath);
      if (digest !== record.manifest[index]!.sha256) throw new Error(`Integrity verification failed for ${record.manifest[index]!.name}`);
      temporaryPaths.push(target.temporaryPath);
    }
    const malware = await scanDownloadedFiles(temporaryPaths);
    if (malware.status === "threat") throw new Error("The local malware scanner blocked the received files");
    const finalizedPaths: string[] = [];
    try {
      for (const target of record.files.values()) {
        await link(target.temporaryPath, target.finalPath);
        finalizedPaths.push(target.finalPath);
      }
    } catch (error) {
      await Promise.all(finalizedPaths.map((path) => rm(path, { force: true })));
      throw new Error("A destination file already exists or could not be created safely", { cause: error });
    }
    await Promise.all([...record.files.values()].map((target) => unlink(target.temporaryPath)));
    await rm(record.temporaryDirectory, { recursive: true, force: true });
    this.wipeIncoming(record);
    this.incoming.delete(transferId);
    this.emit("complete", {
      transferId,
      direction: "receive",
      message: malware.status === "clean" ? `Files received and scanned by ${malware.scanner}` : "Files received; integrity verified (no local malware scanner available)",
    });
  }

  private emitFailure(transferId: string, error: unknown): void {
    const message = error instanceof Error ? error.message : "Unexpected transfer failure";
    this.wipeOutgoing(this.outgoing.get(transferId));
    this.outgoing.delete(transferId);
    const incoming = this.incoming.get(transferId);
    this.wipeIncoming(incoming);
    this.incoming.delete(transferId);
    if (incoming) {
      void Promise.all([...incoming.files.values()].map((file) => file.handle.close().catch(() => undefined)))
        .then(() => incoming.temporaryDirectory ? rm(incoming.temporaryDirectory, { recursive: true, force: true }) : undefined)
        .catch(() => undefined);
    }
    this.emit("failure", { transferId, message });
  }

  private wipeOutgoing(record: OutgoingRecord | undefined): void {
    record?.session?.encryptionKey.fill(0);
    record?.session?.confirmationKey.fill(0);
  }

  private wipeIncoming(record: IncomingRecord | undefined): void {
    record?.accepted?.session.encryptionKey.fill(0);
    record?.accepted?.session.confirmationKey.fill(0);
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [transferId, record] of this.incoming) {
      if (record.offer.expiresAt < now && !record.destination) {
        this.wipeIncoming(record);
        this.incoming.delete(transferId);
      }
    }
    for (const [transferId, record] of this.outgoing) {
      if (record.state.offer.expiresAt < now && !record.streaming) {
        this.wipeOutgoing(record);
        this.outgoing.delete(transferId);
      }
    }
  }
}

function uniqueDestination(root: string, name: string, transferId: string): string {
  const candidate = resolve(root, name);
  if (!candidate.startsWith(`${resolve(root)}${process.platform === "win32" ? "\\" : "/"}`)) throw new Error("Unsafe destination path");
  const extensionAt = name.lastIndexOf(".");
  const stem = extensionAt > 0 ? name.slice(0, extensionAt) : name;
  const extension = extensionAt > 0 ? name.slice(extensionAt) : "";
  return join(root, `${stem} (${transferId.slice(0, 6)})${extension}`);
}
