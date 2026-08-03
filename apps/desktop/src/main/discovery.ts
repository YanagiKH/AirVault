import { EventEmitter } from "node:events";
import { createSocket, type Socket } from "node:dgram";
import { randomBytes } from "node:crypto";
import {
  canonicalJson,
  deviceIdFromPublicKey,
  MAX_CLOCK_SKEW_MS,
  signObject,
  verifyObject,
  type DeviceIdentity,
} from "@airvault/protocol";

const GROUP = "239.255.77.77";
const PORT = 53545;
const MAX_BEACON_BYTES = 8192;
const MAX_SEEN_BEACONS = 4096;
const MAX_BEACONS_PER_SECOND = 256;

interface Beacon {
  version: 1;
  type: "airvault-discovery";
  deviceId: string;
  publicKey: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

export class SecureDiscovery extends EventEmitter {
  private socket?: Socket;
  private timer?: NodeJS.Timeout;
  private readonly seen = new Map<string, number>();
  private receiveWindowStartedAt = Date.now();
  private receiveWindowCount = 0;

  constructor(private readonly identity: DeviceIdentity) {
    super();
  }

  start(): void {
    if (this.socket) return;
    const socket = createSocket({ type: "udp4", reuseAddr: true });
    this.socket = socket;
    socket.on("error", (error) => this.emit("warning", error.message));
    socket.on("message", (message) => this.receive(message));
    socket.bind(PORT, () => {
      try {
        socket.addMembership(GROUP);
        socket.setMulticastTTL(1);
        this.broadcast();
        this.timer = setInterval(() => this.broadcast(), 15_000);
        this.timer.unref();
      } catch (error) {
        this.emit("warning", error instanceof Error ? error.message : "Local discovery failed");
      }
    });
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.socket?.close();
    this.socket = undefined;
  }

  private broadcast(): void {
    if (!this.socket) return;
    const unsigned = {
      version: 1 as const,
      type: "airvault-discovery" as const,
      deviceId: this.identity.deviceId,
      publicKey: this.identity.publicKeyPem,
      timestamp: Date.now(),
      nonce: randomBytes(12).toString("base64url"),
    };
    const message = Buffer.from(canonicalJson({ ...unsigned, signature: signObject(this.identity.privateKeyPem, unsigned) }));
    if (message.length <= MAX_BEACON_BYTES) this.socket.send(message, PORT, GROUP);
  }

  private receive(message: Buffer): void {
    if (message.length > MAX_BEACON_BYTES) return;
    const now = Date.now();
    if (now - this.receiveWindowStartedAt >= 1_000) {
      this.receiveWindowStartedAt = now;
      this.receiveWindowCount = 0;
    }
    this.receiveWindowCount += 1;
    if (this.receiveWindowCount > MAX_BEACONS_PER_SECOND) return;
    try {
      const beacon = JSON.parse(message.toString("utf8")) as Beacon;
      if (beacon.version !== 1 || beacon.type !== "airvault-discovery" || beacon.deviceId === this.identity.deviceId) return;
      if (Math.abs(now - beacon.timestamp) > MAX_CLOCK_SKEW_MS) return;
      if (!/^[A-Za-z0-9_-]{16}$/.test(beacon.nonce) || deviceIdFromPublicKey(beacon.publicKey) !== beacon.deviceId) return;
      const { signature, ...unsigned } = beacon;
      if (!verifyObject(beacon.publicKey, unsigned, signature)) return;
      const replayKey = beacon.deviceId + ":" + beacon.nonce;
      if (this.seen.has(replayKey)) return;
      for (const [key, expiresAt] of this.seen) if (expiresAt < now) this.seen.delete(key);
      if (this.seen.size >= MAX_SEEN_BEACONS) return;
      this.seen.set(replayKey, now + MAX_CLOCK_SKEW_MS);
      this.emit("device", { deviceId: beacon.deviceId, publicKey: beacon.publicKey });
    } catch {
      // Untrusted multicast traffic is ignored without affecting the app.
    }
  }
}
