import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import { canonicalJson, signObject, type DeviceIdentity } from "@airvault/protocol";
import WebSocket from "ws";

export interface RoutedMessage {
  from: string;
  transferId: string;
  payload: Record<string, unknown>;
}

export class RelayClient extends EventEmitter {
  private socket?: WebSocket;
  private reconnectTimer?: NodeJS.Timeout;
  private stopped = false;
  private attempt = 0;

  constructor(private url: string, private readonly identity: DeviceIdentity) {
    super();
  }

  connect(): void {
    this.stopped = false;
    this.validateUrl();
    const socket = new WebSocket(this.url, { handshakeTimeout: 10_000, maxPayload: 2 * 1024 * 1024, perMessageDeflate: false });
    this.socket = socket;
    socket.on("open", () => {
      this.attempt = 0;
      const payload = {
        version: 1 as const,
        deviceId: this.identity.deviceId,
        publicKey: this.identity.publicKeyPem,
        timestamp: Date.now(),
        nonce: randomBytes(18).toString("base64url"),
      };
      socket.send(canonicalJson({ type: "register", ...payload, signature: signObject(this.identity.privateKeyPem, payload) }));
    });
    socket.on("message", (data, isBinary) => {
      const size = Array.isArray(data) ? data.reduce((sum, part) => sum + part.byteLength, 0) : data.byteLength;
      if (isBinary || size > 2 * 1024 * 1024) return;
      try {
        const message = JSON.parse(data.toString()) as Record<string, unknown>;
        if (message.type === "registered") this.emit("status", "connected");
        else if (message.type === "routed" && typeof message.from === "string" && typeof message.transferId === "string" && isRecord(message.payload)) {
          this.emit("routed", { from: message.from, transferId: message.transferId, payload: message.payload } satisfies RoutedMessage);
        } else if (message.type === "error") this.emit("protocol-error", String(message.code ?? "relay_error"));
      } catch {
        this.emit("protocol-error", "invalid_relay_response");
      }
    });
    socket.on("close", () => {
      if (this.socket === socket) this.socket = undefined;
      this.emit("status", "disconnected");
      this.scheduleReconnect();
    });
    socket.on("error", () => this.emit("status", "error"));
  }

  disconnect(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.socket?.close(1000, "client_shutdown");
    this.socket = undefined;
  }

  updateUrl(url: string): void {
    this.disconnect();
    this.url = url;
    this.connect();
  }

  route(to: string, transferId: string, payload: Record<string, unknown>): void {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) throw new Error("The relay is offline");
    if (this.socket.bufferedAmount > 32 * 1024 * 1024) throw new Error("The relay connection is congested; the transfer was stopped safely");
    this.socket.send(canonicalJson({ type: "route", to, transferId, payload }));
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer) return;
    const delay = Math.min(30_000, 1_000 * 2 ** Math.min(this.attempt++, 5)) + Math.floor(Math.random() * 500);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect();
    }, delay);
  }

  private validateUrl(): void {
    const parsed = new URL(this.url);
    const local = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1";
    if (parsed.protocol !== "wss:" && !(local && parsed.protocol === "ws:")) throw new Error("Remote relay connections require wss://");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
