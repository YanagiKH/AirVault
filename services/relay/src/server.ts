import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import {
  canonicalJson,
  deviceIdFromPublicKey,
  MAX_CLOCK_SKEW_MS,
  verifyObject,
} from "@airvault/protocol";
import { WebSocket, WebSocketServer } from "ws";

const DEVICE_ID = /^AV-[A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}$/;
const TRANSFER_ID = /^[A-Za-z0-9_-]{16,64}$/;
const MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
const RATE_WINDOW_MS = 10_000;
const RATE_LIMIT = 2048;
const BYTE_RATE_LIMIT = 512 * 1024 * 1024;
const MAX_NONCE_CACHE = 20_000;
const DEFAULT_MAX_CONNECTIONS = 1_000;

interface RegisterMessage {
  type: "register";
  version: 1;
  deviceId: string;
  publicKey: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

interface RouteMessage {
  type: "route";
  to: string;
  transferId: string;
  payload: unknown;
}

interface ClientState {
  deviceId?: string;
  publicKey?: string;
  windowStartedAt: number;
  messageCount: number;
  byteCount: number;
}

export interface RelayOptions {
  host?: string;
  port?: number;
  allowedOrigins?: string[];
  maxConnections?: number;
}

export interface RunningRelay {
  server: Server;
  websocketServer: WebSocketServer;
  host: string;
  port: number;
  close: () => Promise<void>;
}

function send(socket: WebSocket, value: unknown): void {
  if (socket.readyState === WebSocket.OPEN) socket.send(canonicalJson(value));
}

function registerPayload(message: RegisterMessage): Omit<RegisterMessage, "type" | "signature"> {
  return {
    version: message.version,
    deviceId: message.deviceId,
    publicKey: message.publicKey,
    timestamp: message.timestamp,
    nonce: message.nonce,
  };
}

export async function startRelay(options: RelayOptions = {}): Promise<RunningRelay> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8787;
  const allowedOrigins = new Set(options.allowedOrigins ?? []);
  const maxConnections = options.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  if (!Number.isSafeInteger(maxConnections) || maxConnections < 1 || maxConnections > 100_000) {
    throw new Error("maxConnections must be between 1 and 100000");
  }
  const connections = new Map<string, WebSocket>();
  const usedNonces = new Map<string, number>();

  const server = createServer((request, response) => {
    if (request.url === "/healthz") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      response.end(JSON.stringify({ status: "ok", connectedDevices: connections.size }));
      return;
    }
    response.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
    response.end(JSON.stringify({ error: "not_found" }));
  });
  const websocketServer = new WebSocketServer({
    server,
    maxPayload: MAX_MESSAGE_BYTES,
    perMessageDeflate: false,
    verifyClient: ({ origin }: { origin: string }) => allowedOrigins.size === 0 || !origin || allowedOrigins.has(origin),
  });

  websocketServer.on("connection", (socket) => {
    if (websocketServer.clients.size > maxConnections) {
      socket.close(1013, "capacity");
      return;
    }
    const state: ClientState = { windowStartedAt: Date.now(), messageCount: 0, byteCount: 0 };
    socket.on("message", (raw, isBinary) => {
      try {
        const rawSize = Array.isArray(raw) ? raw.reduce((sum, part) => sum + part.byteLength, 0) : raw.byteLength;
        if (isBinary || rawSize > MAX_MESSAGE_BYTES) throw new Error("invalid_message");
        const now = Date.now();
        if (now - state.windowStartedAt >= RATE_WINDOW_MS) {
          state.windowStartedAt = now;
          state.messageCount = 0;
          state.byteCount = 0;
        }
        state.messageCount += 1;
        state.byteCount += rawSize;
        if (state.messageCount > RATE_LIMIT || state.byteCount > BYTE_RATE_LIMIT) {
          socket.close(1008, "rate_limit");
          return;
        }
        const message = JSON.parse(raw.toString()) as Record<string, unknown>;
        if (message.type === "register") {
          const candidate = message as unknown as RegisterMessage;
          if (state.deviceId) throw new Error("already_registered");
          if (candidate.version !== 1 || !DEVICE_ID.test(candidate.deviceId) || typeof candidate.publicKey !== "string") throw new Error("invalid_registration");
          if (!Number.isSafeInteger(candidate.timestamp) || Math.abs(now - candidate.timestamp) > MAX_CLOCK_SKEW_MS) throw new Error("stale_registration");
          if (usedNonces.size >= MAX_NONCE_CACHE) throw new Error("registration_capacity");
          if (!/^[A-Za-z0-9_-]{22,64}$/.test(candidate.nonce) || usedNonces.has(candidate.nonce)) throw new Error("replayed_registration");
          if (deviceIdFromPublicKey(candidate.publicKey) !== candidate.deviceId) throw new Error("identity_mismatch");
          if (!verifyObject(candidate.publicKey, registerPayload(candidate), candidate.signature)) throw new Error("invalid_signature");
          const previous = connections.get(candidate.deviceId);
          if (previous && previous !== socket) previous.close(4001, "new_session");
          state.deviceId = candidate.deviceId;
          state.publicKey = candidate.publicKey;
          connections.set(candidate.deviceId, socket);
          usedNonces.set(candidate.nonce, now + MAX_CLOCK_SKEW_MS);
          send(socket, { type: "registered", deviceId: candidate.deviceId, relaySession: randomBytes(12).toString("base64url") });
          return;
        }
        if (message.type === "route") {
          const candidate = message as unknown as RouteMessage;
          if (!state.deviceId) throw new Error("authentication_required");
          if (!DEVICE_ID.test(candidate.to) || !TRANSFER_ID.test(candidate.transferId) || candidate.payload === undefined) throw new Error("invalid_route");
          if (canonicalJson(candidate.payload).length > MAX_MESSAGE_BYTES - 1024) throw new Error("payload_too_large");
          const destination = connections.get(candidate.to);
          if (!destination || destination.readyState !== WebSocket.OPEN) {
            send(socket, { type: "delivery", transferId: candidate.transferId, delivered: false, reason: "offline" });
            return;
          }
          send(destination, { type: "routed", from: state.deviceId, transferId: candidate.transferId, payload: candidate.payload });
          send(socket, { type: "delivery", transferId: candidate.transferId, delivered: true });
          return;
        }
        throw new Error("unsupported_message");
      } catch (error) {
        const code = error instanceof Error ? error.message : "invalid_message";
        send(socket, { type: "error", code });
      }
    });
    socket.on("close", () => {
      if (state.deviceId && connections.get(state.deviceId) === socket) connections.delete(state.deviceId);
    });
  });

  const nonceCleanup = setInterval(() => {
    const now = Date.now();
    for (const [nonce, expiresAt] of usedNonces) if (expiresAt <= now) usedNonces.delete(nonce);
  }, 60_000);
  nonceCleanup.unref();

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Relay did not bind to a TCP port");

  return {
    server,
    websocketServer,
    host,
    port: address.port,
    close: async () => {
      clearInterval(nonceCleanup);
      for (const client of websocketServer.clients) client.close(1001, "shutdown");
      await new Promise<void>((resolve) => websocketServer.close(() => server.close(() => resolve())));
    },
  };
}
