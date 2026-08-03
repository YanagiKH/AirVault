import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { createDeviceIdentity, signObject } from "@airvault/protocol";
import WebSocket from "ws";
import { startRelay } from "../src/server";

function nextMessage(socket: WebSocket): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timed out waiting for relay message")), 3_000);
    socket.once("message", (data) => {
      clearTimeout(timer);
      resolve(JSON.parse(data.toString()) as Record<string, unknown>);
    });
  });
}

async function openClient(url: string): Promise<WebSocket> {
  const socket = new WebSocket(url);
  await new Promise<void>((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("error", reject);
  });
  return socket;
}

async function register(socket: WebSocket, identity: ReturnType<typeof createDeviceIdentity>): Promise<void> {
  const payload = {
    version: 1 as const,
    deviceId: identity.deviceId,
    publicKey: identity.publicKeyPem,
    timestamp: Date.now(),
    nonce: randomBytes(18).toString("base64url"),
  };
  socket.send(JSON.stringify({ type: "register", ...payload, signature: signObject(identity.privateKeyPem, payload) }));
  assert.equal((await nextMessage(socket)).type, "registered");
}

test("relay authenticates devices and routes opaque ciphertext", async () => {
  const relay = await startRelay({ port: 0 });
  const alice = createDeviceIdentity();
  const bob = createDeviceIdentity();
  const aliceSocket = await openClient(`ws://127.0.0.1:${relay.port}`);
  const bobSocket = await openClient(`ws://127.0.0.1:${relay.port}`);
  try {
    await register(aliceSocket, alice);
    await register(bobSocket, bob);
    const ciphertext = { nonce: "opaque", ciphertext: "still-opaque", tag: "authenticated" };
    aliceSocket.send(JSON.stringify({ type: "route", to: bob.deviceId, transferId: randomBytes(18).toString("base64url"), payload: ciphertext }));
    const routed = await nextMessage(bobSocket);
    assert.equal(routed.from, alice.deviceId);
    assert.deepEqual(routed.payload, ciphertext);
  } finally {
    aliceSocket.close();
    bobSocket.close();
    await relay.close();
  }
});

test("relay rejects forged registration", async () => {
  const relay = await startRelay({ port: 0 });
  const identity = createDeviceIdentity();
  const socket = await openClient(`ws://127.0.0.1:${relay.port}`);
  try {
    socket.send(JSON.stringify({
      type: "register",
      version: 1,
      deviceId: identity.deviceId,
      publicKey: identity.publicKeyPem,
      timestamp: Date.now(),
      nonce: randomBytes(18).toString("base64url"),
      signature: "forged",
    }));
    assert.equal((await nextMessage(socket)).code, "invalid_signature");
  } finally {
    socket.close();
    await relay.close();
  }
});

test("relay rejects re-registration on an authenticated socket", async () => {
  const relay = await startRelay({ port: 0 });
  const identity = createDeviceIdentity();
  const socket = await openClient(`ws://127.0.0.1:${relay.port}`);
  try {
    await register(socket, identity);
    const payload = {
      version: 1 as const,
      deviceId: identity.deviceId,
      publicKey: identity.publicKeyPem,
      timestamp: Date.now(),
      nonce: randomBytes(18).toString("base64url"),
    };
    socket.send(JSON.stringify({ type: "register", ...payload, signature: signObject(identity.privateKeyPem, payload) }));
    assert.equal((await nextMessage(socket)).code, "already_registered");
  } finally {
    socket.close();
    await relay.close();
  }
});
