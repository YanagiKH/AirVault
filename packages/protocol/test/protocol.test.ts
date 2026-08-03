import assert from "node:assert/strict";
import { test } from "node:test";
import {
  acceptTransferOffer,
  completeTransferAccept,
  createDeviceIdentity,
  createTransferOffer,
  decryptPacket,
  deviceIdFromPublicKey,
  encryptPacket,
  scanManifest,
  canonicalJson,
  sha256,
  type FileManifestEntry,
} from "../src/index";

const manifest: FileManifestEntry[] = [{
  name: "photo.jpg",
  relativePath: "holiday/photo.jpg",
  size: 12,
  sha256: "a".repeat(64),
  mimeType: "image/jpeg",
}];

test("device IDs are stable fingerprints of Ed25519 keys", () => {
  const identity = createDeviceIdentity();
  assert.equal(identity.deviceId, deviceIdFromPublicKey(identity.publicKeyPem));
  assert.match(identity.deviceId, /^AV-[A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}$/);
});

test("PIN-authorized X25519 sessions encrypt and authenticate packets", () => {
  const sender = createDeviceIdentity();
  const receiver = createDeviceIdentity();
  const outgoing = createTransferOffer(sender, receiver.deviceId, manifest);
  const incoming = acceptTransferOffer(outgoing.offer, receiver, outgoing.pin);
  const senderSession = completeTransferAccept(outgoing, incoming.accept);
  const packet = encryptPacket(senderSession, "file:0", 1, Buffer.from("airvault payload"));
  assert.equal(decryptPacket(incoming.session, "file:0", 1, packet).toString(), "airvault payload");
  assert.throws(() => decryptPacket(incoming.session, "file:0", 2, packet));
});

test("QR authorization works without exposing plaintext data to the relay", () => {
  const sender = createDeviceIdentity();
  const receiver = createDeviceIdentity();
  const outgoing = createTransferOffer(sender, receiver.deviceId, manifest);
  const incoming = acceptTransferOffer(outgoing.offer, receiver, outgoing.qrSecret);
  const senderSession = completeTransferAccept(outgoing, incoming.accept, receiver.publicKeyPem);
  const packet = encryptPacket(senderSession, "manifest", 0, Buffer.from(JSON.stringify(manifest)));
  assert.deepEqual(JSON.parse(decryptPacket(incoming.session, "manifest", 0, packet).toString()), manifest);
});

test("wrong PIN, identity substitution, and path traversal are rejected", () => {
  const sender = createDeviceIdentity();
  const receiver = createDeviceIdentity();
  const attacker = createDeviceIdentity();
  const outgoing = createTransferOffer(sender, receiver.deviceId, manifest);
  const wrongPin = outgoing.pin === "000000" ? "000001" : "000000";
  assert.throws(() => acceptTransferOffer(outgoing.offer, receiver, wrongPin));
  const incoming = acceptTransferOffer(outgoing.offer, receiver, outgoing.pin);
  assert.throws(() => completeTransferAccept(outgoing, incoming.accept, attacker.publicKeyPem));
  const result = scanManifest([{ ...manifest[0]!, name: "passwd", relativePath: "../../etc/passwd" }]);
  assert.equal(result.safe, false);
});

test("canonical transcripts are stable and every packet coordinate has a unique nonce", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: true, b: [3, 2, 1] } }), '{"a":{"b":[3,2,1],"y":true},"z":1}');
  const sender = createDeviceIdentity();
  const receiver = createDeviceIdentity();
  const outgoing = createTransferOffer(sender, receiver.deviceId, manifest);
  const incoming = acceptTransferOffer(outgoing.offer, receiver, outgoing.pin);
  const session = completeTransferAccept(outgoing, incoming.accept);
  const coordinates = [
    encryptPacket(session, "manifest", 0, Buffer.alloc(0)).nonce,
    encryptPacket(session, "control", 0, Buffer.alloc(0)).nonce,
    encryptPacket(session, "file:0", 0, Buffer.alloc(0)).nonce,
    encryptPacket(session, "file:0", 1, Buffer.alloc(0)).nonce,
  ];
  assert.equal(new Set(coordinates).size, coordinates.length);
});

test("canonical JSON preserves prototype-named properties without mutation", () => {
  const value = JSON.parse('{"__proto__":{"polluted":true},"constructor":"data","safe":1}') as Record<string, unknown>;
  assert.equal(canonicalJson(value), '{"__proto__":{"polluted":true},"constructor":"data","safe":1}');
  assert.equal(({} as { polluted?: boolean }).polluted, undefined);
});

test("tampered offers and ciphertext never release plaintext", () => {
  const sender = createDeviceIdentity();
  const receiver = createDeviceIdentity();
  const outgoing = createTransferOffer(sender, receiver.deviceId, manifest);
  const modified = { ...outgoing.offer, manifestDigest: "f".repeat(64) };
  assert.throws(() => acceptTransferOffer(modified, receiver, outgoing.pin));
  const incoming = acceptTransferOffer(outgoing.offer, receiver, outgoing.pin);
  const session = completeTransferAccept(outgoing, incoming.accept);
  const packet = encryptPacket(session, "file:0", 0, Buffer.from("confidential"));
  const bytes = Buffer.from(packet.ciphertext, "base64url");
  bytes[0] = bytes[0]! ^ 1;
  assert.throws(() => decryptPacket(incoming.session, "file:0", 0, { ...packet, ciphertext: bytes.toString("base64url") }));
});

test("multi-file chunk simulation decrypts byte-for-byte across a full session", () => {
  const sender = createDeviceIdentity();
  const receiver = createDeviceIdentity();
  const simulated = [
    Buffer.alloc(1024 * 1024 + 17, 0xa5),
    Buffer.from(""),
    Buffer.from("AirVault cross-platform test vector"),
  ];
  const manifests = simulated.map((content, index) => ({
    name: `file-${index}.bin`,
    relativePath: `file-${index}.bin`,
    size: content.length,
    sha256: sha256(content),
    mimeType: "application/octet-stream",
  }));
  const outgoing = createTransferOffer(sender, receiver.deviceId, manifests);
  const incoming = acceptTransferOffer(outgoing.offer, receiver, outgoing.qrSecret);
  const senderSession = completeTransferAccept(outgoing, incoming.accept);
  for (let fileIndex = 0; fileIndex < simulated.length; fileIndex += 1) {
    const source = simulated[fileIndex]!;
    const restored: Buffer[] = [];
    const chunks = Math.max(1, Math.ceil(source.length / (256 * 1024)));
    for (let index = 0; index < chunks; index += 1) {
      const plaintext = source.subarray(index * 256 * 1024, Math.min(source.length, (index + 1) * 256 * 1024));
      const encrypted = encryptPacket(senderSession, `file:${fileIndex}`, index, plaintext);
      restored.push(decryptPacket(incoming.session, `file:${fileIndex}`, index, encrypted));
    }
    assert.deepEqual(Buffer.concat(restored), source);
  }
});
