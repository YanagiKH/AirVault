import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomInt,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { basename, normalize, sep } from "node:path";

export const PROTOCOL_VERSION = 1 as const;
export const MAX_CLOCK_SKEW_MS = 5 * 60_000;
export const DEFAULT_OFFER_LIFETIME_MS = 10 * 60_000;
export const MAX_FILE_COUNT = 256;
export const MAX_TOTAL_BYTES = 100 * 1024 * 1024 * 1024;
export const CHUNK_BYTES = 256 * 1024;

export interface DeviceIdentity {
  deviceId: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface FileManifestEntry {
  name: string;
  relativePath: string;
  size: number;
  sha256: string;
  mimeType?: string;
}

export interface TransferOffer {
  version: typeof PROTOCOL_VERSION;
  transferId: string;
  senderId: string;
  receiverId: string;
  senderIdentityPublicKey: string;
  senderEphemeralPublicKey: string;
  challenge: string;
  manifestDigest: string;
  createdAt: number;
  expiresAt: number;
  pinCommitment: string;
  qrCommitment: string;
  signature: string;
}

export interface TransferAccept {
  version: typeof PROTOCOL_VERSION;
  transferId: string;
  receiverId: string;
  receiverIdentityPublicKey: string;
  receiverEphemeralPublicKey: string;
  authorizationMethod: "pin" | "qr";
  authorizationProof: string;
  acceptedAt: number;
  signature: string;
}

export interface OutgoingOfferState {
  offer: TransferOffer;
  pin: string;
  qrSecret: string;
  qrPayload: string;
  manifests: FileManifestEntry[];
  ephemeralPrivateKeyPem: string;
}

export interface IncomingAcceptState {
  accept: TransferAccept;
  session: SessionKeys;
}

export interface SessionKeys {
  transferId: string;
  encryptionKey: Buffer;
  confirmationKey: Buffer;
}

export interface EncryptedPacket {
  nonce: string;
  ciphertext: string;
  tag: string;
}

export interface ScanFinding {
  severity: "info" | "warning" | "blocked";
  file: string;
  reason: string;
}

export interface ManifestScanResult {
  safe: boolean;
  findings: ScanFinding[];
  totalBytes: number;
}

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export function canonicalJson(value: unknown): string {
  const visit = (candidate: unknown): JsonValue => {
    if (candidate === null || typeof candidate === "boolean" || typeof candidate === "string") return candidate;
    if (typeof candidate === "number") {
      if (!Number.isFinite(candidate)) throw new Error("Canonical JSON rejects non-finite numbers");
      return candidate;
    }
    if (Array.isArray(candidate)) return candidate.map(visit);
    if (typeof candidate === "object") {
      const result = Object.create(null) as { [key: string]: JsonValue };
      for (const key of Object.keys(candidate as Record<string, unknown>).sort()) {
        const item = (candidate as Record<string, unknown>)[key];
        if (item !== undefined) result[key] = visit(item);
      }
      return result;
    }
    throw new Error(`Unsupported canonical JSON value: ${typeof candidate}`);
  };
  return JSON.stringify(visit(value));
}

function base64url(data: Buffer): string {
  return data.toString("base64url");
}

function decode64(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

export function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(secret: string | Buffer, data: string): string {
  return base64url(createHmac("sha256", secret).update(data).digest());
}

function constantTimeTextEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function encodeBase32(input: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}

export function deviceIdFromPublicKey(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  const der = key.export({ type: "spki", format: "der" });
  const fingerprint = encodeBase32(createHash("sha256").update(der).digest()).slice(0, 20);
  return `AV-${fingerprint.slice(0, 5)}-${fingerprint.slice(5, 10)}-${fingerprint.slice(10, 15)}-${fingerprint.slice(15, 20)}`;
}

export function createDeviceIdentity(): DeviceIdentity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    deviceId: deviceIdFromPublicKey(publicKeyPem),
    publicKeyPem,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

export function signObject(privateKeyPem: string, value: unknown): string {
  return base64url(sign(null, Buffer.from(canonicalJson(value)), createPrivateKey(privateKeyPem)));
}

export function verifyObject(publicKeyPem: string, value: unknown, signature: string): boolean {
  try {
    return verify(null, Buffer.from(canonicalJson(value)), createPublicKey(publicKeyPem), decode64(signature));
  } catch {
    return false;
  }
}

function unsignedOffer(offer: TransferOffer): Omit<TransferOffer, "signature"> {
  const { signature: _signature, ...unsigned } = offer;
  return unsigned;
}

function offerBase(offer: Omit<TransferOffer, "pinCommitment" | "qrCommitment" | "signature">): string {
  return canonicalJson(offer);
}

function unsignedAccept(accept: TransferAccept): Omit<TransferAccept, "signature"> {
  const { signature: _signature, ...unsigned } = accept;
  return unsigned;
}

export function createTransferOffer(
  identity: DeviceIdentity,
  receiverId: string,
  manifests: FileManifestEntry[],
  lifetimeMs = DEFAULT_OFFER_LIFETIME_MS,
): OutgoingOfferState {
  const normalizedReceiver = receiverId.trim().toUpperCase();
  if (!/^AV-[A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}$/.test(normalizedReceiver)) throw new Error("Invalid AirVault device ID");
  const scan = scanManifest(manifests);
  if (!scan.safe) throw new Error(`Unsafe manifest: ${scan.findings.map((item) => item.reason).join(", ")}`);

  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralPublicKey = ephemeral.publicKey.export({ type: "spki", format: "pem" }).toString();
  const now = Date.now();
  const pin = randomInt(0, 1_000_000).toString().padStart(6, "0");
  const qrSecret = base64url(randomBytes(32));
  const core: Omit<TransferOffer, "pinCommitment" | "qrCommitment" | "signature"> = {
    version: PROTOCOL_VERSION,
    transferId: base64url(randomBytes(18)),
    senderId: identity.deviceId,
    receiverId: normalizedReceiver,
    senderIdentityPublicKey: identity.publicKeyPem,
    senderEphemeralPublicKey: ephemeralPublicKey,
    challenge: base64url(randomBytes(24)),
    manifestDigest: sha256(canonicalJson(manifests)),
    createdAt: now,
    expiresAt: now + Math.min(Math.max(lifetimeMs, 60_000), 30 * 60_000),
  };
  const transcript = offerBase(core);
  const unsigned: Omit<TransferOffer, "signature"> = {
    ...core,
    pinCommitment: hmac(pin, `airvault:pin:${transcript}`),
    qrCommitment: hmac(qrSecret, `airvault:qr:${transcript}`),
  };
  const offer: TransferOffer = { ...unsigned, signature: signObject(identity.privateKeyPem, unsigned) };
  const qrPayload = `airvault://accept?v=1&transfer=${encodeURIComponent(offer.transferId)}&secret=${encodeURIComponent(qrSecret)}`;
  return {
    offer,
    pin,
    qrSecret,
    qrPayload,
    manifests,
    ephemeralPrivateKeyPem: ephemeral.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

export function verifyTransferOffer(offer: TransferOffer, expectedReceiverId: string, now = Date.now()): void {
  if (offer.version !== PROTOCOL_VERSION) throw new Error("Unsupported protocol version");
  if (offer.receiverId !== expectedReceiverId) throw new Error("Offer targets a different device");
  if (deviceIdFromPublicKey(offer.senderIdentityPublicKey) !== offer.senderId) throw new Error("Sender identity does not match its device ID");
  if (offer.createdAt > now + MAX_CLOCK_SKEW_MS || offer.expiresAt < now) throw new Error("Transfer offer is expired or not yet valid");
  if (offer.expiresAt - offer.createdAt > 30 * 60_000) throw new Error("Transfer offer lifetime is too long");
  if (!verifyObject(offer.senderIdentityPublicKey, unsignedOffer(offer), offer.signature)) throw new Error("Invalid sender signature");
}

function resolveAuthorization(offer: TransferOffer, secret: string): "pin" | "qr" {
  const { pinCommitment: _pin, qrCommitment: _qr, signature: _sig, ...core } = offer;
  const transcript = offerBase(core);
  if (/^\d{6}$/.test(secret) && constantTimeTextEqual(hmac(secret, `airvault:pin:${transcript}`), offer.pinCommitment)) return "pin";
  if (constantTimeTextEqual(hmac(secret, `airvault:qr:${transcript}`), offer.qrCommitment)) return "qr";
  throw new Error("The PIN or QR authorization is incorrect");
}

function deriveSession(
  transferId: string,
  offer: TransferOffer,
  localPrivateKeyPem: string,
  remotePublicKeyPem: string,
  authorizationSecret: string,
): SessionKeys {
  const shared = diffieHellman({
    privateKey: createPrivateKey(localPrivateKeyPem),
    publicKey: createPublicKey(remotePublicKeyPem),
  });
  const salt = createHash("sha256")
    .update("AirVault/v1/session\0")
    .update(canonicalJson(unsignedOffer(offer)))
    .update("\0")
    .update(authorizationSecret)
    .digest();
  const material = Buffer.from(hkdfSync("sha256", shared, salt, Buffer.from(transferId), 64));
  shared.fill(0);
  return { transferId, encryptionKey: material.subarray(0, 32), confirmationKey: material.subarray(32, 64) };
}

export function acceptTransferOffer(
  offer: TransferOffer,
  receiverIdentity: DeviceIdentity,
  authorizationSecret: string,
): IncomingAcceptState {
  verifyTransferOffer(offer, receiverIdentity.deviceId);
  const method = resolveAuthorization(offer, authorizationSecret);
  const ephemeral = generateKeyPairSync("x25519");
  const receiverEphemeralPublicKey = ephemeral.publicKey.export({ type: "spki", format: "pem" }).toString();
  const proofTranscript = canonicalJson({ offer: unsignedOffer(offer), receiverEphemeralPublicKey });
  const unsigned: Omit<TransferAccept, "signature"> = {
    version: PROTOCOL_VERSION,
    transferId: offer.transferId,
    receiverId: receiverIdentity.deviceId,
    receiverIdentityPublicKey: receiverIdentity.publicKeyPem,
    receiverEphemeralPublicKey,
    authorizationMethod: method,
    authorizationProof: hmac(authorizationSecret, `airvault:accept:${proofTranscript}`),
    acceptedAt: Date.now(),
  };
  const accept: TransferAccept = { ...unsigned, signature: signObject(receiverIdentity.privateKeyPem, unsigned) };
  const session = deriveSession(
    offer.transferId,
    offer,
    ephemeral.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    offer.senderEphemeralPublicKey,
    authorizationSecret,
  );
  return { accept, session };
}

export function completeTransferAccept(
  outgoing: OutgoingOfferState,
  accept: TransferAccept,
  expectedPinnedPublicKey?: string,
): SessionKeys {
  if (accept.version !== PROTOCOL_VERSION || accept.transferId !== outgoing.offer.transferId) throw new Error("Accept does not match this transfer");
  if (accept.receiverId !== outgoing.offer.receiverId) throw new Error("Unexpected receiving device");
  if (deviceIdFromPublicKey(accept.receiverIdentityPublicKey) !== accept.receiverId) throw new Error("Receiver identity does not match its device ID");
  if (expectedPinnedPublicKey && expectedPinnedPublicKey !== accept.receiverIdentityPublicKey) throw new Error("Receiver identity key changed; re-pairing is required");
  if (!verifyObject(accept.receiverIdentityPublicKey, unsignedAccept(accept), accept.signature)) throw new Error("Invalid receiver signature");
  if (Math.abs(Date.now() - accept.acceptedAt) > MAX_CLOCK_SKEW_MS) throw new Error("Receiver response is stale");

  const authorizationSecret = accept.authorizationMethod === "pin" ? outgoing.pin : outgoing.qrSecret;
  const proofTranscript = canonicalJson({ offer: unsignedOffer(outgoing.offer), receiverEphemeralPublicKey: accept.receiverEphemeralPublicKey });
  const expectedProof = hmac(authorizationSecret, `airvault:accept:${proofTranscript}`);
  if (!constantTimeTextEqual(expectedProof, accept.authorizationProof)) throw new Error("Receiver authorization proof is invalid");
  return deriveSession(
    outgoing.offer.transferId,
    outgoing.offer,
    outgoing.ephemeralPrivateKeyPem,
    accept.receiverEphemeralPublicKey,
    authorizationSecret,
  );
}

function packetAad(session: SessionKeys, purpose: string, index: number): Buffer {
  if (!Number.isSafeInteger(index) || index < 0) throw new Error("Invalid packet index");
  if (!/^[a-z0-9:_-]{1,80}$/i.test(purpose)) throw new Error("Invalid packet purpose");
  return Buffer.from(canonicalJson({ version: PROTOCOL_VERSION, transferId: session.transferId, purpose, index }));
}

function packetNonce(session: SessionKeys, purpose: string, index: number): Buffer {
  return createHmac("sha256", session.confirmationKey).update(packetAad(session, purpose, index)).digest().subarray(0, 12);
}

export function encryptPacket(session: SessionKeys, purpose: string, index: number, plaintext: Buffer): EncryptedPacket {
  const nonce = packetNonce(session, purpose, index);
  const cipher = createCipheriv("aes-256-gcm", session.encryptionKey, nonce, { authTagLength: 16 });
  cipher.setAAD(packetAad(session, purpose, index));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce: base64url(nonce), ciphertext: base64url(ciphertext), tag: base64url(cipher.getAuthTag()) };
}

export function decryptPacket(session: SessionKeys, purpose: string, index: number, packet: EncryptedPacket): Buffer {
  const nonce = decode64(packet.nonce);
  const expectedNonce = packetNonce(session, purpose, index);
  if (nonce.length !== expectedNonce.length || !timingSafeEqual(nonce, expectedNonce)) throw new Error("Packet nonce is invalid");
  const decipher = createDecipheriv("aes-256-gcm", session.encryptionKey, nonce, { authTagLength: 16 });
  decipher.setAAD(packetAad(session, purpose, index));
  decipher.setAuthTag(decode64(packet.tag));
  return Buffer.concat([decipher.update(decode64(packet.ciphertext)), decipher.final()]);
}

const BLOCKED_EXTENSIONS = new Set([
  ".apk", ".app", ".bat", ".cmd", ".com", ".cpl", ".dll", ".dmg", ".exe", ".hta", ".jar", ".js", ".jse",
  ".lnk", ".msi", ".msp", ".ps1", ".reg", ".scr", ".sh", ".sys", ".vb", ".vbe", ".vbs", ".wsf",
]);

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;

export function scanManifest(entries: FileManifestEntry[]): ManifestScanResult {
  const findings: ScanFinding[] = [];
  let totalBytes = 0;
  if (entries.length === 0) findings.push({ severity: "blocked", file: "(manifest)", reason: "No files were selected" });
  if (entries.length > MAX_FILE_COUNT) findings.push({ severity: "blocked", file: "(manifest)", reason: `More than ${MAX_FILE_COUNT} files were selected` });
  const seen = new Set<string>();

  for (const entry of entries) {
    const file = entry.relativePath || entry.name;
    if (!Number.isSafeInteger(entry.size) || entry.size < 0) {
      findings.push({ severity: "blocked", file, reason: "Invalid file size" });
      continue;
    }
    totalBytes += entry.size;
    const unixPath = entry.relativePath.replaceAll("\\", "/");
    const clean = normalize(unixPath).split(sep).join("/");
    if (unixPath.startsWith("/") || /^[a-z]:/i.test(unixPath) || clean === ".." || clean.startsWith("../") || clean.includes("/../") || unixPath.includes("\0")) {
      findings.push({ severity: "blocked", file, reason: "Unsafe path traversal or absolute path" });
    }
    if (basename(unixPath) !== entry.name || entry.name === "." || entry.name === ".." || WINDOWS_RESERVED.test(entry.name)) {
      findings.push({ severity: "blocked", file, reason: "Unsafe or reserved filename" });
    }
    const key = clean.toLocaleLowerCase("en-US");
    if (seen.has(key)) findings.push({ severity: "blocked", file, reason: "Duplicate destination path" });
    seen.add(key);
    const extension = entry.name.includes(".") ? `.${entry.name.split(".").pop()?.toLowerCase() ?? ""}` : "";
    if (BLOCKED_EXTENSIONS.has(extension)) findings.push({ severity: "warning", file, reason: "Potentially executable file; explicit receiver approval is required" });
    if (!/^[a-f0-9]{64}$/i.test(entry.sha256)) findings.push({ severity: "blocked", file, reason: "Invalid SHA-256 digest" });
  }
  if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_TOTAL_BYTES) {
    findings.push({ severity: "blocked", file: "(manifest)", reason: "Transfer exceeds the 100 GiB safety limit" });
  }
  return { safe: !findings.some((finding) => finding.severity === "blocked"), findings, totalBytes };
}
