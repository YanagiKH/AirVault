import { app, safeStorage } from "electron";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createDeviceIdentity, type DeviceIdentity } from "@airvault/protocol";

export interface SavedPeer {
  deviceId: string;
  name: string;
  identityPublicKey?: string;
  verifiedAt?: number;
  addedAt: number;
  lastSeenAt?: number;
}

interface StoredState {
  schemaVersion: 1;
  protectedIdentity: string;
  peers: SavedPeer[];
  relayUrl: string;
}

const DEFAULT_RELAY = "wss://relay.example.airvault.invalid";

export class AirVaultStore {
  private state?: StoredState;
  private readonly filePath: string;

  constructor(filePath = join(app.getPath("userData"), "airvault-state.json")) {
    this.filePath = filePath;
  }

  async load(): Promise<void> {
    try {
      const parsed = JSON.parse(await readFile(this.filePath, "utf8")) as Partial<StoredState>;
      if (parsed.schemaVersion !== 1 || typeof parsed.protectedIdentity !== "string" || !Array.isArray(parsed.peers)) throw new Error("Invalid state format");
      this.state = {
        schemaVersion: 1,
        protectedIdentity: parsed.protectedIdentity,
        peers: parsed.peers.filter((peer): peer is SavedPeer => Boolean(peer && typeof peer.deviceId === "string" && typeof peer.name === "string")),
        relayUrl: typeof parsed.relayUrl === "string" ? parsed.relayUrl : DEFAULT_RELAY,
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        await rename(this.filePath, `${this.filePath}.corrupt-${Date.now()}`).catch(() => undefined);
        throw new Error("AirVault state failed integrity validation and was preserved as a .corrupt file", { cause: error });
      }
      const identity = createDeviceIdentity();
      this.state = { schemaVersion: 1, protectedIdentity: this.protectIdentity(identity), peers: [], relayUrl: DEFAULT_RELAY };
      await this.persist();
    }
  }

  get identity(): DeviceIdentity {
    if (!this.state) throw new Error("Store has not been loaded");
    const encrypted = Buffer.from(this.state.protectedIdentity, "base64");
    const plaintext = safeStorage.isEncryptionAvailable() ? safeStorage.decryptString(encrypted) : encrypted.toString("utf8");
    return JSON.parse(plaintext) as DeviceIdentity;
  }

  get relayUrl(): string {
    if (!this.state) throw new Error("Store has not been loaded");
    return this.state.relayUrl;
  }

  listPeers(): SavedPeer[] {
    return this.requireState().peers.map((peer) => ({ ...peer }));
  }

  findPeer(deviceId: string): SavedPeer | undefined {
    return this.requireState().peers.find((peer) => peer.deviceId === deviceId);
  }

  async savePeer(deviceId: string, name: string): Promise<SavedPeer> {
    const normalized = deviceId.trim().toUpperCase();
    if (!/^AV-[A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}$/.test(normalized)) throw new Error("Enter a valid AirVault device ID");
    if (normalized === this.identity.deviceId) throw new Error("This is your own device ID");
    const state = this.requireState();
    let peer = state.peers.find((item) => item.deviceId === normalized);
    if (peer) peer.name = cleanName(name || peer.name);
    else {
      peer = { deviceId: normalized, name: cleanName(name || `Device ${normalized.slice(-5)}`), addedAt: Date.now() };
      state.peers.push(peer);
    }
    await this.persist();
    return { ...peer };
  }

  async removePeer(deviceId: string): Promise<void> {
    const state = this.requireState();
    state.peers = state.peers.filter((peer) => peer.deviceId !== deviceId);
    await this.persist();
  }

  async pinPeerIdentity(deviceId: string, publicKey: string): Promise<void> {
    const state = this.requireState();
    const peer = state.peers.find((item) => item.deviceId === deviceId);
    if (!peer) throw new Error("The device is not in your saved list");
    if (peer.identityPublicKey && peer.identityPublicKey !== publicKey) throw new Error("SECURITY ALERT: the saved device identity key changed");
    peer.identityPublicKey = publicKey;
    peer.verifiedAt ??= Date.now();
    peer.lastSeenAt = Date.now();
    await this.persist();
  }

  async observeDiscoveredPeer(deviceId: string, publicKey: string): Promise<boolean> {
    const peer = this.findPeer(deviceId);
    if (!peer) return false;
    if (peer.identityPublicKey && peer.identityPublicKey !== publicKey) throw new Error("SECURITY ALERT: a local device is advertising a changed identity key");
    peer.lastSeenAt = Date.now();
    await this.persist();
    return true;
  }

  async setRelayUrl(value: string): Promise<void> {
    const url = new URL(value.trim());
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
    if (url.protocol !== "wss:" && !(local && url.protocol === "ws:")) throw new Error("Use wss://, or ws:// only for a local relay");
    this.requireState().relayUrl = url.toString();
    await this.persist();
  }

  private requireState(): StoredState {
    if (!this.state) throw new Error("Store has not been loaded");
    return this.state;
  }

  private protectIdentity(identity: DeviceIdentity): string {
    const plaintext = JSON.stringify(identity);
    const protectedBytes = safeStorage.isEncryptionAvailable() ? safeStorage.encryptString(plaintext) : Buffer.from(plaintext);
    return protectedBytes.toString("base64");
  }

  private async persist(): Promise<void> {
    const state = this.requireState();
    await mkdir(dirname(this.filePath), { recursive: true });
    const temporary = `${this.filePath}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, this.filePath);
    await chmod(this.filePath, 0o600).catch(() => undefined);
  }
}

function cleanName(value: string): string {
  const clean = value.replace(/[\u0000-\u001f\u007f<>]/g, "").trim().slice(0, 64);
  if (!clean) throw new Error("Device name cannot be empty");
  return clean;
}
