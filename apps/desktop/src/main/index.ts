import { app, BrowserWindow, dialog, ipcMain, session, shell } from "electron";
import { join } from "node:path";
import QRCode from "qrcode";
import { AirVaultStore } from "./store";
import { RelayClient } from "./relay-client";
import { TransferManager } from "./transfer-manager";
import { SecureDiscovery } from "./discovery";

let mainWindow: BrowserWindow | undefined;
let store: AirVaultStore;
let relay: RelayClient;
let transfers: TransferManager;
let discovery: SecureDiscovery;
const approvedSendPaths = new Set<string>();
const MAX_APPROVED_PATHS = 256;

type Result<T> = { ok: true; value: T } | { ok: false; error: string };

function resultHandler<TArgs extends unknown[], TValue>(handler: (...args: TArgs) => Promise<TValue> | TValue) {
  return async (_event: Electron.IpcMainInvokeEvent, ...args: TArgs): Promise<Result<TValue>> => {
    try {
      return { ok: true, value: await handler(...args) };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : "Unexpected application error" };
    }
  };
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 820,
    minHeight: 600,
    backgroundColor: "#08111f",
    show: false,
    title: "AirVault",
    webPreferences: {
      preload: join(__dirname, "..", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });
  void mainWindow.loadFile(join(__dirname, "..", "renderer", "index.html"));
  mainWindow.once("ready-to-show", () => mainWindow?.show());
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://github.com/YanagiKH/AirVault")) void shell.openExternal(url);
    return { action: "deny" };
  });
  mainWindow.webContents.on("will-navigate", (event) => event.preventDefault());
  mainWindow.on("closed", () => { mainWindow = undefined; });
}

function publishEvent(type: string, detail: unknown): void {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send("airvault:event", { type, detail });
}

function registerIpc(): void {
  ipcMain.handle("airvault:init", resultHandler(async () => ({
    deviceId: store.identity.deviceId,
    peers: store.listPeers(),
    relayUrl: store.relayUrl,
  })));
  ipcMain.handle("airvault:choose-files", resultHandler(async () => {
    if (!mainWindow) throw new Error("The main window is unavailable");
    const selection = await dialog.showOpenDialog(mainWindow, { properties: ["openFile", "multiSelections"], title: "Choose files to send" });
    if (selection.canceled) return [];
    approvedSendPaths.clear();
    for (const path of selection.filePaths.slice(0, MAX_APPROVED_PATHS)) approvedSendPaths.add(path);
    return [...approvedSendPaths];
  }));
  ipcMain.handle("airvault:register-dropped-files", resultHandler((paths: string[]) => {
    if (!Array.isArray(paths) || paths.length === 0 || paths.length > MAX_APPROVED_PATHS
        || paths.some((path) => typeof path !== "string" || !path)) throw new Error("Drop between 1 and 256 local files");
    approvedSendPaths.clear();
    for (const path of paths) approvedSendPaths.add(path);
    return [...approvedSendPaths];
  }));
  ipcMain.handle("airvault:add-peer", resultHandler(async (deviceId: string, name: string) => {
    await store.savePeer(deviceId, name);
    return store.listPeers();
  }));
  ipcMain.handle("airvault:remove-peer", resultHandler(async (deviceId: string) => {
    await store.removePeer(deviceId);
    return store.listPeers();
  }));
  ipcMain.handle("airvault:set-relay", resultHandler(async (url: string) => {
    await store.setRelayUrl(url);
    relay.updateUrl(store.relayUrl);
    return store.relayUrl;
  }));
  ipcMain.handle("airvault:send", resultHandler(async (paths: string[], receiverId: string) => {
    if (!Array.isArray(paths) || paths.length === 0 || paths.length > MAX_APPROVED_PATHS
        || paths.some((path) => typeof path !== "string" || !approvedSendPaths.has(path))) {
      throw new Error("Select or drop the files again before sending");
    }
    for (const path of paths) approvedSendPaths.delete(path);
    try {
      const offer = await transfers.beginSend(paths, receiverId);
      return { ...offer, qrDataUrl: await QRCode.toDataURL(offer.qrPayload, { errorCorrectionLevel: "M", margin: 2, width: 320 }) };
    } catch (error) {
      for (const path of paths) approvedSendPaths.add(path);
      throw error;
    }
  }));
  ipcMain.handle("airvault:accept", resultHandler(async (transferId: string, authorization: string) => {
    await transfers.acceptIncoming(transferId, authorization);
    return true;
  }));
  ipcMain.handle("airvault:approve", resultHandler(async (transferId: string) => {
    if (!mainWindow) throw new Error("The main window is unavailable");
    const selection = await dialog.showOpenDialog(mainWindow, { properties: ["openDirectory", "createDirectory"], title: "Choose a secure save location" });
    if (selection.canceled || !selection.filePaths[0]) return false;
    await transfers.approveIncoming(transferId, selection.filePaths[0]);
    return true;
  }));
  ipcMain.handle("airvault:reject", resultHandler((transferId: string) => {
    transfers.rejectIncoming(transferId);
    return true;
  }));
}

app.whenReady().then(async () => {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "Content-Security-Policy": ["default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"],
      },
    });
  });
  store = new AirVaultStore();
  await store.load();
  relay = new RelayClient(store.relayUrl, store.identity);
  transfers = new TransferManager(store, relay);
  discovery = new SecureDiscovery(store.identity);
  for (const event of ["offer", "review", "progress", "complete", "failure"] as const) transfers.on(event, (detail) => publishEvent(event, detail));
  relay.on("status", (status) => publishEvent("relay-status", status));
  relay.on("protocol-error", (code) => publishEvent("failure", { transferId: "relay", message: "Relay rejected a message: " + String(code) }));
  discovery.on("device", (device: { deviceId: string; publicKey: string }) => {
    void store.observeDiscoveredPeer(device.deviceId, device.publicKey)
      .then((saved) => { if (saved) publishEvent("discovered", { deviceId: device.deviceId }); })
      .catch((error: unknown) => publishEvent("failure", { transferId: "discovery", message: error instanceof Error ? error.message : "Discovery identity check failed" }));
  });
  registerIpc();
  createWindow();
  try {
    relay.connect();
  } catch (error) {
    publishEvent("failure", { transferId: "relay", message: error instanceof Error ? error.message : "Relay connection failed" });
  }
  discovery.start();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
}).catch((error: unknown) => {
  dialog.showErrorBox("AirVault could not start", error instanceof Error ? error.message : "Unexpected startup failure");
  app.quit();
});

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
app.on("before-quit", () => {
  discovery?.stop();
  relay?.disconnect();
});
