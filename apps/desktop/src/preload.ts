import { contextBridge, ipcRenderer, webUtils } from "electron";

type Listener = (event: { type: string; detail: unknown }) => void;

contextBridge.exposeInMainWorld("airvault", {
  init: () => ipcRenderer.invoke("airvault:init"),
  chooseFiles: () => ipcRenderer.invoke("airvault:choose-files"),
  addPeer: (deviceId: string, name: string) => ipcRenderer.invoke("airvault:add-peer", deviceId, name),
  removePeer: (deviceId: string) => ipcRenderer.invoke("airvault:remove-peer", deviceId),
  setRelay: (url: string) => ipcRenderer.invoke("airvault:set-relay", url),
  send: (paths: string[], receiverId: string) => ipcRenderer.invoke("airvault:send", paths, receiverId),
  accept: (transferId: string, authorization: string) => ipcRenderer.invoke("airvault:accept", transferId, authorization),
  approve: (transferId: string) => ipcRenderer.invoke("airvault:approve", transferId),
  reject: (transferId: string) => ipcRenderer.invoke("airvault:reject", transferId),
  registerDroppedFiles: (files: File[]) => {
    if (!Array.isArray(files) || files.length === 0 || files.length > 256) {
      return Promise.resolve({ ok: false, error: "Drop between 1 and 256 local files" });
    }
    const paths = files.map((file) => webUtils.getPathForFile(file));
    if (paths.some((path) => !path)) return Promise.resolve({ ok: false, error: "Every dropped item must be a local file" });
    return ipcRenderer.invoke("airvault:register-dropped-files", paths);
  },
  onEvent: (listener: Listener) => {
    const wrapped = (_event: Electron.IpcRendererEvent, payload: { type: string; detail: unknown }) => listener(payload);
    ipcRenderer.on("airvault:event", wrapped);
    return () => ipcRenderer.removeListener("airvault:event", wrapped);
  },
});
