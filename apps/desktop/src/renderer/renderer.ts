interface Peer { deviceId: string; name: string; verifiedAt?: number }
interface FileInfo { name: string; relativePath: string; size: number; sha256: string }
interface InvokeResult<T> { ok: boolean; value?: T; error?: string }
interface AirVaultApi {
  init(): Promise<InvokeResult<{ deviceId: string; peers: Peer[]; relayUrl: string }>>;
  chooseFiles(): Promise<InvokeResult<string[]>>;
  addPeer(id: string, name: string): Promise<InvokeResult<Peer[]>>;
  removePeer(id: string): Promise<InvokeResult<Peer[]>>;
  setRelay(url: string): Promise<InvokeResult<string>>;
  send(paths: string[], receiver: string): Promise<InvokeResult<{ transferId: string; pin: string; qrDataUrl: string; files: FileInfo[] }>>;
  accept(id: string, secret: string): Promise<InvokeResult<boolean>>;
  approve(id: string): Promise<InvokeResult<boolean>>;
  reject(id: string): Promise<InvokeResult<boolean>>;
  registerDroppedFiles(files: File[]): Promise<InvokeResult<string[]>>;
  onEvent(listener: (event: { type: string; detail: any }) => void): () => void;
}
declare global { interface Window { airvault: AirVaultApi } }

const state: { peers: Peer[]; paths: string[]; currentOffer?: string } = { peers: [], paths: [] };
const $ = <T extends HTMLElement>(selector: string) => document.querySelector<T>(selector)!;

async function unwrap<T>(request: Promise<InvokeResult<T>>): Promise<T> {
  const result = await request;
  if (!result.ok) throw new Error(result.error || "The operation failed");
  return result.value as T;
}

function toast(message: string, type: "info" | "error" | "success" = "info"): void {
  const element = $("#toast");
  element.textContent = message;
  element.className = "toast visible " + type;
  window.setTimeout(() => element.classList.remove("visible"), 5000);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return String(bytes) + " B";
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let unit = units[0]!;
  for (let index = 1; value >= 1024 && index < units.length; index += 1) {
    value /= 1024;
    unit = units[index]!;
  }
  return value.toFixed(value >= 10 ? 1 : 2) + " " + unit;
}

function renderPeers(): void {
  const list = $("#peer-list");
  const select = $("#peer-select") as HTMLSelectElement;
  list.replaceChildren();
  select.replaceChildren(new Option("Choose a saved device", ""));
  for (const peer of state.peers) {
    const row = document.createElement("div");
    row.className = "peer-row";
    const identity = document.createElement("div");
    const title = document.createElement("strong");
    const status = document.createElement("span");
    title.textContent = peer.name;
    status.textContent = peer.deviceId + " · " + (peer.verifiedAt ? "Verified" : "Awaiting first PIN verification");
    identity.append(title, status);
    const remove = document.createElement("button");
    remove.className = "icon-button";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => {
      void unwrap(window.airvault.removePeer(peer.deviceId)).then((peers) => {
        state.peers = peers;
        renderPeers();
      }).catch(showError);
    });
    row.append(identity, remove);
    list.append(row);
    select.append(new Option(peer.name + " · " + peer.deviceId.slice(-11), peer.deviceId));
  }
  if (!state.peers.length) list.textContent = "No saved devices yet. Add a permanent peer with its AirVault ID.";
}

function renderFiles(): void {
  const list = $("#file-list");
  list.replaceChildren();
  for (const path of state.paths) {
    const item = document.createElement("li");
    item.textContent = path.split(/[\\/]/).pop() || path;
    list.append(item);
  }
  $("#drop-copy").textContent = state.paths.length
    ? String(state.paths.length) + " file" + (state.paths.length === 1 ? "" : "s") + " ready"
    : "Drop files here or browse";
}

function showModal(id: string): void { $(id).classList.add("open"); }
function hideModal(id: string): void { $(id).classList.remove("open"); }
function showError(error: unknown): void { toast(error instanceof Error ? error.message : "Unexpected error", "error"); }

async function initialize(): Promise<void> {
  const data = await unwrap(window.airvault.init());
  $("#device-id").textContent = data.deviceId;
  ($("#relay-url") as HTMLInputElement).value = data.relayUrl;
  state.peers = data.peers;
  renderPeers();

  $("#copy-id").addEventListener("click", () => {
    void navigator.clipboard.writeText(data.deviceId).then(() => toast("Device ID copied", "success"));
  });
  $("#browse-files").addEventListener("click", () => {
    void unwrap(window.airvault.chooseFiles()).then((paths) => {
      state.paths = paths;
      renderFiles();
    }).catch(showError);
  });
  $("#add-peer-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const id = ($("#peer-id") as HTMLInputElement).value;
    const name = ($("#peer-name") as HTMLInputElement).value;
    void unwrap(window.airvault.addPeer(id, name)).then((peers) => {
      state.peers = peers;
      renderPeers();
      ($("#peer-id") as HTMLInputElement).value = "";
      ($("#peer-name") as HTMLInputElement).value = "";
      toast("Device saved", "success");
    }).catch(showError);
  });
  $("#send-button").addEventListener("click", () => {
    const receiver = ($("#peer-select") as HTMLSelectElement).value;
    void unwrap(window.airvault.send(state.paths, receiver)).then((offer) => {
      state.currentOffer = offer.transferId;
      $("#pin-code").textContent = offer.pin.slice(0, 3) + " " + offer.pin.slice(3);
      ($("#qr-image") as HTMLImageElement).src = offer.qrDataUrl;
      $("#offer-files").textContent = offer.files.map((file) => file.name + " (" + formatBytes(file.size) + ")").join(" · ");
      showModal("#send-modal");
    }).catch(showError);
  });
  $("#save-relay").addEventListener("click", () => {
    void unwrap(window.airvault.setRelay(($("#relay-url") as HTMLInputElement).value))
      .then(() => toast("Relay connection updated", "success"))
      .catch(showError);
  });
  $("#close-send-modal").addEventListener("click", () => hideModal("#send-modal"));
  $("#cancel-auth").addEventListener("click", () => {
    const transferId = ($("#incoming-transfer") as HTMLInputElement).value;
    void window.airvault.reject(transferId);
    hideModal("#receive-auth-modal");
  });
  $("#authorize-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const transferId = ($("#incoming-transfer") as HTMLInputElement).value;
    const secret = ($("#authorization") as HTMLInputElement).value;
    void unwrap(window.airvault.accept(transferId, secret)).then(() => hideModal("#receive-auth-modal")).catch(showError);
  });

  const dropZone = $("#drop-zone");
  for (const eventName of ["dragenter", "dragover"]) {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.add("dragging");
    });
  }
  for (const eventName of ["dragleave", "drop"]) {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.remove("dragging");
    });
  }
  dropZone.addEventListener("drop", (event) => {
    const files = Array.from((event as DragEvent).dataTransfer!.files);
    void unwrap(window.airvault.registerDroppedFiles(files))
      .then((paths) => {
        state.paths = paths;
        renderFiles();
      })
      .catch(showError);
  });

  window.airvault.onEvent(({ type, detail }) => {
    if (type === "relay-status") {
      const badge = $("#relay-status");
      badge.textContent = String(detail);
      badge.dataset.status = String(detail);
    } else if (type === "offer") {
      $("#incoming-copy").textContent = String(detail.senderName) + " wants to send files. Enter the six-digit PIN or paste the scanned AirVault QR link.";
      ($("#incoming-transfer") as HTMLInputElement).value = String(detail.transferId);
      ($("#authorization") as HTMLInputElement).value = "";
      showModal("#receive-auth-modal");
    } else if (type === "review") {
      const files = detail.files as FileInfo[];
      const warningCount = detail.scan.findings.filter((item: { severity: string }) => item.severity === "warning").length;
      const warning = warningCount ? "\n" + String(warningCount) + " potentially executable file warning(s)." : "";
      const accepted = window.confirm(
        "Security preflight passed for " + String(files.length) + " file(s), " + formatBytes(detail.scan.totalBytes) + " total." +
        warning + "\n\nAccept and choose a download folder?",
      );
      if (accepted) void unwrap(window.airvault.approve(detail.transferId)).catch(showError);
      else void window.airvault.reject(detail.transferId);
    } else if (type === "progress") {
      const progress = $("#progress") as HTMLProgressElement;
      progress.value = Number(detail.percent ?? 0);
      $("#activity-text").textContent = String(detail.status);
    } else if (type === "complete") {
      ($("#progress") as HTMLProgressElement).value = 100;
      $("#activity-text").textContent = String(detail.message);
      toast(String(detail.message), "success");
    } else if (type === "failure") {
      showError(new Error(String(detail.message)));
    }
  });
}

void initialize().catch(showError);
export {};
