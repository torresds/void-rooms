import init, { BrowserMlsLab } from "../pkg/void_mls_spike.js";
import initClientCore, { BrowserDeviceIdentity } from "../pkg/client_core/void_client_core.js";
import { clearVault, loadVault, saveVault } from "./vault-persistence.js";
import {
  clearSnapshots,
  loadSnapshot,
  replaceSnapshot,
  saveSnapshot,
} from "./persistence.js";

await init();
await initClientCore();
document.querySelector("#status").textContent = "WebAssembly module initialized";

window.mlsLab = {
  BrowserMlsLab,
  BrowserDeviceIdentity,
  clearSnapshots,
  loadSnapshot,
  replaceSnapshot,
  saveSnapshot,
};

Object.assign(window.mlsLab, { clearVault, loadVault, saveVault });
