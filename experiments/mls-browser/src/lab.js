import init, { BrowserMlsLab } from "../pkg/void_mls_spike.js";
import {
  clearSnapshots,
  loadSnapshot,
  replaceSnapshot,
  saveSnapshot,
} from "./persistence.js";

await init();
document.querySelector("#status").textContent = "WebAssembly module initialized";

window.mlsLab = {
  BrowserMlsLab,
  clearSnapshots,
  loadSnapshot,
  replaceSnapshot,
  saveSnapshot,
};
