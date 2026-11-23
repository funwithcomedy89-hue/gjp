import { encodeMessage, decodeMessage, getUtf8ByteLength } from "./stego.js";

const $ = (id) => document.getElementById(id);

const state = {
  carrier: "👁️",
  lastEncoded: "",
  lastDecoded: "",
  deferredInstallPrompt: null,
};

const els = {
  tabs: document.querySelectorAll(".tab"),
  panels: {
    encode: $("panel-encode"),
    decode: $("panel-decode"),
  },
  emojiChips: document.querySelectorAll(".emoji-chip"),
  customEmoji: $("customEmoji"),
  secretInput: $("secretInput"),
  byteCount: $("byteCount"),
  encodeKey: $("encodeKey"),
  encodeBtn: $("encodeBtn"),
  encodeResult: $("encodeResult"),
  encodedPreview: $("encodedPreview"),
  encodedStatus: $("encodedStatus"),
  encodedStats: $("encodedStats"),
  copyEncodedBtn: $("copyEncodedBtn"),

  encodedInput: $("encodedInput"),
  pasteBtn: $("pasteBtn"),
  decodeKeyField: $("decodeKeyField"),
  decodeKey: $("decodeKey"),
  lockBadge: $("lockBadge"),
  decodeBtn: $("decodeBtn"),
  decodeResult: $("decodeResult"),
  decodeResultLabel: $("decodeResultLabel"),
  decodedOutput: $("decodedOutput"),
  copyDecodedBtn: $("copyDecodedBtn"),

  installBtn: $("installBtn"),
  toast: $("toast"),
};

let toastTimer;
function showToast(msg) {
  clearTimeout(toastTimer);
  els.toast.textContent = msg;
  toastTimer = setTimeout(() => {
    els.toast.textContent = "";
  }, 2400);
}

async function copyText(text, successMsg) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    showToast(successMsg);
  } catch {
    const temp = document.createElement("textarea");
    temp.value = text;
    temp.style.position = "fixed";
    temp.style.opacity = "0";
    document.body.appendChild(temp);
    temp.select();
    document.execCommand("copy");
    document.body.removeChild(temp);
    showToast(successMsg);
  }
}

// Tabs
els.tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const mode = tab.dataset.tab;
    els.tabs.forEach((t) => {
      const active = t === tab;
      t.classList.toggle("active", active);
      t.setAttribute("aria-selected", String(active));
    });
    Object.entries(els.panels).forEach(([key, panel]) => {
      panel.classList.toggle("active", key === mode);
    });
  });
});

// Carrier emoji chips
els.emojiChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    els.emojiChips.forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    els.customEmoji.value = "";
    state.carrier = chip.dataset.emoji;
  });
});

els.customEmoji.addEventListener("input", () => {
  const val = els.customEmoji.value.trim();
  if (val) {
    els.emojiChips.forEach((c) => c.classList.remove("active"));
    state.carrier = val;
  }
});

// Byte counter
els.secretInput.addEventListener("input", () => {
  const bytes = getUtf8ByteLength(els.secretInput.value);
  els.byteCount.textContent = bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
});

// Password visibility toggles
document.querySelectorAll(".toggle-vis").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = $(btn.dataset.target);
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    btn.textContent = isPassword ? "Hide" : "Show";
  });
});

// Encode action
els.encodeBtn.addEventListener("click", async () => {
  try {
    const { output, hiddenBytes, encrypted } = await encodeMessage(
      state.carrier,
      els.secretInput.value,
      els.encodeKey.value
    );

    state.lastEncoded = output;
    els.encodedPreview.textContent = output;
    els.encodedStatus.textContent = encrypted ? "Encoded & AES-256 locked" : "Encoded inside emoji";
    els.encodedStats.textContent = `${hiddenBytes} hidden bytes`;
    els.encodeResult.classList.remove("hidden");

    await copyText(output, "Copied encoded emoji");
  } catch (err) {
    showToast(err.message || "Encoding failed");
  }
});

els.copyEncodedBtn.addEventListener("click", () => {
  copyText(state.lastEncoded, "Copied encoded emoji");
});

// Decode action
async function runDecode({ silentEmpty = false } = {}) {
  els.decodeKeyField.classList.remove("needs-key");
  els.lockBadge.textContent = "Only if locked";

  const raw = els.encodedInput.value;
  if (!raw.trim()) {
    els.decodeResult.classList.add("hidden");
    if (!silentEmpty) showToast("Paste an emoji first");
    return;
  }

  try {
    const res = await decodeMessage(raw, els.decodeKey.value);

    if (!res.found) {
      els.decodeResult.classList.add("hidden");
      if (!silentEmpty) showToast("No hidden message found");
      return;
    }

    if (res.needsKey) {
      els.decodeResult.classList.add("hidden");
      els.decodeKeyField.classList.add("needs-key");
      els.lockBadge.textContent = "Passphrase required";
      els.decodeKey.focus();
      showToast("Locked message — enter passphrase");
      return;
    }

    state.lastDecoded = res.text;
    els.decodedOutput.textContent = res.text;
    els.decodeResultLabel.textContent = res.encrypted
      ? "Decrypted payload (AES-256)"
      : "Hidden payload";
    els.decodeResult.classList.remove("hidden");
    showToast("Message revealed");
  } catch (err) {
    els.decodeResult.classList.add("hidden");
    showToast(err.message || "Decode failed");
  }
}

els.decodeBtn.addEventListener("click", () => runDecode({ silentEmpty: false }));

// Auto-decode when user pastes into decode box
els.encodedInput.addEventListener("input", () => {
  runDecode({ silentEmpty: true });
});

els.decodeKey.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    runDecode({ silentEmpty: false });
  }
});

els.pasteBtn.addEventListener("click", async () => {
  try {
    const clip = await navigator.clipboard.readText();
    if (!clip) {
      showToast("Clipboard is empty");
      return;
    }
    els.encodedInput.value = clip;
    runDecode({ silentEmpty: false });
  } catch {
    showToast("Paste manually (clipboard blocked)");
    els.encodedInput.focus();
  }
});

els.copyDecodedBtn.addEventListener("click", () => {
  copyText(state.lastDecoded, "Copied message");
});

// PWA install handling
window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  state.deferredInstallPrompt = e;
  els.installBtn.classList.remove("hidden");
});

els.installBtn.addEventListener("click", async () => {
  if (!state.deferredInstallPrompt) return;
  state.deferredInstallPrompt.prompt();
  const { outcome } = await state.deferredInstallPrompt.userChoice;
  if (outcome === "accepted") {
    els.installBtn.classList.add("hidden");
  }
  state.deferredInstallPrompt = null;
});

window.addEventListener("appinstalled", () => {
  els.installBtn.classList.add("hidden");
  showToast("App installed");
});

// Service Worker registration (relative path for GitHub Pages compatibility)
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  });
                                                 }
