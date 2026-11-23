import {
  encodeMessage,
  decodeMessage,
  getUtf8ByteLength,
  evaluatePassphrase,
  hasHiddenPayload,
} from "./stego.js";

const shell = document.getElementById("appShell");
const $ = (id) => shell.querySelector(`#${id}`);

const state = {
  carrier: "👁️",
  lastEncoded: "",
  lastDecoded: "",
  deferredInstallPrompt: null,
  pipWindow: null,
  busy: false,
};

const els = {
  tabs: shell.querySelectorAll(".tab"),
  panels: {
    encode: $("panel-encode"),
    decode: $("panel-decode"),
  },
  emojiChips: shell.querySelectorAll(".emoji-chip"),
  customEmoji: $("customEmoji"),
  secretInput: $("secretInput"),
  byteCount: $("byteCount"),
  clearEncodeBtn: $("clearEncodeBtn"),
  encodeKey: $("encodeKey"),
  strengthWrap: $("strengthWrap"),
  strengthBars: $("strengthBars"),
  strengthLabel: $("strengthLabel"),
  strengthTime: $("strengthTime"),
  encodeBtn: $("encodeBtn"),
  encodeResult: $("encodeResult"),
  encodedPreview: $("encodedPreview"),
  encodedStatus: $("encodedStatus"),
  encodedStats: $("encodedStats"),
  shareEncodedBtn: $("shareEncodedBtn"),
  copyEncodedBtn: $("copyEncodedBtn"),

  encodedInput: $("encodedInput"),
  clearDecodeBtn: $("clearDecodeBtn"),
  pasteBtn: $("pasteBtn"),
  decodeKeyField: $("decodeKeyField"),
  decodeKey: $("decodeKey"),
  lockBadge: $("lockBadge"),
  decodeBtn: $("decodeBtn"),
  decodeResult: $("decodeResult"),
  decodeResultLabel: $("decodeResultLabel"),
  decodedOutput: $("decodedOutput"),
  copyDecodedBtn: $("copyDecodedBtn"),

  pipBtn: $("pipBtn"),
  installBtn: $("installBtn"),
  toast: $("toast"),
};

let toastTimer;
function showToast(msg) {
  clearTimeout(toastTimer);
  els.toast.textContent = msg;
  toastTimer = setTimeout(() => {
    els.toast.textContent = "";
  }, 2500);
}

function getActiveWindow() {
  return shell.ownerDocument?.defaultView || window;
}

async function copyText(text, successMsg) {
  if (!text) return;
  const activeWin = getActiveWindow();
  const activeDoc = shell.ownerDocument || document;
  try {
    await activeWin.navigator.clipboard.writeText(text);
    showToast(successMsg);
  } catch {
    const temp = activeDoc.createElement("textarea");
    temp.value = text;
    temp.style.position = "fixed";
    temp.style.opacity = "0";
    activeDoc.body.appendChild(temp);
    temp.select();
    activeDoc.execCommand("copy");
    activeDoc.body.removeChild(temp);
    showToast(successMsg);
  }
}

function switchTab(mode) {
  els.tabs.forEach((t) => {
    const active = t.dataset.tab === mode;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", String(active));
  });
  Object.entries(els.panels).forEach(([key, panel]) => {
    panel.classList.toggle("active", key === mode);
  });
}

// Tabs
els.tabs.forEach((tab) => {
  tab.addEventListener("click", () => switchTab(tab.dataset.tab));
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

// Byte counter & Clear button
function updateEncodeControls() {
  const text = els.secretInput.value;
  const bytes = getUtf8ByteLength(text);
  els.byteCount.textContent =
    bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
  els.clearEncodeBtn.classList.toggle(
    "hidden",
    !text && !els.encodeKey.value && !state.lastEncoded
  );
}

els.secretInput.addEventListener("input", updateEncodeControls);

// Live Passphrase Strength Meter
function updateStrengthMeter() {
  const pass = els.encodeKey.value;
  updateEncodeControls();

  const res = evaluatePassphrase(pass);
  if (!res) {
    els.strengthWrap.classList.add("hidden");
    return;
  }

  els.strengthWrap.classList.remove("hidden");
  els.strengthBars.dataset.tone = res.tone;
  els.strengthLabel.dataset.tone = res.tone;
  els.strengthLabel.textContent = res.label;
  els.strengthTime.textContent = res.crackTime;

  const bars = els.strengthBars.querySelectorAll(".s-bar");
  bars.forEach((bar, idx) => {
    bar.classList.toggle("filled", idx < res.score);
  });
}

els.encodeKey.addEventListener("input", updateStrengthMeter);

els.clearEncodeBtn.addEventListener("click", () => {
  els.secretInput.value = "";
  els.encodeKey.value = "";
  state.lastEncoded = "";
  els.encodeResult.classList.add("hidden");
  updateStrengthMeter();
  showToast("Cleared");
});

// Password visibility toggles (works inside main window & PiP)
shell.querySelectorAll(".toggle-vis").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = btn.closest(".input-wrap").querySelector("input");
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    btn.textContent = isPassword ? "Hide" : "Show";
  });
});

// Show native Share button if supported
if (typeof navigator.share === "function") {
  els.shareEncodedBtn.classList.remove("hidden");
}

// Encode action
els.encodeBtn.addEventListener("click", async () => {
  if (state.busy) return;
  const hasKey = els.encodeKey.value.length > 0;

  try {
    state.busy = true;
    els.encodeBtn.disabled = true;
    if (hasKey) els.encodeBtn.textContent = "Encrypting...";

    const { output, hiddenBytes, encrypted, paddedSize } = await encodeMessage(
      state.carrier,
      els.secretInput.value,
      els.encodeKey.value
    );

    state.lastEncoded = output;
    els.encodedPreview.textContent = output;
    els.encodedStatus.textContent = encrypted
      ? "AES-256-GCM locked"
      : "Encoded inside emoji";
    els.encodedStats.textContent = encrypted
      ? `${hiddenBytes} B · ${paddedSize}B padded`
      : `${hiddenBytes} hidden bytes`;
    els.encodeResult.classList.remove("hidden");
    updateEncodeControls();

    await copyText(output, "Copied encoded emoji");
  } catch (err) {
    showToast(err.message || "Encoding failed");
  } finally {
    state.busy = false;
    els.encodeBtn.disabled = false;
    els.encodeBtn.textContent = "Encode into Emoji";
  }
});

els.copyEncodedBtn.addEventListener("click", () => {
  copyText(state.lastEncoded, "Copied encoded emoji");
});

els.shareEncodedBtn.addEventListener("click", async () => {
  if (!state.lastEncoded || typeof navigator.share !== "function") return;
  try {
    await navigator.share({ text: state.lastEncoded });
  } catch (err) {
    if (err.name !== "AbortError") {
      showToast("Share failed — use Copy");
    }
  }
});

// Decode action
function updateDecodeControls() {
  const hasAny =
    els.encodedInput.value.length > 0 ||
    els.decodeKey.value.length > 0 ||
    state.lastDecoded.length > 0;
  els.clearDecodeBtn.classList.toggle("hidden", !hasAny);
}

async function runDecode({ silentEmpty = false } = {}) {
  if (state.busy) return;
  els.decodeKeyField.classList.remove("needs-key");
  els.lockBadge.textContent = "Only if locked";
  updateDecodeControls();

  const raw = els.encodedInput.value;
  if (!raw.trim()) {
    els.decodeResult.classList.add("hidden");
    if (!silentEmpty) showToast("Paste an emoji first");
    return;
  }

  const key = els.decodeKey.value;
  const mayDecrypt = key.length > 0;

  try {
    state.busy = true;
    els.decodeBtn.disabled = true;
    if (mayDecrypt) els.decodeBtn.textContent = "Decrypting...";

    const res = await decodeMessage(raw, key);

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
      ? `Decrypted (AES-256 · v${res.version})`
      : "Hidden payload";
    els.decodeResult.classList.remove("hidden");
    updateDecodeControls();
    showToast("Message revealed");
  } catch (err) {
    els.decodeResult.classList.add("hidden");
    showToast(err.message || "Decode failed");
  } finally {
    state.busy = false;
    els.decodeBtn.disabled = false;
    els.decodeBtn.textContent = "Reveal Message";
  }
}

els.decodeBtn.addEventListener("click", () => runDecode({ silentEmpty: false }));

els.encodedInput.addEventListener("input", () => {
  runDecode({ silentEmpty: true });
});

els.decodeKey.addEventListener("input", updateDecodeControls);

els.decodeKey.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    runDecode({ silentEmpty: false });
  }
});

els.clearDecodeBtn.addEventListener("click", () => {
  els.encodedInput.value = "";
  els.decodeKey.value = "";
  state.lastDecoded = "";
  els.decodeResult.classList.add("hidden");
  els.decodeKeyField.classList.remove("needs-key");
  els.lockBadge.textContent = "Only if locked";
  updateDecodeControls();
  showToast("Cleared");
});

els.pasteBtn.addEventListener("click", async () => {
  const activeWin = getActiveWindow();
  try {
    const clip = await activeWin.navigator.clipboard.readText();
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

// Web Share Target incoming handler (Share -> VEIL)
function handleIncomingShare() {
  const params = new URLSearchParams(window.location.search);
  const candidates = [
    params.get("shared_text"),
    params.get("shared_title"),
    params.get("shared_url"),
  ].filter(Boolean);

  if (candidates.length === 0) return;

  const payloadCarrier =
    candidates.find((val) => hasHiddenPayload(val)) || candidates.join(" ");

  switchTab("decode");
  els.encodedInput.value = payloadCarrier;

  // Clean URL query params so reload won't replay old share
  window.history.replaceState({}, "", window.location.pathname);
  runDecode({ silentEmpty: false });
}

handleIncomingShare();

// Desktop Always-on-Top Floating Mini Window (Document Picture-in-Picture API)
if ("documentPictureInPicture" in window) {
  els.pipBtn.classList.remove("hidden");

  els.pipBtn.addEventListener("click", async () => {
    if (state.pipWindow) {
      state.pipWindow.close();
      return;
    }

    try {
      const pipWin = await window.documentPictureInPicture.requestWindow({
        width: 360,
        height: 540,
      });

      document.querySelectorAll('link[rel="stylesheet"]').forEach((link) => {
        const clone = pipWin.document.createElement("link");
        clone.rel = "stylesheet";
        clone.href = link.href;
        pipWin.document.head.appendChild(clone);
      });

      pipWin.document.title = "VEIL Mini";
      pipWin.document.body.classList.add("pip-mode");
      pipWin.document.body.appendChild(shell);

      state.pipWindow = pipWin;
      els.pipBtn.textContent = "Dock";

      pipWin.addEventListener("pagehide", () => {
        document.body.appendChild(shell);
        state.pipWindow = null;
        els.pipBtn.textContent = "Mini";
      });
    } catch {
      showToast("Mini window unavailable");
    }
  });
}

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

// Service Worker registration
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  });
}
