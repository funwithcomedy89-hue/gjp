const MAGIC = [0x7f, 0x45, 0x4d]; // Header signature: DEL 'E' 'M'
const FLAG_PLAIN = 0x00;
const FLAG_ENCRYPTED_V1 = 0x01; // Legacy: 100k PBKDF2, unpadded
const FLAG_ENCRYPTED_V2 = 0x02; // Hardened: 600k PBKDF2, 64B padded, AAD-bound

const PBKDF2_V1_ITERATIONS = 100000;
const PBKDF2_V2_ITERATIONS = 600000;
const PADDING_BLOCK_SIZE = 64;

const MAX_PLAIN_BYTES = 65535;
const MAX_ENCRYPTED_RAW_BYTES = 65470; // Fits padded + salt + iv + GCM tag inside 65535B

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function byteToVariationSelector(byte) {
  if (byte < 16) {
    return String.fromCodePoint(0xfe00 + byte);
  }
  return String.fromCodePoint(0xe0100 + (byte - 16));
}

function variationSelectorToByte(codePoint) {
  if (codePoint >= 0xfe00 && codePoint <= 0xfe0f) {
    return codePoint - 0xfe00;
  }
  if (codePoint >= 0xe0100 && codePoint <= 0xe01ef) {
    return codePoint - 0xe0100 + 16;
  }
  return -1;
}

function extractVariationBytes(input) {
  const bytes = [];
  for (const ch of input) {
    const byte = variationSelectorToByte(ch.codePointAt(0));
    if (byte !== -1) {
      bytes.push(byte);
    }
  }
  return bytes;
}

function findMagicIndex(bytes) {
  for (let i = 0; i <= bytes.length - 6; i++) {
    if (
      bytes[i] === MAGIC[0] &&
      bytes[i + 1] === MAGIC[1] &&
      bytes[i + 2] === MAGIC[2]
    ) {
      return i;
    }
  }
  return -1;
}

// 64-byte random block padding to hide exact message length
function padBytes(rawBytes) {
  const needed = 2 + rawBytes.length;
  const totalLen = Math.max(
    PADDING_BLOCK_SIZE,
    Math.ceil(needed / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE
  );
  const padded = new Uint8Array(totalLen);
  padded[0] = (rawBytes.length >> 8) & 0xff;
  padded[1] = rawBytes.length & 0xff;
  padded.set(rawBytes, 2);

  const padLen = totalLen - needed;
  if (padLen > 0) {
    crypto.getRandomValues(padded.subarray(needed));
  }
  return padded;
}

function unpadBytes(padded) {
  if (padded.length < 2) {
    throw new Error("Corrupted padded payload.");
  }
  const realLen = (padded[0] << 8) | padded[1];
  if (2 + realLen > padded.length) {
    throw new Error("Invalid payload length.");
  }
  return padded.slice(2, 2 + realLen);
}

async function deriveAesKey(passphrase, salt, iterations, usages) {
  if (!window.crypto?.subtle) {
    throw new Error("Encryption requires HTTPS or localhost.");
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}

async function encryptBytesV2(paddedBytes, passphrase, headerAad) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(passphrase, salt, PBKDF2_V2_ITERATIONS, ["encrypt"]);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: headerAad },
    key,
    paddedBytes
  );

  const cipherBytes = new Uint8Array(cipherBuffer);
  const packed = new Uint8Array(salt.length + iv.length + cipherBytes.length);
  packed.set(salt, 0);
  packed.set(iv, salt.length);
  packed.set(cipherBytes, salt.length + iv.length);
  return packed;
}

async function decryptBytes(packedBytes, passphrase, { iterations, headerAad = null }) {
  if (packedBytes.length < 16 + 12 + 16) {
    throw new Error("Corrupted encrypted payload.");
  }

  const salt = packedBytes.slice(0, 16);
  const iv = packedBytes.slice(16, 28);
  const cipherBytes = packedBytes.slice(28);
  const key = await deriveAesKey(passphrase, salt, iterations, ["decrypt"]);

  const algo = headerAad
    ? { name: "AES-GCM", iv, additionalData: headerAad }
    : { name: "AES-GCM", iv };

  try {
    const plainBuffer = await crypto.subtle.decrypt(algo, key, cipherBytes);
    return new Uint8Array(plainBuffer);
  } catch {
    throw new Error("Wrong passphrase or tampered emoji.");
  }
}

export function getUtf8ByteLength(text) {
  return textEncoder.encode(text).length;
}

export function hasHiddenPayload(input) {
  if (!input) return false;
  return findMagicIndex(extractVariationBytes(input)) !== -1;
}

export function evaluatePassphrase(pass) {
  if (!pass) return null;

  let poolSize = 0;
  if (/[a-z]/.test(pass)) poolSize += 26;
  if (/[A-Z]/.test(pass)) poolSize += 26;
  if (/[0-9]/.test(pass)) poolSize += 10;
  if (/[^a-zA-Z0-9\s]/.test(pass)) poolSize += 32;
  if (/\s/.test(pass)) poolSize += 1;
  if (/[^\x00-\x7F]/.test(pass)) poolSize += 64;

  const uniqueChars = new Set([...pass]).size;
  const effectiveLen = Math.min(pass.length, uniqueChars * 2.2);
  let bits = effectiveLen * Math.log2(Math.max(2, poolSize));

  const lower = pass.toLowerCase();
  const weakPatterns = [
    "1234", "0000", "1111", "9999", "abcd", "qwerty", "asdf",
    "zxcv", "password", "pass", "admin", "secret", "welcome", "iloveyou",
  ];
  const hasWeakPattern = weakPatterns.some((p) => lower.includes(p));
  const isOnlyDigits = /^\d+$/.test(pass);

  if (hasWeakPattern) bits *= 0.48;
  if (isOnlyDigits && pass.length <= 6) bits = Math.min(bits, 20);
  if (uniqueChars <= 2) bits = Math.min(bits, 14);

  bits = Math.max(1, Math.round(bits));

  // RTX 4090 @ 600k PBKDF2-SHA256 ≈ 10,000 guesses/sec (average 50% keyspace)
  const avgSeconds = Math.pow(2, bits - 1) / 10000;
  const crackTime = formatCrackTime(avgSeconds);

  if (bits < 36) {
    return { score: 1, tone: "weak", label: "Weak", crackTime };
  }
  if (bits < 55) {
    return { score: 2, tone: "fair", label: "Fair", crackTime };
  }
  if (bits < 75) {
    return { score: 3, tone: "strong", label: "Strong", crackTime };
  }
  return { score: 4, tone: "hardened", label: "Hardened", crackTime };
}

function formatCrackTime(sec) {
  if (sec < 1) return "Instant crack";
  if (sec < 60) return `~${Math.round(sec)} sec crack`;
  if (sec < 3600) return `~${Math.round(sec / 60)} min crack`;
  if (sec < 86400) return `~${Math.round(sec / 3600)} hrs crack`;
  if (sec < 86400 * 365) return `~${Math.round(sec / 86400)} days crack`;
  const years = sec / (86400 * 365);
  if (years < 1000) return `~${Math.round(years)} yrs crack`;
  return "Centuries+";
}

export async function encodeMessage(carrier, message, passphrase = "") {
  const cleanCarrier = carrier.trim();
  if (!cleanCarrier) {
    throw new Error("Choose a carrier emoji first.");
  }
  if (!message) {
    throw new Error("Write a message to hide.");
  }

  const rawBytes = textEncoder.encode(message);
  const hasPassphrase = passphrase.length > 0;
  let frame;
  let paddedSize = null;

  if (hasPassphrase) {
    if (rawBytes.length > MAX_ENCRYPTED_RAW_BYTES) {
      throw new Error("Message is too large for encryption (max 63 KB).");
    }

    const padded = padBytes(rawBytes);
    paddedSize = padded.length;
    const expectedPayloadLen = 16 + 12 + padded.length + 16;

    const header = new Uint8Array([
      MAGIC[0],
      MAGIC[1],
      MAGIC[2],
      FLAG_ENCRYPTED_V2,
      (expectedPayloadLen >> 8) & 0xff,
      expectedPayloadLen & 0xff,
    ]);

    const payload = await encryptBytesV2(padded, passphrase, header);
    frame = new Uint8Array(6 + payload.length);
    frame.set(header, 0);
    frame.set(payload, 6);
  } else {
    if (rawBytes.length > MAX_PLAIN_BYTES) {
      throw new Error("Message is too large (max 64 KB).");
    }

    frame = new Uint8Array(6 + rawBytes.length);
    frame[0] = MAGIC[0];
    frame[1] = MAGIC[1];
    frame[2] = MAGIC[2];
    frame[3] = FLAG_PLAIN;
    frame[4] = (rawBytes.length >> 8) & 0xff;
    frame[5] = rawBytes.length & 0xff;
    frame.set(rawBytes, 6);
  }

  let hidden = "";
  for (let i = 0; i < frame.length; i++) {
    hidden += byteToVariationSelector(frame[i]);
  }

  return {
    output: cleanCarrier + hidden,
    hiddenBytes: frame.length,
    encrypted: hasPassphrase,
    paddedSize,
  };
}

export async function decodeMessage(input, passphrase = "") {
  if (!input) {
    return { found: false };
  }

  const extracted = extractVariationBytes(input);
  const start = findMagicIndex(extracted);
  if (start === -1) {
    return { found: false };
  }

  const flag = extracted[start + 3];
  const length = (extracted[start + 4] << 8) | extracted[start + 5];
  const payloadStart = start + 6;
  const payloadEnd = payloadStart + length;

  if (extracted.length < payloadEnd) {
    throw new Error("Hidden data is incomplete or was stripped by an app.");
  }

  const header = new Uint8Array(extracted.slice(start, payloadStart));
  const payload = new Uint8Array(extracted.slice(payloadStart, payloadEnd));

  if (flag === FLAG_PLAIN) {
    return {
      found: true,
      encrypted: false,
      needsKey: false,
      text: textDecoder.decode(payload),
    };
  }

  if (flag === FLAG_ENCRYPTED_V2 || flag === FLAG_ENCRYPTED_V1) {
    if (!passphrase) {
      return {
        found: true,
        encrypted: true,
        needsKey: true,
        version: flag === FLAG_ENCRYPTED_V2 ? 2 : 1,
      };
    }

    if (flag === FLAG_ENCRYPTED_V2) {
      const decryptedPadded = await decryptBytes(payload, passphrase, {
        iterations: PBKDF2_V2_ITERATIONS,
        headerAad: header,
      });
      const rawBytes = unpadBytes(decryptedPadded);
      return {
        found: true,
        encrypted: true,
        needsKey: false,
        version: 2,
        text: textDecoder.decode(rawBytes),
      };
    }

    const decryptedLegacy = await decryptBytes(payload, passphrase, {
      iterations: PBKDF2_V1_ITERATIONS,
    });
    return {
      found: true,
      encrypted: true,
      needsKey: false,
      version: 1,
      text: textDecoder.decode(decryptedLegacy),
    };
  }

  throw new Error("Unsupported payload version.");
      }
