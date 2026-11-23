const MAGIC = [0x7f, 0x45, 0x4d]; // Header signature: DEL 'E' 'M'
const FLAG_PLAIN = 0x00;
const FLAG_ENCRYPTED = 0x01;
const MAX_PAYLOAD_BYTES = 65535;
const PBKDF2_ITERATIONS = 100000;

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

async function deriveAesKey(passphrase, salt, usages) {
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
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}

async function encryptBytes(plainBytes, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(passphrase, salt, ["encrypt"]);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plainBytes
  );

  const cipherBytes = new Uint8Array(cipherBuffer);
  const packed = new Uint8Array(salt.length + iv.length + cipherBytes.length);
  packed.set(salt, 0);
  packed.set(iv, salt.length);
  packed.set(cipherBytes, salt.length + iv.length);
  return packed;
}

async function decryptBytes(packedBytes, passphrase) {
  if (packedBytes.length < 16 + 12 + 16) {
    throw new Error("Corrupted encrypted payload.");
  }

  const salt = packedBytes.slice(0, 16);
  const iv = packedBytes.slice(16, 28);
  const cipherBytes = packedBytes.slice(28);
  const key = await deriveAesKey(passphrase, salt, ["decrypt"]);

  try {
    const plainBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipherBytes
    );
    return new Uint8Array(plainBuffer);
  } catch {
    throw new Error("Wrong passphrase or tampered emoji.");
  }
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

export function getUtf8ByteLength(text) {
  return textEncoder.encode(text).length;
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
  const payload = hasPassphrase
    ? await encryptBytes(rawBytes, passphrase)
    : rawBytes;

  if (payload.length > MAX_PAYLOAD_BYTES) {
    throw new Error("Message is too large (max 64 KB).");
  }

  // Frame: [3B Magic][1B Flag][2B Length][Payload]
  const frame = new Uint8Array(6 + payload.length);
  frame[0] = MAGIC[0];
  frame[1] = MAGIC[1];
  frame[2] = MAGIC[2];
  frame[3] = hasPassphrase ? FLAG_ENCRYPTED : FLAG_PLAIN;
  frame[4] = (payload.length >> 8) & 0xff;
  frame[5] = payload.length & 0xff;
  frame.set(payload, 6);

  let hidden = "";
  for (let i = 0; i < frame.length; i++) {
    hidden += byteToVariationSelector(frame[i]);
  }

  return {
    output: cleanCarrier + hidden,
    hiddenBytes: frame.length,
    encrypted: hasPassphrase,
  };
}

export async function decodeMessage(input, passphrase = "") {
  if (!input) {
    return { found: false };
  }

  const extracted = [];
  for (const ch of input) {
    const byte = variationSelectorToByte(ch.codePointAt(0));
    if (byte !== -1) {
      extracted.push(byte);
    }
  }

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

  const payload = new Uint8Array(extracted.slice(payloadStart, payloadEnd));

  if (flag === FLAG_ENCRYPTED) {
    if (!passphrase) {
      return { found: true, encrypted: true, needsKey: true };
    }
    const decrypted = await decryptBytes(payload, passphrase);
    return {
      found: true,
      encrypted: true,
      needsKey: false,
      text: textDecoder.decode(decrypted),
    };
  }

  if (flag === FLAG_PLAIN) {
    return {
      found: true,
      encrypted: false,
      needsKey: false,
      text: textDecoder.decode(payload),
    };
  }

  throw new Error("Unsupported payload version.");
}
  
