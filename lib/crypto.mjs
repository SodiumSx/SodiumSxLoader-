/**
 * Shared crypto primitives for FreeHub Guard.
 *
 * Every function here has a byte-for-byte twin inside lua/vm.lua + lua/sha.lua.
 * Keep the two sides in sync: the Lua VM derives the same keystream/MAC that
 * this module produces, otherwise payloads decode to garbage.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const U32 = 0x100000000;

export const sha256Hex = (data) =>
  createHash("sha256").update(data).digest("hex");

export const hmacHex = (key, data) =>
  createHmac("sha256", key).update(data).digest("hex");

export const b64u = (buf) => Buffer.from(buf).toString("base64url");
export const unb64u = (str) => Buffer.from(str, "base64url");
export const randomHex = (bytes) => randomBytes(bytes).toString("hex");
export const randomId = (bytes) => randomBytes(bytes).toString("base64url");

/** Constant-time string compare. */
export function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Derive the 4x32-bit session key words from master secret + script id + nonce.
 * The Lua side receives the key as 32 hex chars (16 bytes) and reads the same
 * four little-endian words.
 */
export function sessionKeyWords(master, scriptId, nonce) {
  const digest = createHmac("sha256", master)
    .update(`freehub|key|${scriptId}|${nonce}`)
    .digest();
  return [
    digest.readUInt32LE(0),
    digest.readUInt32LE(4),
    digest.readUInt32LE(8),
    digest.readUInt32LE(12),
  ];
}

export const keyWordsToHex = (words) => {
  const buf = Buffer.alloc(16);
  words.forEach((w, i) => buf.writeUInt32LE(w >>> 0, i * 4));
  return buf.toString("hex");
};

export const keyWordsFromHex = (hex) => {
  const buf = Buffer.from(hex, "hex");
  return [
    buf.readUInt32LE(0),
    buf.readUInt32LE(4),
    buf.readUInt32LE(8),
    buf.readUInt32LE(12),
  ];
};

export const imul = (a, b) => Math.imul(a, b) >>> 0;

export function xorshift32(x) {
  x >>>= 0;
  x ^= x << 13;
  x >>>= 0;
  x ^= x >>> 17;
  x ^= x << 5;
  return x >>> 0;
}

export function rotl32(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * Keyed byte stream. Same output as lua/vm.lua ksSeg().
 * @param {number[]} k four key words
 * @param {number} seed segment index
 * @param {number} length bytes needed
 */
export function ksSeg(k, seed, length) {
  const out = Buffer.alloc(length);
  let p = 0;
  let j = 0;
  while (p < length) {
    let x = (k[0] + imul(seed + 1, 0x9e3779b1)) >>> 0;
    x = (x ^ k[1]) >>> 0;
    x = xorshift32(x);
    x = (x + imul(j + 1, 0x85ebca6b)) >>> 0;
    x = (x ^ k[2]) >>> 0;
    x = xorshift32(x);
    x = (x ^ k[3]) >>> 0;
    for (let b = 0; b < 4 && p < length; b++) {
      out[p++] = (x >>> (b * 8)) & 0xff;
    }
    j++;
  }
  return out;
}

/** XOR a buffer with a keystream segment (symmetric). */
export function xorSeg(bytes, k, seed) {
  const stream = ksSeg(k, seed, bytes.length);
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ stream[i];
  return out;
}

/**
 * Fast keyed MAC (4-lane FNV + folds). Mirrors lua/vm.lua `mac()`.
 * Not a replacement for AES-GCM, but it detects tampering cheaply on the
 * client, which is all it is for; transport is already authenticated by TLS.
 */
export function mac(bytes, k) {
  const lanes = [
    (0x811c9dc5 ^ k[0]) >>> 0,
    (0x01000193 ^ k[1]) >>> 0,
    (0x9e3779b9 ^ k[2]) >>> 0,
    (0x85ebca6b ^ k[3]) >>> 0,
  ];
  for (let i = 0; i < bytes.length; i++) {
    const lane = i & 3;
    lanes[lane] = imul(lanes[lane] ^ bytes[i], 0x01000193);
  }
  for (let round = 0; round < 3; round++) {
    for (let i = 0; i < 4; i++) {
      const next = lanes[(i + 1) & 3];
      lanes[i] = imul(lanes[i] ^ rotl32(next, 13), 0x85ebca6b);
    }
  }
  return lanes.map((w) => (w >>> 0).toString(16).padStart(8, "0")).join("");
}

/** Number of leading zero bits in a hex digest. */
export function leadingZeroBits(hex) {
  let bits = 0;
  for (const ch of hex) {
    const nibble = parseInt(ch, 16);
    if (nibble === 0) {
      bits += 4;
      continue;
    }
    bits += Math.clz32(nibble) - 28;
    break;
  }
  return bits;
}
