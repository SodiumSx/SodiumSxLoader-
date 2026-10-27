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
 *
 * One xorshift32 round plus a key XOR per word, three bytes per word. Three is
 * deliberate: a base64url group is four characters for three bytes, so the
 * decoder consumes exactly one word per group and needs no carry state. The
 * previous version cost two 32-bit multiplies per word, which was more than
 * half of the whole client-side decode time.
 *
 * @param {number[]} k four key words
 * @param {number} seed segment index
 * @param {number} length bytes needed
 */
export function ksSeg(k, seed, length) {
  const out = Buffer.alloc(length);
  let t = ((imul(seed + 1, 0x9e3779b1) + k[0]) >>> 0) ^ k[1];
  t >>>= 0;
  let p = 0;
  while (p < length) {
    t = (t ^ (t << 13)) >>> 0;
    t = (t ^ (t >>> 17)) >>> 0;
    t = (t ^ (t << 5)) >>> 0;
    t = (t ^ k[2]) >>> 0;
    out[p++] = t & 0xff;
    if (p < length) out[p++] = (t >>> 8) & 0xff;
    if (p < length) out[p++] = (t >>> 16) & 0xff;
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
 * Fast keyed MAC: four polynomial lanes over every byte, folded twice.
 * Mirrors lua/vm.lua `vm_mac()`.
 *
 * 65599 * (2^32-1) stays below 2^53, so a plain double multiply plus `% 2^32`
 * gives exactly the same result in JavaScript and in Lua, and it needs one
 * multiply per byte instead of the FNV round's multiply-xor chain. Not a
 * replacement for AES-GCM: it detects tampering cheaply on the client, which is
 * all it is for; transport is already authenticated by TLS.
 */
export function mac(bytes, k) {
  const len = bytes.length;
  let h0 = (0x811c9dc5 ^ k[0]) >>> 0;
  let h1 = (0x01000193 ^ k[1]) >>> 0;
  let h2 = (0x9e3779b9 ^ k[2]) >>> 0;
  let h3 = (0x85ebca6b ^ k[3]) >>> 0;
  const full = len - (len & 3);
  let i = 0;
  while (i < full) {
    h0 = (h0 * 65599 + bytes[i]) % 0x100000000;
    h1 = (h1 * 65599 + bytes[i + 1]) % 0x100000000;
    h2 = (h2 * 65599 + bytes[i + 2]) % 0x100000000;
    h3 = (h3 * 65599 + bytes[i + 3]) % 0x100000000;
    i += 4;
  }
  while (i < len) {
    const lane = i & 3;
    const add = bytes[i];
    if (lane === 0) h0 = (h0 * 65599 + add) % 0x100000000;
    else if (lane === 1) h1 = (h1 * 65599 + add) % 0x100000000;
    else if (lane === 2) h2 = (h2 * 65599 + add) % 0x100000000;
    else h3 = (h3 * 65599 + add) % 0x100000000;
    i += 1;
  }
  h3 = (h3 + len) % 0x100000000;
  for (let round = 0; round < 2; round++) {
    const t0 = h0;
    const t1 = h1;
    const t2 = h2;
    const t3 = h3;
    h0 = (h0 * 65599 + t1) % 0x100000000;
    h1 = (h1 * 65599 + t2) % 0x100000000;
    h2 = (h2 * 65599 + t3) % 0x100000000;
    h3 = (h3 * 65599 + t0) % 0x100000000;
  }
  return [h0, h1, h2, h3].map((w) => (w >>> 0).toString(16).padStart(8, "0")).join("");
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
