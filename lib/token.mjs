/**
 * Session tokens + proof-of-work. Everything is derived from HUB_SECRET, so the
 * hub needs no database: the only stateful thing is the optional one-time
 * stage-ticket claim in lib/kv.mjs.
 */
import { createHmac, randomBytes } from "node:crypto";
import { b64u, unb64u, leadingZeroBits, safeEqual, sha256Hex } from "./crypto.mjs";

export const TOKEN_TTL_MS = 180_000;
export const POW_STEP_MS = 120_000;
const configuredBits = Number(process.env.HUB_POW_BITS || 10);
export const POW_BITS =
  Number.isInteger(configuredBits) && configuredBits >= 1 && configuredBits <= 20
    ? configuredBits
    : 10;

export const SCRIPT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
export const NONCE_RE = /^[0-9a-f]{32}$/;

const hmac = (master, data) =>
  createHmac("sha256", master).update(data).digest();

export function signToken(master, claims) {
  const body = b64u(JSON.stringify(claims));
  const sig = b64u(hmac(master, `freehub|tok|${body}`));
  return `${body}.${sig}`;
}

export function openToken(master, token) {
  if (typeof token !== "string" || token.length > 2048) return null;
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!safeEqual(sig, b64u(hmac(master, `freehub|tok|${body}`)))) return null;
  let claims;
  try {
    claims = JSON.parse(unb64u(body).toString("utf8"));
  } catch {
    return null;
  }
  if (!claims || typeof claims !== "object") return null;
  if (typeof claims.exp !== "number" || claims.exp < Date.now()) return null;
  if (typeof claims.sid !== "string" || !SCRIPT_ID_RE.test(claims.sid)) return null;
  return claims;
}

export function issueToken(master, { scriptId, nonce, executor, place }) {
  const now = Date.now();
  const claims = {
    kind: "session",
    sid: scriptId,
    n: nonce,
    e: executor,
    p: place,
    iat: now,
    exp: now + TOKEN_TTL_MS,
  };
  return { token: signToken(master, claims), claims };
}

export const STAGE_TTL_DEFAULT_S = 5;
const STAGE_TTL_MIN_S = 2;
const STAGE_TTL_MAX_S = 120;

/**
 * Ticket lifetime in ms. The legit path fetches the stage immediately after the
 * raw link, so the window only has to cover the HTTP round trip plus the in-VM
 * decode (measured: 30–120 ms). Five seconds covers a cold serverless start and
 * a slow mobile link with room to spare, while still being far too short to copy
 * a stage URL anywhere. Tune with HUB_STAGE_TTL (seconds, 2–120).
 */
export function stageTtlMs() {
  const raw = Number(process.env.HUB_STAGE_TTL);
  const seconds =
    Number.isFinite(raw) && raw > 0
      ? Math.min(STAGE_TTL_MAX_S, Math.max(STAGE_TTL_MIN_S, Math.floor(raw)))
      : STAGE_TTL_DEFAULT_S;
  return seconds * 1000;
}

/**
 * Short-lived ticket for the stage endpoint. It comes from the raw link, so a
 * stage URL copied or scraped from another user goes stale within seconds.
 * Each ticket carries a fresh nonce so the stage endpoint can burn it once.
 */
export function issueStageToken(master, scriptId) {
  const now = Date.now();
  return signToken(master, {
    kind: "stage",
    sid: scriptId,
    n: randomBytes(16).toString("hex"),
    iat: now,
    exp: now + stageTtlMs(),
  });
}

const stepOf = (ms = Date.now()) => Math.floor(ms / POW_STEP_MS);

export function powChallenge(master, scriptId, nonce, step = stepOf()) {
  return hmac(master, `freehub|pow|${scriptId}|${nonce}|${step}`).toString("hex");
}

/**
 * Verify a solved challenge. The current and previous time step are accepted so
 * a client that started solving just before a step boundary is not punished.
 */
export function verifyPow(master, scriptId, nonce, solution, bits = POW_BITS) {
  if (!/^\d{1,10}$/.test(String(solution ?? ""))) return false;
  const now = stepOf();
  for (const step of [now, now - 1]) {
    const challenge = powChallenge(master, scriptId, nonce, step);
    if (leadingZeroBits(sha256Hex(`${challenge}:${solution}`)) >= bits) return true;
  }
  return false;
}
