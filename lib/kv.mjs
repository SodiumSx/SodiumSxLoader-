/**
 * One-time ticket store.
 *
 * A stage ticket carries a random nonce, and the stage endpoint claims it with
 * `SET key 1 NX EX ttl`: Redis applies that atomically, so exactly one request
 * can spend a ticket. Replays — a captured stage URL pasted into another
 * executor, a proxy cache, a friend — get 403 even inside the 20s window.
 *
 * Vercel KV was sunset in December 2024 and migrated to Upstash, which is why
 * this speaks the Upstash REST protocol directly: one HTTP POST per load, no
 * SDK, no persistent socket, nothing to keep alive between invocations.
 *
 *   UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN   (Upstash console)
 *   KV_REST_API_URL        / KV_REST_API_TOKEN          (Vercel Marketplace)
 *
 * No store configured: dev and tests use an in-process map (the dev server is a
 * single process, so that is correct there) and Vercel falls back to the TTL
 * alone. A store that errors also falls back to the TTL, so a Redis outage can
 * never take the loader down — it only loses the single-use guarantee.
 */
const MEMORY = new Map();
const MEMORY_MAX = 2000;
let warned = false;

/** Configured store, or null. Read per call so tests can flip env vars. */
export function kvStore() {
  const url = (process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL || "")
    .trim()
    .replace(/\/+$/, "");
  const token = (process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || "").trim();
  if (!/^https?:\/\//i.test(url) || !token) return null;
  return { url, token };
}

function noteOnce(reason) {
  if (warned) return;
  warned = true;
  console.warn(`[FreeHub] one-time stage tickets off (${reason}); links fall back to the TTL only`);
}

function memoryClaim(key, ttlSeconds) {
  const now = Date.now();
  if (MEMORY.size >= MEMORY_MAX) {
    for (const [k, exp] of MEMORY) if (exp <= now) MEMORY.delete(k);
    if (MEMORY.size >= MEMORY_MAX) MEMORY.clear();
  }
  const exp = MEMORY.get(key);
  if (exp && exp > now) return "used";
  MEMORY.set(key, now + ttlSeconds * 1000);
  return "first";
}

/**
 * Claim `key` for one use.
 * @returns {"first"|"used"|"unavailable"} "first" means this call owns it,
 *   "used" means somebody already spent it, "unavailable" means no store.
 */
export async function consumeOnce(key, ttlSeconds, { timeoutMs = 1500 } = {}) {
  const ttl = Math.min(3600, Math.max(1, Math.ceil(Number(ttlSeconds) || 1)));
  const remote = kvStore();
  if (!remote) {
    if (process.env.VERCEL) {
      noteOnce("no store configured");
      return "unavailable";
    }
    return memoryClaim(key, ttl);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Command-array form: exactly what `SET key 1 NX EX ttl` means in redis-cli,
    // so the NX decision is made inside Redis in one round trip.
    const response = await fetch(remote.url, {
      method: "POST",
      headers: { Authorization: `Bearer ${remote.token}` },
      body: JSON.stringify(["SET", key, "1", "NX", "EX", String(ttl)]),
      signal: controller.signal,
    });
    if (!response.ok) {
      noteOnce(`store replied ${response.status}`);
      return "unavailable";
    }
    const payload = await response.json().catch(() => null);
    const result = payload ? payload.result : null;
    if (result === "OK") return "first";
    if (result === null) return "used";
    noteOnce("unexpected store reply");
    return "unavailable";
  } catch (error) {
    noteOnce(error && error.name === "AbortError" ? "store timeout" : "store unreachable");
    return "unavailable";
  } finally {
    clearTimeout(timer);
  }
}
