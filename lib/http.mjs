/** HTTP helpers for Vercel Node functions (also used by tools/dev.mjs). */

const MAX_BODY = 64 * 1024;

export function requestUrl(req) {
  const host = req.headers.host || "localhost:3000";
  return new URL(req.url || "/", `http://${host}`);
}

export function queryOf(req) {
  return requestUrl(req).searchParams;
}

/** Dynamic route parameter, e.g. `[id]` — works on Vercel and in tools/dev.mjs. */
export function param(req, name = "id") {
  const direct = req.query && req.query[name];
  if (typeof direct === "string" && direct.length) return direct;
  const parts = requestUrl(req).pathname.split("/").filter(Boolean);
  try {
    return decodeURIComponent(parts[parts.length - 1] || "");
  } catch {
    return "";
  }
}

function sanitizeHost(host) {
  return String(host || "")
    .toLowerCase()
    .replace(/[^a-z0-9.\-:]/g, "")
    .replace(/^[:.]+/, "");
}

/**
 * Public base URL used inside generated Lua. Defaults to the request host so
 * preview deployments work, but an explicit env value wins and an allowlist
 * prevents host-header poisoning.
 */
export function publicBaseUrl(req) {
  const configured = (process.env.HUB_PUBLIC_URL || "").trim().replace(/\/+$/, "");
  if (configured) return configured;
  const host = sanitizeHost(req.headers.host);
  const allow = (process.env.HUB_ALLOWED_HOSTS || "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  let safeHost = host || "localhost:3000";
  if (allow.length && !allow.includes(safeHost)) safeHost = allow[0];
  let proto = String(req.headers["x-forwarded-proto"] || "https").split(",")[0].trim().toLowerCase();
  if (proto !== "http" && proto !== "https") proto = "https";
  return `${proto}://${safeHost}`;
}

export async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function readJson(req) {
  try {
    const raw = await readBody(req);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return null;
  }
}

export function setCommon(res, { type = "text/plain; charset=utf-8", status = 200, cache = "no-store", extra = {} } = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", type);
  res.setHeader("Cache-Control", cache);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
}

export function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader("Location", location);
  res.setHeader("Cache-Control", "no-store");
  res.end();
  return true;
}

export function sendText(res, body, opts = {}) {
  setCommon(res, opts);
  res.end(body);
  return true;
}

export function sendJson(res, obj, opts = {}) {
  setCommon(res, { ...opts, type: "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
  return true;
}

export function fail(res, status, message = "request rejected") {
  return sendJson(res, { error: message }, { status });
}
