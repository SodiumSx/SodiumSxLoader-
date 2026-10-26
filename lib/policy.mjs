/** Request policy shared by session + payload endpoints. */

export const BOT_MARKERS = [
  "curl",
  "wget",
  "python",
  "httpie",
  "postman",
  "insomnia",
  "browser",
  "axios",
  "node.js",
  "go-http-client",
];

/**
 * User-Agent fragments that only automated tooling sends. Executors inherit
 * Roblox's own agent (`Roblox/WinInet`, `RobloxStudio/WinInet`), so anything
 * from this list is a scraper, a deobfuscation service or a fetch library.
 */
export const SCRAPER_MARKERS = [
  "curl",
  "wget",
  "python",
  "aiohttp",
  "httpx",
  "urllib",
  "httpie",
  "postman",
  "insomnia",
  "axios",
  "node-fetch",
  "node",
  "undici",
  "bun/",
  "deno/",
  "go-http-client",
  "okhttp",
  "libwww",
  "lwp-",
  "java/",
  "php/",
  "scrapy",
  "mechanize",
  "phantomjs",
  "puppeteer",
  "scraper",
  "crawler",
  "spider",
  "headlesschrome",
  "webdriver",
];

export function scraperLike(userAgent) {
  const ua = String(userAgent || "").toLowerCase();
  if (!ua) return false; // executors may send no agent at all
  return SCRAPER_MARKERS.some((marker) => ua.includes(marker));
}

export function cleanExecutor(value) {
  if (typeof value !== "string") return "";
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 48);
  return clean;
}

export function botLike(executor) {
  const name = String(executor || "").toLowerCase();
  if (!name) return true;
  return BOT_MARKERS.some((marker) => name.includes(marker));
}

export function cleanPlace(value) {
  const raw = String(value ?? "").trim();
  if (!/^\d{1,20}$/.test(raw)) return null;
  const place = Number(raw);
  return Number.isSafeInteger(place) && place >= 0 ? place : null;
}
