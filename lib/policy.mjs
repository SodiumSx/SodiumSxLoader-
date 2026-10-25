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
