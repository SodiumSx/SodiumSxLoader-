/**
 * HUB_SECRET signs session tokens, derives payload keys and salts the
 * proof-of-work challenge. It must never reach the client or the repo.
 */
const DEV_SECRET = "freehub-dev-only-secret-please-change-me";

export function masterSecret() {
  const secret = (process.env.HUB_SECRET || "").trim();
  if (secret.length >= 24) return secret;
  const production = process.env.VERCEL || process.env.NODE_ENV === "production";
  if (production) {
    throw new Error("HUB_SECRET is missing or shorter than 24 characters");
  }
  return DEV_SECRET;
}

export function isDevSecret() {
  const secret = (process.env.HUB_SECRET || "").trim();
  return secret.length < 24;
}
