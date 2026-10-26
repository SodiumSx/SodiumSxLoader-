import { findScript } from "../../lib/data.mjs";
import { fail, param, publicBaseUrl, queryOf, sendText } from "../../lib/http.mjs";
import { consumeOnce } from "../../lib/kv.mjs";
import { masterSecret } from "../../lib/secret.mjs";
import { renderStage } from "../../lib/stage.mjs";
import { openToken } from "../../lib/token.mjs";

/**
 * Layer 1: the loader core, VM-compiled and re-randomized on every request.
 * Requires the short-lived ticket from the raw link, so hotlinking a stage URL
 * from another hub or a scraper cache fails after ~5 seconds.
 *
 * A ticket is also single-use: its nonce is claimed with an atomic SET NX, so a
 * stage URL captured in transit is dead as soon as it has been served once. If
 * the claim store is missing or down the endpoint keeps working with the TTL
 * alone rather than failing closed — a Redis outage must not take the loader
 * offline.
 */
export default async function handler(req, res) {
  const id = param(req);
  const script = findScript(id);
  if (!script) return fail(res, 404, "unknown script");

  let secret;
  try {
    secret = masterSecret();
  } catch (error) {
    return fail(res, 500, error.message);
  }

  const ticket = queryOf(req).get("s") || "";
  const claims = openToken(secret, ticket);
  if (!claims || claims.kind !== "stage" || claims.sid !== id) {
    return fail(res, 403, "invalid or expired link");
  }

  // Tickets minted before this deploy carry no nonce; they keep the TTL-only
  // behaviour and are already seconds from expiring.
  if (typeof claims.n === "string" && claims.n.length) {
    const ttl = Math.ceil((claims.exp - Date.now()) / 1000);
    const claim = await consumeOnce(`freehub:stage:${claims.sid}:${claims.n}`, ttl);
    if (claim === "used") return fail(res, 403, "link already used");
  }

  try {
    const { code } = renderStage({ host: publicBaseUrl(req), scriptId: script.id });
    return sendText(res, code, {
      type: "text/plain; charset=utf-8",
      extra: { "X-Robots-Tag": "noindex, nofollow" },
    });
  } catch (error) {
    return fail(res, 500, error.message);
  }
}
