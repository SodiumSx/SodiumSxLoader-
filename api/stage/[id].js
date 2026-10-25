import { findScript } from "../../lib/data.mjs";
import { fail, param, publicBaseUrl, queryOf, sendText } from "../../lib/http.mjs";
import { masterSecret } from "../../lib/secret.mjs";
import { renderStage } from "../../lib/stage.mjs";
import { openToken } from "../../lib/token.mjs";

/**
 * Layer 1: the loader core, VM-compiled and re-randomized on every request.
 * Requires the short-lived ticket from the raw link, so hotlinking a stage URL
 * from another hub or a scraper cache fails after two minutes.
 */
export default function handler(req, res) {
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
