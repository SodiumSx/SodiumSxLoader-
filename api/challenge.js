import { findScript } from "../lib/data.mjs";
import { queryOf, sendText, fail } from "../lib/http.mjs";
import { masterSecret } from "../lib/secret.mjs";
import { NONCE_RE, POW_BITS, SCRIPT_ID_RE, powChallenge } from "../lib/token.mjs";

/**
 * Anti-bot gate, step 1: hand out a stateless challenge. Solving it costs CPU
 * per request, which makes mass scraping of the payload endpoint expensive.
 */
export default function handler(req, res) {
  const query = queryOf(req);
  const id = query.get("id") || "";
  const nonce = (query.get("n") || "").toLowerCase();

  if (!SCRIPT_ID_RE.test(id) || !NONCE_RE.test(nonce)) return fail(res, 400, "bad request");
  if (!findScript(id)) return fail(res, 404, "unknown script");

  let secret;
  try {
    secret = masterSecret();
  } catch (error) {
    return fail(res, 500, error.message);
  }

  const challenge = powChallenge(secret, id, nonce);
  return sendText(res, `c=${challenge}&d=${POW_BITS}`, {
    extra: { "Access-Control-Allow-Origin": "*" },
  });
}
