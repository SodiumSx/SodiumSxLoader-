import { findScript } from "../lib/data.mjs";
import { queryOf, readJson, sendText, fail } from "../lib/http.mjs";
import { masterSecret } from "../lib/secret.mjs";
import { keyWordsToHex, sessionKeyWords } from "../lib/crypto.mjs";
import { botLike, cleanExecutor, cleanPlace } from "../lib/policy.mjs";
import { NONCE_RE, SCRIPT_ID_RE, issueToken, verifyPow } from "../lib/token.mjs";

/**
 * Anti-bot gate, step 2. The response carries:
 *   t = short-lived HMAC token bound to script id + nonce + executor + place
 *   k = 16-byte key derived from HUB_SECRET, the script and the nonce
 *   x = expiry (seconds)
 * Nothing here is reusable: a new nonce produces a new key, and the payload
 * program is only valid with the matching key.
 */
export default async function handler(req, res) {
  if (req.method !== "GET" && req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return fail(res, 405, "method not allowed");
  }

  const query = queryOf(req);
  const input = {
    id: query.get("id") || "",
    n: (query.get("n") || "").toLowerCase(),
    w: query.get("w") || "",
    e: query.get("e") || "",
    p: query.get("p") || "",
  };

  if (req.method === "POST") {
    const body = await readJson(req);
    if (!body) return fail(res, 400, "invalid body");
    for (const key of ["id", "n", "w", "e", "p"]) {
      if (body[key] !== undefined) input[key] = String(body[key]);
    }
  }

  if (!SCRIPT_ID_RE.test(input.id) || !NONCE_RE.test(input.n)) return fail(res, 400, "bad request");
  if (!findScript(input.id)) return fail(res, 404, "unknown script");

  const executor = cleanExecutor(input.e);
  const place = cleanPlace(input.p);
  if (!executor || place === null) return fail(res, 400, "bad fingerprint");
  if (botLike(executor)) return fail(res, 403, "unsupported client");

  let secret;
  try {
    secret = masterSecret();
  } catch (error) {
    return fail(res, 500, error.message);
  }

  if (!verifyPow(secret, input.id, input.n, input.w)) return fail(res, 403, "pow");

  const words = sessionKeyWords(secret, input.id, input.n);
  const { token, claims } = issueToken(secret, {
    scriptId: input.id,
    nonce: input.n,
    executor,
    place,
  });

  return sendText(
    res,
    `t=${token}\nk=${keyWordsToHex(words)}\nx=${Math.floor(claims.exp / 1000)}\n`,
    { extra: { "Access-Control-Allow-Origin": "*" } },
  );
}
