import { findScript, BUILD } from "../../lib/data.mjs";
import { fail, param, queryOf, sendText } from "../../lib/http.mjs";
import { masterSecret } from "../../lib/secret.mjs";
import { mac, sessionKeyWords } from "../../lib/crypto.mjs";
import { botLike } from "../../lib/policy.mjs";
import { openToken } from "../../lib/token.mjs";
import { compileVm } from "../../lib/vm.mjs";

/**
 * Layer 2: per-session payload program.
 *
 * The payload bytes are re-chunked, re-registered and re-encrypted with the
 * session key on every request. The response is `header\n\nprogram`, where the
 * header carries the keyed tamper tag and the plaintext length.
 */
export default function handler(req, res) {
  const id = param(req);
  const script = findScript(id);
  if (!script) return fail(res, 404, "unknown script");

  const token = queryOf(req).get("t") || "";
  let secret;
  try {
    secret = masterSecret();
  } catch (error) {
    return fail(res, 500, error.message);
  }

  const claims = openToken(secret, token);
  if (!claims || claims.kind !== "session" || claims.sid !== id) {
    return fail(res, 401, "invalid session");
  }
  if (botLike(claims.e)) return fail(res, 403, "unsupported client");

  const words = sessionKeyWords(secret, id, claims.n);
  const { program } = compileVm(script.code, { keyWords: words });
  const tag = mac(Buffer.from(script.code, "utf8"), words);
  const length = Buffer.byteLength(script.code, "utf8");

  return sendText(res, `m=${tag}&z=${length}&b=${BUILD.version}\n\n${program}`, {
    extra: { "X-Robots-Tag": "noindex, nofollow" },
  });
}
