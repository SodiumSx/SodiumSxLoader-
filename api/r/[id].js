import { findScript } from "../../lib/data.mjs";
import { isBrowserRequest, param, publicBaseUrl, sendBlackout, sendText } from "../../lib/http.mjs";
import { scraperLike } from "../../lib/policy.mjs";
import { masterSecret } from "../../lib/secret.mjs";
import { renderRawStub } from "../../lib/stub.mjs";
import { issueStageToken } from "../../lib/token.mjs";

/**
 * The raw link. It must never show hub source, and it must not hand a readable
 * `loadstring(game:HttpGet(...))` line to anyone: executors get a VM-packed stub
 * that decodes the stage URL at runtime, everything else gets a black page.
 *
 * Rejected before any token is minted:
 *   - browsers (a person opening the link in a tab)
 *   - scraper UAs (curl, wget, python, node, axios, okhttp, headless…)
 *
 * The ticket inside the stub keeps a stolen stage URL usable for ~5 seconds.
 */
export default function handler(req, res) {
  if (isBrowserRequest(req)) return sendBlackout(res);
  if (scraperLike(req.headers["user-agent"])) return sendBlackout(res, { status: 403 });

  const id = param(req);
  const script = findScript(id);
  if (!script) {
    return sendText(res, 'warn("[FreeHub] unknown script")\n', { status: 404 });
  }

  let ticket;
  try {
    ticket = issueStageToken(masterSecret(), script.id);
  } catch (error) {
    return sendText(res, `warn("[FreeHub] ${error.message}")\n`, { status: 500 });
  }

  let stub;
  try {
    stub = renderRawStub({ host: publicBaseUrl(req), scriptId: script.id, ticket });
  } catch (error) {
    return sendText(res, `warn("[FreeHub] ${error.message}")\n`, { status: 500 });
  }

  return sendText(res, stub, {
    type: "text/plain; charset=utf-8",
    cache: "no-store",
    extra: { "X-Robots-Tag": "noindex, nofollow", Vary: "User-Agent, Accept" },
  });
}
