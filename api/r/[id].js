import { findScript } from "../../lib/data.mjs";
import { isBrowserRequest, param, publicBaseUrl, sendBlackout, sendText } from "../../lib/http.mjs";
import { masterSecret } from "../../lib/secret.mjs";
import { issueStageToken } from "../../lib/token.mjs";

/**
 * The raw link. It must never show hub source: only the one-line bootstrap.
 *   loadstring(game:HttpGet("https://host/api/stage/<id>?s=<ticket>"))()
 * The ticket keeps a stolen stage URL usable for two minutes only.
 *
 * A browser page visit gets a black screen instead: the bootstrap line is for
 * executors (Roblox/WinInet), not for people reading the link in a tab.
 */
export default function handler(req, res) {
  if (isBrowserRequest(req)) return sendBlackout(res);

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

  const base = publicBaseUrl(req);
  const line = `loadstring(game:HttpGet("${base}/api/stage/${script.id}?s=${ticket}"))()\n`;
  return sendText(res, line, {
    cache: "no-store",
    extra: { "X-Robots-Tag": "noindex, nofollow", Vary: "User-Agent, Accept" },
  });
}
