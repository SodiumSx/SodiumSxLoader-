import { BUILD, publicScripts } from "../lib/data.mjs";
import { publicBaseUrl, sendJson } from "../lib/http.mjs";

export default function handler(req, res) {
  const base = publicBaseUrl(req);
  const scripts = publicScripts().map((script) => ({
    ...script,
    raw: `${base}/api/r/${script.id}`,
  }));
  return sendJson(
    res,
    { build: BUILD, scripts },
    { cache: "public, max-age=60, s-maxage=300", extra: { "Access-Control-Allow-Origin": "*" } },
  );
}
