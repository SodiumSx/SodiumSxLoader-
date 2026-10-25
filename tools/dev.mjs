#!/usr/bin/env node
/**
 * Local dev server that routes like Vercel does (api/**\/*.js as Node functions)
 * and serves public/ statically. Used by `npm run dev` and the test suite.
 */
import http from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const publicDir = join(root, "public");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

const ROUTES = [
  { pattern: /^\/api\/r\/([^/]+)\/?$/, module: "api/r/[id].js", param: "id" },
  { pattern: /^\/api\/stage\/([^/]+)\/?$/, module: "api/stage/[id].js", param: "id" },
  { pattern: /^\/api\/payload\/([^/]+)\/?$/, module: "api/payload/[id].js", param: "id" },
  { pattern: /^\/api\/challenge\/?$/, module: "api/challenge.js" },
  { pattern: /^\/api\/session\/?$/, module: "api/session.js" },
  { pattern: /^\/api\/hub\/?$/, module: "api/hub.js" },
];

export function createServer() {
  return http.createServer(async (req, res) => {
    // Vercel always sets these; the fake keeps local URLs http://127.0.0.1:PORT.
    req.headers["x-forwarded-proto"] ||= "http";
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

    try {
      for (const route of ROUTES) {
        const match = route.pattern.exec(url.pathname);
        if (!match) continue;
        req.query = {};
        if (route.param) req.query[route.param] = decodeURIComponent(match[1]);
        const mod = await import(new URL(`../${route.module}`, import.meta.url).href);
        await mod.default(req, res);
        return;
      }

      if (url.pathname.startsWith("/api/")) {
        res.statusCode = 404;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify({ error: "not found" }));
        return;
      }

      const relative = url.pathname === "/" ? "index.html" : url.pathname.replace(/^\/+/, "");
      const filePath = normalize(join(publicDir, relative));
      if (!filePath.startsWith(publicDir)) {
        res.statusCode = 403;
        res.end("forbidden");
        return;
      }
      const body = await readFile(filePath);
      res.statusCode = 200;
      res.setHeader("Content-Type", MIME[extname(filePath)] || "application/octet-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.end(body);
    } catch (error) {
      if (error.code === "ENOENT") {
        res.statusCode = 404;
        res.end("not found");
        return;
      }
      console.error("[dev]", error);
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: error.message }));
    }
  });
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const preferred = Number(process.env.PORT || 3000);
  const server = createServer();
  const listen = (port) =>
    new Promise((resolveListen, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", () => {
        server.removeListener("error", reject);
        resolveListen();
      });
    });

  let port = preferred;
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      await listen(port);
      break;
    } catch (error) {
      if (error.code !== "EADDRINUSE") throw error;
      console.log(`port ${port} busy, trying ${port + 1}`);
      port += 1;
    }
  }

  const actual = server.address().port;
  console.log(`FreeHub dev server → http://127.0.0.1:${actual}`);
  console.log(`raw link example    → http://127.0.0.1:${actual}/api/r/example`);
}
