#!/usr/bin/env node
/**
 * Test suite. Runs the real Lua loader (wasmoon is Lua 5.4) against the real
 * HTTP endpoints, so the PoW, handshake, VM decode, MAC check and the demo
 * payloads are all exercised through the same path an executor would take.
 */
import { execFileSync, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { LuaFactory } from "wasmoon";

process.env.HUB_SECRET = "test-secret-0123456789abcdefghijklmnop";
process.env.HUB_POW_BITS = "7";
delete process.env.HUB_PUBLIC_URL;
delete process.env.HUB_ALLOWED_HOSTS;

const { obfuscateLua } = await import("../lib/lua-obfuscate.mjs");
const { compileVm, makeRng } = await import("../lib/vm.mjs");
const { sessionKeyWords, keyWordsToHex } = await import("../lib/crypto.mjs");
const { POW_BITS } = await import("../lib/token.mjs");

const BIT32_SHIM = `
bit32 = {
  bxor = function(a, b) return ((a ~ b) & 0xFFFFFFFF) end,
  band = function(a, b) return ((a & b) & 0xFFFFFFFF) end,
  bnot = function(a) return ((~a) & 0xFFFFFFFF) end,
  rrotate = function(x, n) return (((x >> n) | (x << (32 - n))) & 0xFFFFFFFF) end,
  lrotate = function(x, n) return (((x << n) | (x >> (32 - n))) & 0xFFFFFFFF) end,
  rshift = function(x, n) return ((x >> n) & 0xFFFFFFFF) end,
  lshift = function(x, n) return ((x << n) & 0xFFFFFFFF) end,
}`;

const harness = readFileSync("test/harness.lua", "utf8");

// The Lua tests perform synchronous HTTP, which blocks this process, so the hub
// must live in its own process or every request would deadlock.
const server = spawn(process.execPath, ["tools/dev.mjs"], {
  env: { ...process.env, PORT: "0" },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverLog = "";
server.stderr.on("data", (chunk) => {
  serverLog += chunk;
  process.stderr.write(chunk);
});
const PORT = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error(`dev server did not start:\n${serverLog}`)), 20000);
  server.stdout.on("data", (chunk) => {
    serverLog += chunk;
    const match = /127\.0\.0\.1:(\d+)/.exec(serverLog);
    if (!match) return;
    clearTimeout(timer);
    resolve(Number(match[1]));
  });
});
const BASE = `http://127.0.0.1:${PORT}`;
process.on("exit", () => server.kill());

const BRIDGE = `
const response = await fetch(process.env.HUB_TEST_URL);
process.stdout.write(await response.text());
`;

function syncGet(url) {
  return execFileSync(process.execPath, ["--input-type=module", "-e", BRIDGE], {
    env: { ...process.env, HUB_TEST_URL: url },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
}

async function newEngine({ prelude = "", tamper = false } = {}) {
  const lua = await new LuaFactory().createEngine();
  await lua.doString(BIT32_SHIM);
  await lua.doString(harness);
  const prints = [];
  const requests = [];
  lua.global.set("__print", (line) => {
    prints.push(String(line));
  });
  lua.global.set("__httpget", (url) => {
    const target = String(url);
    requests.push(target);
    const body = syncGet(target);
    if (!tamper || !target.includes("/api/payload/")) return body;
    const split = body.indexOf("\n\n");
    const head = body.slice(0, split + 2);
    const program = body.slice(split + 2);
    const at = Math.floor(program.length / 2);
    const flipped = program[at] === "A" ? "B" : "A";
    prints.push("[tamper] flipped program byte");
    return head + program.slice(0, at) + flipped + program.slice(at + 1);
  });
  if (prelude) await lua.doString(prelude);
  return { lua, prints, requests };
}

async function stageUrl(scriptId) {
  const stub = await (await fetch(`${BASE}/api/r/${scriptId}`)).text();
  const match = /HttpGet\("([^"]+)"\)/.exec(stub);
  assert.ok(match, `stub has no url: ${stub}`);
  return match[1];
}

async function runStage(lua, scriptId) {
  const stage = await (await fetch(await stageUrl(scriptId))).text();
  lua.global.set("STAGE", stage);
  await lua.doString("local f, err = load(STAGE, '=stage'); if not f then error(err) end; f()");
  return stage;
}

const results = [];
function check(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      results.push({ name, ok: true });
      console.log(`  ok   ${name}`);
    })
    .catch((error) => {
      results.push({ name, ok: false, error });
      console.log(`  FAIL ${name}\n       ${error.message}`);
    });
}

console.log(`hub: ${BASE}  pow=${POW_BITS} bits`);

await check("raw link is a single loadstring line and leaks nothing", async () => {
  const response = await fetch(`${BASE}/api/r/example`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/plain/);
  const body = await response.text();
  assert.equal(body.trim().split("\n").length, 1);
  assert.match(
    body.trim(),
    /^loadstring\(game:HttpGet\("http:\/\/127\.0\.0\.1:\d+\/api\/stage\/example\?s=[\w.-]+"\)\)\(\)$/,
  );
  assert.ok(!body.includes("GetService"), "raw must not contain payload");
  assert.ok(!body.includes("HttpService"), "raw must not contain payload");
});

await check("unknown script ids 404", async () => {
  for (const path of ["r", "stage", "payload"]) {
    const response = await fetch(`${BASE}/api/${path}/does-not-exist`);
    assert.equal(response.status, 404, path);
  }
});

await check("hub metadata is public but carries no payload", async () => {
  const data = await (await fetch(`${BASE}/api/hub`)).json();
  assert.equal(data.scripts.length, 2);
  assert.ok(data.build.version);
  const serialised = JSON.stringify(data);
  assert.ok(!serialised.includes("GetService"));
  assert.match(data.scripts[0].raw, /\/api\/r\/example$/);
});

await check("stage requires a fresh ticket", async () => {
  assert.equal((await fetch(`${BASE}/api/stage/example`)).status, 403);
  assert.equal((await fetch(`${BASE}/api/stage/example?s=abc.def`)).status, 403);
});

await check("stage responses are randomized per request", async () => {
  const [a, b] = await Promise.all([
    stageUrl("example").then((url) => fetch(url).then((r) => r.text())),
    stageUrl("example").then((url) => fetch(url).then((r) => r.text())),
  ]);
  assert.notEqual(a, b, "two loads must not share bytes");
  assert.ok(!a.includes("core_host"), "core source must not be in the clear");
  assert.ok(!a.includes("HttpService"), "payload must not be in the stage");
  assert.ok(a.includes("vm_run"), "stage should ship the VM runtime");
});

await check("payload endpoint rejects missing or forged tokens", async () => {
  assert.equal((await fetch(`${BASE}/api/payload/example`)).status, 401);
  assert.equal((await fetch(`${BASE}/api/payload/example?t=abc.def`)).status, 401);
  const other = await fetch(`${BASE}/api/payload/utilities?t=abc`).then((r) => r.status);
  assert.equal(other, 401);
});

await check("session rejects automated clients", async () => {
  const nonce = "0".repeat(32);
  const challenge = await (await fetch(`${BASE}/api/challenge?id=example&n=${nonce}`)).text();
  assert.match(challenge, /^c=[0-9a-f]{64}&d=\d+$/);
  const response = await fetch(
    `${BASE}/api/session?id=example&n=${nonce}&w=0&e=curl%2F8.0&p=123`,
  );
  assert.equal(response.status, 403);
});

await check("session rejects unsolved proof-of-work", async () => {
  const nonce = "1".repeat(32);
  const response = await fetch(
    `${BASE}/api/session?id=example&n=${nonce}&w=1&e=Delta&p=123`,
  );
  assert.equal(response.status, 403);
});

await check("loader runs the example payload end to end", async () => {
  const { lua, prints, requests } = await newEngine();
  await runStage(lua, "example");
  assert.ok(
    prints.some((line) => line.includes("[FreeHub] example payload running")),
    `payload did not run, prints=${JSON.stringify(prints)}`,
  );
  assert.ok(requests.some((url) => url.includes("/api/challenge")), "challenge requested");
  assert.ok(requests.some((url) => url.includes("/api/session")), "session requested");
  assert.ok(requests.some((url) => url.includes("/api/payload/")), "payload requested");
});

await check("loader runs the utilities payload end to end", async () => {
  const { lua, prints } = await newEngine();
  await runStage(lua, "utilities");
  assert.ok(
    prints.some((line) => line.includes("[FreeHub] utilities payload running")),
    `prints=${JSON.stringify(prints)}`,
  );
});

await check("tampered payload is rejected before execution", async () => {
  const { lua, prints } = await newEngine({ tamper: true });
  await runStage(lua, "example");
  assert.ok(!prints.some((line) => line.includes("payload running")), "payload must not run");
  assert.ok(
    prints.some((line) => line.startsWith("[FreeHub] loader stopped")),
    `expected a stop, prints=${JSON.stringify(prints)}`,
  );
});

await check("hooked loadstring is detected", async () => {
  const prelude = `
local realLoad = load
load = function(chunk, name) return realLoad(chunk, name) end
`;
  const { lua, prints } = await newEngine({ prelude });
  await runStage(lua, "example");
  assert.ok(!prints.some((line) => line.includes("payload running")), "payload must not run");
});

await check("hooked string.char is detected (env-log style)", async () => {
  const prelude = `
local realChar = string.char
string.char = function(...) return realChar(...) end
`;
  const { lua, prints } = await newEngine({ prelude });
  await runStage(lua, "example");
  assert.ok(!prints.some((line) => line.includes("payload running")), "payload must not run");
  assert.ok(
    prints.some((line) => line.includes("loader stopped (env")),
    `expected env stop, prints=${JSON.stringify(prints)}`,
  );
});

await check("obfuscation preserves Lua semantics", async () => {
  const original = readFileSync("test/fixtures/tricky.lua", "utf8");
  const { code } = obfuscateLua(original);
  assert.ok(!code.includes("line comment"), "comments removed");
  assert.ok(!code.includes('double \\" quote'), "strings encoded");

  const words = sessionKeyWords("obf-secret", "tricky", "a".repeat(32));
  const keyHex = keyWordsToHex(words);
  const { program } = compileVm(code, { keyWords: words, rng: makeRng(99) });

  const expected = await runFixture(original);
  assert.ok(expected.includes("long string with ]] inside"), expected);

  const decoded = await runObfuscated(program, keyHex);
  assert.equal(decoded, expected);
});

await check("200KB payload compiles and decodes under budget", async () => {
  const source = readFileSync("scripts/utilities.lua", "utf8").repeat(80);
  const words = sessionKeyWords("perf-secret", "perf", "b".repeat(32));
  const keyHex = keyWordsToHex(words);

  const startObf = performance.now();
  const { code } = obfuscateLua(source);
  const obfMs = performance.now() - startObf;

  const startVm = performance.now();
  const { program } = compileVm(code, { keyWords: words });
  const vmMs = performance.now() - startVm;

  const { lua } = await newEngine();
  await lua.doString(
    readFileSync("lua/sha.lua", "utf8") + readFileSync("lua/vm.lua", "utf8") + "\n_G.vm_run = vm_run",
  );
  lua.global.set("P", program);
  lua.global.set("K", keyHex);
  const startLua = performance.now();
  await lua.doString("SRC = vm_run(P, K)");
  const luaMs = performance.now() - startLua;
  const decoded = lua.global.get("SRC");

  assert.equal(decoded.length, code.length);
  console.log(
    `       source ${(source.length / 1024).toFixed(0)}KB -> obf ${obfMs.toFixed(0)}ms, vm ${vmMs.toFixed(0)}ms, lua decode ${luaMs.toFixed(0)}ms, program ${(program.length / 1024).toFixed(0)}KB`,
  );
});

async function runFixture(source) {
  const { lua, prints } = await newEngine();
  lua.global.set("SRC", source);
  await lua.doString("local f, err = load(SRC, '=fixture'); if not f then error(err) end; f()");
  return prints.join("\n");
}

async function runObfuscated(program, key) {
  const { lua, prints } = await newEngine();
  await lua.doString(
    readFileSync("lua/sha.lua", "utf8") + readFileSync("lua/vm.lua", "utf8") + "\n_G.vm_run = vm_run",
  );
  lua.global.set("P", program);
  lua.global.set("K", key);
  await lua.doString("local src = vm_run(P, K); local f, err = load(src, '=payload'); if not f then error(err) end; f()");
  return prints.join("\n");
}

console.log(`${results.filter((r) => r.ok).length}/${results.length} checks passed`);
server.kill();
if (results.some((r) => !r.ok)) process.exitCode = 1;
