import { randomBytes } from "node:crypto";
import { RUNNER, STUB } from "../data/generated.mjs";
import { b64u, keyWordsFromHex, keyWordsToHex, ksSeg, mac } from "./crypto.mjs";
import { obfuscateLua, scanLua } from "./lua-obfuscate.mjs";
import { renameLocals } from "./lua-rename.mjs";
import { OPS, compileVm, makeRng, randInt, randomKeyWords, shuffle } from "./vm.mjs";

const HOST_RE = /^https?:\/\/[a-z0-9.\-:]+$/i;

/**
 * Innermost layer: fetch the stage with its ticket and run it. `HttpGet` and the
 * stage path are never written literally, and the URL only exists as an encoded
 * string table (the obfuscator pass runs before this is VM-packed).
 */
function fetchSnippet({ host, scriptId, ticket }) {
  return [
    `local u="${host}/api/stage/${scriptId}?s=${ticket}"`,
    `local g=game`,
    `local h=g["Http".."Get"]`,
    `if type(h)~="function" then return end`,
    `local f=loadstring or load`,
    `if type(f)~="function" then return end`,
    `local b=h(g,u)`,
    `if type(b)~="string" or #b<256 then return end`,
    `local r=f(b,"="..string.format("%x",math.random(1,2147483646)))`,
    `if type(r)=="function" then r() end`,
  ].join("\n");
}

/* ------------------------------------------------------------------ *
 * Per-request VM renaming
 * ------------------------------------------------------------------ */

/**
 * Rename every local with a fresh random name. A captured stub then says
 * nothing about our internals: `vm_run`, `vm_boot`, `vm_mac` and friends do not
 * exist in the delivered text, so a signature-based tool has no anchor and a
 * hand-written patch written against one build does not apply to the next.
 *
 * The scope-aware renamer is used rather than a flat find/replace: it leaves
 * globals (`string`, `pcall`, ...) and table fields alone by construction, which
 * is what keeps the runtime callable. String obfuscation runs afterwards with
 * its own rename pass disabled.
 */
function packVm(rng) {
  const renamed = renameLocals(scanLua(RUNNER.vm), rng);
  // Never fail the request over renaming: if the scope machine ever refuses a
  // new construct in lua/vm.lua, the runtime still ships string-encrypted under
  // its real names.
  const entry = renamed.names.get("vm_boot") || "vm_boot";
  const source = renamed.skipped ? RUNNER.vm : renamed.code;
  const obfuscated = obfuscateLua(source, { rng, chunkName: "rt", rename: false });
  return { code: obfuscated.code, entry };
}

/* ------------------------------------------------------------------ *
 * Nested program chain
 * ------------------------------------------------------------------ */

/** Seal `text` into PUSHX constants for the given key: const i uses seed i-1. */
function sealConsts(text, keyWords, rng) {
  const bytes = Buffer.from(text, "utf8");
  const consts = [];
  let offset = 0;
  while (offset < bytes.length) {
    const size = Math.min(randInt(rng, 96, 260), bytes.length - offset);
    const part = bytes.subarray(offset, offset + size);
    const stream = ksSeg(keyWords, consts.length, part.length);
    const xored = Buffer.alloc(part.length);
    for (let i = 0; i < part.length; i++) xored[i] = part[i] ^ stream[i];
    consts.push(b64u(xored));
    offset += size;
  }
  return consts;
}

/**
 * Wrap one program inside another. The outer program decodes the inner text with
 * its own key and then hands it to NEST, which derives the child key from
 * `mac(salt, parentKey)` inside the VM. The inner text is therefore useless on
 * its own: without the parent key the salt does not produce a working key.
 */
function nestProgram({ inner, parentWords, salt, rng }) {
  const chunks = sealConsts(inner, parentWords, rng);
  const consts = [...chunks, b64u(Buffer.from(salt, "utf8"))];

  // One register per chunk plus one per concat node, shuffled. Drawing from a
  // fixed 0..110 range spins forever once a larger inner program exhausts it.
  const registerPool = shuffle(
    rng,
    Array.from({ length: chunks.length * 2 + 8 }, (_, i) => i),
  );
  let registerCursor = 0;
  const used = new Set();
  const alloc = () => {
    if (registerCursor >= registerPool.length) throw new Error("nestProgram: out of registers");
    const r = registerPool[registerCursor++];
    used.add(r);
    return r;
  };

  const instrs = [];
  const regOf = [];
  for (const index of shuffle(rng, chunks.map((_, i) => i))) {
    const reg = alloc();
    regOf[index] = reg;
    instrs.push({ op: "PUSHX", args: [reg, index + 1] });
  }

  const build = (lo, hi) => {
    if (hi - lo === 1) return regOf[lo];
    const cut = lo + Math.max(1, Math.min(hi - lo - 1, Math.floor((hi - lo) / 2) + randInt(rng, -1, 1)));
    const left = build(lo, cut);
    const right = build(cut, hi);
    const reg = alloc();
    instrs.push({ op: "CAT", args: [reg, left, right] });
    return reg;
  };
  const joined = build(0, chunks.length);

  // Dead arithmetic: real registers, no effect on the chain.
  for (let i = 0, n = randInt(rng, 1, 3); i < n; i++) {
    const a = alloc();
    instrs.push({ op: "PUSHN", args: [a, randInt(rng, 1, 999)] });
    const b = alloc();
    instrs.push({ op: "MOV", args: [b, a] });
  }

  const saltReg = alloc();
  instrs.push({ op: "SETL", args: [saltReg, consts.length] });
  instrs.push({ op: "NEST", args: [joined, saltReg] });

  const perm = shuffle(rng, Array.from({ length: OPS.length }, (_, i) => i));
  const lines = [
    `${perm.join(",")}|${Math.max(...used) + 1}`,
    consts.join(","),
    instrs.map((ins) => [perm[OPS.indexOf(ins.op)], ...ins.args].join(",")).join(";"),
  ];
  return lines.join("\n");
}

/**
 * Build the raw link body for an executor.
 *
 * The response is a renamed + string-encrypted VM runtime plus a chain of nested
 * programs (2-4 deep, randomized). Every layer is decoded with a key derived
 * inside the VM from the previous layer's key, and only the innermost program
 * ends with EXEC, which runs the snippet without ever returning its source. There
 * is no `local sS = vm_run(...)` to rewrite: dump the delivered text and you have
 * opaque programs and a keyless outer blob, not a loadstring line.
 */
export function renderRawStub({ host, scriptId, ticket }) {
  if (!HOST_RE.test(host)) throw new Error("renderRawStub: invalid host");
  if (!ticket) throw new Error("renderRawStub: missing ticket");

  const rng = makeRng(randomBytes(4).readUInt32LE(0));

  const baseWords = randomKeyWords().words;

  // One key per layer: k[i+1] = mac(salt[i], k[i]), computed identically in Lua.
  const depth = randInt(rng, 2, 3);
  const keys = [baseWords];
  const salts = [];
  for (let i = 0; i < depth; i++) {
    const salt = randomBytes(12).toString("hex");
    salts.push(salt);
    keys.push(keyWordsFromHex(mac(Buffer.from(salt, "utf8"), keys[i])));
  }

  const snippet = obfuscateLua(fetchSnippet({ host, scriptId, ticket }), { chunkName: scriptId });
  let program = compileVm(snippet.code, {
    keyWords: keys[depth],
    tail: "EXEC",
    rng,
    chunkMin: 40,
    chunkMax: 110,
  }).program;
  for (let i = depth - 1; i >= 0; i--) {
    program = nestProgram({ inner: program, parentWords: keys[i], salt: salts[i], rng });
  }

  const vm = packVm(rng);

  return STUB.split("--@@VM@@")
    .join(vm.code)
    .split("__PROGRAM__")
    .join(program)
    .split("__KEY__")
    .join(keyWordsToHex(baseWords))
    .split("__ENTRY__")
    .join(vm.entry);
}
