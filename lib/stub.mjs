import { RUNNER, STUB } from "../data/generated.mjs";
import { obfuscateLua } from "./lua-obfuscate.mjs";
import { compileVm, randomKeyWords } from "./vm.mjs";

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

/**
 * Relay layer between the stub runner and the snippet. It receives `vm_run` from
 * the runner (so the VM runtime is not shipped twice) and decodes the snippet
 * program with a second, independent key.
 */
function relaySource({ program, hex }) {
  return [
    `local vm_run=...`,
    `local sl=loadstring or load`,
    `if type(sl)~="function" then return end`,
    `local sS=vm_run([==[${program}]==],"${hex}")`,
    `if type(sS)~="string" then return end`,
    `local f=sl(sS,"="..string.format("%x",math.random(1,2147483646)))`,
    `if type(f)=="function" then f() end`,
  ].join("\n");
}

function pack(source) {
  const { words, hex } = randomKeyWords();
  const { program } = compileVm(source, { keyWords: words, chunkMin: 48, chunkMax: 132 });
  return { program, hex };
}

/**
 * Build the raw link body for an executor.
 *
 * Two nested VM layers plus a string-encryption pass, all re-randomized on every
 * request: a dump of the delivered text gives a program, not source; running it
 * once gives a second program under a different key; that one decodes to a
 * snippet whose strings are still XOR-encoded. There is no
 * `loadstring(game:HttpGet(...))` line anywhere in the response, and a sample
 * captured from one load does not decode the next.
 */
export function renderRawStub({ host, scriptId, ticket }) {
  if (!HOST_RE.test(host)) throw new Error("renderRawStub: invalid host");
  if (!ticket) throw new Error("renderRawStub: missing ticket");

  const snippet = obfuscateLua(fetchSnippet({ host, scriptId, ticket }), { chunkName: scriptId });
  const inner = pack(snippet.code);
  const relay = pack(relaySource(inner));

  return STUB.split("--@@VM@@")
    .join(RUNNER.vm)
    .split("__PROGRAM__")
    .join(relay.program)
    .split("__KEY__")
    .join(relay.hex);
}
