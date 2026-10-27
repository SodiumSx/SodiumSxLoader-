import { randomBytes } from "node:crypto";
import { CORE, RUNNER } from "../data/generated.mjs";
import { obfuscateLua, scanLua } from "./lua-obfuscate.mjs";
import { renameLocals } from "./lua-rename.mjs";
import { chunkSizesFor } from "./obf-profile.mjs";
import { compileVm, makeRng, randomKeyWords } from "./vm.mjs";

const HOST_RE = /^https?:\/\/[a-z0-9.\-:]+$/i;

/**
 * Build the stage response: a tiny VM runtime plus the core source compiled
 * into a randomized program. Every request gets new chunk boundaries, register
 * numbering and key, so two visitors never receive the same bytes.
 *
 * The delivered runtime is renamed and string-encrypted too. It used to ship
 * `vm_run`, `vm_unseal` and friends in the clear, which handed a deobfuscator
 * both anchors to search for and plaintext constants to fingerprint
 * (`"[C]"`, the base64 alphabet, the format strings). Nothing in the response
 * now names an internal function; the runner calls the decoder through the
 * per-request name substituted from the rename map.
 */
export function renderStage({ host, scriptId }) {
  if (!HOST_RE.test(host)) throw new Error("renderStage: invalid host");
  const { words, hex } = randomKeyWords();
  const { program, chunks, instructions } = compileVm(CORE, {
    keyWords: words,
    ...chunkSizesFor(CORE.length),
  });

  const rng = makeRng(randomBytes(4).readUInt32LE(0));
  const renamed = renameLocals(scanLua(RUNNER.vm), rng);
  // Fall back to the real names rather than failing the load: a construct the
  // renamer does not understand must never take the hub offline.
  const entry = renamed.names.get("vm_run") || "vm_run";
  const source = renamed.skipped ? RUNNER.vm : renamed.code;
  const runtime = obfuscateLua(source, { rng, chunkName: "st", rename: false });

  const code = RUNNER.tpl
    .split("--@@VM@@")
    .join(runtime.code)
    .split("__RUN__")
    .join(entry)
    .split("__PROGRAM__")
    .join(program)
    .split("__KEY__")
    .join(hex)
    .split("__HOST__")
    .join(host)
    .split("__SID__")
    .join(scriptId);

  return { code, chunks, instructions };
}
