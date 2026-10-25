import { CORE, RUNNER } from "../data/generated.mjs";
import { compileVm, randomKeyWords } from "./vm.mjs";

const HOST_RE = /^https?:\/\/[a-z0-9.\-:]+$/i;

/**
 * Build the stage response: a tiny VM runtime plus the core source compiled
 * into a randomized program. Every request gets new chunk boundaries, register
 * numbering and key, so two visitors never receive the same bytes.
 */
export function renderStage({ host, scriptId }) {
  if (!HOST_RE.test(host)) throw new Error("renderStage: invalid host");
  const { words, hex } = randomKeyWords();
  const { program, chunks, instructions } = compileVm(CORE, { keyWords: words });

  const code = RUNNER.tpl
    .split("--@@VM@@")
    .join(RUNNER.vm)
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
