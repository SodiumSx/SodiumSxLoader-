/**
 * FreeHub Guard — obfuscation profile ("optimizer").
 *
 * Obfuscation costs the *client* CPU: every encrypted string literal is a
 * decode call the first time it is evaluated, and every extra VM chunk is one
 * more keystream seed to derive before the script can start. Protection is
 * worth that cost; paying it in the wrong places is not.
 *
 * This module measures the script and picks the trade-off per payload:
 *
 *  - 1–2 byte literals are inlined as plain text. They are punctuation (`" "`,
 *    `"."`, `"/"`), they reveal nothing, and they are exactly the strings that
 *    appear in hot loops, where a decode call per iteration is felt.
 *  - the decoder flushes through `string.char()` in blocks, so a typical short
 *    literal is one C call instead of one call per byte.
 *  - decoy slots scale with the table, so a five-string script is not padded
 *    with more noise than data (which would slow first use for nothing).
 *  - a literal that appears more than once is *hoisted*: it is decoded once at
 *    load into a file-scope local and every use site reads that local. A loop
 *    body then costs a variable read instead of a call, a cache lookup and a
 *    table index per iteration, and the plaintext still never appears in the
 *    file. Hoisting is capped, because a chunk can only hold ~200 locals.
 *  - VM chunk sizes grow with the payload: more chunks means more per-chunk
 *    key material and a more scrambled layout, worth it on a 4 KB script,
 *    expensive on a 300 KB one.
 *
 * Nothing here changes the semantics of the payload: it only chooses how the
 * wrapper is built.
 */

/** Token statistics used by the profile. */
export function analyzeTokens(tokens) {
  let bytes = 0;
  let strings = 0;
  let stringBytes = 0;
  let shortStrings = 0;
  let numerics = 0;
  let functions = 0;
  let loops = 0;
  let locals = 0;
  const unique = new Set();

  for (const tok of tokens) {
    switch (tok.type) {
      case "ws":
      case "comment":
        bytes += tok.text.length;
        break;
      case "str":
        strings++;
        stringBytes += tok.value.length;
        if (tok.value.length <= 2) shortStrings++;
        unique.add(tok.value);
        break;
      case "num":
        numerics++;
        break;
      case "kw":
        if (tok.text === "function") functions++;
        else if (tok.text === "for" || tok.text === "while" || tok.text === "repeat") loops++;
        else if (tok.text === "local") locals++;
        break;
      default:
        break;
    }
  }

  return {
    bytes,
    strings,
    uniqueStrings: unique.size,
    stringBytes,
    shortStrings,
    numerics,
    functions,
    loops,
    locals,
  };
}

const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

/**
 * Choose the build settings for one payload.
 *
 * @param {ReturnType<typeof analyzeTokens>} stats
 * @returns {{name: string, inlineMax: number, block: number, decoys: number, rename: boolean, junk: boolean}}
 */
export function chooseProfile(stats) {
  // A 1-byte literal is punctuation and 90% of the hot-loop string traffic;
  // 2-byte literals are the same class. Never inline anything longer: that is
  // where real text (URLs, UI copy, keys) starts.
  const inlineMax = 2;

  // ~12% noise, but never more decoys than real slots, and always at least a
  // couple so the table has no visible structure.
  const decoys = clamp(Math.round(stats.uniqueStrings * 0.12), 2, 6);

  // Hoisting pays off when the same literal is evaluated again and again: loop
  // bodies, repeated UI updates, retry paths. A script with no loops and no
  // functions evaluates each literal once, so a hoist would only add a local.
  // The cap keeps the chunk well clear of the 200-local limit and stops a big
  // payload from decoding its whole table before the first line runs.
  const repeats = stats.loops > 0 || stats.functions > 0;
  const hoist = repeats
    ? clamp(Math.round(stats.uniqueStrings * 0.5), 0, stats.bytes > 96 * 1024 ? 12 : 24)
    : 0;

  return {
    name: stats.bytes > 96 * 1024 ? "throughput" : stats.bytes > 16 * 1024 ? "balanced" : "compact",
    inlineMax,
    decoys,
    hoist,
    block: 32,
    rename: true,
    junk: true,
  };
}

/**
 * VM chunk size for a payload of `bytes` source bytes.
 *
 * Small payloads get small chunks: more chunks means more constants, more
 * concatenation steps and more shuffled registers, which is cheap when the
 * whole program is a few KB. Large payloads get large chunks, because the
 * client-side decode cost is dominated by per-chunk work (one keystream seed,
 * one base64 tail, one function call) and a 300 KB payload with 64-byte chunks
 * spends most of its startup time in that overhead.
 */
export function chunkSizesFor(bytes) {
  if (bytes <= 6 * 1024) return { chunkMin: 96, chunkMax: 280 };
  if (bytes <= 24 * 1024) return { chunkMin: 192, chunkMax: 512 };
  if (bytes <= 96 * 1024) return { chunkMin: 384, chunkMax: 900 };
  return { chunkMin: 640, chunkMax: 1400 };
}

/** One log line describing the build. */
export function describeProfile(profile, stats) {
  return `profile   ${profile.name} (${stats.uniqueStrings} strings, inline<=${profile.inlineMax}, ${profile.decoys} decoys)`;
}

