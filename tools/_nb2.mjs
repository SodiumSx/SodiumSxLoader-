import { obfuscateLua } from "../lib/lua-obfuscate.mjs";
process.stdout.write("start\n");
const source = 'local n = 0 for i = 1, 4 do n = n + #("xor-check") end print(n)';
const t = Date.now();
const out = obfuscateLua(source, { rng: () => 0.1 });
process.stdout.write(`done in ${Date.now() - t}ms, fallback=${out.code.includes("bit32 and bit32.bxor")}\n`);
