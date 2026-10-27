// Measures the hot-literal hoist: same script, obfuscated with and without it.
import { LuaFactory } from "wasmoon";
import { obfuscateLua } from "../lib/lua-obfuscate.mjs";

const source = `
local acc = 0
for i = 1, 300000 do
  if i % 2 == 0 then
    acc = acc + #("hot-literal-A" .. tostring(i))
  else
    acc = acc + #("hot-literal-A") + #("cold-literal-B")
  end
end
print(acc)
`;

async function run(label, code) {
  const factory = new LuaFactory();
  const lua = await factory.createEngine();
  const logs = [];
  lua.global.set("__print", (s) => logs.push(s));
  // Luau ships bit32; wasmoon (stock Lua 5.4) does not, so shim it the way the
  // test harness does before any obfuscated chunk runs.
  await lua.doString(`bit32 = {
    bxor = function(a, b) return ((a ~ b) & 0xFFFFFFFF) end,
  }
  print = function(...) local t = {} for i = 1, select('#', ...) do t[i] = tostring(select(i, ...)) end __print(table.concat(t, ' ')) end`);
  const start = performance.now();
  await lua.doString(code);
  const ms = performance.now() - start;
  lua.global.close();
  console.log(`${label.padEnd(22)} ${ms.toFixed(1).padStart(8)} ms   out=${logs.join("|")}`);
  return { ms, out: logs.join("|") };
}

const plain = await run("plain lua", source);
const noHoist = obfuscateLua(source, { profile: { name: "no-hoist", inlineMax: 2, decoys: 2, hoist: 0, block: 32, rename: true, junk: true } });
const hoisted = obfuscateLua(source);
const a = await run("obf (no hoist)", noHoist.code);
const b = await run("obf (hoisted)", hoisted.code);

console.log(`hoisted literals: ${hoisted.stats.hoisted}, reuse sites: ${hoisted.stats.reused}`);
console.log(`same output: ${plain.out === a.out && a.out === b.out}`);
console.log(`hoist gain: ${(a.ms - b.ms).toFixed(1)} ms (${(((a.ms - b.ms) / a.ms) * 100).toFixed(1)}%)`);
