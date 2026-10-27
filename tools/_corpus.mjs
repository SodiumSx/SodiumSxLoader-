// Executes a corpus of realistic scripts plain and obfuscated, several seeds
// each, and reports any behavioural difference. Scratch tool, not part of test.
import { LuaFactory } from "wasmoon";
import { obfuscateLua } from "../lib/lua-obfuscate.mjs";

const BIT32 = `bit32 = { bxor = function(a,b) return ((a ~ b) & 0xFFFFFFFF) end }`;
const HARNESS = `
__out = {}
function say(...) local t = {} for i = 1, select('#', ...) do t[i] = tostring(select(i, ...)) end __out[#__out + 1] = table.concat(t, ' ') end
print = say
warn = say
game = { PlaceId = 7, JobId = "j", GetService = function(_, n) return { LocalPlayer = { Name = "P" }, MaxPlayers = 8, GetPlayers = function() return {} end } end }
Instance = { new = function(c) local t = { ClassName = c } return setmetatable(t, { __index = function(s, k) local v = { Text = "", Parent = nil } rawset(s, k, v) return v end }) end }
UDim2 = { new = function() return {} end, fromOffset = function() return {} end }
UDim = { new = function() return {} end }
Color3 = { fromRGB = function() return {} end, new = function() return {} end }
Enum = { Font = { Code = 1, Gotham = 2, GothamBold = 3 }, TextXAlignment = { Left = 1 } }
task = { wait = function() end, spawn = function(f) return f end, delay = function() end, defer = function() end }
typeof = type
`;

const cases = {
  closures: `
local function counter(start)
  local n = start
  return function(step)
    n = n + (step or 1)
    return n
  end
end
local c = counter(10)
c(); c(5)
print(c(0), c())
`,
  varargs: `
local function pack(...)
  local n = select("#", ...)
  local t = { ... }
  return n, t
end
local n, t = pack(1, nil, 3)
print(n, #t, t[1], tostring(t[2]), t[3])
`,
  methods: `
local obj = { value = 5 }
function obj:get(add)
  return self.value + (add or 0)
end
function obj:set(v)
  self.value = v
  return self
end
print(obj:get(), obj:set(9):get(1), obj.value)
`,
  genericFor: `
local src = { a = 1, b = 2, c = 3 }
local keys = {}
for k, v in pairs(src) do keys[#keys + 1] = k .. "=" .. v end
table.sort(keys)
print(table.concat(keys, ","))
local sum = 0
for _, v in ipairs({ 10, 20, 30 }) do sum = sum + v end
print(sum)
`,
  tableKeys: `
local t = { [1] = "one", ["two"] = 2, three = 3, [4] = 4 }
local out = {}
for _, k in ipairs({ 1, 4 }) do out[#out + 1] = tostring(t[k]) end
out[#out + 1] = tostring(t.two) .. tostring(t.three)
print(table.concat(out, "|"))
`,
  multipleReturn: `
local function two() return 1, 2 end
local a, b = two()
local c = two()
print(a, b, c)
local t = { two(), two() }
print(#t, t[1], t[3])
`,
  upvaluesInLoops: `
local fns = {}
for i = 1, 3 do
  fns[i] = function() return i * 2 end
end
local total = 0
for i = 1, #fns do total = total + fns[i]() end
print(total)
`,
  shadowing: `
local x = "outer"
do
  local x = "inner"
  print(x)
end
print(x)
local function f(x)
  x = x .. "!"
  return x
end
print(f("arg"), x)
`,
  recursion: `
local function fib(n)
  if n < 2 then return n end
  return fib(n - 1) + fib(n - 2)
end
print(fib(18))
`,
  stringOps: `
local s = "FreeHub/Guard"
print(s:sub(1, 7), s:upper(), #s, s:find("/"), s:gsub("u", "U"))
print(("%s-%d"):format("x", 12))
print(string.rep("ab", 3), ("pad"):rep(2, "-"))
`,
  pcallPath: `
local ok, err = pcall(function() error("boom") end)
print(ok, tostring(err):match("boom") ~= nil)
local ok2, v = pcall(function() return 42 end)
print(ok2, v)
`,
  robux: `
local Players = game:GetService("Players")
local gui = Instance.new("ScreenGui")
gui.Name = "Hub"
gui.ResetOnSpawn = false
local frame = Instance.new("Frame")
frame.Size = UDim2.fromOffset(200, 80)
frame.BackgroundColor3 = Color3.fromRGB(20, 20, 25)
frame.Parent = gui
local label = Instance.new("TextLabel")
label.Text = "Loaded for " .. Players.LocalPlayer.Name
label.Font = Enum.Font.GothamBold
label.Parent = frame
print(gui.Name, frame.Parent ~= nil, label.Text, tostring(Players.MaxPlayers))
`,
  loops: `
local i = 0
while true do
  i = i + 1
  if i >= 4 then break end
end
local j = 0
for k = 1, 10, 3 do j = j + k end
print(i, j)
`,
  compound: `
local a, b = 2, 3
a = a + b * 2 - 1
b = a // 2
print(a, b, a % b, 2 ^ 3)
`,
  sugarAndKeys: `
local t = { key = "value" }
local function id(x) return x end
print "plain-sugar"
print "plain-sugar"
print [[long
string body]]
print(({ "ế", "đặc biệt" })[1], #"ế")
print(("receiver"):upper(), ("receiver"):len())
print(t["key"], ("a" .. "b"):rep(2))
print(id "twice", id "twice")
print(#("count-me"), ("count-me"):sub(1, 5), "x" .. ("count-me"))
`,
  manyLocals: `
local total = 0
local a1, a2, a3, a4, a5, a6, a7, a8 = 1, 2, 3, 4, 5, 6, 7, 8
local function sum(...)
  local s = 0
  for i = 1, select("#", ...) do s = s + select(i, ...) end
  return s
end
total = sum(a1, a2, a3, a4, a5, a6, a7, a8)
print(total)
`,
  closuresInTable: `
local handlers = {
  on = function(x) return "on:" .. x end,
  off = function(x) return "off:" .. x end,
}
handlers.extra = function(self, x) return handlers.off(x) .. "!" end
print(handlers.on("a"), handlers:extra("b"))
`,
};

async function run(source) {
  const lua = await new LuaFactory().createEngine();
  await lua.doString(BIT32);
  await lua.doString(HARNESS);
  await lua.doString(source);
  const out = lua.global.get("__out");
  const lines = Array.isArray(out)
    ? out.map(String)
    : out
      ? Array.from({ length: out.length }, (_, i) => String(out.get(i + 1)))
      : [];
  lua.global.close();
  return lines.join("\n");
}

const seeds = [1, 2, 3, 4, 5];
let failures = 0;
for (const [name, source] of Object.entries(cases)) {
  const expected = await run(source);
  for (const seed of seeds) {
    let code;
    try {
      code = obfuscateLua(source, { rng: ((s) => () => {
        s = (s * 1103515245 + 12345) % 2147483648;
        return s / 2147483648;
      })(seed * 7919) }).code;
    } catch (err) {
      console.log(`BUILD FAIL ${name} seed=${seed}: ${err.message}`);
      failures++;
      continue;
    }
    let got;
    try {
      got = await run(code);
    } catch (err) {
      console.log(`RUN FAIL   ${name} seed=${seed}: ${err.message}`);
      failures++;
      continue;
    }
    if (got !== expected) {
      console.log(`MISMATCH   ${name} seed=${seed}\n  want: ${JSON.stringify(expected)}\n  got:  ${JSON.stringify(got)}`);
      failures++;
    }
  }
}
console.log(`${Object.keys(cases).length} scripts x ${seeds.length} seeds -> ${failures} failure(s)`);
