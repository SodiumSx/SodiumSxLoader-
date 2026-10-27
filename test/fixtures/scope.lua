-- Scope torture test: every construct that a local renamer can get wrong.
-- tools/test.mjs runs this twice (plain and obfuscated) and compares output.
local log = {}
local function add(v)
  log[#log + 1] = tostring(v)
end

-- plain locals and block shadowing
local x = 1
do
  local x = 2
  add("shadow:" .. x)
end
add("outer:" .. x)

-- a declaration's initialiser sees the previous binding, not itself
local y = 5
local y = y + 1
add("selfinit:" .. y)

-- block scope restores the outer binding
local status = "outer"
if true then
  local status = "inner"
  add("innerstatus:" .. status)
end
add("outerstatus:" .. status)

-- closures capture by reference
local counter = 0
local function bump()
  counter = counter + 1
  return counter
end
bump()
bump()
add("closure:" .. counter)

-- recursion through a local function
local function fib(n)
  if n < 2 then
    return n
  end
  return fib(n - 1) + fib(n - 2)
end
add("fib:" .. fib(10))

-- loop variables, and a local that shadows the loop variable
local total = 0
for i = 1, 4 do
  local i = i * 10
  total = total + i
end
add("for:" .. total)

for k, v in ipairs({ "a", "b" }) do
  total = total + k
end
add("ipairs:" .. total)

-- while + break
local n = 0
while true do
  n = n + 1
  if n >= 3 then
    break
  end
end
add("while:" .. n)

-- varargs and multiple returns
local function packAll(...)
  local count = select("#", ...)
  local first, second = ...
  return count, first, second
end
local c, f, s = packAll("p", "q", "r")
add("varargs:" .. c .. f .. s)

-- table constructor keys are data, never variables
local record = { alpha = 1, beta = 2, ["gamma"] = 3 }
add("keys:" .. record.alpha .. record.beta .. record.gamma)

-- method definitions keep their field name, keep `self` implicit
local function makeThing()
  local thing = {}
  function thing:method(a)
    return (self.base or 0) + a
  end
  thing.base = 10
  return thing
end
add("method:" .. makeThing():method(5))

-- parameters shadow outer locals
local value = 7
local function shadowParam(value)
  return value + 1
end
add("param:" .. shadowParam(1) .. value)

-- if / elseif / else scoping
local pick
if x == 1 then
  local tag = "one"
  pick = tag
elseif x == 2 then
  local tag = "two"
  pick = tag
else
  local tag = "other"
  pick = tag
end
add("branch:" .. pick)

-- expressions broken across lines, multi-line tables
local sum =
  1 +
  2 +
  3
add("sum:" .. sum)

local config = {
  a = 1,
  b = {
    c = 2,
  },
}
add("table:" .. config.a .. config.b.c)

-- a local shared by a nested closure declared later
local suffix = "!"
local function shout(text)
  return string.upper(text) .. suffix
end
add("shout:" .. shout("ok"))

-- globals stay globals
function globalHelper(v)
  return v * 2
end
add("global:" .. globalHelper(21))

-- closure in an argument list
pcall(function()
  local inner = "inner"
  add("cb:" .. inner)
end)

-- concatenation and arithmetic across statements
local acc = 1
acc = acc + 2
local tail = "t"
tail = tail .. "ail"
add("compound:" .. acc .. tail)

-- long string / comment edge cases around the rewritten code
add("long:" .. [[raw ]] .. "-- not a comment" .. [==[x]==])

print(table.concat(log, "|"))
