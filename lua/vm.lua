-- FreeHub Guard — VM runtime.
-- Byte-for-byte twin of lib/crypto.mjs (ksSeg/mac) and lib/vm.mjs (program
-- format). Executed inside the client, so it only uses bit32 + string + table.
local vm_bit = bit32
local vm_mod = 4294967296
local vm_floor = math.floor

local function vm_bxor(a, b)
  return vm_bit.bxor(a, b)
end

local function vm_x3(a, b, c)
  return vm_bit.bxor(vm_bit.bxor(a, b), c)
end

-- 32-bit multiply without floating point overflow.
local function vm_imul(a, b)
  local ah = vm_floor(a / 65536)
  local al = a % 65536
  return (al * b + ((ah * b) % 65536) * 65536) % vm_mod
end

local function vm_xorshift(x)
  x = vm_bxor(x, (x * 8192) % vm_mod)
  x = vm_bxor(x, vm_floor(x / 131072))
  x = vm_bxor(x, (x * 32) % vm_mod)
  return x
end

-- Mirrors ksSeg() in lib/crypto.mjs. Returns a byte array.
local function vm_ks(k, seed, len)
  local out = {}
  local p, j = 1, 0
  local base = vm_imul(seed + 1, 2654435761)
  while p <= len do
    local x = (k[1] + base) % vm_mod
    x = vm_bxor(x, k[2])
    x = vm_xorshift(x)
    x = (x + vm_imul(j + 1, 2246822507)) % vm_mod
    x = vm_bxor(x, k[3])
    x = vm_xorshift(x)
    x = vm_bxor(x, k[4])
    out[p] = x % 256
    out[p + 1] = vm_floor(x / 256) % 256
    out[p + 2] = vm_floor(x / 65536) % 256
    out[p + 3] = vm_floor(x / 16777216) % 256
    p = p + 4
    j = j + 1
  end
  return out
end

local vm_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
local vm_b64map = {}
for i = 1, 64 do
  vm_b64map[string.byte(vm_alpha, i)] = i - 1
end

local function vm_b64(s)
  local out, n = {}, 0
  local acc, count = 0, 0
  for i = 1, #s do
    local c = vm_b64map[string.byte(s, i)]
    if c then
      acc = acc * 64 + c
      count = count + 1
      if count == 4 then
        n = n + 1
        out[n] = string.char(vm_floor(acc / 65536) % 256, vm_floor(acc / 256) % 256, acc % 256)
        acc, count = 0, 0
      end
    end
  end
  if count == 2 then
    n = n + 1
    out[n] = string.char(vm_floor(acc / 16) % 256)
  elseif count == 3 then
    n = n + 1
    out[n] = string.char(vm_floor(acc / 1024) % 256, vm_floor(acc / 4) % 256)
  end
  return table.concat(out)
end

local function vm_key(hex)
  local k = {}
  for i = 0, 3 do
    local o = i * 8
    local b1 = tonumber(hex:sub(o + 1, o + 2), 16) or 0
    local b2 = tonumber(hex:sub(o + 3, o + 4), 16) or 0
    local b3 = tonumber(hex:sub(o + 5, o + 6), 16) or 0
    local b4 = tonumber(hex:sub(o + 7, o + 8), 16) or 0
    k[i + 1] = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
  end
  return k
end

local function vm_unseal(data, k, seed)
  local n = #data
  local stream = vm_ks(k, seed, n)
  local out = {}
  for i = 1, n do
    out[i] = string.char(vm_bxor(string.byte(data, i), stream[i]))
  end
  return table.concat(out)
end

-- Keyed tamper check. Mirrors mac() in lib/crypto.mjs.
local function vm_mac(data, k)
  local lanes = {
    vm_bxor(2166136261, k[1]),
    vm_bxor(16777619, k[2]),
    vm_bxor(2654435769, k[3]),
    vm_bxor(2246822507, k[4]),
  }
  for i = 1, #data do
    local lane = (i - 1) % 4 + 1
    lanes[lane] = vm_imul(vm_bxor(lanes[lane], string.byte(data, i)), 16777619)
  end
  for _ = 1, 3 do
    for i = 1, 4 do
      local nxt = lanes[i % 4 + 1]
      lanes[i] = vm_imul(vm_bxor(lanes[i], vm_bit.lrotate(nxt, 13)), 2246822507)
    end
  end
  local parts = {}
  for i = 1, 4 do
    local x, buf = lanes[i], {}
    for b = 8, 1, -1 do
      buf[b] = string.sub("0123456789abcdef", x % 16 + 1, x % 16 + 1)
      x = vm_floor(x / 16)
    end
    parts[i] = table.concat(buf)
  end
  return table.concat(parts)
end-- Native runner + guard live inside the VM so the delivered stub has no
-- top-level "decode then load" line to patch. `vm_native` rejects any loader or
-- string helper that was replaced by a Lua closure (env loggers, hook tools).
local vm_load = loadstring or load

-- Luau spells it debug.info(fn, "s") and returns the source directly; stock Lua
-- spells it debug.getinfo(fn, "S") and returns a table. Try both.
local function vm_src(fn)
  local d = debug
  if not d then return nil end
  local gi = d.info or d.getinfo
  if not gi then return nil end
  for _, what in ipairs({ "S", "s" }) do
    local ok, info = pcall(gi, fn, what)
    if ok then
      if type(info) == "table" then info = info.source end
      if type(info) == "string" then return info end
    end
  end
  return nil
end

local function vm_native(fn)
  if type(fn) ~= "function" then return false end
  local src = vm_src(fn)
  if not src then return false end
  return src == "[C]" or src == "=[C]"
end

local function vm_chunkname()
  return "=" .. string.format("%x", math.random(1, 2147483646))
end

local vm_run

vm_run = function (program, keyhex, maxSteps, depth)
  depth = depth or 1
  if depth > 6 then return nil end
  if type(program) ~= "string" or type(keyhex) ~= "string" or #keyhex < 32 then
    return nil
  end
  local n1 = string.find(program, "\n", 1, true)
  if not n1 then return nil end
  local n2 = string.find(program, "\n", n1 + 1, true)
  if not n2 then return nil end
  local head = string.sub(program, 1, n1 - 1)
  local constsText = string.sub(program, n1 + 1, n2 - 1)
  local codeText = string.sub(program, n2 + 1)

  local permText, regText = string.match(head, "^(.-)|(%d+)$")
  if not permText then return nil end

  local rev, internal = {}, 0
  for num in string.gmatch(permText, "%d+") do
    rev[tonumber(num)] = internal
    internal = internal + 1
  end

  local consts, ci = {}, 0
  for c in string.gmatch(constsText, "[^,]+") do
    ci = ci + 1
    consts[ci] = c
  end

  local code, count = {}, 0
  for line in string.gmatch(codeText, "[^;]+") do
    count = count + 1
    code[count] = line
  end

  local key = vm_key(keyhex)
  local regs = {}
  local pc = 1
  local steps = 0
  local limit = maxSteps or (count * 16 + 200000)

  while true do
    steps = steps + 1
    if steps > limit then return nil end
    local line = code[pc]
    if not line then return nil end

    local f, fc = {}, 0
    for part in string.gmatch(line, "[^,]+") do
      fc = fc + 1
      f[fc] = tonumber(part)
    end
    if fc < 2 then return nil end
    local op = rev[f[1]]
    local nextpc = pc + 1

    if op == 0 then
      local idx = f[3]
      local raw = consts[idx]
      if not raw then return nil end
      regs[f[2]] = vm_unseal(vm_b64(raw), key, idx - 1)
    elseif op == 1 then
      local raw = consts[f[3]]
      if not raw then return nil end
      regs[f[2]] = vm_b64(raw)
    elseif op == 2 then
      regs[f[2]] = regs[f[3]]
    elseif op == 3 then
      regs[f[2]] = regs[f[3]] .. regs[f[4]]
    elseif op == 4 then
      local a, b = regs[f[3]], regs[f[4]]
      if type(a) ~= "string" or type(b) ~= "string" or #b == 0 then return nil end
      local out, lb = {}, #b
      for i = 1, #a do
        out[i] = string.char(vm_bxor(string.byte(a, i), string.byte(b, (i - 1) % lb + 1)))
      end
      regs[f[2]] = table.concat(out)
    elseif op == 5 then
      local a = regs[f[3]]
      if type(a) ~= "string" then return nil end
      regs[f[2]] = string.sub(a, f[4] + 1, f[4] + f[5])
    elseif op == 6 then
      local a = regs[f[3]]
      if type(a) ~= "string" then return nil end
      regs[f[2]] = string.reverse(a)
    elseif op == 7 then
      regs[f[2]] = f[3]
    elseif op == 8 then
      nextpc = f[2]
    elseif op == 9 then
      if regs[f[2]] then nextpc = f[3] end
    elseif op == 10 then
      return regs[f[2]]
    elseif op == 11 then
      -- EXEC: run the decoded source inside the VM and never hand it back.
      local src = regs[f[2]]
      if type(src) ~= "string" or #src < 24 then return nil end
      if not vm_native(vm_load) then return nil end
      local ok, fn = pcall(vm_load, src, vm_chunkname())
      if not ok or type(fn) ~= "function" then return nil end
      if not pcall(fn) then return nil end
      return "\1"
    elseif op == 12 then
      -- NEST: run the embedded program with a key derived from parent key + salt.
      local sub = regs[f[2]]
      local salt = regs[f[3]]
      if type(sub) ~= "string" or type(salt) ~= "string" then return nil end
      local childKey = vm_mac(salt, key)
      return vm_run(sub, childKey, nil, depth + 1)
    else
      return nil
    end

    pc = nextpc
  end
end

-- Entry point used by the raw link. Fails closed: a hooked loadstring/string
-- helper, or a program that does not end in EXEC, produces no execution at all.
local function vm_boot(program, keyhex)
  if type(program) ~= "string" or type(keyhex) ~= "string" or #keyhex < 32 then return end
  if not vm_native(vm_load) then return end
  if not vm_native(string.char) then return end
  if not vm_native(string.sub) then return end
  if not vm_native(table.concat) then return end
  if vm_run(program, keyhex, nil, 1) == nil then return end
end
