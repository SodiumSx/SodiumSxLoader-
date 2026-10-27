-- FreeHub Guard — VM runtime.
-- Byte-for-byte twin of lib/crypto.mjs (ksSeg/mac) and lib/vm.mjs (program
-- format). Executed inside the client, so it only uses bit32 + string + table.
--
-- Performance notes (measured, Lua 5.4 in WASM):
--   * conts are decoded in one pass: base64 + keystream XOR folded together and
--     flushed through string.char() in blocks instead of once per byte
--   * the keystream is a xorshift word XORed with the key each round (no
--     32-bit multiply in the hot loop)
--   * instructions are parsed once into a flat numeric array, so the dispatch
--     loop never touches string patterns again
local vm_bit = bit32
local vm_mod = 4294967296
local vm_floor = math.floor
local vm_byte = string.byte
local vm_char = string.char
local vm_sub = string.sub
local vm_find = string.find
local vm_gmatch = string.gmatch
local vm_match = string.match
local vm_concat = table.concat
local vm_unpack = unpack or table.unpack

local function vm_bxor(a, b)
  return vm_bit.bxor(a, b)
end

-- 32-bit multiply without floating point overflow (only used off the hot path).
local function vm_imul(a, b)
  local ah = vm_floor(a / 65536)
  local al = a % 65536
  return (al * b + ((ah * b) % 65536) * 65536) % vm_mod
end

local vm_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
local vm_b64map = {}
for i = 1, 64 do
  vm_b64map[vm_byte(vm_alpha, i)] = i - 1
end

-- Base64url decode of a plain constant (no keystream). Used by SETL.
local function vm_b64(s)
  local n = #s
  local m = vm_b64map
  local parts, pn = {}, 0
  local buf, bn = {}, 0
  local i = 1
  local full = n - (n % 4)
  while i <= full do
    local v = ((m[vm_byte(s, i)] * 64 + m[vm_byte(s, i + 1)]) * 64
      + m[vm_byte(s, i + 2)]) * 64 + m[vm_byte(s, i + 3)]
    i = i + 4
    buf[bn + 1] = vm_floor(v / 65536)
    buf[bn + 2] = vm_floor(v / 256) % 256
    buf[bn + 3] = v % 256
    bn = bn + 3
    if bn >= 45 then
      pn = pn + 1
      parts[pn] = vm_char(vm_unpack(buf, 1, bn))
      buf, bn = {}, 0
    end
  end
  if i <= n then
    local v = 0
    local left = 0
    while i <= n do
      v = v * 64 + m[vm_byte(s, i)]
      i = i + 1
      left = left + 6
    end
    if left == 12 then
      buf[bn + 1] = vm_floor(v / 16) % 256
      bn = bn + 1
    elseif left == 18 then
      buf[bn + 1] = vm_floor(v / 1024) % 256
      buf[bn + 2] = vm_floor(v / 4) % 256
      bn = bn + 2
    end
  end
  if bn > 0 then
    pn = pn + 1
    parts[pn] = vm_char(vm_unpack(buf, 1, bn))
  end
  return vm_concat(parts)
end

-- Keystream + base64 decode in a single pass.
--
-- The keystream word is xorshift32(t) ^ k[3], three bytes per word, which
-- mirrors ksSeg() in lib/crypto.mjs exactly. Base64url groups are four chars
-- for three bytes, so every iteration consumes one word and one group: no
-- carry state, no intermediate string, and one string.char() call per block.
local vm_blk = 60

local function vm_unseal(raw, k, seed)
  local n = #raw
  local m = vm_b64map
  local bx, by, ch, up = vm_bxor, vm_byte, string.char, vm_unpack
  local k2, k3 = k[2], k[3]
  local t = bx((k[1] + vm_imul(seed + 1, 2654435761)) % vm_mod, k2)
  local parts, pn = {}, 0
  local buf, bn = {}, 0
  local i = 1
  local full = n - (n % 4)
  while i <= full do
    local v = ((m[by(raw, i)] * 64 + m[by(raw, i + 1)]) * 64
      + m[by(raw, i + 2)]) * 64 + m[by(raw, i + 3)]
    i = i + 4
    t = bx(t, (t * 8192) % vm_mod)
    t = bx(t, vm_floor(t / 131072))
    t = bx(t, (t * 32) % vm_mod)
    t = bx(t, k3)
    buf[bn + 1] = bx(vm_floor(v / 65536), t % 256)
    buf[bn + 2] = bx(vm_floor(v / 256) % 256, vm_floor(t / 256) % 256)
    buf[bn + 3] = bx(v % 256, vm_floor(t / 65536) % 256)
    bn = bn + 3
    if bn >= vm_blk then
      pn = pn + 1
      parts[pn] = ch(up(buf, 1, bn))
      buf, bn = {}, 0
    end
  end
  if i <= n then
    -- 2 or 3 leftover chars: 1 or 2 plaintext bytes from the next word.
    local v, left = 0, 0
    while i <= n do
      v = v * 64 + m[by(raw, i)]
      i = i + 1
      left = left + 6
    end
    t = bx(t, (t * 8192) % vm_mod)
    t = bx(t, vm_floor(t / 131072))
    t = bx(t, (t * 32) % vm_mod)
    t = bx(t, k3)
    if left == 12 then
      buf[bn + 1] = bx(vm_floor(v / 16) % 256, t % 256)
      bn = bn + 1
    elseif left == 18 then
      buf[bn + 1] = bx(vm_floor(v / 1024) % 256, t % 256)
      buf[bn + 2] = bx(vm_floor(v / 4) % 256, vm_floor(t / 256) % 256)
      bn = bn + 2
    end
  end
  if bn > 0 then
    pn = pn + 1
    parts[pn] = ch(up(buf, 1, bn))
  end
  return vm_concat(parts)
end

local function vm_key(hex)
  local k = {}
  for i = 0, 3 do
    local o = i * 8
    local b1 = tonumber(vm_sub(hex, o + 1, o + 2), 16) or 0
    local b2 = tonumber(vm_sub(hex, o + 3, o + 4), 16) or 0
    local b3 = tonumber(vm_sub(hex, o + 5, o + 6), 16) or 0
    local b4 = tonumber(vm_sub(hex, o + 7, o + 8), 16) or 0
    k[i + 1] = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
  end
  return k
end

local vm_hexmap = "0123456789abcdef"

local function vm_hex8(x)
  local buf = {}
  for i = 8, 1, -1 do
    local nib = x % 16
    buf[i] = vm_sub(vm_hexmap, nib + 1, nib + 1)
    x = vm_floor(x / 16)
  end
  return vm_concat(buf)
end

-- Keyed tamper check: four polynomial lanes over every byte, folded twice.
-- Mirrors mac() in lib/crypto.mjs. 65599 * (2^32-1) is exactly representable,
-- so doubles and integers agree to the last bit.
local function vm_mac(data, k)
  local h1 = vm_bxor(2166136261, k[1])
  local h2 = vm_bxor(16777619, k[2])
  local h3 = vm_bxor(2654435769, k[3])
  local h4 = vm_bxor(2246822507, k[4])
  local n = #data
  local by = vm_byte
  local full = n - (n % 4)
  local i = 1
  while i <= full do
    local a, b, c, d = by(data, i, i + 3)
    h1 = (h1 * 65599 + a) % vm_mod
    h2 = (h2 * 65599 + b) % vm_mod
    h3 = (h3 * 65599 + c) % vm_mod
    h4 = (h4 * 65599 + d) % vm_mod
    i = i + 4
  end
  while i <= n do
    local lane = (i - 1) % 4
    local b = by(data, i)
    if lane == 0 then
      h1 = (h1 * 65599 + b) % vm_mod
    elseif lane == 1 then
      h2 = (h2 * 65599 + b) % vm_mod
    elseif lane == 2 then
      h3 = (h3 * 65599 + b) % vm_mod
    else
      h4 = (h4 * 65599 + b) % vm_mod
    end
    i = i + 1
  end
  h4 = (h4 + n) % vm_mod
  for _ = 1, 2 do
    local t1, t2, t3, t4 = h1, h2, h3, h4
    h1 = (h1 * 65599 + t2) % vm_mod
    h2 = (h2 * 65599 + t3) % vm_mod
    h3 = (h3 * 65599 + t4) % vm_mod
    h4 = (h4 * 65599 + t1) % vm_mod
  end
  return vm_hex8(h1) .. vm_hex8(h2) .. vm_hex8(h3) .. vm_hex8(h4)
end

-- Native runner + guard live inside the VM so the delivered stub has no
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

-- Flat instruction array: five slots per instruction (opcode + four args).
local function vm_parse(codeText, rev)
  local ins, count = {}, 0
  for line in vm_gmatch(codeText, "[^;]+") do
    local a, b, c, d, e = vm_match(line, "^(%d+),(%d+),?(%d*),?(%d*),?(%d*)$")
    local o = count * 5
    count = count + 1
    ins[o + 1] = rev[tonumber(a) or -1]
    ins[o + 2] = tonumber(b) or 0
    ins[o + 3] = tonumber(c) or 0
    ins[o + 4] = tonumber(d) or 0
    ins[o + 5] = tonumber(e) or 0
  end
  return ins, count
end

local function vm_step(program, keyhex, maxSteps, depth)
  if depth > 6 then return nil end
  if type(program) ~= "string" or type(keyhex) ~= "string" or #keyhex < 32 then
    return nil
  end
  local n1 = vm_find(program, "\n", 1, true)
  if not n1 then return nil end
  local n2 = vm_find(program, "\n", n1 + 1, true)
  if not n2 then return nil end
  local head = vm_sub(program, 1, n1 - 1)
  local constsText = vm_sub(program, n1 + 1, n2 - 1)
  local codeText = vm_sub(program, n2 + 1)

  local permText, regText = vm_match(head, "^(.-)|(%d+)$")
  if not permText then return nil end

  local rev, internal = {}, 0
  for num in vm_gmatch(permText, "%d+") do
    rev[tonumber(num)] = internal
    internal = internal + 1
  end

  local consts, ci = {}, 0
  for c in vm_gmatch(constsText, "[^,]+") do
    ci = ci + 1
    consts[ci] = c
  end

  local ins, count = vm_parse(codeText, rev)
  if count == 0 then return nil end

  local key = vm_key(keyhex)
  local regs = {}
  local pc, steps = 1, 0
  local limit = maxSteps or (count * 16 + 200000)

  while true do
    steps = steps + 1
    if steps > limit or pc < 1 or pc > count then return nil end

    local o = (pc - 1) * 5
    local op = ins[o + 1]
    local a, b, c, d = ins[o + 2], ins[o + 3], ins[o + 4], ins[o + 5]
    local nextpc = pc + 1

    if op == 0 then
      local raw = consts[b]
      if not raw then return nil end
      regs[a] = vm_unseal(raw, key, b - 1)
    elseif op == 1 then
      local raw = consts[b]
      if not raw then return nil end
      regs[a] = vm_b64(raw)
    elseif op == 2 then
      regs[a] = regs[b]
    elseif op == 3 then
      regs[a] = regs[b] .. regs[c]
    elseif op == 4 then
      local x, y = regs[b], regs[c]
      if type(x) ~= "string" or type(y) ~= "string" or #y == 0 then return nil end
      local out, lb, n = {}, #y, #x
      for i = 1, n do
        out[i] = vm_char(vm_bxor(vm_byte(x, i), vm_byte(y, (i - 1) % lb + 1)))
      end
      regs[a] = vm_concat(out)
    elseif op == 5 then
      local x = regs[b]
      if type(x) ~= "string" then return nil end
      regs[a] = vm_sub(x, c + 1, c + d)
    elseif op == 6 then
      local x = regs[b]
      if type(x) ~= "string" then return nil end
      regs[a] = string.reverse(x)
    elseif op == 7 then
      regs[a] = b
    elseif op == 8 then
      nextpc = a
    elseif op == 9 then
      if regs[a] then nextpc = b end
    elseif op == 10 then
      return regs[a]
    elseif op == 11 then
      -- EXEC: run the decoded source inside the VM and never hand it back.
      local src = regs[a]
      if type(src) ~= "string" or #src < 24 then return nil end
      if not vm_native(vm_load) then return nil end
      local ok, fn = pcall(vm_load, src, vm_chunkname())
      if not ok or type(fn) ~= "function" then return nil end
      if not pcall(fn) then return nil end
      return "\1"
    elseif op == 12 then
      -- NEST: run the embedded program with a key derived from parent key + salt.
      local sub, salt = regs[a], regs[b]
      if type(sub) ~= "string" or type(salt) ~= "string" then return nil end
      return vm_run(sub, vm_mac(salt, key), nil, depth + 1)
    else
      return nil
    end

    pc = nextpc
  end
end

-- Public entry point. Every failure mode (bad program, hooked natives, corrupt
-- const) returns nil instead of raising, so a tampered delivery can never turn
-- into an "attempt to call a nil value" in the console.
vm_run = function (program, keyhex, maxSteps, depth)
  local ok, result = pcall(vm_step, program, keyhex, maxSteps, depth or 1)
  if ok then return result end
  return nil
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
