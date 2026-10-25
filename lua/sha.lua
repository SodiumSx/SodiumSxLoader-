-- FreeHub Guard — SHA-256 (bit32, no external deps).
-- Used for the anti-bot proof-of-work and for integrity tags.
local sha_bit = bit32
local sha_mod = 4294967296
local sha_floor = math.floor

local sha_k = {
  1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993,
  2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987,
  1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774,
  264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
  2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711,
  113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
  1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411,
  3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
  430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
  1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424,
  2428436474, 2756734187, 3204031479, 3329325298,
}

local function sha_x3(a, b, c)
  return sha_bit.bxor(sha_bit.bxor(a, b), c)
end

local function sha_hex8(x)
  local buf = {}
  for i = 8, 1, -1 do
    local nib = x % 16
    buf[i] = string.sub("0123456789abcdef", nib + 1, nib + 1)
    x = sha_floor(x / 16)
  end
  return table.concat(buf)
end

local function sha256_hex(msg)
  local h0, h1, h2, h3 = 1779033703, 3144134277, 1013904242, 2773480762
  local h4, h5, h6, h7 = 1359893119, 2600822924, 528734635, 1541459225

  local len = #msg
  local bitlen = len * 8
  local pad = (56 - ((len + 1) % 64)) % 64
  local hi = sha_floor(bitlen / 4294967296)
  local lo = bitlen % 4294967296

  msg = msg
    .. "\128"
    .. string.rep("\0", pad)
    .. string.char(
      sha_floor(hi / 16777216) % 256,
      sha_floor(hi / 65536) % 256,
      sha_floor(hi / 256) % 256,
      hi % 256,
      sha_floor(lo / 16777216) % 256,
      sha_floor(lo / 65536) % 256,
      sha_floor(lo / 256) % 256,
      lo % 256
    )

  local w = {}
  for off = 1, #msg, 64 do
    for i = 1, 16 do
      local o = off + (i - 1) * 4
      local b1, b2, b3, b4 = string.byte(msg, o, o + 3)
      w[i] = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
    end
    for i = 17, 64 do
      local x = w[i - 15]
      local y = w[i - 2]
      local s0 = sha_x3(sha_bit.rrotate(x, 7), sha_bit.rrotate(x, 18), sha_bit.rshift(x, 3))
      local s1 = sha_x3(sha_bit.rrotate(y, 17), sha_bit.rrotate(y, 19), sha_bit.rshift(y, 10))
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % sha_mod
    end

    local a, b, c, d = h0, h1, h2, h3
    local e, f, g, h = h4, h5, h6, h7

    for i = 1, 64 do
      local S1 = sha_x3(sha_bit.rrotate(e, 6), sha_bit.rrotate(e, 11), sha_bit.rrotate(e, 25))
      local ch = sha_bit.bxor(sha_bit.band(e, f), sha_bit.band(sha_bit.bnot(e), g))
      local t1 = (h + S1 + ch + sha_k[i] + w[i]) % sha_mod
      local S0 = sha_x3(sha_bit.rrotate(a, 2), sha_bit.rrotate(a, 13), sha_bit.rrotate(a, 22))
      local maj = sha_x3(sha_bit.band(a, b), sha_bit.band(a, c), sha_bit.band(b, c))
      local t2 = (S0 + maj) % sha_mod
      h = g
      g = f
      f = e
      e = (d + t1) % sha_mod
      d = c
      c = b
      b = a
      a = (t1 + t2) % sha_mod
    end

    h0 = (h0 + a) % sha_mod
    h1 = (h1 + b) % sha_mod
    h2 = (h2 + c) % sha_mod
    h3 = (h3 + d) % sha_mod
    h4 = (h4 + e) % sha_mod
    h5 = (h5 + f) % sha_mod
    h6 = (h6 + g) % sha_mod
    h7 = (h7 + h) % sha_mod
  end

  return sha_hex8(h0) .. sha_hex8(h1) .. sha_hex8(h2) .. sha_hex8(h3)
    .. sha_hex8(h4) .. sha_hex8(h5) .. sha_hex8(h6) .. sha_hex8(h7)
end
