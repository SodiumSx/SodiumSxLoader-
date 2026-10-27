-- FreeHub Guard — SHA-256 (bit32, no external deps).
-- Used for the anti-bot proof-of-work and for integrity tags.
--
-- Split into three parts on purpose: `sha_prefix` compresses the full 64-byte
-- blocks of a message and keeps the state, `sha_finish` pads and compresses the
-- remainder. The proof-of-work grinds `challenge .. ":" .. counter`, where the
-- prefix is identical for every attempt and is exactly one block long, so the
-- fixed work happens once per challenge instead of once per hash.
local sha_bit = bit32
local sha_mod = 4294967296
local sha_floor = math.floor
local sha_bxor = sha_bit.bxor
local sha_band = sha_bit.band
local sha_bnot = sha_bit.bnot
local sha_rrotate = sha_bit.rrotate
local sha_rshift = sha_bit.rshift
local sha_byte = string.byte
local sha_char = string.char
local sha_rep = string.rep
local sha_sub = string.sub
local sha_format = string.format
local sha_concat = table.concat

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

local function sha_hex8(x)
  return sha_format("%08x", x)
end

-- Compress one 64-byte block starting at `off` into the given state.
local function sha_block(h0, h1, h2, h3, h4, h5, h6, h7, msg, off)
  local w = {}
  for i = 1, 16 do
    local o = off + (i - 1) * 4
    local b1, b2, b3, b4 = sha_byte(msg, o, o + 3)
    w[i] = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
  end
  for i = 17, 64 do
    local x = w[i - 15]
    local y = w[i - 2]
    local s0 = sha_bxor(sha_bxor(sha_rrotate(x, 7), sha_rrotate(x, 18)), sha_rshift(x, 3))
    local s1 = sha_bxor(sha_bxor(sha_rrotate(y, 17), sha_rrotate(y, 19)), sha_rshift(y, 10))
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % sha_mod
  end

  local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

  for i = 1, 64 do
    local S1 = sha_bxor(sha_bxor(sha_rrotate(e, 6), sha_rrotate(e, 11)), sha_rrotate(e, 25))
    local ch = sha_bxor(sha_band(e, f), sha_band(sha_bnot(e), g))
    local t1 = (h + S1 + ch + sha_k[i] + w[i]) % sha_mod
    local S0 = sha_bxor(sha_bxor(sha_rrotate(a, 2), sha_rrotate(a, 13)), sha_rrotate(a, 22))
    local maj = sha_bxor(sha_bxor(sha_band(a, b), sha_band(a, c)), sha_band(b, c))
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

  return (h0 + a) % sha_mod, (h1 + b) % sha_mod, (h2 + c) % sha_mod, (h3 + d) % sha_mod,
    (h4 + e) % sha_mod, (h5 + f) % sha_mod, (h6 + g) % sha_mod, (h7 + h) % sha_mod
end

local function sha_state()
  return 1779033703, 3144134277, 1013904242, 2773480762,
    1359893119, 2600822924, 528734635, 1541459225
end

-- Compress the full 64-byte blocks of `data`; return the state, how many bytes
-- were consumed, and the unterminated remainder.
local function sha_prefix(data)
  local n = #data
  local full = n - (n % 64)
  local h0, h1, h2, h3, h4, h5, h6, h7 = sha_state()
  for off = 1, full, 64 do
    h0, h1, h2, h3, h4, h5, h6, h7 = sha_block(h0, h1, h2, h3, h4, h5, h6, h7, data, off)
  end
  local rest = ""
  if full < n then rest = sha_sub(data, full + 1) end
  return h0, h1, h2, h3, h4, h5, h6, h7, full, rest
end

-- Pad `rest` (the bytes after `done` already-compressed bytes) and finish.
local function sha_finish(h0, h1, h2, h3, h4, h5, h6, h7, done, rest)
  local pad = (56 - ((#rest + 1) % 64)) % 64
  local bitlen = (done + #rest) * 8
  local hi = sha_floor(bitlen / sha_mod)
  local lo = bitlen % sha_mod
  local tail = rest
    .. "\128"
    .. sha_rep("\0", pad)
    .. sha_char(
      sha_floor(hi / 16777216) % 256,
      sha_floor(hi / 65536) % 256,
      sha_floor(hi / 256) % 256,
      hi % 256,
      sha_floor(lo / 16777216) % 256,
      sha_floor(lo / 65536) % 256,
      sha_floor(lo / 256) % 256,
      lo % 256
    )
  for off = 1, #tail, 64 do
    h0, h1, h2, h3, h4, h5, h6, h7 = sha_block(h0, h1, h2, h3, h4, h5, h6, h7, tail, off)
  end
  return sha_concat({
    sha_hex8(h0), sha_hex8(h1), sha_hex8(h2), sha_hex8(h3),
    sha_hex8(h4), sha_hex8(h5), sha_hex8(h6), sha_hex8(h7),
  })
end

local function sha256_hex(msg)
  local h0, h1, h2, h3, h4, h5, h6, h7, done, rest = sha_prefix(msg)
  return sha_finish(h0, h1, h2, h3, h4, h5, h6, h7, done, rest)
end
