-- FreeHub Guard — loader core.
-- Delivered only as a VM program (layer 1). Receives HOST and SCRIPT ID from
-- the stage runner as chunk arguments.

local core_host, core_sid = ...
core_host = tostring(core_host or "")
core_sid = tostring(core_sid or "")
while string.sub(core_host, -1) == "/" do
  core_host = string.sub(core_host, 1, -2)
end

local core_cat = table.concat
local core_loader = loadstring or load

local function core_rndhex(bytes)
  local out = {}
  for i = 1, bytes do
    out[i] = string.format("%02x", math.random(0, 255))
  end
  return core_cat(out)
end

local function core_urlenc(s)
  local out = {}
  for i = 1, #s do
    local b = string.byte(s, i)
    local c = string.char(b)
    if string.find(c, "[%w%-%._~]") then
      out[i] = c
    else
      out[i] = string.format("%%%02X", b)
    end
  end
  return core_cat(out)
end

local function core_kv(text)
  local t = {}
  if type(text) ~= "string" then return t end
  for k, v in string.gmatch(text, "([%w_]+)=([^&\r\n]*)") do
    t[k] = v
  end
  return t
end

local function core_request(url)
  local genv = _G
  if type(getgenv) == "function" then
    local ok, g = pcall(getgenv)
    if ok and type(g) == "table" then genv = g end
  end
  local fn = genv.request or genv.http_request
  if type(fn) ~= "function" and type(genv.syn) == "table" then fn = genv.syn.request end
  if type(fn) ~= "function" and type(genv.fluxus) == "table" then fn = genv.fluxus.request end
  if type(fn) ~= "function" then return nil end
  local ok, res = pcall(fn, { Url = url, Method = "GET", Headers = { ["Accept"] = "text/plain" } })
  if not ok or type(res) ~= "table" then return nil end
  return res.Body or res.body
end

local function core_get(url)
  if type(game) == "table" or type(game) == "userdata" then
    local ok, body = pcall(function()
      return game:HttpGet(url)
    end)
    if ok and type(body) == "string" and #body > 0 then return body end
  end
  return core_request(url)
end

local function core_zeroBits(hex)
  local bits = 0
  for i = 1, #hex do
    local n = tonumber(string.sub(hex, i, i), 16)
    if not n then return bits end
    if n ~= 0 then
      if n < 2 then
        bits = bits + 3
      elseif n < 4 then
        bits = bits + 2
      elseif n < 8 then
        bits = bits + 1
      end
      return bits
    end
    bits = bits + 4
  end
  return bits
end

local function core_solve(challenge, bits)
  -- The challenge prefix is fixed for every attempt, and it is exactly one
  -- SHA-256 block long, so its compression is done once here instead of once
  -- per hash. That halves the cost of the whole proof-of-work grind.
  local prefix = challenge .. ":"
  local h0, h1, h2, h3, h4, h5, h6, h7, done, rest = sha_prefix(prefix)
  local limit = 2 ^ bits + (2 ^ bits) * 4
  if limit > 4000000 then limit = 4000000 end
  for w = 0, limit do
    local hex = sha_finish(h0, h1, h2, h3, h4, h5, h6, h7, done, rest .. w)
    if core_zeroBits(hex) >= bits then return w end
  end
  return nil
end

local function core_fail(tag)
  pcall(function() print("[FreeHub] loader stopped (" .. tostring(tag) .. ")") end)
end

local function core_invoke(src)
  local okCall, fn = pcall(function()
    return core_loader(src, "=" .. core_rndhex(6))
  end)
  if not okCall or type(fn) ~= "function" then return false end

  local real = _G
  if type(getgenv) == "function" then
    local ok, g = pcall(getgenv)
    if ok and type(g) == "table" then real = g end
  end
  if type(real) ~= "table" then real = _G end

  -- Sandbox with a *table* fallback instead of a function.
  --
  -- `__index = real` means reading an untouched global is one C-level table
  -- lookup; the previous version routed every global read through a Lua
  -- closure, which is a real cost in a payload that polls in a loop. Writes
  -- land in the sandbox table itself (via __newindex on the first write, and
  -- directly afterwards), so they shadow the real environment without ever
  -- touching it.
  local env = setmetatable({}, {
    __index = real,
    __newindex = function(t, k, v)
      rawset(t, k, v)
    end,
    __metatable = false,
    __tostring = function() return "env" end,
  })

  rawset(env, "getgenv", function() return env end)
  rawset(env, "getfenv", function() return env end)
  rawset(env, "getrenv", function() return real end)
  rawset(env, "setfenv", function(f) return f end)

  if type(setfenv) == "function" then
    pcall(setfenv, fn, env)
  end
  local okRun, runErr = pcall(fn)
  -- Hub authors can opt into script errors with __FREEHUB_DEBUG = true.
  if not okRun and rawget(env, "__FREEHUB_DEBUG") == true then
    pcall(function() print("[FreeHub] script error: " .. tostring(runErr)) end)
  end
  env = nil
  return okRun
end

local function core_main()
  local executor = "unknown"
  if type(identifyexecutor) == "function" then
    local ok, name = pcall(identifyexecutor)
    if ok and type(name) == "string" and #name > 0 then executor = name end
  end

  local place = 0
  pcall(function()
    if type(game) == "table" or type(game) == "userdata" then
      place = tonumber(game.PlaceId) or tonumber(game.GameId) or 0
    end
  end)

  if guard_audit(executor) >= 3 then
    core_fail("env")
    return
  end

  local nonce = core_rndhex(16)
  local challengeText = core_get(core_host .. "/api/challenge?id=" .. core_sid .. "&n=" .. nonce .. "&r=" .. core_rndhex(3))
  local challenge = core_kv(challengeText)
  local bits = tonumber(challenge.d)
  if type(challenge.c) ~= "string" or #challenge.c < 32 or not bits or bits < 1 or bits > 24 then
    core_fail("challenge")
    return
  end

  local solution = core_solve(challenge.c, bits)
  if not solution then
    core_fail("pow")
    return
  end

  local sessionText = core_get(
    core_host
      .. "/api/session?id="
      .. core_sid
      .. "&n="
      .. nonce
      .. "&w="
      .. solution
      .. "&e="
      .. core_urlenc(executor)
      .. "&p="
      .. tostring(math.floor(place))
      .. "&r="
      .. core_rndhex(4)
  )
  local session = core_kv(sessionText)
  local token, key = session.t, session.k
  if type(token) ~= "string" or #token < 24 or type(key) ~= "string" or #key ~= 32 then
    core_fail("session")
    return
  end

  local payloadText = core_get(
    core_host .. "/api/payload/" .. core_sid .. "?t=" .. core_urlenc(token) .. "&r=" .. core_rndhex(4)
  )
  local split = type(payloadText) == "string" and string.find(payloadText, "\n\n", 1, true) or nil
  if not split then
    core_fail("payload")
    return
  end
  local meta = core_kv(string.sub(payloadText, 1, split - 1))
  local program = string.sub(payloadText, split + 2)
  if not meta.m or #meta.m ~= 32 then
    core_fail("meta")
    return
  end

  local source = vm_run(program, key)
  if type(source) ~= "string" or #source < 8 then
    core_fail("decode")
    return
  end
  if vm_mac(source, vm_key(key)) ~= meta.m then
    core_fail("tamper")
    return
  end
  if meta.z and tonumber(meta.z) ~= #source then
    core_fail("length")
    return
  end

  if guard_audit(executor) >= 3 then
    core_fail("env2")
    return
  end

  core_invoke(source)
end

core_main()
