-- FreeHub Guard — runtime environment audit.
--
-- Protection here is layered and fail-closed: hooks installed by environment
-- loggers, dumpers and spyware usually replace a native C function with a Lua
-- closure. Luau reports the chunk source of a function, so a wrapped native is
-- detectable even before it is used.
local guard_first = nil

local function guard_src(f)
  if type(f) ~= "function" then return nil end
  local d = debug
  if not d then return nil end
  local ok, src = pcall(function()
    if d.info then return d.info(f, "s") end
    if d.getinfo then
      local info = d.getinfo(f, "S")
      return info and info.source
    end
    return nil
  end)
  if ok and type(src) == "string" then return src end
  return nil
end

-- A native is always reported as "[C]" (Luau) / "=[C]" (Lua). Anything else
-- means a Lua closure replaced it: that is exactly what env loggers, dumpers
-- and hooking libraries install.
local function guard_wrapped(f)
  local src = guard_src(f)
  if not src then return false end
  return src ~= "[C]" and src ~= "=[C]"
end

local function guard_lower(s)
  return type(s) == "string" and string.lower(s) or ""
end

-- Detects natives being swapped between two audit passes (late-installed spy).
local function guard_drift()
  local current = {
    loadstring or load,
    string.char,
    string.sub,
    table.concat,
    tostring,
    pcall,
    setmetatable,
  }
  if guard_first then
    for i = 1, #current do
      if current[i] ~= guard_first[i] then return true end
    end
    return false
  end
  guard_first = current
  return false
end

local function guard_audit(executor)
  local score, tags = 0, {}
  local function bump(n, tag)
    score = score + n
    tags[#tags + 1] = tag
  end

  local natives = {
    { "loadstring", loadstring or load },
    { "string.char", string.char },
    { "string.sub", string.sub },
    { "table.concat", table.concat },
    { "tostring", tostring },
    { "setmetatable", setmetatable },
    { "pcall", pcall },
  }
  for i = 1, #natives do
    if guard_wrapped(natives[i][2]) then
      bump(3, "hook:" .. natives[i][1])
    end
  end

  -- __namecall / metamethod hooks are how most spying tools observe the game.
  local gameType = type(game)
  if type(getrawmetatable) == "function" and (gameType == "table" or gameType == "userdata") then
    local ok, mt = pcall(getrawmetatable, game)
    if ok and type(mt) == "table" then
      local names = { "__namecall", "__index", "__newindex", "__tostring", "__eq", "__concat" }
      for i = 1, #names do
        local fn = rawget(mt, names[i])
        if fn ~= nil and guard_wrapped(fn) then
          bump(3, "mt:" .. names[i])
        end
      end
    end
  end

  local genv
  if type(getgenv) == "function" then
    local ok, g = pcall(getgenv)
    if ok and type(g) == "table" then genv = g end
  end
  genv = genv or _G

  if type(genv) == "table" then
    local mt = getmetatable(genv)
    if type(mt) == "table" then
      if rawget(mt, "__index") ~= nil or rawget(mt, "__newindex") ~= nil then
        bump(2, "envproxy")
      end
    end
  end

  if debug and type(debug.gethook) == "function" then
    local ok, hook = pcall(debug.gethook)
    if ok and hook ~= nil then bump(2, "debughook") end
  end

  local spies = {
    "envlog", "env_log", "envlogger", "__envlog", "envlog_hook",
    "keylogger", "key_log", "__spy", "spy", "capture_env", "envdump",
  }
  if type(genv) == "table" then
    pcall(function()
      local seen = 0
      for k in pairs(genv) do
        seen = seen + 1
        if seen > 900 then break end
        if type(k) == "string" then
          local low = string.lower(k)
          for i = 1, #spies do
            if low == spies[i] then
              bump(3, "spy:" .. low)
              break
            end
          end
        end
      end
    end)
  end

  -- A hook that calls into us from a C boundary breaks the executor's caller
  -- chain. Synapse/Fluxus style wrapper predicates catch the rest.
  if type(checkcaller) == "function" then
    local ok, caller = pcall(checkcaller)
    if ok and caller == false then bump(3, "caller") end
  end

  local wrapperChecks = {
    "is_synapse_function",
    "is_protosmasher_closure",
    "is_sirhurt_closure",
    "is_fluxus_closure",
  }
  for i = 1, #wrapperChecks do
    local probe = rawget(_G, wrapperChecks[i])
    if type(probe) == "function" then
      for j = 1, #natives do
        local ok, hit = pcall(probe, natives[j][2])
        if ok and hit == true then bump(3, "wrapper:" .. natives[j][1]) break end
      end
    end
  end

  local name = guard_lower(executor)
  if name == "" or name == "unknown" then
    bump(2, "noexec")
  end
  local bots = { "curl", "wget", "python", "httpie", "postman", "insomnia", "browser", "node.js", "axios" }
  for i = 1, #bots do
    if string.find(name, bots[i], 1, true) then
      bump(5, "bot")
      break
    end
  end

  if guard_drift() then bump(3, "drift") end

  return score, tags
end
