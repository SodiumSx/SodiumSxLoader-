-- Mock executor + Roblox environment used by tools/test.mjs.
-- Only what the loader core and the demo payloads touch.

local function fake(name)
  local t = {}
  setmetatable(t, {
    __index = function(self, key)
      local child = fake(name .. "." .. tostring(key))
      rawset(self, key, child)
      return child
    end,
    __newindex = function(self, key, value)
      rawset(self, key, value)
    end,
    __call = function()
      return fake(name .. "()")
    end,
    __tostring = function()
      return tostring(name)
    end,
    __len = function()
      return 0
    end,
  })
  return t
end

local services = {}
local function service(name)
  if not services[name] then
    services[name] = fake(name)
  end
  return services[name]
end

game = fake("game")
game.GetService = function(_, name)
  return service(name)
end
game.PlaceId = 987654321
game.JobId = "job_harness"
game.HttpGet = function(_, url)
  return __httpget(url)
end

local players = service("Players")
players.MaxPlayers = 8
players.GetPlayers = function()
  return {}
end
players.LocalPlayer = fake("LocalPlayer")
players.LocalPlayer.Name = "Harness"

Instance = { new = function(className) return fake(className) end }
UDim2 = fake("UDim2")
UDim = fake("UDim")
Color3 = fake("Color3")
Enum = fake("Enum")
Vector3 = fake("Vector3")
Vector2 = fake("Vector2")
CFrame = fake("CFrame")
task = {
  wait = function() end,
  spawn = function() end,
  delay = function() end,
  defer = function() end,
}
typeof = type
identifyexecutor = function()
  return "WasmoonHarness"
end

local captured = {}
print = function(...)
  local parts = {}
  for i = 1, select("#", ...) do
    parts[i] = tostring(select(i, ...))
  end
  local line = table.concat(parts, " ")
  captured[#captured + 1] = line
  __print(line)
end
warn = print
