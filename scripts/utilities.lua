-- FreeHub utilities demo.
local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

local function copy(text)
  if setclipboard then
    pcall(setclipboard, text)
    return true
  end
  return false
end

local function info()
  local placeId = game.PlaceId
  local jobId = game.JobId
  local ping = "n/a"
  pcall(function()
    ping = math.floor(LocalPlayer:GetNetworkPing() * 1000) .. " ms"
  end)
  return table.concat({
    "Place: " .. tostring(placeId),
    "Job: " .. tostring(jobId ~= "" and jobId or "private"),
    "Ping: " .. ping,
    "Players: " .. #Players:GetPlayers() .. "/" .. Players.MaxPlayers,
  }, "\n")
end

local screen = Instance.new("ScreenGui")
screen.Name = "FreeHubUtilities"
screen.ResetOnSpawn = false
screen.Parent = LocalPlayer:WaitForChild("PlayerGui")

local panel = Instance.new("Frame")
panel.Size = UDim2.fromOffset(300, 220)
panel.Position = UDim2.fromOffset(320, 24)
panel.BackgroundColor3 = Color3.fromRGB(16, 17, 21)
panel.BorderSizePixel = 0
panel.Active = true
panel.Draggable = true
panel.Parent = screen

local corner = Instance.new("UICorner")
corner.CornerRadius = UDim.new(0, 10)
corner.Parent = panel

local label = Instance.new("TextLabel")
label.Size = UDim2.new(1, -20, 0, 150)
label.Position = UDim2.fromOffset(10, 10)
label.BackgroundTransparency = 1
label.Font = Enum.Font.Code
label.TextSize = 13
label.TextColor3 = Color3.fromRGB(220, 220, 230)
label.TextXAlignment = Enum.TextXAlignment.Left
label.TextYAlignment = Enum.TextYAlignment.Top
label.Text = info()
label.Parent = panel

local button = Instance.new("TextButton")
button.Size = UDim2.new(0, 130, 0, 32)
button.Position = UDim2.fromOffset(10, 172)
button.BackgroundColor3 = Color3.fromRGB(88, 101, 242)
button.BorderSizePixel = 0
button.Font = Enum.Font.GothamBold
button.TextSize = 13
button.TextColor3 = Color3.new(1, 1, 1)
button.Text = "Copy job id"
button.Parent = panel

local buttonCorner = Instance.new("UICorner")
buttonCorner.CornerRadius = UDim.new(0, 6)
buttonCorner.Parent = button

button.MouseButton1Click:Connect(function()
  if copy(game.JobId) then
    button.Text = "Copied"
  else
    button.Text = "No clipboard"
  end
  task.wait(1.5)
  button.Text = "Copy job id"
end)

local refresh = button:Clone()
refresh.Position = UDim2.fromOffset(150, 172)
refresh.Text = "Refresh"
refresh.Parent = panel
refresh.MouseButton1Click:Connect(function()
  label.Text = info()
end)

task.spawn(function()
  while panel.Parent do
    label.Text = info()
    task.wait(5)
  end
end)

print("[FreeHub] utilities payload running • " .. tostring(game.PlaceId))
