-- FreeHub demo payload. Keep the first line descriptive: the build shows it in logs.
local Players = game:GetService("Players")
local player = Players.LocalPlayer

local function notify(text)
  pcall(function()
    game:GetService("StarterGui"):SetCore("SendNotification", {
      Title = "FreeHub",
      Text = text,
      Duration = 5,
    })
  end)
end

notify("Loaded for " .. tostring(player and player.Name or "player"))

local gui = Instance.new("ScreenGui")
gui.Name = "FreeHubExample"
gui.ResetOnSpawn = false
gui.Parent = player:WaitForChild("PlayerGui")

local frame = Instance.new("Frame")
frame.Size = UDim2.fromOffset(260, 110)
frame.Position = UDim2.fromOffset(24, 24)
frame.BackgroundColor3 = Color3.fromRGB(18, 18, 22)
frame.BorderSizePixel = 0
frame.Active = true
frame.Draggable = true
frame.Parent = gui

local corner = Instance.new("UICorner")
corner.CornerRadius = UDim.new(0, 8)
corner.Parent = frame

local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, -16, 0, 28)
title.Position = UDim2.fromOffset(8, 8)
title.BackgroundTransparency = 1
title.Font = Enum.Font.GothamBold
title.TextSize = 15
title.TextColor3 = Color3.fromRGB(240, 240, 245)
title.TextXAlignment = Enum.TextXAlignment.Left
title.Text = "FreeHub • Example"
title.Parent = frame

local body = Instance.new("TextLabel")
body.Size = UDim2.new(1, -16, 1, -44)
body.Position = UDim2.fromOffset(8, 36)
body.BackgroundTransparency = 1
body.Font = Enum.Font.Gotham
body.TextSize = 13
body.TextColor3 = Color3.fromRGB(160, 160, 175)
body.TextXAlignment = Enum.TextXAlignment.Left
body.TextYAlignment = Enum.TextYAlignment.Top
body.TextWrapped = true
body.Text = "Loaded from a protected raw link.\nNo key, no HWID, no login."
body.Parent = frame

print("[FreeHub] example payload running")
