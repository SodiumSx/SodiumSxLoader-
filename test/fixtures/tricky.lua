-- line comment that must disappear
local out = {}

local quoted = "double \" quote, backslash \\ and newline \n end"
out[#out + 1] = quoted

out[#out + 1] = 'single \' quote'
out[#out + 1] = "tab\there and bell\7"

--[[ block
     comment ]]
out[#out + 1] = [==[long string with ]] inside]==]
out[#out + 1] = [[
leading newline is dropped]]

local number = 0x1F + 1.5e2 + .5
out[#out + 1] = tostring(number)
out[#out + 1] = ("ab"):rep(3) .. "c"
out[#out + 1] = tostring(("x" == 'x') and "eq" or "neq")
out[#out + 1] = string.format("%d-%s", 42, "fmt")

-- semicolons and tight syntax
local a, b = 2, 3; out[#out + 1] = tostring(a ^ b * 2 - 1)

print(table.concat(out, "|"))
