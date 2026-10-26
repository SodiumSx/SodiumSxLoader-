local sP,sK=[[__PROGRAM__]],"__KEY__"
local sl=loadstring or load
if type(sl)~="function" then return end
do
  local d=debug
  local gi=d and (d.info or d.getinfo)
  if gi then
    local ok,src=pcall(gi,sl,"s")
    if ok and type(src)=="table" then src=src.source end
    if ok and type(src)=="string" and src~="[C]" and src~="=[C]" then return end
  end
end
--@@VM@@
local sS=vm_run(sP,sK)
if type(sS)~="string" then return end
local sF=sl(sS,"="..string.format("%x",math.random(1,2147483646)))
if type(sF)~="function" then return end
sF(vm_run)
