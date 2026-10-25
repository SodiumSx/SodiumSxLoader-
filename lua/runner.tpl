local sP,sK,sH,sI=[[__PROGRAM__]],"__KEY__","__HOST__","__SID__"
local sl=loadstring or load
do
  local d=debug
  local getinfo=d and (d.info or d.getinfo)
  if getinfo then
    local ok,src=pcall(getinfo,sl,"s")
    if ok and type(src)=="table" then src=src.source end
    if ok and type(src)=="string" and src~="[C]" and src~="=[C]" then return end
  end
end
--@@VM@@
local sS=vm_run(sP,sK)
if type(sS)~="string" or #sS<64 then return end
local sF=sl(sS,"="..string.format("%x",math.random(1,2147483646)))
if type(sF)~="function" then return end
sF(sH,sI)
