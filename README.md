# FreeHub Guard

Loader/hub script kiểu Luarmor nhưng **không license, không HWID, không login** — free 100% và chạy trên Vercel.
Client chỉ nhận chương trình VM đã mã hoá, không bao giờ nhận source.

```
Người dùng dán:  loadstring(game:HttpGet("https://hub.vercel.app/api/r/example"))()
Trình duyệt thấy: màn hình đen, không có loadstring lẫn source
```

## Có gì trong này

| Thành phần | Mô tả |
| --- | --- |
| `api/r/[id].js` | Raw link — trình duyệt/bot thấy màn đen, executor nhận stub đã obfuscate (không còn dòng `loadstring(game:HttpGet(...))` đọc được) |
| `lua/stub.tpl`, `lib/stub.mjs` | Stub raw link: VM-pack + mã hoá string, sinh lại ngẫu nhiên mỗi request |
| `api/stage/[id].js` | **VM lớp 1**: loader core được compile lại ngẫu nhiên mỗi request |
| `api/challenge.js` | Phát challenge proof-of-work (chống bot/scraper) |
| `api/session.js` | Xác thực PoW + fingerprint, cấp token 180s + key riêng cho phiên |
| `api/payload/[id].js` | **VM lớp 2**: payload mã hoá theo phiên + tag chống sửa |
| `api/hub.js` | Danh sách script cho dashboard |
| `lua/core.lua` | Loader: handshake, PoW, tải payload, verify MAC, chạy sandbox |
| `lua/guard.lua` | Anti-hook / anti-envlog / anti-spy / anti-bot runtime |
| `lua/vm.lua`, `lib/vm.mjs` | Cặp VM compile (JS) ↔ runtime (Lua) |
| `lib/lua-obfuscate.mjs` | Obfuscator Lua: xoá comment, mã hoá mọi string literal |
| `tools/build.mjs` | Build payload + core vào `data/generated.mjs` |

Không có database, không có KV: token, key và PoW đều suy ra từ `HUB_SECRET` bằng HMAC.

## Chạy local

```bash
npm install
npm run dev        # build + http://127.0.0.1:3000
npm test           # 17 check end-to-end bằng Lua thật (wasmoon)
```

`npm run dev` in ra link raw mẫu. Mở link đó trên trình duyệt sẽ chỉ thấy màn hình đen, và `curl`/`wget`/`python`/UA bot nhận `403` — chỉ client kiểu executor (`Roblox/WinInet`) nhận stub, mà stub thì đã bị VM-pack nên không đọc được URL stage bên trong.

## Deploy Vercel

1. Push repo lên GitHub rồi **Add New Project** trên Vercel (framework: *Other*).
2. Build Command: `npm run build` (mặc định đã đúng). Output: `public/`.
3. Environment Variables:
   - `HUB_SECRET` = chuỗi ngẫu nhiên ≥ 32 ký tự (`openssl rand -hex 32`)
   - `HUB_POW_BITS` = `10` (tuỳ chọn)
   - `HUB_PUBLIC_URL` / `HUB_ALLOWED_HOSTS` (tuỳ chọn)
4. Deploy. Mọi thứ còn lại tự sinh theo host của request, nên preview và production đều chạy.

Không đặt `HUB_SECRET` thì API trả 500 (fail-closed) chứ không chạy bằng secret mặc định.

## Thêm / sửa script

Sửa `hub.config.json`:

```json
{
  "id": "my-script",
  "file": "scripts/my-script.lua",
  "name": "My Script",
  "description": "...",
  "author": "you",
  "version": "1.0.0",
  "tags": ["utility"]
}
```

Rồi `npm run build` và deploy lại. `id` chỉ dùng `[a-z0-9_-]`; link raw là `/api/r/<id>`.

## Luồng tải

```
executor
  └─ GET /api/r/<id>                → stub VM 2 lớp + string-encode (ngẫu nhiên mỗi lần)
     └─ VM giải stub                → loadstring(game:HttpGet(".../api/stage/<id>?s=<ticket>"))()
        └─ GET /api/stage/<id>?s=.. → runtime VM + chương trình lớp 1 (ngẫu nhiên mỗi lần)
           └─ VM giải mã core       → handshake
              ├─ GET /api/challenge → c=<hmac>&d=<bits>
              ├─ giải PoW bằng SHA-256 (Lua)
              ├─ GET /api/session   → t=<token>&k=<key 32 hex>&x=<exp>
              ├─ GET /api/payload/<id>?t= → m=<MAC>&z=<len>\n\n<chương trình lớp 2>
              ├─ VM lớp 2 giải mã payload bằng key phiên
              ├─ verify MAC + độ dài
              └─ audit môi trường → loadstring + sandbox env → chạy
```

Mỗi lần load, chương trình VM đổi chunk, đổi số thanh ghi, đổi thứ tự lệnh, đổi key. Chương trình bắt được ở lần trước không dùng lại được cho lần sau.

## Các lớp bảo vệ

| Cơ chế | Chống gì | Ghi chú |
| --- | --- | --- |
| Raw link màn đen | Người mở link bằng trình duyệt đọc/copy bootstrap | Trình duyệt nhận HTML đen, không phát ticket stage |
| Bot/scraper UA bị chặn | `curl`, `wget`, `python`, `node`, `axios`, `okhttp`, headless… | `403` + trang đen, không sinh code |
| Stub raw được obfuscate | Copy stub rồi grep `HttpGet`, URL stage, host | 2 lớp VM lồng nhau + string-encode, key/layout mới mỗi request |
| Ticket stage 120s | Hotlink/chia sẻ URL stage đã bắt | Lấy link mới mỗi lần load |
| VM 2 lớp + key theo phiên | Dump tĩnh, chia sẻ file đã bắt | Payload luôn được compile lại theo phiên |
| String encryption + strip comment | `grep`/đọc trộm payload | Mọi string literal thành bảng XOR |
| Anti-hook native | `loadstring`, `string.char`, `table.concat`… bị bọc bằng Lua closure | Native thật luôn là `[C]` |
| Anti-metamethod | `__namecall`, `__index`, `__newindex` bị hook | Dùng `getrawmetatable(game)` |
| Anti-env-log | `getgenv` có proxy `__index/__newindex`, spy toàn cục, debug hook | Fail-closed |
| `checkcaller` + wrapper predicates | Hook gọi loader từ C boundary, wrapper Synapse/Fluxus | Nếu executor hỗ trợ |
| Anti-tamper | Sửa payload trên đường truyền | MAC khoá theo phiên + check length |
| Anti-bot / anti-curl | Scraper tự động, `curl`/`wget`/`python` | UA blocklist ở raw link + PoW + fingerprint executor |
| Token 180s | Dùng lại link payload | HMAC, gắn script id + nonce + place |
| Sandbox env | Script ghi bẩn `getgenv`, spy đọc global | Global của script nằm trong bảng riêng |

## Giới hạn — nói thẳng

Đây là bảo vệ **client-side**, nên không có gì là tuyệt đối. Cụ thể:

- Ai đó chạy loader trong môi trường của họ và hook đúng `loadstring` **trước khi** guard chạy vẫn có thể lấy được source tại thời điểm thực thi. Guard phát hiện wrapper phổ biến và dừng lại, nhưng một RE kiên nhẫn với custom build của executor thì không có cách chặn tuyệt đối.
- VM làm tăng chi phí đọc/dump, không phải mã hoá bất khả xâm phạm. Key phiên nằm trong RAM client.
- Stub raw link cũng vậy: nó chặn tool tự động (1 lần dump chỉ ra thêm một chương trình VM khác), nhưng người ngồi giải tay từng lớp vẫn lấy được URL stage — chỉ có điều URL đó chết sau 120s.
- Không HWID/license nghĩa là không thể ban theo người dùng; chống lạm dụng dựa vào PoW + fingerprint + rotate `HUB_SECRET`.
- Không có rate limit theo IP (Vercel không có store). Nếu bị flood thật, tăng `HUB_POW_BITS` hoặc gắn thêm Vercel Firewall/Upstash.
- Obfuscator không đổi tên biến (để không phá script). Muốn mạnh hơn thì thêm bước rename theo scope, đây là hướng mở rộng.
- Script chạy trong env riêng: `getgenv()` là bảng của riêng lần chạy đó, không chia sẻ với script khác (đổi lại env-log không đọc được global của script). Nếu cần share global, sửa `core_invoke`.
- Gặp lỗi khi phát triển script? Bật `getgenv().__FREEHUB_DEBUG = true` ở đầu payload để loader in lỗi ra console.

Nếu cần bảo mật ngang Luarmor ở mức "không thể lấy source", chỉ có một cách đúng: **không gửi source xuống client** — chạy logic trên server hoặc chia nhỏ theo từng tính năng được mở khoá bằng token ngắn hạn. Kiến trúc này đã sẵn sàng cho hướng đó (mỗi script có token/phiên riêng).

## Hiệu năng (đo trên máy test)

Payload 204 KB (đã obfuscate):

```
obfuscate      ~100 ms
compile VM      ~55 ms
Lua decode     ~500 ms   (Lua 5.4 trong WASM; Luau thường nhanh hơn)
program size    365 KB
```

Script hub thường 20–80 KB nên decode thực tế khoảng 100–300 ms.

## Cấu trúc

```
api/            Vercel functions (Node, ESM)
lib/            crypto, token, PoW, obfuscator, VM compiler, policy
lua/            core loader + guard + VM runtime + SHA-256
public/         dashboard
scripts/        payload Lua
data/           generated.mjs (build output, commit để deploy)
tools/          build, dev server, test
test/           harness Roblox giả lập + fixture
```

## Lệnh

```bash
npm run build   # obfuscate payload + core → data/generated.mjs
npm run dev     # build + dev server (route giống Vercel)
npm test        # build + 17 check end-to-end
```
