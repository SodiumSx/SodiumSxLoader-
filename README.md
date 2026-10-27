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
| `lua/stub.tpl`, `lib/stub.mjs` | Stub raw link: VM đổi tên biến + 2–4 lớp chương trình lồng nhau, key suy ra trong VM, sinh lại ngẫu nhiên mỗi request |
| `api/stage/[id].js` | **VM lớp 1**: loader core được compile lại ngẫu nhiên mỗi request |
| `api/challenge.js` | Phát challenge proof-of-work (chống bot/scraper) |
| `api/session.js` | Xác thực PoW + fingerprint, cấp token 180s + key riêng cho phiên |
| `api/payload/[id].js` | **VM lớp 2**: payload mã hoá theo phiên + tag chống sửa |
| `api/hub.js` | Danh sách script cho dashboard |
| `lua/core.lua` | Loader: handshake, PoW, tải payload, verify MAC, chạy sandbox |
| `lua/guard.lua` | Anti-hook / anti-envlog / anti-spy / anti-bot runtime |
| `lua/vm.lua`, `lib/vm.mjs` | Cặp VM compile (JS) ↔ runtime (Lua) |
| `lib/lua-obfuscate.mjs` | Obfuscator Lua: xoá comment, mã hoá string literal, chèn dead branch |
| `lib/lua-rename.mjs` | Đổi tên local/param/biến vòng lặp theo scope, có bail-out an toàn |
| `lib/obf-profile.mjs` | Optimizer: đo script rồi chọn tham số obf cho nhanh mà vẫn chắc |
| `lib/kv.mjs` | Claim nonce một lần (Upstash REST, tuỳ chọn) |
| `tools/build.mjs` | Build payload + core vào `data/generated.mjs` |

Không cần database: token, key và PoW đều suy ra từ `HUB_SECRET` bằng HMAC. Chỉ khi bạn muốn ticket stage **dùng một lần** thì mới cần một store key-value (Upstash Redis, free tier) — xem mục Deploy.

## Chạy local

```bash
npm install
npm run dev        # build + http://127.0.0.1:3000
npm test           # 24 check end-to-end bằng Lua thật (wasmoon)
```

`npm run dev` in ra link raw mẫu. Mở link đó trên trình duyệt sẽ chỉ thấy màn hình đen, và `curl`/`wget`/`python`/UA bot nhận `403` — chỉ client kiểu executor (`Roblox/WinInet`) nhận stub, mà stub thì đã bị VM-pack nên không đọc được URL stage bên trong.

## Deploy Vercel

1. Push repo lên GitHub rồi **Add New Project** trên Vercel (framework: *Other*).
2. Build Command: `npm run build` (mặc định đã đúng). Output: `public/`.
3. Environment Variables:
   - `HUB_SECRET` = chuỗi ngẫu nhiên ≥ 32 ký tự (`openssl rand -hex 32`)
   - `HUB_POW_BITS` = `10` (tuỳ chọn)
   - `HUB_STAGE_TTL` = `5` (tuỳ chọn, giây — thời gian sống của ticket stage, 2–120)
   - `HUB_PUBLIC_URL` / `HUB_ALLOWED_HOSTS` (tuỳ chọn)
   - `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` (tuỳ chọn — bật ticket dùng một lần)
4. Deploy. Mọi thứ còn lại tự sinh theo host của request, nên preview và production đều chạy.

Không đặt `HUB_SECRET` thì API trả 500 (fail-closed) chứ không chạy bằng secret mặc định.

### Ticket dùng một lần (tuỳ chọn, nên bật)

Mỗi ticket stage mang một nonce ngẫu nhiên, và `/api/stage` tiêu thụ nó bằng `SET <key> 1 NX EX <ttl>` — Redis xử lý NX nguyên tử, nên đúng **một** request được dùng vé. URL stage bị bắt giữa đường rồi đem đi dùng lại (executor khác, bạn bè, cache) nhận `403 link already used`, kể cả khi còn trong 5 giây.

Cách bật trên Vercel (Vercel KV đã sunset, thay bằng Upstash qua Marketplace):

1. Vercel → **Storage / Marketplace** → **Upstash Redis** → tạo database free tier → **Connect to Project**.
2. Vercel tự thêm 2 biến `KV_REST_API_URL` / `KV_REST_API_TOKEN` (Upstash dùng tên `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`; `lib/kv.mjs` đọc cả hai).
3. Redeploy.

Không có store: dev/test chạy memory trong cùng process (đúng, vì dev server một process), còn production lùi về chỉ dựa TTL 5s và in một dòng cảnh báo. Store lỗi/timeout cũng lùi về TTL — Redis chết không làm loader chết, chỉ mất tính dùng-một-lần.

Đánh đổi: hai request tranh cùng vé thì request thứ hai `403`; người dùng thật chỉ cần load lại link raw (ra vé mới).

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
  └─ GET /api/r/<id>                → stub: VM đã đổi tên + chuỗi 2–4 chương trình lồng nhau (ngẫu nhiên mỗi lần)
     └─ VM giải từng lớp (key lớp sau = mac(salt, key lớp trước), tính trong VM)
        └─ op EXEC chạy snippet bằng loadstring native **bên trong VM** — không trả source ra ngoài
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
| Stub raw được obfuscate | Copy stub rồi grep `HttpGet`, URL stage, host | VM đổi tên biến + string-encode + 2–3 lớp lồng nhau, key/layout mới mỗi request |
| Đổi tên local theo scope | Đọc source: tên hàm, biến, tham số của tác giả | Mọi `local`/param/biến vòng lặp thành tên ngẫu nhiên; global, field, key bảng và `self` giữ nguyên |
| Stage runtime cũng bị rename | Lấy tên `vm_run`, `vm_unseal`… làm mốc để hook/signature | Runtime trong stage được rename + mã hoá string mỗi request, runner gọi qua tên ngẫu nhiên |
| Không có ranh giới plaintext | Vá stub kiểu `print(sS)` / `sF(vm_run)` để moi lớp trong | Việc chạy code nằm trong VM (op `EXEC`); stub chỉ còn `return <entry>(p,k)` |
| Key theo tầng | Dump một lớp rồi giải tay | Key lớp sau = `mac(salt, key lớp trước)`, chỉ tính được khi chạy đúng VM |
| Ticket stage dùng một lần | Dùng lại URL stage bắt được, chia sẻ link, cache | `SET NX` nguyên tử trên Upstash (tuỳ chọn); không có store thì chỉ còn TTL |
| Ticket stage 5s | Hotlink/chia sẻ URL stage đã bắt | Lấy link mới mỗi lần load; đổi bằng `HUB_STAGE_TTL` (2–120s) |
| VM 2 lớp + key theo phiên | Dump tĩnh, chia sẻ file đã bắt | Payload luôn được compile lại theo phiên |
| String encryption + strip comment | `grep`/đọc trộm payload | String > 2 ký tự vào bảng XOR, decode theo block, có cache; string 1–2 ký tự giữ nguyên để không chậm vòng lặp nóng |
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
- Stub raw link: bản bắt được chỉ gồm chương trình đã mã hoá + VM đã đổi tên, không có dòng `vm_run(...)` nào để vá thành `print`. Mỗi lớp dump ra còn thiếu key (key lớp sau suy ra từ key lớp trước bên trong VM), nên muốn đi tiếp phải viết lại đúng VM. Người kiên nhẫn vẫn làm được, nhưng URL stage lấy ra chỉ sống 5 giây (`HUB_STAGE_TTL`), và vé đó không gắn với ai nên chia sẻ lại gần như vô dụng.
- Vé dùng một lần chỉ mạnh khi đã bật store: xem mục *Ticket dùng một lần*. Không có store thì URL stage bắt được vẫn dùng lại được trong 5 giây.
- Ai đọc được stub trên đường truyền vẫn có thể **tranh** tiêu vé trước người dùng thật (họ nhận `403`, load lại là xong); đó là phá hoại, không phải lấy được code.
- Không HWID/license nghĩa là không thể ban theo người dùng; chống lạm dụng dựa vào PoW + fingerprint + rotate `HUB_SECRET`.
- Không có rate limit theo IP (Vercel không có store). Nếu bị flood thật, tăng `HUB_POW_BITS`, gắn Vercel Firewall, hoặc dùng chính Upstash bạn đã bật cho vé dùng một lần.
- Rename chỉ áp dụng cho **local**, không đụng global/field/key bảng — đó là điều kiện để script không gãy. Có 5 trường hợp được **bỏ qua rename** (vẫn obfuscate string bình thường) vì scope không chứng minh được: `goto`/label, `repeat ... until`, type annotation của Luau, `if ... then ... else` dạng biểu thức, và string interpolation (backtick). Gặp là bỏ rename cho cả file, fail-safe theo hướng an toàn.
- Script chạy trong env riêng: `getgenv()` là bảng của riêng lần chạy đó, không chia sẻ với script khác (đổi lại env-log không đọc được global của script). Nếu cần share global, sửa `core_invoke`.
- Gặp lỗi khi phát triển script? Bật `getgenv().__FREEHUB_DEBUG = true` ở đầu payload để loader in lỗi ra console.

Nếu cần bảo mật ngang Luarmor ở mức "không thể lấy source", chỉ có một cách đúng: **không gửi source xuống client** — chạy logic trên server hoặc chia nhỏ theo từng tính năng được mở khoá bằng token ngắn hạn. Kiến trúc này đã sẵn sàng cho hướng đó (mỗi script có token/phiên riêng).

## Hệ thống tối ưu (optimizer)

`lib/obf-profile.mjs` đo từng script rồi chọn cách obfuscate, vì bảo vệ nào cũng
phải trả bằng CPU của client:

| Quyết định | Vì sao |
| --- | --- |
| String 1–2 ký tự để nguyên | Toàn dấu câu (`" "`, `"."`, `"/"`) và là loại xuất hiện trong vòng lặp nóng; decode chúng chỉ tốn thêm |
| Decode theo block 32 byte + cache | 1 lệnh `string.char()` cho cả block thay vì 1 lệnh mỗi byte, mỗi literal chỉ decode 1 lần |
| Chỉ số key chạy vòng (không `%`) | Bớt 1 phép chia mỗi byte, đo nhanh hơn ~30% |
| Số decoy slot theo bảng thật | Script 5 string không bị độn nhiều rác hơn dữ liệu |
| Chunk VM theo kích thước payload | Script nhỏ chia nhỏ để nhiều entropy layout; payload lớn chia to để giảm overhead mỗi chunk |
| Sandbox `__index` là **bảng** | Đọc global thành 1 lookup C thay vì 1 lệnh gọi Lua |

Đo trên máy test (Lua 5.4 trong WASM, chậm hơn Luau của Roblox):

```
đọc global trong sandbox   81 ms -> 21 ms   (300k lần đọc)
decode 400 string 18 byte  14.4 ms -> 10.5 ms
PoW 10 bit                348 ms -> 182 ms  (block đầu của challenge chỉ hash 1 lần)
```

## Hiệu năng (đo trên máy test)

Payload 204 KB (đã obfuscate):

```
obfuscate      ~410 ms   (build time, không ảnh hưởng client)
compile VM      ~25 ms
Lua decode     ~196 ms   (trước: 552 ms)  + MAC ~16 ms (trước: 96 ms)
program size    416 KB
```

Script hub thường 20–80 KB nên decode thực tế khoảng 20–80 ms.

Raw stub (`/api/r/<id>`): ~30 KB tuỳ độ sâu (2–3 lớp ngẫu nhiên) vì runtime
giờ được rename + mã hoá string, render phía Vercel ~20 ms. Stage ~48 KB,
render ~25 ms. Một lần load đầy đủ (stub → stage → challenge → session →
payload → chạy) đo bằng Lua 5.4 trong WASM: ~480 ms CPU client, trong đó PoW
chiếm phần lớn; Luau trong executor nhanh hơn nhiều lần.

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
npm test        # build + 24 check end-to-end
```
