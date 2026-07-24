# ductu

```
  ____              _______
 |  _ \ _   _  ___ |__   __|   _
 | | | | | | |/ __|   | | | | | |
 | |_| | |_| | (__    | | | |_| |
 |____/ \__,_|\___|   |_|  \__,_|
        DucTu recon — subdomain + directory scanner
        authorized testing only
```

A small, dependency-free recon CLI written in Go. It scans **subdomains** and
**web directories** — optionally **both in a single run**, each with its own
wordlist. Standard library only (`net`, `net/http`, `flag`, `encoding/json`, …).

> ⚠️ **Legal / authorized use only.** Run `ductu` **only** against systems you
> own or have **explicit written permission** to test. Unauthorized scanning may
> be illegal. You are responsible for how you use this tool.

---

## Build

```bash
go build -o ductu .
```

Requires Go 1.22+ (no third-party modules). The result is a single static-ish
binary named `ductu`.

---

## Modes (auto-selected by the flags you pass)

| Flags present               | What runs            |
| --------------------------- | -------------------- |
| `-d` + `-ws`                | Subdomain scan       |
| `-u` + `-wd`                | Directory scan       |
| `-d` + `-ws` + `-u` + `-wd` | **Both**, in one run |

If none of these combinations are satisfied, `ductu` prints usage and exits `1`.

---

## Flags

| Flag              | Default | Description                                                     |
| ----------------- | ------- | --------------------------------------------------------------- |
| `-d` string       |         | Root domain for subdomain scan (e.g. `example.com`)             |
| `-u` string       |         | Base URL for directory scan (e.g. `https://target.lab`)         |
| `-ws` string      |         | Subdomain wordlist (SecLists DNS style)                         |
| `-wd` string      |         | Directory wordlist (DirBuster / Web-Content style)              |
| `-t` int          | `50`    | Concurrent workers (goroutines + semaphore)                     |
| `-timeout` int    | `4`     | Per-request timeout in seconds                                  |
| `-e` string       |         | Extensions appended to dir paths, CSV (e.g. `php,html,txt,bak`) |
| `-codes` string   |         | Only show these status codes (e.g. `200,301,403`)               |
| `-hide-codes` str | `404`   | Hide these status codes                                         |
| `-k`              | `false` | Skip TLS verification (self-signed lab certs)                   |
| `-follow`         | `false` | Follow redirects (default: report the 3xx + `Location`)         |
| `-o` string       |         | Write a JSON report to this file                                |
| `-no-color`       | `false` | Disable ANSI colors                                             |
| `-list-wordlists` | `false` | Print common SecLists paths and exit                            |

`--flag` and `-flag` are both accepted (e.g. `--timeout` or `-timeout`).

---

## Examples

**Both scans in one run (the intended workflow):**

```bash
./ductu -d target.lab \
  -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://target.lab \
  -t 60 -e php,txt,bak -o report.json
```

**Subdomain scan only:**

```bash
./ductu -d target.lab -ws subs.txt -t 80 --timeout 5
```

**Directory scan only, self-signed lab, filter to interesting codes:**

```bash
./ductu -u https://target.lab -wd common.txt -e php,bak -k \
  --codes 200,301,302,403 -o dirs.json
```

**List common SecLists wordlist paths:**

```bash
./ductu -list-wordlists
```

---

## What it does

**Subdomain scan**

- Joins each word with the root domain into an FQDN, de-dupes, drops
  blank/`#`-comment lines.
- Resolves A/AAAA in parallel and captures a meaningful CNAME.
- **Wildcard DNS detection:** resolves a few random labels; if they resolve to a
  common IP set, hosts that only match that catch-all set (and carry no
  distinguishing CNAME) are filtered as noise.
- Table columns: `SUBDOMAIN | IP(s) | CNAME`.

**Directory scan**

- Joins the base URL with each path, appending each `-e` extension.
- Parallel HTTP GET; `404` hidden by default.
- **Soft-404 calibration:** probes random non-existent paths first; if the server
  returns a catch-all page, matching responses (same status, similar size) are
  filtered so you only see real content.
- Redirects are reported (status + `Location`) unless `--follow` is set.
- Table columns: `CODE | SIZE | PATH | NOTE` (redirect target / content-type).

**Display**

- Cyan/bold ASCII banner on startup; scanning begins right below it.
- Fixed-width, aligned columns; human-readable sizes (`B`/`K`/`M`); long values
  truncated so columns never drift.
- Status colors: `2xx` green, `3xx` cyan, `401/403` (and other 4xx) yellow,
  `5xx` red. Disable with `-no-color`.
- Live progress on **stderr** (so piping stdout / JSON stays clean).
- Final **SUMMARY**: subdomains found, directories found, wildcard/soft-404
  status, and total run time.

**JSON report (`-o`)** contains target info, timing, wildcard + soft-404 info,
the full subdomain and directory result sets, and a summary block.

---

## Notes & limitations

- Wildcard and soft-404 filtering are heuristics; on unusual targets a real host
  or page could be filtered (or noise could slip through). Cross-check important
  findings manually.
- Uses your system DNS resolver (Go resolver, `PreferGo`). Point `/etc/resolv.conf`
  at the resolver you want.
- Body size is read up to a 2 MB cap for speed; larger bodies report the
  `Content-Length` when the server provides it.

---

## Legal

`ductu` is intended for authorized security testing, CTFs, and lab environments.
Do not use it against systems you are not permitted to test.

---

---

# ductu (Tiếng Việt)

```
  ____              _______
 |  _ \ _   _  ___ |__   __|   _
 | | | | | | |/ __|   | | | | | |
 | |_| | |_| | (__    | | | |_| |
 |____/ \__,_|\___|   |_|  \__,_|
        DucTu recon — subdomain + directory scanner
        chỉ dùng khi đã được ủy quyền
```

Một CLI recon nhỏ gọn, không phụ thuộc thư viện ngoài, viết bằng Go. Tool quét
**subdomain** và **thư mục web** — có thể quét **cả hai cùng lúc**, mỗi loại
dùng wordlist riêng. Chỉ dùng standard library (`net`, `net/http`, `flag`,
`encoding/json`, …).

> ⚠️ **Chỉ sử dụng khi được phép.** Chỉ chạy `ductu` với các hệ thống bạn
> **sở hữu** hoặc có **văn bản cho phép rõ ràng** để kiểm thử. Quét trái phép
> có thể là hành vi vi phạm pháp luật. Bạn chịu trách nhiệm hoàn toàn về cách
> sử dụng tool này.

---

## Build

```bash
go build -o ductu .
```

Yêu cầu Go 1.22+ (không cần module bên thứ ba). Kết quả là 1 file binary tĩnh
duy nhất tên `ductu`.

---

## Các chế độ (tự động chọn theo flag bạn truyền vào)

| Flags có mặt                | Chế độ chạy                  |
| --------------------------- | ---------------------------- |
| `-d` + `-ws`                | Quét subdomain               |
| `-u` + `-wd`                | Quét thư mục                 |
| `-d` + `-ws` + `-u` + `-wd` | **Cả hai**, trong 1 lần chạy |

Nếu không đủ 1 trong các tổ hợp trên, `ductu` sẽ in hướng dẫn sử dụng và
thoát với mã `1`.

---

## Danh sách flag

| Flag              | Mặc định | Mô tả                                                                     |
| ----------------- | -------- | ------------------------------------------------------------------------- |
| `-d` string       |          | Domain gốc để quét subdomain (vd: `example.com`)                          |
| `-u` string       |          | URL gốc để quét thư mục (vd: `https://target.lab`)                        |
| `-ws` string      |          | Wordlist cho subdomain (kiểu SecLists DNS)                                |
| `-wd` string      |          | Wordlist cho thư mục (kiểu DirBuster / Web-Content)                       |
| `-t` int          | `50`     | Số luồng chạy song song (goroutine + semaphore)                           |
| `-timeout` int    | `4`      | Timeout mỗi request (giây)                                                |
| `-e` string       |          | Extension thêm vào cuối path, phân cách dấu phẩy (vd: `php,html,txt,bak`) |
| `-codes` string   |          | Chỉ hiện các status code này (vd: `200,301,403`)                          |
| `-hide-codes` str | `404`    | Ẩn các status code này                                                    |
| `-k`              | `false`  | Bỏ qua verify TLS (cho cert self-signed trong lab)                        |
| `-follow`         | `false`  | Follow theo redirect (mặc định: chỉ báo cáo mã 3xx + `Location`)          |
| `-o` string       |          | Ghi báo cáo JSON ra file này                                              |
| `-no-color`       | `false`  | Tắt màu ANSI                                                              |
| `-list-wordlists` | `false`  | In các đường dẫn SecLists thường dùng rồi thoát                           |

Cả 2 kiểu `--flag` và `-flag` đều dùng được (vd: `--timeout` hoặc `-timeout`).

---

## Ví dụ sử dụng

**Quét cả hai cùng lúc (workflow chính):**

```bash
./ductu -d target.lab \
  -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://target.lab \
  -t 60 -e php,txt,bak -o report.json
```

**Chỉ quét subdomain:**

```bash
./ductu -d target.lab -ws subs.txt -t 80 --timeout 5
```

**Chỉ quét thư mục, lab dùng cert self-signed, chỉ lọc mã quan tâm:**

```bash
./ductu -u https://target.lab -wd common.txt -e php,bak -k \
  --codes 200,301,302,403 -o dirs.json
```

**Liệt kê các đường dẫn wordlist SecLists phổ biến:**

```bash
./ductu -list-wordlists
```

---

## Tool làm gì

**Quét subdomain**

- Ghép mỗi từ trong wordlist với domain gốc thành FQDN, loại trùng lặp, bỏ
  dòng trống/comment (`#`).
- Resolve A/AAAA song song và lấy CNAME có ý nghĩa (nếu có).
- **Phát hiện wildcard DNS:** resolve thử vài label ngẫu nhiên; nếu chúng đều
  trỏ về cùng 1 tập IP chung, các host chỉ khớp tập IP catch-all đó (và không
  có CNAME phân biệt) sẽ bị lọc bỏ vì là nhiễu.
- Cột bảng: `SUBDOMAIN | IP(s) | CNAME`.

**Quét thư mục**

- Ghép URL gốc với mỗi path trong wordlist, thêm từng extension `-e`.
- HTTP GET song song; mặc định ẩn mã `404`.
- **Hiệu chỉnh soft-404:** thử trước vài path ngẫu nhiên không tồn tại; nếu
  server trả về trang catch-all, các response giống vậy (cùng status, kích
  thước tương tự) sẽ bị lọc để chỉ còn lại nội dung thật.
- Redirect được báo cáo (status + `Location`) trừ khi bật `--follow`.
- Cột bảng: `CODE | SIZE | PATH | NOTE` (đích redirect / content-type).

**Hiển thị**

- Banner ASCII màu cyan/đậm khi khởi động; quá trình quét bắt đầu ngay bên dưới.
- Cột căn chỉnh cố định độ rộng; kích thước dễ đọc (`B`/`K`/`M`); giá trị dài
  bị cắt bớt để cột không bị lệch.
- Màu theo status: `2xx` xanh lá, `3xx` cyan, `401/403` (và 4xx khác) vàng,
  `5xx` đỏ. Tắt màu bằng `-no-color`.
- Progress trực tiếp trên **stderr** (để pipe stdout / JSON luôn sạch).
- **SUMMARY** cuối cùng: số subdomain tìm được, số thư mục tìm được, trạng
  thái wildcard/soft-404, và tổng thời gian chạy.

**Báo cáo JSON (`-o`)** chứa thông tin target, thời gian, thông tin
wildcard + soft-404, toàn bộ kết quả subdomain và thư mục, và 1 khối summary.

---

## Lưu ý & giới hạn

- Lọc wildcard và soft-404 là các cơ chế heuristic (phỏng đoán); với target
  đặc biệt, có thể lọc nhầm 1 host/trang thật (hoặc để lọt nhiễu). Nên kiểm
  tra thủ công lại các phát hiện quan trọng.
- Dùng DNS resolver hệ thống của bạn (Go resolver, `PreferGo`). Chỉnh
  `/etc/resolv.conf` để trỏ về resolver bạn muốn dùng.
- Body response chỉ đọc tối đa 2 MB để tăng tốc độ; body lớn hơn sẽ báo cáo
  theo `Content-Length` nếu server có cung cấp.

---

## Pháp lý

`ductu` được tạo ra cho mục đích kiểm thử bảo mật có ủy quyền, CTF, và môi
trường lab. Không sử dụng tool này với các hệ thống bạn không được phép
kiểm thử.
