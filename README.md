# ductu

`ductu` là CLI recon viết bằng Go, dùng để scan subdomain và directory/web path
trong môi trường lab, CTF, hoặc pentest được ủy quyền.

Tool chỉ dùng Go standard library, không cần thư viện bên thứ ba.

```text
  ____              _______
 |  _ \ _   _  ___ |__   __|   _
 | | | | | | |/ __|   | | | | | |
 | |_| | |_| | (__    | | | |_| |
 |____/ \__,_|\___|   |_|  \__,_|
```

> Chỉ sử dụng với hệ thống bạn sở hữu hoặc được phép kiểm thử. Không scan hệ
> thống khi chưa được ủy quyền.

## Tính năng chính

- Scan subdomain bằng wordlist DNS.
- Scan directory/path bằng wordlist Web-Content.
- Có 3 mode rõ ràng: `sub`, `dir`, `all`.
- Mode cũ bằng flag `-d/-ws/-u/-wd` vẫn hoạt động.
- Wildcard DNS detection để lọc subdomain nhiễu.
- Soft-404 calibration để lọc path giả.
- Recursive directory scan, mặc định depth là `4`.
- Filter theo status code, size, words, lines, regex body.
- Extension mode: append/replace, có prefix/suffix path.
- Dedup body hash để giảm kết quả trùng nội dung.
- Rate limit, retry, custom DNS resolver.
- Resume state và JSON report.
- Output table có màu, có cột `WORDS` và `LINES`.

## Cài đặt trên Kali

Cài Go và SecLists:

```bash
sudo apt update
sudo apt install -y golang seclists
```

Giải nén project:

```bash
unzip ductu.zip
cd ductu
```

Build:

```bash
go build -o ductu .
```

Chạy thử:

```bash
./ductu -h
```

Muốn gọi `ductu` ở mọi nơi:

```bash
sudo cp ./ductu /usr/local/bin/ductu
ductu -h
```

Nếu gặp lỗi:

```text
go: go.mod file not found
```

Nghĩa là bạn đang build sai thư mục. Hãy vào đúng thư mục project:

```bash
cd ~/ductu
go build -o ductu .
```

## Cách dùng nhanh

Scan subdomain:

```bash
ductu sub example.com -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Scan directory:

```bash
ductu dir https://example.com -wd /usr/share/seclists/Discovery/Web-Content/common.txt
```

Scan cả subdomain và directory:

```bash
ductu all https://example.com \
  -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt
```

Scan directory kèm extension:

```bash
ductu dir http://target.htb \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e php,txt,bak
```

Lưu ý: nếu không truyền `-e`, tool chỉ scan path gốc trong wordlist. Ví dụ
`admin` sẽ chỉ thành `/admin`, không tự sinh `/admin.php`, `/admin.txt`.

## 3 mode chính

### 1. Subdomain mode

```bash
ductu sub <domain> -ws <sub_wordlist>
```

Ví dụ:

```bash
ductu sub bedside.htb -ws subs.txt
```

Flag hay dùng:

```bash
ductu sub bedside.htb -ws subs.txt -ct -dns-extra -permute
```

### 2. Directory mode

```bash
ductu dir <base_url> -wd <dir_wordlist>
```

Ví dụ:

```bash
ductu dir http://bedside.htb -wd common.txt -e php,txt,bak
```

Recursive scan:

```bash
ductu dir http://bedside.htb -wd common.txt -r -depth 4
```

### 3. All mode

```bash
ductu all <base_url> -ws <sub_wordlist> -wd <dir_wordlist>
```

Ví dụ:

```bash
ductu all http://bedside.htb \
  -ws subs.txt \
  -wd common.txt \
  -e php,txt,bak
```

Trong `all` mode, nếu bạn đưa vào `http://example.com`, tool tự lấy domain
`example.com` để scan subdomain. Nếu muốn override domain thì thêm `-d`:

```bash
ductu all http://app.example.com -d example.com -ws subs.txt -wd common.txt
```

## Flag quan trọng

### Global

| Flag | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `-t` | `50` | Số worker chạy song song |
| `-timeout` | `4` | Timeout mỗi request, tính bằng giây |
| `-rate` | `0` | Giới hạn request/resolve mỗi giây, `0` là không giới hạn |
| `-retries` | `0` | Số lần retry khi lỗi DNS/HTTP |
| `-retry-delay` | `500ms` | Delay cơ bản giữa các lần retry |
| `-resume` | | File resume JSON |
| `-o` | | Ghi report JSON |
| `-no-color` | `false` | Tắt màu ANSI |
| `-no-banner` | `false` | Tắt banner lúc khởi động |
| `-list-wordlists` | `false` | In wordlist SecLists gợi ý |

### Subdomain

| Flag | Ý nghĩa |
| --- | --- |
| `-d` | Domain gốc, ví dụ `example.com` |
| `-ws` | Wordlist subdomain |
| `-ct` | Lấy thêm hostname từ crt.sh |
| `-permute` | Tạo biến thể subdomain sau pass resolve đầu |
| `-dns-server` | DNS resolver riêng, ví dụ `1.1.1.1:53` |
| `-dns-extra` | Lookup MX/NS/TXT và lấy hostname tìm thấy |

### Directory

| Flag | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `-u` | | Base URL, ví dụ `https://target.lab` |
| `-wd` | | Wordlist directory/path |
| `-e` | | Extension CSV, ví dụ `php,html,txt,bak` |
| `-ext-mode` | `append` | `append` hoặc `replace` với `%EXT%` |
| `-no-extension` | `false` | Bỏ qua logic extension |
| `-prefixes` | | Tạo thêm biến thể prefix, CSV |
| `-suffixes` | | Tạo thêm biến thể suffix, CSV |
| `-r` | `false` | Bật recursive scan |
| `-recursive` | `false` | Giống `-r` |
| `-depth` | `4` | Độ sâu recursive tối đa |
| `-recursion-strategy` | `default` | `default` hoặc `greedy` |
| `-exclude-subdirs` | | Bỏ qua segment path khi recursive, CSV |

### HTTP

| Flag | Ý nghĩa |
| --- | --- |
| `-H` | Thêm HTTP header, có thể lặp lại: `-H 'Name: value'` |
| `-cookie` | Gán raw Cookie header |
| `-auth` | Basic Auth dạng `username:password` |
| `-proxy` | HTTP proxy, ví dụ `http://127.0.0.1:8080` |
| `-k` | Bỏ qua TLS verify |
| `-follow` | Follow redirect thay vì chỉ in 3xx + Location |

## Filter kết quả directory

`ductu` hỗ trợ match/filter theo metadata response.

Quy tắc:

- Match: tất cả điều kiện match đang bật phải đúng.
- Filter: nếu trúng bất kỳ điều kiện filter nào thì bỏ qua.
- Sau đó mới áp dụng `-codes` và `-hide-codes`.

Status code hỗ trợ range:

```bash
-codes 200,301-303,403
-hide-codes 400,404
```

Filter theo size:

```bash
ductu dir http://target.htb -wd common.txt -fs 316
```

Match theo words/lines:

```bash
ductu dir http://target.htb -wd common.txt -mw 20-200 -ml 5-80
```

Regex body:

```bash
ductu dir http://target.htb -wd common.txt -mr "admin|login"
ductu dir http://target.htb -wd common.txt -fr "not found|error"
```

Tắt dedup body hash:

```bash
ductu dir http://target.htb -wd common.txt -no-dedup
```

Đổi ngưỡng dedup:

```bash
ductu dir http://target.htb -wd common.txt -dedup-threshold 5
```

Lưu ý: dedup chỉ lọc kết quả cuối từ thời điểm hash đạt ngưỡng. Vì kết quả được
in realtime, các dòng đã in trước đó sẽ không bị xóa khỏi terminal.

## Extension và path generation

Mặc định `-ext-mode append`:

```text
admin -> admin, admin.php, admin.txt
```

Khi wordlist có `%EXT%`, dùng `replace`:

```bash
ductu dir http://target.htb -wd raft.txt -e php,txt -ext-mode replace
```

Bỏ qua extension hoàn toàn:

```bash
ductu dir http://target.htb -wd common.txt -no-extension
```

Thêm prefix/suffix:

```bash
ductu dir http://target.htb -wd common.txt -prefixes old-,dev- -suffixes .bak,~
```

## Recursive scan

Bật recursive:

```bash
ductu dir http://target.htb -wd common.txt -r
```

Mặc định depth là `4`. Đổi depth:

```bash
ductu dir http://target.htb -wd common.txt -r -depth 2
```

Strategy mặc định chỉ đi tiếp theo những kết quả được xem là directory hợp lý.
Greedy strategy sẽ xử lý tiếp mọi kết quả đã pass filter:

```bash
ductu dir http://target.htb -wd common.txt -r -recursion-strategy greedy
```

Loại trừ segment khi recursive:

```bash
ductu dir http://target.htb -wd common.txt -r -exclude-subdirs backup,tmp,cache
```

`exclude-subdirs` so khớp theo segment path, không phải substring. `backup` sẽ
khớp `/backup/` nhưng không khớp `/backup2/`.

## Resume và report

Dùng resume:

```bash
ductu dir http://target.htb -wd common.txt -resume ductu.resume.json
```

Nếu dùng Ctrl+C, tool sẽ cố gắng lưu state. Lần sau chạy lại cùng config và
cùng file resume, tool sẽ tiếp tục từ phần đã scan.

Ghi report JSON:

```bash
ductu all http://target.htb -ws subs.txt -wd common.txt -o report.json
```

Report gồm:

- Target domain/base URL.
- Thời gian bắt đầu và duration.
- Wildcard DNS info.
- Soft-404 info.
- Danh sách subdomain.
- Danh sách directory/path.
- Summary.

## Wordlist gợi ý trên Kali

Subdomain:

```bash
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
```

Directory:

```bash
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
```

Tool cũng có lệnh:

```bash
ductu -list-wordlists
```

## Ví dụ thực chiến CTF/lab

Subdomain trước:

```bash
ductu sub bedside.htb \
  -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -dns-extra
```

Directory với extension:

```bash
ductu dir http://bedside.htb \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e php,txt,bak
```

Directory recursive:

```bash
ductu dir http://bedside.htb \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e php,txt,bak \
  -r -depth 4
```

All in one:

```bash
ductu all http://bedside.htb \
  -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e php,txt,bak \
  -o bedside-report.json
```

## Build verify

Chạy các lệnh này trước khi release:

```bash
go test ./...
go vet ./...
go build -o ductu .
```

Trong môi trường Codex hiện tại, `go` không có trong PATH nên mình không verify
được build trực tiếp ở đây. Trên Kali có Go thì các lệnh trên sẽ là cách kiểm
tra đúng.

## Giới hạn

- Wildcard DNS và soft-404 là heuristic, có thể lọc nhầm trên target lạ.
- `-ct` cần internet để query crt.sh.
- Scan recursive với wordlist lớn có thể rất chậm và tạo nhiều request.
- Output realtime nên một số dòng đã in sẽ không bị xóa nếu sau đó bị dedup.
- Tool không thay thế Burp/ffuf/dirsearch trong mọi tình huống, nhưng gọn và đủ
  tốt cho workflow subdomain + directory cơ bản.

## License

MIT License. Xem chi tiết trong [LICENSE](LICENSE).

Copyright (c) 2026 Duc Tu.

Bạn vẫn giữ bản quyền của project. License này cho phép người khác xem, tải,
sử dụng, sửa đổi và phân phối lại code, miễn là họ giữ lại thông báo copyright
và nội dung license.
