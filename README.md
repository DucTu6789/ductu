# ductu

`ductu` la CLI recon viet bang Go, dung de scan subdomain va directory/web path
trong moi truong lab, CTF, hoac pentest duoc uy quyen.

Tool chi dung Go standard library, khong can thu vien ben thu ba.

```text
  ____              _______
 |  _ \ _   _  ___ |__   __|   _
 | | | | | | |/ __|   | | | | | |
 | |_| | |_| | (__    | | | |_| |
 |____/ \__,_|\___|   |_|  \__,_|
```

> Chi su dung voi he thong ban so huu hoac duoc phep kiem thu. Khong scan he
> thong khong duoc uy quyen.

## Tinh nang chinh

- Scan subdomain bang wordlist DNS.
- Scan directory/path bang wordlist Web-Content.
- Co 3 mode ro rang: `sub`, `dir`, `all`.
- Mode cu bang flag `-d/-ws/-u/-wd` van hoat dong.
- Wildcard DNS detection de loc subdomain nhieu.
- Soft-404 calibration de loc path gia.
- Recursive directory scan, mac dinh depth la `4`.
- Filter theo status code, size, words, lines, regex body.
- Extension mode: append/replace, co prefix/suffix path.
- Dedup body hash de giam ket qua trung noi dung.
- Rate limit, retry, custom DNS resolver.
- Resume state va JSON report.
- Output table co mau, co cot `WORDS` va `LINES`.

## Cai dat tren Kali

Cai Go va SecLists:

```bash
sudo apt update
sudo apt install -y golang seclists
```

Giai nen project:

```bash
unzip ductu.zip
cd ductu
```

Build:

```bash
go build -o ductu .
```

Chay thu:

```bash
./ductu -h
```

Muon goi `ductu` o moi noi:

```bash
sudo cp ./ductu /usr/local/bin/ductu
ductu -h
```

Neu gap loi:

```text
go: go.mod file not found
```

Thi ban dang build sai thu muc. Hay vao dung thu muc project:

```bash
cd ~/ductu
go build -o ductu .
```

## Cach dung nhanh

Scan subdomain:

```bash
ductu sub example.com -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Scan directory:

```bash
ductu dir https://example.com -wd /usr/share/seclists/Discovery/Web-Content/common.txt
```

Scan ca subdomain va directory:

```bash
ductu all https://example.com \
  -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt
```

Scan directory kem extension:

```bash
ductu dir http://target.htb \
  -wd /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e php,txt,bak
```

Luu y: neu khong truyen `-e`, tool chi scan path goc trong wordlist. Vi du
`admin` se chi thanh `/admin`, khong tu sinh `/admin.php`, `/admin.txt`.

## 3 mode chinh

### 1. Subdomain mode

```bash
ductu sub <domain> -ws <sub_wordlist>
```

Vi du:

```bash
ductu sub bedside.htb -ws subs.txt
```

Flag hay dung:

```bash
ductu sub bedside.htb -ws subs.txt -ct -dns-extra -permute
```

### 2. Directory mode

```bash
ductu dir <base_url> -wd <dir_wordlist>
```

Vi du:

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

Vi du:

```bash
ductu all http://bedside.htb \
  -ws subs.txt \
  -wd common.txt \
  -e php,txt,bak
```

Trong `all` mode, neu ban dua vao `http://example.com`, tool tu lay domain
`example.com` de scan subdomain. Neu muon override domain thi them `-d`:

```bash
ductu all http://app.example.com -d example.com -ws subs.txt -wd common.txt
```

## Flag quan trong

### Global

| Flag | Mac dinh | Y nghia |
| --- | --- | --- |
| `-t` | `50` | So worker chay song song |
| `-timeout` | `4` | Timeout moi request, tinh bang giay |
| `-rate` | `0` | Gioi han request/resolve moi giay, `0` la khong gioi han |
| `-retries` | `0` | So lan retry khi loi DNS/HTTP |
| `-retry-delay` | `500ms` | Delay co ban giua cac lan retry |
| `-resume` | | File resume JSON |
| `-o` | | Ghi report JSON |
| `-no-color` | `false` | Tat mau ANSI |
| `-no-banner` | `false` | Tat banner luc khoi dong |
| `-list-wordlists` | `false` | In wordlist SecLists goi y |

### Subdomain

| Flag | Y nghia |
| --- | --- |
| `-d` | Domain goc, vi du `example.com` |
| `-ws` | Wordlist subdomain |
| `-ct` | Lay them hostname tu crt.sh |
| `-permute` | Tao bien the subdomain sau pass resolve dau |
| `-dns-server` | DNS resolver rieng, vi du `1.1.1.1:53` |
| `-dns-extra` | Lookup MX/NS/TXT va lay hostname tim thay |

### Directory

| Flag | Mac dinh | Y nghia |
| --- | --- | --- |
| `-u` | | Base URL, vi du `https://target.lab` |
| `-wd` | | Wordlist directory/path |
| `-e` | | Extension CSV, vi du `php,html,txt,bak` |
| `-ext-mode` | `append` | `append` hoac `replace` voi `%EXT%` |
| `-no-extension` | `false` | Bo qua logic extension |
| `-prefixes` | | Tao them bien the prefix, CSV |
| `-suffixes` | | Tao them bien the suffix, CSV |
| `-r` | `false` | Bat recursive scan |
| `-recursive` | `false` | Giong `-r` |
| `-depth` | `4` | Do sau recursive toi da |
| `-recursion-strategy` | `default` | `default` hoac `greedy` |
| `-exclude-subdirs` | | Bo qua segment path khi recursive, CSV |

### HTTP

| Flag | Y nghia |
| --- | --- |
| `-H` | Them HTTP header, co the lap lai: `-H 'Name: value'` |
| `-cookie` | Gan raw Cookie header |
| `-auth` | Basic Auth dang `username:password` |
| `-proxy` | HTTP proxy, vi du `http://127.0.0.1:8080` |
| `-k` | Bo qua TLS verify |
| `-follow` | Follow redirect thay vi chi in 3xx + Location |

## Filter ket qua directory

`ductu` ho tro match/filter theo metadata response.

Quy tac:

- Match: tat ca dieu kien match dang bat phai dung.
- Filter: neu trung bat ky dieu kien filter nao thi bo qua.
- Sau do moi ap dung `-codes` va `-hide-codes`.

Status code ho tro range:

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

Tat dedup body hash:

```bash
ductu dir http://target.htb -wd common.txt -no-dedup
```

Doi nguong dedup:

```bash
ductu dir http://target.htb -wd common.txt -dedup-threshold 5
```

Luu y: dedup chi loc ket qua cuoi tu thoi diem hash dat nguong. Vi ket qua duoc
in realtime, cac dong da in truoc do se khong bi xoa khoi terminal.

## Extension va path generation

Mac dinh `-ext-mode append`:

```text
admin -> admin, admin.php, admin.txt
```

Khi wordlist co `%EXT%`, dung `replace`:

```bash
ductu dir http://target.htb -wd raft.txt -e php,txt -ext-mode replace
```

Bo qua extension hoan toan:

```bash
ductu dir http://target.htb -wd common.txt -no-extension
```

Them prefix/suffix:

```bash
ductu dir http://target.htb -wd common.txt -prefixes old-,dev- -suffixes .bak,~
```

## Recursive scan

Bat recursive:

```bash
ductu dir http://target.htb -wd common.txt -r
```

Mac dinh depth la `4`. Doi depth:

```bash
ductu dir http://target.htb -wd common.txt -r -depth 2
```

Strategy mac dinh chi di tiep theo nhung ket qua duoc xem la directory hop ly.
Greedy strategy se xu ly tiep moi ket qua da pass filter:

```bash
ductu dir http://target.htb -wd common.txt -r -recursion-strategy greedy
```

Loai tru segment khi recursive:

```bash
ductu dir http://target.htb -wd common.txt -r -exclude-subdirs backup,tmp,cache
```

`exclude-subdirs` so khop theo segment path, khong phai substring. `backup` se
khop `/backup/` nhung khong khop `/backup2/`.

## Resume va report

Dung resume:

```bash
ductu dir http://target.htb -wd common.txt -resume ductu.resume.json
```

Neu dung Ctrl+C, tool se co gang luu state. Lan sau chay lai cung config va
cung file resume, tool se tiep tuc tu phan da scan.

Ghi report JSON:

```bash
ductu all http://target.htb -ws subs.txt -wd common.txt -o report.json
```

Report gom:

- Target domain/base URL.
- Thoi gian bat dau va duration.
- Wildcard DNS info.
- Soft-404 info.
- Danh sach subdomain.
- Danh sach directory/path.
- Summary.

## Wordlist goi y tren Kali

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

Tool cung co lenh:

```bash
ductu -list-wordlists
```

## Vi du thuc chien CTF/lab

Subdomain truoc:

```bash
ductu sub bedside.htb \
  -ws /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -dns-extra
```

Directory voi extension:

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

Chay cac lenh nay truoc khi release:

```bash
go test ./...
go vet ./...
go build -o ductu .
```

Trong moi truong Codex hien tai, `go` khong co trong PATH nen minh khong verify
duoc build truc tiep o day. Tren Kali co Go thi cac lenh tren se la cach kiem
tra dung.

## Gioi han

- Wildcard DNS va soft-404 la heuristic, co the loc nham tren target la.
- `-ct` can internet de query crt.sh.
- Scan recursive voi wordlist lon co the rat cham va tao nhieu request.
- Output realtime nen mot so dong da in se khong bi xoa neu sau do bi dedup.
- Tool khong thay the Burp/ffuf/dirsearch trong moi tinh huong, nhung gon va du
  tot cho workflow subdomain + directory co ban.
