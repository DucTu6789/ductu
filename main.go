// ductu - a small recon CLI for AUTHORIZED pentest/lab use only.
//
// It scans BOTH subdomains and directories in a single run, each with its
// own wordlist. Standard library only (net, net/http, flag, encoding/json...).
//
// Build:  go build -o ductu .
// Legal:  use only against systems you own or are explicitly permitted to test.
package main

import (
        "bufio"
        "context"
        "crypto/tls"
        "encoding/json"
        "flag"
        "fmt"
        "io"
        "math/rand"
        "net"
        "net/http"
        "net/url"
        "os"
        "sort"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

// ---------------------------------------------------------------------------
// ANSI colors
// ---------------------------------------------------------------------------

const (
        cReset  = "\033[0m"
        cBold   = "\033[1m"
        cRed    = "\033[31m"
        cGreen  = "\033[32m"
        cYellow = "\033[33m"
        cCyan   = "\033[36m"
        cGray   = "\033[90m"
)

func colorize(noColor bool, color, s string) string {
        if noColor || color == "" {
                return s
        }
        return color + s + cReset
}

// colorForStatus maps an HTTP status code to a color per the spec:
// 2xx green, 3xx cyan, 401/403 yellow, other 4xx yellow, 5xx red.
func colorForStatus(code int) string {
        switch {
        case code >= 200 && code < 300:
                return cGreen
        case code >= 300 && code < 400:
                return cCyan
        case code >= 400 && code < 500:
                return cYellow
        case code >= 500:
                return cRed
        default:
                return ""
        }
}

// ---------------------------------------------------------------------------
// Column layout (fixed widths, rune-aware padding for clean alignment)
// ---------------------------------------------------------------------------

const (
        wSub   = 40
        wIP    = 34
        wCName = 28

        wCode = 4
        wSize = 8
        wPath = 44
        wNote = 40

        sep = "  "
)

// cell truncates+left-pads s to exactly `width` runes (adds "..." if cut).
func cell(s string, width int) string {
        r := []rune(s)
        if len(r) > width {
                if width > 3 {
                        s = string(r[:width-3]) + "..."
                } else {
                        s = string(r[:width])
                }
                r = []rune(s)
        }
        if len(r) < width {
                return s + strings.Repeat(" ", width-len(r))
        }
        return s
}

// cellRight is like cell but right-aligned (used for SIZE).
func cellRight(s string, width int) string {
        r := []rune(s)
        if len(r) > width {
                s = string(r[:width])
                r = []rune(s)
        }
        if len(r) < width {
                return strings.Repeat(" ", width-len(r)) + s
        }
        return s
}

func humanSize(n int64) string {
        switch {
        case n < 0:
                return "-"
        case n < 1024:
                return fmt.Sprintf("%dB", n)
        case n < 1024*1024:
                return fmt.Sprintf("%.1fK", float64(n)/1024)
        case n < 1024*1024*1024:
                return fmt.Sprintf("%.1fM", float64(n)/(1024*1024))
        default:
                return fmt.Sprintf("%.1fG", float64(n)/(1024*1024*1024))
        }
}

func truncate(s string, max int) string {
        r := []rune(s)
        if len(r) <= max {
                return s
        }
        if max <= 3 {
                return string(r[:max])
        }
        return string(r[:max-3]) + "..."
}

// tail shortens a long path by keeping the last n chars with a leading "...".
func tail(s string, n int) string {
        if len(s) <= n {
                return s
        }
        if n <= 3 {
                return s[len(s)-n:]
        }
        return "..." + s[len(s)-(n-3):]
}

func shortCT(ct string) string {
        if i := strings.Index(ct, ";"); i >= 0 {
                ct = ct[:i]
        }
        return strings.TrimSpace(ct)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Config struct {
        Domain    string
        BaseURL   string
        SubWL     string
        DirWL     string
        Threads   int
        Timeout   time.Duration
        Exts      []string
        Codes     map[int]bool
        HideCodes map[int]bool
        Insecure  bool
        Follow    bool
        OutFile   string
        NoColor   bool
}

type SubResult struct {
        FQDN  string   `json:"fqdn"`
        IPs   []string `json:"ips"`
        CNAME string   `json:"cname,omitempty"`
}

type dirResult struct {
        Path        string `json:"path"`
        URL         string `json:"url"`
        Status      int    `json:"status"`
        Size        int64  `json:"size"`
        Location    string `json:"location,omitempty"`
        ContentType string `json:"content_type,omitempty"`
        Err         string `json:"error,omitempty"`
}

type WildcardInfo struct {
        Detected bool     `json:"detected"`
        IPs      []string `json:"ips,omitempty"`
        Filtered int      `json:"filtered_noise"`
}

type Soft404Info struct {
        Detected bool   `json:"detected"`
        Note     string `json:"note,omitempty"`
        Filtered int    `json:"filtered_noise"`
}

type soft404Sig struct {
        status int
        size   int64
}

type Summary struct {
        TotalSubdomains  int     `json:"total_subdomains"`
        TotalDirectories int     `json:"total_directories"`
        Wildcard         bool    `json:"wildcard"`
        Soft404          bool    `json:"soft_404"`
        DurationSeconds  float64 `json:"duration_seconds"`
}

type Report struct {
        Target struct {
                Domain  string `json:"domain,omitempty"`
                BaseURL string `json:"base_url,omitempty"`
        } `json:"target"`
        StartedAt   string        `json:"started_at"`
        Duration    string        `json:"duration"`
        Wildcard    *WildcardInfo `json:"wildcard,omitempty"`
        Soft404     *Soft404Info  `json:"soft_404,omitempty"`
        Subdomains  []SubResult   `json:"subdomains"`
        Directories []dirResult   `json:"directories"`
        Summary     Summary       `json:"summary"`
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

func banner(noColor bool) {
        art := `  ____              _______     
 |  _ \ _   _  ___ |__   __|   _ 
 | | | | | | |/ __|   | | | | | |
 | |_| | |_| | (__    | | | |_| |
 |____/ \__,_|\___|   |_|  \__,_|`

        if noColor {
                fmt.Println(art)
        } else {
                fmt.Println(cCyan + cBold + art + cReset)
        }
        fmt.Println()
}

func sectionHeader(noColor bool, title, info string) {
        line := strings.Repeat("─", 60)
        fmt.Println()
        fmt.Println(colorize(noColor, cCyan+cBold, line))
        fmt.Println(colorize(noColor, cCyan+cBold, "  "+title))
        if info != "" {
                for _, l := range strings.Split(info, "\n") {
                        if !strings.HasPrefix(l, "  ") {
                                l = "  " + l
                        }
                        fmt.Println(colorize(noColor, cGray, l))
                }
        }
        fmt.Println(colorize(noColor, cCyan+cBold, line))
}

// ---------------------------------------------------------------------------
// Wordlist / candidate builders
// ---------------------------------------------------------------------------

// loadWordlist reads a file, dropping blank lines and #-comments, de-duping.
func loadWordlist(path string) ([]string, error) {
        f, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer f.Close()

        var words []string
        seen := make(map[string]bool)
        sc := bufio.NewScanner(f)
        sc.Buffer(make([]byte, 1024*1024), 1024*1024) // allow long lines
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                if seen[line] {
                        continue
                }
                seen[line] = true
                words = append(words, line)
        }
        if err := sc.Err(); err != nil {
                return nil, err
        }
        return words, nil
}

// buildFQDNs joins each word with the root domain, de-dupes, lowercases.
func buildFQDNs(words []string, domain string) []string {
        domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
        seen := make(map[string]bool)
        var out []string
        for _, w := range words {
                w = strings.ToLower(strings.Trim(strings.TrimSpace(w), "."))
                if w == "" || strings.HasPrefix(w, "#") {
                        continue
                }
                var fqdn string
                if w == domain || strings.HasSuffix(w, "."+domain) {
                        fqdn = w // wordlist already carries the domain
                } else if w == "@" {
                        fqdn = domain // apex
                } else {
                        fqdn = w + "." + domain
                }
                if !seen[fqdn] {
                        seen[fqdn] = true
                        out = append(out, fqdn)
                }
        }
        return out
}

// buildPaths joins each word with the requested extensions, de-dupes.
func buildPaths(words []string, exts []string) []string {
        seen := make(map[string]bool)
        var out []string
        add := func(p string) {
                if p == "" || seen[p] {
                        return
                }
                seen[p] = true
                out = append(out, p)
        }
        for _, w := range words {
                w = strings.TrimSpace(w)
                if w == "" || strings.HasPrefix(w, "#") {
                        continue
                }
                w = strings.TrimPrefix(w, "/")
                add(w)
                for _, e := range exts {
                        add(w + "." + e)
                }
        }
        return out
}

func joinURL(base, p string) string {
        base = strings.TrimRight(base, "/")
        p = strings.TrimLeft(p, "/")
        return base + "/" + p
}

func randLabel(n int) string {
        const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
        b := make([]byte, n)
        for i := range b {
                b[i] = letters[rand.Intn(len(letters))]
        }
        return "zzq" + string(b) // improbable prefix
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

// resolveHost resolves A/AAAA (LookupHost) plus a meaningful CNAME.
func resolveHost(ctx context.Context, r *net.Resolver, host string, timeout time.Duration) ([]string, string, error) {
        c1, cancel1 := context.WithTimeout(ctx, timeout)
        defer cancel1()
        ips, err := r.LookupHost(c1, host)
        if err != nil {
                return nil, "", err
        }
        sort.Strings(ips)

        cname := ""
        c2, cancel2 := context.WithTimeout(ctx, timeout)
        defer cancel2()
        if cn, e := r.LookupCNAME(c2, host); e == nil {
                cn = strings.TrimSuffix(cn, ".")
                if cn != "" && !strings.EqualFold(cn, host) {
                        cname = cn
                }
        }
        return ips, cname, nil
}

// detectWildcard resolves a few random labels; if most resolve, it's wildcard
// DNS and we record the catch-all IP set so we can filter noise later.
func detectWildcard(ctx context.Context, r *net.Resolver, domain string, timeout time.Duration) WildcardInfo {
        ipset := make(map[string]bool)
        hits := 0
        const tries = 3
        for i := 0; i < tries; i++ {
                host := randLabel(12) + "." + domain
                ips, _, err := resolveHost(ctx, r, host, timeout)
                if err == nil && len(ips) > 0 {
                        hits++
                        for _, ip := range ips {
                                ipset[ip] = true
                        }
                }
        }
        info := WildcardInfo{}
        if hits >= 2 {
                info.Detected = true
                for ip := range ipset {
                        info.IPs = append(info.IPs, ip)
                }
                sort.Strings(info.IPs)
        }
        return info
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

// probe performs a single GET and captures status, size, redirect + type.
func probe(client *http.Client, rawURL string) dirResult {
        res := dirResult{URL: rawURL}
        req, err := http.NewRequest(http.MethodGet, rawURL, nil)
        if err != nil {
                res.Err = err.Error()
                return res
        }
        req.Header.Set("User-Agent", "ductu-recon/1.0 (authorized testing)")
        req.Header.Set("Accept", "*/*")

        resp, err := client.Do(req)
        if err != nil {
                res.Err = err.Error()
                return res
        }
        defer resp.Body.Close()

        const cap = 2 << 20 // read at most 2MB to size the body
        n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, cap))
        res.Status = resp.StatusCode
        res.Size = n
        if resp.ContentLength > n {
                res.Size = resp.ContentLength
        }
        res.ContentType = resp.Header.Get("Content-Type")
        res.Location = resp.Header.Get("Location")
        return res
}

// calibrateSoft404 probes random paths to fingerprint catch-all responses.
func calibrateSoft404(client *http.Client, base string, exts []string) (Soft404Info, []soft404Sig) {
        probes := []string{randLabel(16), randLabel(18), randLabel(14) + "/"}
        if len(exts) > 0 {
                probes = append(probes, randLabel(15)+"."+exts[0])
        }
        var sigs []soft404Sig
        softStatuses := make(map[int]int)
        for _, p := range probes {
                r := probe(client, joinURL(base, p))
                if r.Err != "" {
                        continue
                }
                sigs = append(sigs, soft404Sig{status: r.Status, size: r.Size})
                if r.Status < 400 { // a non-error response to a bogus path = catch-all
                        softStatuses[r.Status]++
                }
        }
        info := Soft404Info{}
        for st, cnt := range softStatuses {
                if cnt >= 2 {
                        info.Detected = true
                        info.Note = fmt.Sprintf("%d catch-all", st)
                }
        }
        return info, sigs
}

func isSoft404(r dirResult, sigs []soft404Sig) bool {
        for _, s := range sigs {
                if s.status < 400 && r.Status == s.status {
                        d := r.Size - s.size
                        if d < 0 {
                                d = -d
                        }
                        tol := s.size / 20 // 5% size tolerance for path-echoing pages
                        if tol < 48 {
                                tol = 48
                        }
                        if d <= tol {
                                return true
                        }
                }
        }
        return false
}

func shouldShow(status int, codes, hideCodes map[int]bool) bool {
        if len(codes) > 0 {
                return codes[status]
        }
        return !hideCodes[status]
}

// ---------------------------------------------------------------------------
// Progress (transient, on stderr so stdout tables stay clean)
// ---------------------------------------------------------------------------

func startProgress(label string, total int, noColor bool) (*int64, func()) {
        var done int64
        stop := make(chan struct{})
        finished := make(chan struct{})
        go func() {
                defer close(finished)
                t := time.NewTicker(150 * time.Millisecond)
                defer t.Stop()
                for {
                        select {
                        case <-stop:
                                fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 60))
                                return
                        case <-t.C:
                                fmt.Fprintf(os.Stderr, "\r  scanning %s ... %d/%d", label, atomic.LoadInt64(&done), total)
                        }
                }
        }()
        return &done, func() { close(stop); <-finished }
}

// ---------------------------------------------------------------------------
// Subdomain scan
// ---------------------------------------------------------------------------

func runSubScan(cfg Config, resolver *net.Resolver) ([]SubResult, WildcardInfo) {
        words, err := loadWordlist(cfg.SubWL)
        if err != nil {
                fmt.Fprintf(os.Stderr, "  [!] cannot read sub wordlist: %v\n", err)
                return nil, WildcardInfo{}
        }
        fqdns := buildFQDNs(words, cfg.Domain)

        ctx := context.Background()
        wc := detectWildcard(ctx, resolver, cfg.Domain, cfg.Timeout)

        wcNote := "none"
        if wc.Detected {
                wcNote = "detected -> " + truncate(strings.Join(wc.IPs, ","), 40)
        }
        info := fmt.Sprintf("candidates: %d   wordlist: %s\ndomain: %s   wildcard: %s",
                len(fqdns), tail(cfg.SubWL, 48), cfg.Domain, wcNote)
        sectionHeader(cfg.NoColor, "SUBDOMAIN SCAN", info)

        wcSet := make(map[string]bool)
        for _, ip := range wc.IPs {
                wcSet[ip] = true
        }

        var (
                mu       sync.Mutex
                results  []SubResult
                filtered int
        )
        donePtr, stop := startProgress("subdomains", len(fqdns), cfg.NoColor)
        sem := make(chan struct{}, cfg.Threads)
        var wg sync.WaitGroup
        for _, fq := range fqdns {
                wg.Add(1)
                sem <- struct{}{}
                go func(host string) {
                        defer wg.Done()
                        defer func() { <-sem }()
                        defer atomic.AddInt64(donePtr, 1)

                        ips, cname, err := resolveHost(ctx, resolver, host, cfg.Timeout)
                        if err != nil || len(ips) == 0 {
                                return
                        }
                        // wildcard noise filter: drop hosts whose IPs are all in the
                        // catch-all set and that carry no distinguishing CNAME.
                        if wc.Detected && cname == "" {
                                all := true
                                for _, ip := range ips {
                                        if !wcSet[ip] {
                                                all = false
                                                break
                                        }
                                }
                                if all {
                                        mu.Lock()
                                        filtered++
                                        mu.Unlock()
                                        return
                                }
                        }
                        mu.Lock()
                        results = append(results, SubResult{FQDN: host, IPs: ips, CNAME: cname})
                        mu.Unlock()
                }(fq)
        }
        wg.Wait()
        stop()

        sort.Slice(results, func(i, j int) bool { return results[i].FQDN < results[j].FQDN })
        wc.Filtered = filtered

        printSubTable(cfg, results)
        foot := fmt.Sprintf("  → %d subdomains resolved", len(results))
        if filtered > 0 {
                foot += fmt.Sprintf("  (filtered %d wildcard noise)", filtered)
        }
        fmt.Println(colorize(cfg.NoColor, cGray, foot))
        return results, wc
}

func printSubTable(cfg Config, results []SubResult) {
        if len(results) == 0 {
                fmt.Println(colorize(cfg.NoColor, cGray, "  (no subdomains resolved)"))
                return
        }
        hdr := cell("SUBDOMAIN", wSub) + sep + cell("IP(s)", wIP) + sep + cell("CNAME", wCName)
        rule := cell(strings.Repeat("-", wSub), wSub) + sep + cell(strings.Repeat("-", wIP), wIP) + sep + cell(strings.Repeat("-", wCName), wCName)
        fmt.Println(colorize(cfg.NoColor, cBold, hdr))
        fmt.Println(colorize(cfg.NoColor, cGray, rule))
        for _, r := range results {
                sc := colorize(cfg.NoColor, cGreen, cell(r.FQDN, wSub))
                ic := cell(strings.Join(r.IPs, ", "), wIP)
                cc := colorize(cfg.NoColor, cCyan, cell(r.CNAME, wCName))
                fmt.Println(sc + sep + ic + sep + cc)
        }
}

// ---------------------------------------------------------------------------
// Directory scan
// ---------------------------------------------------------------------------

func runDirScan(cfg Config, client *http.Client) ([]dirResult, Soft404Info) {
        words, err := loadWordlist(cfg.DirWL)
        if err != nil {
                fmt.Fprintf(os.Stderr, "  [!] cannot read dir wordlist: %v\n", err)
                return nil, Soft404Info{}
        }
        paths := buildPaths(words, cfg.Exts)

        soft, sigs := calibrateSoft404(client, cfg.BaseURL, cfg.Exts)
        softActive := false
        for _, s := range sigs {
                if s.status < 400 {
                        softActive = true
                }
        }

        extNote := "none"
        if len(cfg.Exts) > 0 {
                extNote = strings.Join(cfg.Exts, ",")
        }
        softNote := "none"
        if soft.Detected {
                softNote = soft.Note
        } else if softActive {
                softNote = "possible"
        }
        info := fmt.Sprintf("candidates: %d   exts: %s   wordlist: %s\nbase: %s   soft-404: %s",
                len(paths), extNote, tail(cfg.DirWL, 40), cfg.BaseURL, softNote)
        sectionHeader(cfg.NoColor, "DIRECTORY SCAN", info)

        var (
                mu       sync.Mutex
                results  []dirResult
                filtered int
        )
        donePtr, stop := startProgress("directories", len(paths), cfg.NoColor)
        sem := make(chan struct{}, cfg.Threads)
        var wg sync.WaitGroup
        for _, p := range paths {
                wg.Add(1)
                sem <- struct{}{}
                go func(path string) {
                        defer wg.Done()
                        defer func() { <-sem }()
                        defer atomic.AddInt64(donePtr, 1)

                        r := probe(client, joinURL(cfg.BaseURL, path))
                        r.Path = path
                        if r.Err != "" {
                                return
                        }
                        if softActive && isSoft404(r, sigs) {
                                mu.Lock()
                                filtered++
                                mu.Unlock()
                                return
                        }
                        if !shouldShow(r.Status, cfg.Codes, cfg.HideCodes) {
                                return
                        }
                        mu.Lock()
                        results = append(results, r)
                        mu.Unlock()
                }(p)
        }
        wg.Wait()
        stop()

        sort.Slice(results, func(i, j int) bool {
                if results[i].Status != results[j].Status {
                        return results[i].Status < results[j].Status
                }
                return results[i].Path < results[j].Path
        })
        soft.Filtered = filtered

        printDirTable(cfg, results)
        foot := fmt.Sprintf("  → %d paths", len(results))
        if filtered > 0 {
                foot += fmt.Sprintf("  (filtered %d soft-404 noise)", filtered)
        }
        fmt.Println(colorize(cfg.NoColor, cGray, foot))
        return results, soft
}

func buildNote(r dirResult) string {
        var parts []string
        if r.Status >= 300 && r.Status < 400 && r.Location != "" {
                parts = append(parts, "→ "+r.Location)
        }
        if ct := shortCT(r.ContentType); ct != "" {
                parts = append(parts, ct)
        }
        return strings.Join(parts, " | ")
}

func printDirTable(cfg Config, results []dirResult) {
        if len(results) == 0 {
                fmt.Println(colorize(cfg.NoColor, cGray, "  (no paths matched filters)"))
                return
        }
        hdr := cell("CODE", wCode) + sep + cellRight("SIZE", wSize) + sep + cell("PATH", wPath) + sep + cell("NOTE", wNote)
        rule := cell(strings.Repeat("-", wCode), wCode) + sep + cellRight(strings.Repeat("-", wSize), wSize) + sep + cell(strings.Repeat("-", wPath), wPath) + sep + cell(strings.Repeat("-", wNote), wNote)
        fmt.Println(colorize(cfg.NoColor, cBold, hdr))
        fmt.Println(colorize(cfg.NoColor, cGray, rule))
        for _, r := range results {
                plain := cell(strconv.Itoa(r.Status), wCode) + sep +
                        cellRight(humanSize(r.Size), wSize) + sep +
                        cell(r.Path, wPath) + sep +
                        cell(buildNote(r), wNote)
                fmt.Println(colorize(cfg.NoColor, colorForStatus(r.Status), plain))
        }
}

// ---------------------------------------------------------------------------
// Summary + JSON output
// ---------------------------------------------------------------------------

func printSummary(cfg Config, doSub, doDir bool, subs []SubResult, dirs []dirResult, wc WildcardInfo, soft Soft404Info, dur time.Duration) {
        sectionHeader(cfg.NoColor, "SUMMARY", "")
        if doSub {
                line := fmt.Sprintf("  subdomains found  : %d", len(subs))
                if wc.Detected {
                        line += fmt.Sprintf("   (wildcard: yes, filtered %d)", wc.Filtered)
                } else {
                        line += "   (wildcard: no)"
                }
                fmt.Println(line)
        }
        if doDir {
                line := fmt.Sprintf("  directories found : %d", len(dirs))
                if soft.Detected || soft.Filtered > 0 {
                        line += fmt.Sprintf("   (soft-404: yes, filtered %d)", soft.Filtered)
                } else {
                        line += "   (soft-404: no)"
                }
                fmt.Println(line)
        }
        fmt.Printf("  duration          : %.2fs\n", dur.Seconds())
        fmt.Println(colorize(cfg.NoColor, cCyan+cBold, strings.Repeat("─", 60)))
}

func writeReport(cfg Config, subs []SubResult, dirs []dirResult, wc WildcardInfo, soft Soft404Info, started time.Time, dur time.Duration) error {
        if subs == nil {
                subs = []SubResult{}
        }
        if dirs == nil {
                dirs = []dirResult{}
        }
        var rep Report
        rep.Target.Domain = cfg.Domain
        rep.Target.BaseURL = cfg.BaseURL
        rep.StartedAt = started.Format(time.RFC3339)
        rep.Duration = dur.String()
        if wc.Detected || wc.Filtered > 0 {
                w := wc
                rep.Wildcard = &w
        }
        if soft.Detected || soft.Filtered > 0 {
                s := soft
                rep.Soft404 = &s
        }
        rep.Subdomains = subs
        rep.Directories = dirs
        rep.Summary = Summary{
                TotalSubdomains:  len(subs),
                TotalDirectories: len(dirs),
                Wildcard:         wc.Detected,
                Soft404:          soft.Detected,
                DurationSeconds:  dur.Seconds(),
        }
        b, err := json.MarshalIndent(rep, "", "  ")
        if err != nil {
                return err
        }
        return os.WriteFile(cfg.OutFile, b, 0644)
}

// ---------------------------------------------------------------------------
// Parsing helpers, usage, wordlist hints
// ---------------------------------------------------------------------------

func parseIntSet(s string) map[int]bool {
        m := make(map[int]bool)
        for _, p := range strings.Split(s, ",") {
                p = strings.TrimSpace(p)
                if p == "" {
                        continue
                }
                if n, err := strconv.Atoi(p); err == nil {
                        m[n] = true
                }
        }
        return m
}

func parseExts(s string) []string {
        var out []string
        seen := make(map[string]bool)
        for _, p := range strings.Split(s, ",") {
                p = strings.TrimPrefix(strings.TrimSpace(p), ".")
                if p == "" || seen[p] {
                        continue
                }
                seen[p] = true
                out = append(out, p)
        }
        return out
}

func printWordlists() {
        fmt.Println("Common SecLists wordlists (install: https://github.com/danielmiessler/SecLists):")
        fmt.Println()
        fmt.Println("Subdomain (DNS):")
        fmt.Println("  /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        fmt.Println("  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt")
        fmt.Println("  /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt")
        fmt.Println()
        fmt.Println("Directory / Web-Content:")
        fmt.Println("  /usr/share/seclists/Discovery/Web-Content/common.txt")
        fmt.Println("  /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt")
        fmt.Println("  /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt")
        fmt.Println("  /usr/share/seclists/Discovery/Web-Content/big.txt")
}

func printUsage() {
        w := os.Stderr
        fmt.Fprintln(w, "ductu — subdomain + directory recon scanner (authorized testing only)")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "USAGE:")
        fmt.Fprintln(w, "  ductu -d <domain> -ws <sub_wordlist>                 # subdomain scan")
        fmt.Fprintln(w, "  ductu -u <base_url> -wd <dir_wordlist>               # directory scan")
        fmt.Fprintln(w, "  ductu -d <domain> -ws <wl> -u <url> -wd <wl>         # both in one run")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "MODES (auto-selected by which flags are present):")
        fmt.Fprintln(w, "  -d + -ws     -> subdomain scan")
        fmt.Fprintln(w, "  -u + -wd     -> directory scan")
        fmt.Fprintln(w, "  all four     -> both scans")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "FLAGS:")
        fmt.Fprintln(w, "  -d   string      root domain for subdomain scan (e.g. example.com)")
        fmt.Fprintln(w, "  -u   string      base URL for directory scan (e.g. https://target.lab)")
        fmt.Fprintln(w, "  -ws  string      subdomain wordlist (SecLists DNS style)")
        fmt.Fprintln(w, "  -wd  string      directory wordlist (Web-Content style)")
        fmt.Fprintln(w, "  -t   int         concurrent workers (default 50)")
        fmt.Fprintln(w, "  -timeout int     per-request timeout in seconds (default 4)")
        fmt.Fprintln(w, "  -e   string      extensions for dir paths, csv (e.g. php,html,txt,bak)")
        fmt.Fprintln(w, "  -codes string    only show these status codes (e.g. 200,301,403)")
        fmt.Fprintln(w, "  -hide-codes str  hide these status codes (default 404)")
        fmt.Fprintln(w, "  -k               skip TLS verification (self-signed lab)")
        fmt.Fprintln(w, "  -follow          follow redirects (default: report 3xx + Location)")
        fmt.Fprintln(w, "  -o   string      write JSON report to file")
        fmt.Fprintln(w, "  -no-color        disable ANSI colors")
        fmt.Fprintln(w, "  -list-wordlists  print common SecLists paths and exit")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "EXAMPLE:")
        fmt.Fprintln(w, "  ductu -d target.lab -ws subs.txt -u https://target.lab -wd common.txt \\")
        fmt.Fprintln(w, "        -t 60 -e php,txt,bak -k -o report.json")
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
        domainF := flag.String("d", "", "root domain for subdomain scan")
        baseURLF := flag.String("u", "", "base URL for directory scan")
        subWLF := flag.String("ws", "", "subdomain wordlist")
        dirWLF := flag.String("wd", "", "directory wordlist")
        threadsF := flag.Int("t", 50, "concurrent workers")
        timeoutF := flag.Int("timeout", 4, "per-request timeout seconds")
        extsF := flag.String("e", "", "extensions csv (php,html,txt,bak)")
        codesF := flag.String("codes", "", "only show these status codes")
        hideCodesF := flag.String("hide-codes", "404", "hide these status codes")
        insecureF := flag.Bool("k", false, "skip TLS verification")
        followF := flag.Bool("follow", false, "follow redirects")
        outFileF := flag.String("o", "", "JSON report path")
        noColorF := flag.Bool("no-color", false, "disable ANSI colors")
        listWLF := flag.Bool("list-wordlists", false, "print common SecLists paths and exit")

        flag.Usage = printUsage
        flag.Parse()

        noColor := *noColorF

        if *listWLF {
                banner(noColor)
                printWordlists()
                return
        }

        banner(noColor)

        doSub := *domainF != "" && *subWLF != ""
        doDir := *baseURLF != "" && *dirWLF != ""

        if !doSub && !doDir {
                if *domainF != "" && *subWLF == "" {
                        fmt.Fprintln(os.Stderr, "  [!] -d needs -ws (subdomain wordlist)")
                }
                if *subWLF != "" && *domainF == "" {
                        fmt.Fprintln(os.Stderr, "  [!] -ws needs -d (root domain)")
                }
                if *baseURLF != "" && *dirWLF == "" {
                        fmt.Fprintln(os.Stderr, "  [!] -u needs -wd (directory wordlist)")
                }
                if *dirWLF != "" && *baseURLF == "" {
                        fmt.Fprintln(os.Stderr, "  [!] -wd needs -u (base URL)")
                }
                fmt.Fprintln(os.Stderr)
                printUsage()
                os.Exit(1)
        }

        if doDir {
                u, err := url.Parse(*baseURLF)
                if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
                        fmt.Fprintf(os.Stderr, "  [!] invalid base URL %q (need http:// or https://)\n", *baseURLF)
                        os.Exit(1)
                }
        }

        cfg := Config{
                Domain:    strings.TrimSpace(*domainF),
                BaseURL:   strings.TrimRight(strings.TrimSpace(*baseURLF), "/"),
                SubWL:     *subWLF,
                DirWL:     *dirWLF,
                Threads:   *threadsF,
                Timeout:   time.Duration(*timeoutF) * time.Second,
                Exts:      parseExts(*extsF),
                Codes:     parseIntSet(*codesF),
                HideCodes: parseIntSet(*hideCodesF),
                Insecure:  *insecureF,
                Follow:    *followF,
                OutFile:   *outFileF,
                NoColor:   noColor,
        }
        if cfg.Threads < 1 {
                cfg.Threads = 1
        }

        resolver := &net.Resolver{
                PreferGo: true,
                Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
                        d := net.Dialer{Timeout: cfg.Timeout}
                        return d.DialContext(ctx, network, address)
                },
        }

        transport := &http.Transport{
                TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.Insecure},
                DialContext:           (&net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}).DialContext,
                MaxIdleConns:          cfg.Threads * 2,
                MaxIdleConnsPerHost:   cfg.Threads * 2,
                IdleConnTimeout:       90 * time.Second,
                TLSHandshakeTimeout:   cfg.Timeout,
                ResponseHeaderTimeout: cfg.Timeout,
                ExpectContinueTimeout: time.Second,
        }
        client := &http.Client{
                Timeout:   cfg.Timeout + 2*time.Second,
                Transport: transport,
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        if !cfg.Follow {
                                return http.ErrUseLastResponse // report the 3xx instead of following
                        }
                        if len(via) >= 10 {
                                return fmt.Errorf("stopped after 10 redirects")
                        }
                        return nil
                },
        }

        start := time.Now()
        var (
                subs []SubResult
                dirs []dirResult
                wc   WildcardInfo
                soft Soft404Info
        )
        if doSub {
                subs, wc = runSubScan(cfg, resolver)
        }
        if doDir {
                dirs, soft = runDirScan(cfg, client)
        }
        dur := time.Since(start)

        printSummary(cfg, doSub, doDir, subs, dirs, wc, soft, dur)

        if cfg.OutFile != "" {
                if err := writeReport(cfg, subs, dirs, wc, soft, start, dur); err != nil {
                        fmt.Fprintf(os.Stderr, "  [!] failed to write report: %v\n", err)
                } else {
                        fmt.Println(colorize(cfg.NoColor, cGray, "  report saved: "+cfg.OutFile))
                }
        }
}
