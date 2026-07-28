package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Config struct {
	Mode      string
	Domain    string
	BaseURL   string
	SubWL     string
        DirWL     string
	Threads   int
	Timeout   time.Duration
	Rate      int
	Retries   int
	RetryDelay time.Duration
	Exts      []string
        Codes     map[int]bool
        HideCodes map[int]bool
        Insecure  bool
	Follow    bool
	OutFile   string
	NoColor   bool
	NoBanner  bool
	Recursive bool
	MaxDepth  int
	Headers   []HTTPHeader
	Cookie    string
	AuthUser  string
	AuthPass  string
	Proxy     string
	Resume    string
	CT        bool
	Permute   bool
	DNSServer string
	DNSExtra  bool
	MatchSizes        map[int]bool
	FilterSizes       map[int]bool
	MatchWords        map[int]bool
	FilterWords       map[int]bool
	MatchLines        map[int]bool
	FilterLines       map[int]bool
	MatchRegex        *regexp.Regexp
	FilterRegex       *regexp.Regexp
	ExtMode           string
	NoExtension       bool
	Prefixes          []string
	Suffixes          []string
	DedupThreshold    int
	NoDedup           bool
	RecursionStrategy string
	ExcludeSubdirs    []string
}

type HTTPHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ---------------------------------------------------------------------------
// Parsing helpers, usage, wordlist hints
// ---------------------------------------------------------------------------

type headerFlags []HTTPHeader

func (h *headerFlags) String() string {
	if h == nil {
		return ""
	}
	var parts []string
	for _, v := range *h {
		parts = append(parts, v.Name+": "+v.Value)
	}
	return strings.Join(parts, ", ")
}

func (h *headerFlags) Set(v string) error {
	name, value, ok := strings.Cut(v, ":")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return fmt.Errorf("header must be in 'Header-Name: value' format")
	}
	*h = append(*h, HTTPHeader{Name: name, Value: strings.TrimSpace(value)})
	return nil
}

func parseIntRangeSet(s string) map[int]bool {
        m := make(map[int]bool)
        for _, p := range strings.Split(s, ",") {
                p = strings.TrimSpace(p)
                if p == "" {
                        continue
                }
                if lo, hi, ok := strings.Cut(p, "-"); ok {
                        start, err1 := strconv.Atoi(strings.TrimSpace(lo))
                        end, err2 := strconv.Atoi(strings.TrimSpace(hi))
                        if err1 != nil || err2 != nil {
                                continue
                        }
                        if start > end {
                                start, end = end, start
                        }
                        for n := start; n <= end; n++ {
                                m[n] = true
                        }
                        continue
                }
                if n, err := strconv.Atoi(p); err == nil {
                        m[n] = true
                }
        }
        return m
}

func parseCSVList(s string) []string {
        var out []string
        seen := make(map[string]bool)
        for _, p := range strings.Split(s, ",") {
                p = strings.TrimSpace(p)
                if p == "" || seen[p] {
                        continue
                }
                seen[p] = true
                out = append(out, p)
        }
        return out
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

func parseBasicAuth(s string) (string, string, error) {
	if strings.TrimSpace(s) == "" {
		return "", "", nil
	}
	user, pass, ok := strings.Cut(s, ":")
	if !ok || user == "" {
		return "", "", fmt.Errorf("-auth must be username:password")
	}
	return user, pass, nil
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
        fmt.Fprintln(w, "ductu - subdomain + directory recon scanner (authorized testing only)")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "USAGE:")
        fmt.Fprintln(w, "  ductu sub <domain> -ws <sub_wordlist>                # subdomain scan")
        fmt.Fprintln(w, "  ductu dir <base_url> -wd <dir_wordlist>              # directory scan")
        fmt.Fprintln(w, "  ductu all <base_url> -ws <sub_wl> -wd <dir_wl>       # both in one run")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "MODES:")
        fmt.Fprintln(w, "  sub      uses positional <domain> with -ws")
        fmt.Fprintln(w, "  dir      uses positional <base_url> with -wd")
        fmt.Fprintln(w, "  all      derives the subdomain root from <base_url> unless -d overrides it")
        fmt.Fprintln(w, "  legacy   old -d/-ws/-u/-wd auto-selection is still accepted")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "GLOBAL:")
        fmt.Fprintln(w, "  -t   int         concurrent workers (default 50)")
        fmt.Fprintln(w, "  -timeout int     per-request timeout in seconds (default 4)")
        fmt.Fprintln(w, "  -rate int        max scan operations per second, 0 = unlimited")
        fmt.Fprintln(w, "  -retries int     retry failed DNS/HTTP operations, 0 = no retry")
        fmt.Fprintln(w, "  -retry-delay dur base delay between retries (default 500ms)")
        fmt.Fprintln(w, "  -resume string   resume state JSON path; saves progress and resumes if present")
        fmt.Fprintln(w, "  -o   string      write JSON report to file")
        fmt.Fprintln(w, "  -no-color        disable ANSI colors")
        fmt.Fprintln(w, "  -no-banner       disable startup banner")
        fmt.Fprintln(w, "  -list-wordlists  print common SecLists paths and exit")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "SUBDOMAIN:")
        fmt.Fprintln(w, "  -d   string      root domain for subdomain scan (e.g. example.com)")
        fmt.Fprintln(w, "  -ws  string      subdomain wordlist (SecLists DNS style)")
        fmt.Fprintln(w, "  -ct              add hostnames from crt.sh Certificate Transparency logs")
        fmt.Fprintln(w, "  -permute         generate common subdomain permutations after first resolve pass")
        fmt.Fprintln(w, "  -dns-server str  custom DNS resolver for subdomain scan (e.g. 1.1.1.1:53)")
        fmt.Fprintln(w, "  -dns-extra       lookup MX/NS/TXT and add hostnames found in TXT records")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "DIRECTORY:")
        fmt.Fprintln(w, "  -u   string      base URL for directory scan (e.g. https://target.lab)")
        fmt.Fprintln(w, "  -wd  string      directory wordlist (Web-Content style)")
        fmt.Fprintln(w, "  -e   string      extensions for dir paths, csv (e.g. php,html,txt,bak)")
        fmt.Fprintln(w, "  -ext-mode str    extension mode: append or replace (default append)")
        fmt.Fprintln(w, "  -no-extension    ignore -e and extension expansion")
        fmt.Fprintln(w, "  -prefixes str    path prefixes to add, csv")
        fmt.Fprintln(w, "  -suffixes str    path suffixes to add, csv")
        fmt.Fprintln(w, "  -r               recursively scan discovered directories")
        fmt.Fprintln(w, "  -recursive       same as -r")
        fmt.Fprintln(w, "  -depth int       max recursive depth (default 4)")
        fmt.Fprintln(w, "  -recursion-strategy str  default or greedy (default default)")
        fmt.Fprintln(w, "  -exclude-subdirs str     recursive path segments to skip, csv")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "FILTERS:")
        fmt.Fprintln(w, "  -codes string    only show these status codes/ranges (e.g. 200,301-303,403)")
        fmt.Fprintln(w, "  -hide-codes str  hide these status codes/ranges (default 400,404)")
        fmt.Fprintln(w, "  -ms string       match response size/ranges")
        fmt.Fprintln(w, "  -fs string       filter response size/ranges")
        fmt.Fprintln(w, "  -mw string       match response word-count/ranges")
        fmt.Fprintln(w, "  -fw string       filter response word-count/ranges")
        fmt.Fprintln(w, "  -ml string       match response line-count/ranges")
        fmt.Fprintln(w, "  -fl string       filter response line-count/ranges")
        fmt.Fprintln(w, "  -mr string       match response body regex")
        fmt.Fprintln(w, "  -fr string       filter response body regex")
        fmt.Fprintln(w, "  -dedup-threshold int  body-hash dedup threshold (default 3)")
        fmt.Fprintln(w, "  -no-dedup        disable body-hash dedup")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "HTTP:")
        fmt.Fprintln(w, "  -H   string      add HTTP header for dir scan; repeatable, 'Name: value'")
        fmt.Fprintln(w, "  -cookie string   raw Cookie header for directory scan")
        fmt.Fprintln(w, "  -auth string     HTTP Basic Auth for directory scan, username:password")
        fmt.Fprintln(w, "  -proxy string    HTTP proxy for directory scan (e.g. http://127.0.0.1:8080)")
        fmt.Fprintln(w, "  -k               skip TLS verification (self-signed lab)")
        fmt.Fprintln(w, "  -follow          follow redirects (default: report 3xx + Location)")
        fmt.Fprintln(w, "")
        fmt.Fprintln(w, "EXAMPLES:")
        fmt.Fprintln(w, "  ductu sub example.com -ws subs.txt -ct -dns-extra")
        fmt.Fprintln(w, "  ductu dir https://example.com -wd common.txt -e php,txt -r -depth 4")
        fmt.Fprintln(w, "  ductu all https://example.com -ws subs.txt -wd common.txt -ct -e php,txt -r")
}
