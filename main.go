// ductu - a small recon CLI for AUTHORIZED pentest/lab use only.
//
// It scans BOTH subdomains and directories in a single run, each with its
// own wordlist. Standard library only (net, net/http, flag, encoding/json...).
//
// Build:  go build -o ductu .
// Legal:  use only against systems you own or are explicitly permitted to test.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type cliOptions struct {
	headersF          headerFlags
	recursiveF        bool
	domainF           *string
	baseURLF          *string
	subWLF            *string
	dirWLF            *string
	threadsF          *int
	timeoutF          *int
	rateF             *int
	retriesF          *int
	retryDelayF       *time.Duration
	extsF             *string
	codesF            *string
	hideCodesF        *string
	matchSizesF       *string
	filterSizesF      *string
	matchWordsF       *string
	filterWordsF      *string
	matchLinesF       *string
	filterLinesF      *string
	matchRegexF       *string
	filterRegexF      *string
	extModeF          *string
	noExtensionF      *bool
	prefixesF         *string
	suffixesF         *string
	dedupThresholdF   *int
	noDedupF          *bool
	recursionStrategyF *string
	excludeSubdirsF   *string
	depthF            *int
	cookieF           *string
	authF             *string
	proxyF            *string
	resumeF           *string
	ctF               *bool
	permuteF          *bool
	dnsServerF        *string
	dnsExtraF         *bool
	insecureF         *bool
	followF           *bool
	outFileF          *string
	noColorF          *bool
	noBannerF         *bool
	listWLF           *bool
}

type boolFlag interface {
	IsBoolFlag() bool
}

func registerCLIFlags(fs *flag.FlagSet) *cliOptions {
	o := &cliOptions{}
	o.domainF = fs.String("d", "", "root domain for subdomain scan")
	o.baseURLF = fs.String("u", "", "base URL for directory scan")
	o.subWLF = fs.String("ws", "", "subdomain wordlist")
	o.dirWLF = fs.String("wd", "", "directory wordlist")
	o.threadsF = fs.Int("t", 50, "concurrent workers")
	o.timeoutF = fs.Int("timeout", 4, "per-request timeout seconds")
	o.rateF = fs.Int("rate", 0, "max scan operations per second, 0 = unlimited")
	o.retriesF = fs.Int("retries", 0, "retry failed DNS/HTTP operations, 0 = no retry")
	o.retryDelayF = fs.Duration("retry-delay", 500*time.Millisecond, "base delay between retries")
	o.extsF = fs.String("e", "", "extensions csv (php,html,txt,bak)")
	o.codesF = fs.String("codes", "", "only show these status codes")
	o.hideCodesF = fs.String("hide-codes", "400,404", "hide these status codes")
	o.matchSizesF = fs.String("ms", "", "match response size/ranges")
	o.filterSizesF = fs.String("fs", "", "filter response size/ranges")
	o.matchWordsF = fs.String("mw", "", "match response word-count/ranges")
	o.filterWordsF = fs.String("fw", "", "filter response word-count/ranges")
	o.matchLinesF = fs.String("ml", "", "match response line-count/ranges")
	o.filterLinesF = fs.String("fl", "", "filter response line-count/ranges")
	o.matchRegexF = fs.String("mr", "", "match response body regex")
	o.filterRegexF = fs.String("fr", "", "filter response body regex")
	o.extModeF = fs.String("ext-mode", "append", "extension mode: append or replace")
	o.noExtensionF = fs.Bool("no-extension", false, "ignore -e and extension expansion")
	o.prefixesF = fs.String("prefixes", "", "path prefixes to add, csv")
	o.suffixesF = fs.String("suffixes", "", "path suffixes to add, csv")
	o.dedupThresholdF = fs.Int("dedup-threshold", 3, "body-hash dedup threshold")
	o.noDedupF = fs.Bool("no-dedup", false, "disable body-hash dedup")
	o.recursionStrategyF = fs.String("recursion-strategy", "default", "recursive strategy: default or greedy")
	o.excludeSubdirsF = fs.String("exclude-subdirs", "", "recursive path segments to skip, csv")
	fs.BoolVar(&o.recursiveF, "r", false, "recursively scan directories")
	fs.BoolVar(&o.recursiveF, "recursive", false, "recursively scan directories")
	o.depthF = fs.Int("depth", 4, "max recursive depth")
	fs.Var(&o.headersF, "H", "HTTP header for directory scan; repeatable, 'Name: value'")
	o.cookieF = fs.String("cookie", "", "raw Cookie header for directory scan")
	o.authF = fs.String("auth", "", "HTTP Basic Auth username:password")
	o.proxyF = fs.String("proxy", "", "HTTP proxy for directory scan")
	o.resumeF = fs.String("resume", "", "resume state JSON path")
	o.ctF = fs.Bool("ct", false, "add hostnames from crt.sh Certificate Transparency logs")
	o.permuteF = fs.Bool("permute", false, "generate common subdomain permutations after first resolve pass")
	o.dnsServerF = fs.String("dns-server", "", "custom DNS resolver for subdomain scan (host:port)")
	o.dnsExtraF = fs.Bool("dns-extra", false, "lookup MX/NS/TXT and add hostnames found in TXT records")
	o.insecureF = fs.Bool("k", false, "skip TLS verification")
	o.followF = fs.Bool("follow", false, "follow redirects")
	o.outFileF = fs.String("o", "", "JSON report path")
	o.noColorF = fs.Bool("no-color", false, "disable ANSI colors")
	o.noBannerF = fs.Bool("no-banner", false, "disable startup banner")
	o.listWLF = fs.Bool("list-wordlists", false, "print common SecLists paths and exit")
	return o
}

func parseInterspersedFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}

		name := strings.TrimLeft(arg, "-")
		if idx := strings.Index(name, "="); idx >= 0 {
			flagArgs = append(flagArgs, arg)
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			flagArgs = append(flagArgs, arg)
			continue
		}
		flagArgs = append(flagArgs, arg)
		if bf, ok := f.Value.(boolFlag); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 >= len(args) {
			return positionals, fmt.Errorf("flag needs an argument: %s", arg)
		}
		i++
		flagArgs = append(flagArgs, args[i])
	}
	return positionals, fs.Parse(flagArgs)
}

func parseMode(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", args, nil
	}
	if strings.HasPrefix(args[0], "-") {
		return "", args, nil
	}
	switch args[0] {
	case "sub", "dir", "all":
		return args[0], args[1:], nil
	default:
		return "", nil, fmt.Errorf("unknown mode %q (use sub, dir, or all)", args[0])
	}
}

func domainFromBaseURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("invalid URL %q (need http:// or https://)", rawURL)
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("invalid URL %q (missing host)", rawURL)
	}
	return host, nil
}

func displayMode(mode string, doSub, doDir bool) string {
	if mode != "" {
		return strings.ToUpper(mode)
	}
	switch {
	case doSub && doDir:
		return "ALL"
	case doSub:
		return "SUB"
	case doDir:
		return "DIR"
	default:
		return "UNKNOWN"
	}
}

func selectTargets(mode string, positionals []string, o *cliOptions) (string, string, bool, bool, error) {
	domain := strings.TrimSpace(*o.domainF)
	baseURL := strings.TrimRight(strings.TrimSpace(*o.baseURLF), "/")

	switch mode {
	case "sub":
		if len(positionals) > 1 {
			return "", "", false, false, fmt.Errorf("sub mode usage: ductu sub <domain> -ws <sub_wordlist>")
		}
		if len(positionals) == 1 {
			domain = strings.TrimSpace(positionals[0])
		}
		if domain == "" || strings.TrimSpace(*o.subWLF) == "" {
			return "", "", false, false, fmt.Errorf("sub mode needs <domain> and -ws <sub_wordlist>")
		}
		return domain, "", true, false, nil
	case "dir":
		if len(positionals) > 1 {
			return "", "", false, false, fmt.Errorf("dir mode usage: ductu dir <url> -wd <dir_wordlist>")
		}
		if len(positionals) == 1 {
			baseURL = strings.TrimRight(strings.TrimSpace(positionals[0]), "/")
		}
		if baseURL == "" || strings.TrimSpace(*o.dirWLF) == "" {
			return "", "", false, false, fmt.Errorf("dir mode needs <url> and -wd <dir_wordlist>")
		}
		return domain, baseURL, false, true, nil
	case "all":
		if len(positionals) > 1 {
			return "", "", false, false, fmt.Errorf("all mode usage: ductu all <url> -ws <sub_wordlist> -wd <dir_wordlist>")
		}
		if len(positionals) == 1 {
			baseURL = strings.TrimRight(strings.TrimSpace(positionals[0]), "/")
		}
		if baseURL == "" || strings.TrimSpace(*o.subWLF) == "" || strings.TrimSpace(*o.dirWLF) == "" {
			return "", "", false, false, fmt.Errorf("all mode needs <url>, -ws <sub_wordlist>, and -wd <dir_wordlist>")
		}
		if domain == "" {
			var err error
			domain, err = domainFromBaseURL(baseURL)
			if err != nil {
				return "", "", false, false, err
			}
		}
		return domain, baseURL, true, true, nil
	default:
		if len(positionals) > 0 {
			return "", "", false, false, fmt.Errorf("unexpected positional argument %q (use sub, dir, or all mode)", positionals[0])
		}
		doSub := domain != "" && strings.TrimSpace(*o.subWLF) != ""
		doDir := baseURL != "" && strings.TrimSpace(*o.dirWLF) != ""
		if !doSub && !doDir {
			if domain != "" && strings.TrimSpace(*o.subWLF) == "" {
				return "", "", false, false, fmt.Errorf("-d needs -ws (subdomain wordlist)")
			}
			if strings.TrimSpace(*o.subWLF) != "" && domain == "" {
				return "", "", false, false, fmt.Errorf("-ws needs -d (root domain)")
			}
			if baseURL != "" && strings.TrimSpace(*o.dirWLF) == "" {
				return "", "", false, false, fmt.Errorf("-u needs -wd (directory wordlist)")
			}
			if strings.TrimSpace(*o.dirWLF) != "" && baseURL == "" {
				return "", "", false, false, fmt.Errorf("-wd needs -u (base URL)")
			}
			return "", "", false, false, fmt.Errorf("no scan selected")
		}
		return domain, baseURL, doSub, doDir, nil
	}
}

func buildConfig(o *cliOptions, domain, baseURL string, noColor bool) (Config, error) {
	authUser, authPass, err := parseBasicAuth(*o.authF)
	if err != nil {
		return Config{}, err
	}
	if *o.depthF < 0 {
		*o.depthF = 0
	}
	if *o.rateF < 0 {
		return Config{}, fmt.Errorf("-rate must be >= 0")
	}
	if *o.retriesF < 0 {
		return Config{}, fmt.Errorf("-retries must be >= 0")
	}
	if *o.retryDelayF < 0 {
		return Config{}, fmt.Errorf("-retry-delay must be >= 0")
	}
	extMode := strings.ToLower(strings.TrimSpace(*o.extModeF))
	if extMode == "" {
		extMode = "append"
	}
	if extMode != "append" && extMode != "replace" {
		return Config{}, fmt.Errorf("invalid -ext-mode %q (need append or replace)", *o.extModeF)
	}
	recursionStrategy := strings.ToLower(strings.TrimSpace(*o.recursionStrategyF))
	if recursionStrategy == "" {
		recursionStrategy = "default"
	}
	if recursionStrategy != "default" && recursionStrategy != "greedy" {
		return Config{}, fmt.Errorf("invalid -recursion-strategy %q (need default or greedy)", *o.recursionStrategyF)
	}
	if *o.dedupThresholdF < 1 {
		return Config{}, fmt.Errorf("-dedup-threshold must be >= 1")
	}
	var matchRegex *regexp.Regexp
	if strings.TrimSpace(*o.matchRegexF) != "" {
		matchRegex, err = regexp.Compile(*o.matchRegexF)
		if err != nil {
			return Config{}, fmt.Errorf("invalid -mr regex: %v", err)
		}
	}
	var filterRegex *regexp.Regexp
	if strings.TrimSpace(*o.filterRegexF) != "" {
		filterRegex, err = regexp.Compile(*o.filterRegexF)
		if err != nil {
			return Config{}, fmt.Errorf("invalid -fr regex: %v", err)
		}
	}
	dnsServer := strings.TrimSpace(*o.dnsServerF)
	if dnsServer != "" {
		host, port, err := net.SplitHostPort(dnsServer)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return Config{}, fmt.Errorf("invalid -dns-server %q (need host:port, e.g. 1.1.1.1:53)", dnsServer)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Config{}, fmt.Errorf("invalid -dns-server %q (port must be 1-65535)", dnsServer)
		}
	}

	return Config{
		Domain:            strings.TrimSpace(domain),
		BaseURL:           strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		SubWL:             strings.TrimSpace(*o.subWLF),
		DirWL:             strings.TrimSpace(*o.dirWLF),
		Threads:           *o.threadsF,
		Timeout:           time.Duration(*o.timeoutF) * time.Second,
		Rate:              *o.rateF,
		Retries:           *o.retriesF,
		RetryDelay:        *o.retryDelayF,
		Exts:              parseExts(*o.extsF),
		Codes:             parseIntRangeSet(*o.codesF),
		HideCodes:         parseIntRangeSet(*o.hideCodesF),
		Insecure:          *o.insecureF,
		Follow:            *o.followF,
		OutFile:           *o.outFileF,
		NoColor:           noColor,
		NoBanner:          *o.noBannerF,
		Recursive:         o.recursiveF,
		MaxDepth:          *o.depthF,
		Headers:           append([]HTTPHeader(nil), o.headersF...),
		Cookie:            strings.TrimSpace(*o.cookieF),
		AuthUser:          authUser,
		AuthPass:          authPass,
		Proxy:             strings.TrimSpace(*o.proxyF),
		Resume:            strings.TrimSpace(*o.resumeF),
		CT:                *o.ctF,
		Permute:           *o.permuteF,
		DNSServer:         dnsServer,
		DNSExtra:          *o.dnsExtraF,
		MatchSizes:        parseIntRangeSet(*o.matchSizesF),
		FilterSizes:       parseIntRangeSet(*o.filterSizesF),
		MatchWords:        parseIntRangeSet(*o.matchWordsF),
		FilterWords:       parseIntRangeSet(*o.filterWordsF),
		MatchLines:        parseIntRangeSet(*o.matchLinesF),
		FilterLines:       parseIntRangeSet(*o.filterLinesF),
		MatchRegex:        matchRegex,
		FilterRegex:       filterRegex,
		ExtMode:           extMode,
		NoExtension:       *o.noExtensionF,
		Prefixes:          parseCSVList(*o.prefixesF),
		Suffixes:          parseCSVList(*o.suffixesF),
		DedupThreshold:    *o.dedupThresholdF,
		NoDedup:           *o.noDedupF,
		RecursionStrategy: recursionStrategy,
		ExcludeSubdirs:    parseCSVList(*o.excludeSubdirsF),
	}, nil
}

func validateDirTarget(cfg Config) error {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid base URL %q (need http:// or https://)", cfg.BaseURL)
	}
	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			return fmt.Errorf("invalid proxy URL %q (need http:// or https://)", cfg.Proxy)
		}
	}
	return nil
}

func newResolver(cfg Config) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: cfg.Timeout}
			if cfg.DNSServer != "" {
				address = cfg.DNSServer
			}
			return d.DialContext(ctx, network, address)
		},
	}
}

func newHTTPClient(cfg Config, doDir bool) (*http.Client, error) {
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
	if cfg.Proxy != "" && doDir {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %v", cfg.Proxy, err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
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
	}, nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	mode, args, err := parseMode(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] %v\n\n", err)
		printUsage()
		os.Exit(1)
	}

	fs := flag.NewFlagSet("ductu", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = printUsage
	opts := registerCLIFlags(fs)
	positionals, err := parseInterspersedFlags(fs, args)
	if err != nil {
		if err == flag.ErrHelp {
			return
		}
		fmt.Fprintf(os.Stderr, "  [!] %v\n\n", err)
		printUsage()
		os.Exit(1)
	}

	noColor := *opts.noColorF
	if *opts.listWLF {
		if !*opts.noBannerF {
			banner(noColor)
		}
		printWordlists()
		return
	}

	domain, baseURL, doSub, doDir, err := selectTargets(mode, positionals, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] %v\n\n", err)
		printUsage()
		os.Exit(1)
	}

	cfg, err := buildConfig(opts, domain, baseURL, noColor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] %v\n", err)
		os.Exit(1)
	}
	if cfg.Threads < 1 {
		cfg.Threads = 1
	}
	cfg.Mode = displayMode(mode, doSub, doDir)
	if doDir {
		if err := validateDirTarget(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "  [!] %v\n", err)
			os.Exit(1)
		}
	}

	if !cfg.NoBanner {
		banner(noColor)
	}
	printRunHeader(cfg, doSub, doDir)

	resume := newResumeStore(cfg.Resume, cfg)
	if resume.Loaded() {
		fmt.Fprintf(os.Stderr, "  resume state loaded: %s\n", cfg.Resume)
	}
	installResumeSignalHandler(resume)

	resolver := newResolver(cfg)
	client, err := newHTTPClient(cfg, doDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] %v\n", err)
		os.Exit(1)
	}

	start := time.Now()
	var (
		subs []SubResult
		dirs []dirResult
		wc   WildcardInfo
		soft Soft404Info
	)
	if doSub {
		subs, wc = runSubScan(cfg, resolver, resume)
	}
	if doDir {
		dirs, soft = runDirScan(cfg, client, resume)
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
	if resume != nil {
		if err := resume.Delete(); err != nil {
			fmt.Fprintf(os.Stderr, "  [!] failed to remove resume state: %v\n", err)
		}
	}
}
