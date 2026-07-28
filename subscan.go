package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var permutationAffixes = []string{
	"dev", "staging", "stage", "test", "qa", "uat", "prod", "old", "new", "backup",
	"bak", "internal", "int", "ext", "beta", "alpha", "admin", "v1", "v2",
}

type dnsExtraInfo struct {
	MX        []string
	NS        []string
	Hostnames []string
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
func detectWildcard(ctx context.Context, r *net.Resolver, cfg Config, limiter *rateLimiter) WildcardInfo {
        ipset := make(map[string]bool)
        hits := 0
        const tries = 3
        for i := 0; i < tries; i++ {
                host := randLabel(12) + "." + cfg.Domain
                ips, _, err := resolveHostWithRetry(ctx, r, host, cfg, limiter)
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

func normalizeSubdomainHostname(host, domain string) string {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "*.")
	host = strings.ToLower(strings.Trim(host, "."))
	if domain == "" || host == "" {
		return ""
	}
	if host == domain || strings.HasSuffix(host, "."+domain) {
		return host
	}
	return ""
}

func appendSubdomainCandidates(base []string, extra []string) []string {
	seen := make(map[string]bool)
	for _, h := range base {
		if h == "" {
			continue
		}
		seen[h] = true
	}
	for _, h := range extra {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		base = append(base, h)
	}
	return base
}

func fetchCTHostnames(domain string) ([]string, error) {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://crt.sh/?q=%25." + domain + "&output=json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("crt.sh returned %s", resp.Status)
	}

	var rows []struct {
		NameValue string `json:"name_value"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 10<<20))
	if err := dec.Decode(&rows); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var out []string
	for _, row := range rows {
		for _, line := range strings.Split(row.NameValue, "\n") {
			host := normalizeSubdomainHostname(line, domain)
			if host == "" || seen[host] {
				continue
			}
			seen[host] = true
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out, nil
}

func lookupDNSExtra(ctx context.Context, resolver *net.Resolver, domain string, timeout time.Duration) dnsExtraInfo {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	info := dnsExtraInfo{}

	c1, cancel1 := context.WithTimeout(ctx, timeout)
	if mxs, err := resolver.LookupMX(c1, domain); err == nil {
		for _, mx := range mxs {
			host := strings.TrimSuffix(strings.TrimSpace(mx.Host), ".")
			if host != "" {
				info.MX = append(info.MX, host)
			}
		}
		sort.Strings(info.MX)
	}
	cancel1()

	c2, cancel2 := context.WithTimeout(ctx, timeout)
	if nss, err := resolver.LookupNS(c2, domain); err == nil {
		for _, ns := range nss {
			host := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
			if host != "" {
				info.NS = append(info.NS, host)
			}
		}
		sort.Strings(info.NS)
	}
	cancel2()

	c3, cancel3 := context.WithTimeout(ctx, timeout)
	txts, err := resolver.LookupTXT(c3, domain)
	cancel3()
	if err != nil {
		return info
	}

	hostRe := regexp.MustCompile(`[a-z0-9.-]+\.` + regexp.QuoteMeta(domain))
	seen := make(map[string]bool)
	for _, txt := range txts {
		for _, match := range hostRe.FindAllString(strings.ToLower(txt), -1) {
			host := normalizeSubdomainHostname(match, domain)
			if host == "" || seen[host] {
				continue
			}
			seen[host] = true
			info.Hostnames = append(info.Hostnames, host)
		}
	}
	sort.Strings(info.Hostnames)
	return info
}

func formatDNSExtraValues(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func printDNSExtraBlock(cfg Config, info dnsExtraInfo) {
	fmt.Println(colorize(cfg.NoColor, cGray, "  dns-extra MX: "+formatDNSExtraValues(info.MX)))
	fmt.Println(colorize(cfg.NoColor, cGray, "  dns-extra NS: "+formatDNSExtraValues(info.NS)))
	fmt.Println(colorize(cfg.NoColor, cGray, fmt.Sprintf("  dns-extra TXT hostnames: %d", len(info.Hostnames))))
}

func pendingSubCandidates(candidates []string, resume *ResumeStore) []string {
	var pending []string
	for _, fq := range candidates {
		if resume.IsSubProcessed(fq) {
			continue
		}
		pending = append(pending, fq)
	}
	return pending
}

func resolveSubPass(cfg Config, ctx context.Context, resolver *net.Resolver, resume *ResumeStore, pending []string, wc WildcardInfo, wcSet map[string]bool, results *[]SubResult, filtered *int, mu *sync.Mutex, printMu *sync.Mutex, limiter *rateLimiter) {
	if len(pending) == 0 {
		return
	}
	donePtr, stop := startProgress("subdomains", len(pending), cfg.NoColor, printMu)
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup
	for _, fq := range pending {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer atomic.AddInt64(donePtr, 1)

			ips, cname, err := resolveHostWithRetry(ctx, resolver, host, cfg, limiter)
			if err != nil || len(ips) == 0 {
				resume.UpdateSub(host, nil, false)
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
					(*filtered)++
					mu.Unlock()
					resume.UpdateSub(host, nil, true)
					return
				}
			}
			res := SubResult{FQDN: host, IPs: ips, CNAME: cname}
			mu.Lock()
			*results = append(*results, res)
			mu.Unlock()
			resume.UpdateSub(host, &res, false)
			printMu.Lock()
			clearProgressLine()
			printSubRow(cfg, res)
			printMu.Unlock()
		}(fq)
	}
	wg.Wait()
	stop()
}

func buildPermutationCandidates(domain string, results []SubResult) ([]string, int, int) {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	seeds := append([]SubResult(nil), results...)
	sort.Slice(seeds, func(i, j int) bool { return seeds[i].FQDN < seeds[j].FQDN })
	totalSeeds := len(seeds)
	if len(seeds) > 200 {
		seeds = seeds[:200]
	}

	existing := make(map[string]bool)
	for _, r := range results {
		if host := normalizeSubdomainHostname(r.FQDN, domain); host != "" {
			existing[host] = true
		}
	}

	seen := make(map[string]bool)
	var out []string
	for _, r := range seeds {
		host := normalizeSubdomainHostname(r.FQDN, domain)
		if host == "" || host == domain {
			continue
		}
		label, _, _ := strings.Cut(host, ".")
		if label == "" {
			continue
		}
		for _, affix := range permutationAffixes {
			if label == affix {
				continue
			}
			variants := []string{
				affix + "-" + label,
				label + "-" + affix,
				label + affix,
			}
			for _, v := range variants {
				candidate := normalizeSubdomainHostname(v+"."+domain, domain)
				if candidate == "" || existing[candidate] || seen[candidate] {
					continue
				}
				seen[candidate] = true
				out = append(out, candidate)
			}
		}
	}
	sort.Strings(out)
	return out, len(seeds), totalSeeds
}

// ---------------------------------------------------------------------------
// Subdomain scan
// ---------------------------------------------------------------------------

func runSubScan(cfg Config, resolver *net.Resolver, resume *ResumeStore) ([]SubResult, WildcardInfo) {
        words, err := loadWordlist(cfg.SubWL)
        if err != nil {
                fmt.Fprintf(os.Stderr, "  [!] cannot read sub wordlist: %v\n", err)
                return nil, WildcardInfo{}
        }
        fqdns := buildFQDNs(words, cfg.Domain)

        ctx := context.Background()
        crtCount := 0
        if cfg.CT {
                hosts, err := fetchCTHostnames(cfg.Domain)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "  [!] crt.sh lookup failed: %v\n", err)
                } else {
                        crtCount = len(hosts)
                        fqdns = appendSubdomainCandidates(fqdns, hosts)
                }
        }

        dnsExtra := dnsExtraInfo{}
        if cfg.DNSExtra {
                dnsExtra = lookupDNSExtra(ctx, resolver, cfg.Domain, cfg.Timeout)
                fqdns = appendSubdomainCandidates(fqdns, dnsExtra.Hostnames)
        }

        limiter := newRateLimiter(cfg.Rate)
        defer limiter.Stop()

        wc := detectWildcard(ctx, resolver, cfg, limiter)

        wcNote := "none"
        if wc.Detected {
                wcNote = "detected -> " + truncate(strings.Join(wc.IPs, ","), 40)
        }
        info := fmt.Sprintf("candidates: %d   wordlist: %s", len(fqdns), tail(cfg.SubWL, 48))
        if cfg.CT {
                info += fmt.Sprintf("\ncrt.sh: %d hostnames found", crtCount)
        }
        if cfg.DNSExtra {
                info += fmt.Sprintf("\ndns-extra TXT: %d hostnames found", len(dnsExtra.Hostnames))
        }
        info += fmt.Sprintf("\ndomain: %s   wildcard: %s", cfg.Domain, wcNote)
        sectionHeader(cfg.NoColor, "SUBDOMAIN SCAN", info)
        if cfg.DNSExtra {
                printDNSExtraBlock(cfg, dnsExtra)
        }

        wcSet := make(map[string]bool)
        for _, ip := range wc.IPs {
                wcSet[ip] = true
        }

        var (
                mu       sync.Mutex
                printMu  sync.Mutex
                results  []SubResult
                filtered int
        )
        if old, oldFiltered := resume.SubResults(); len(old) > 0 || oldFiltered > 0 {
                results = append(results, old...)
                filtered += oldFiltered
        }
        pending := pendingSubCandidates(fqdns, resume)
        if skipped := len(fqdns) - len(pending); skipped > 0 {
                fmt.Println(colorize(cfg.NoColor, cGray, fmt.Sprintf("  resume: skipped %d completed candidates", skipped)))
        }
        printSubHeader(cfg)
        for _, r := range results {
                printSubRow(cfg, r)
        }
        resolveSubPass(cfg, ctx, resolver, resume, pending, wc, wcSet, &results, &filtered, &mu, &printMu, limiter)

        if cfg.Permute {
                permCandidates, seedCount, totalSeeds := buildPermutationCandidates(cfg.Domain, results)
                if totalSeeds > seedCount {
                        fmt.Println(colorize(cfg.NoColor, cGray, fmt.Sprintf("  permutation: using first %d of %d resolved subdomains", seedCount, totalSeeds)))
                }
                fmt.Println(colorize(cfg.NoColor, cGray, fmt.Sprintf("  permutation: sinh them %d candidate tu %d subdomain da tim", len(permCandidates), seedCount)))
                pendingPerm := pendingSubCandidates(permCandidates, resume)
                if skipped := len(permCandidates) - len(pendingPerm); skipped > 0 {
                        fmt.Println(colorize(cfg.NoColor, cGray, fmt.Sprintf("  resume: skipped %d completed permutation candidates", skipped)))
                }
                resolveSubPass(cfg, ctx, resolver, resume, pendingPerm, wc, wcSet, &results, &filtered, &mu, &printMu, limiter)
        }

        sort.Slice(results, func(i, j int) bool { return results[i].FQDN < results[j].FQDN })
        wc.Filtered = filtered

        if len(results) == 0 {
                fmt.Println(colorize(cfg.NoColor, cGray, "  (no subdomains resolved)"))
        }
        foot := fmt.Sprintf("  → %d subdomains resolved", len(results))
        if filtered > 0 {
                foot += fmt.Sprintf("  (filtered %d wildcard noise)", filtered)
        }
        fmt.Println(colorize(cfg.NoColor, cGray, foot))
        return results, wc
}
