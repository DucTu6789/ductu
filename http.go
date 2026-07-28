package main

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"strings"
)

func joinURL(base, p string) string {
	base = strings.TrimRight(base, "/")
	p = strings.TrimLeft(p, "/")
	return base + "/" + p
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

// probe performs a single GET and captures status, size, redirect + type.
func probe(client *http.Client, rawURL string, cfg Config) dirResult {
	res := dirResult{URL: rawURL}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "ductu-recon/1.0 (authorized testing)")
	req.Header.Set("Accept", "*/*")
	for _, h := range cfg.Headers {
		req.Header.Add(h.Name, h.Value)
	}
	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}
	if cfg.AuthUser != "" || cfg.AuthPass != "" {
		req.SetBasicAuth(cfg.AuthUser, cfg.AuthPass)
	}

	resp, err := client.Do(req)
	if err != nil {
                res.Err = err.Error()
                return res
        }
        defer resp.Body.Close()

        const cap = 2 << 20 // read at most 2MB to size the body
        body, _ := io.ReadAll(io.LimitReader(resp.Body, cap))
        n := int64(len(body))
        res.Status = resp.StatusCode
        res.Size = n
        if resp.ContentLength > n {
                res.Size = resp.ContentLength
        }
        bodyText := string(body)
        res.Words = len(strings.Fields(bodyText))
        res.Lines = countBodyLines(body)
        h := fnv.New64a()
        _, _ = h.Write(body)
        res.BodyHash = fmt.Sprintf("%016x", h.Sum64())
        if cfg.MatchRegex != nil {
                res.matchRegex = cfg.MatchRegex.Match(body)
        }
        if cfg.FilterRegex != nil {
                res.filterRegex = cfg.FilterRegex.Match(body)
        }
        res.ContentType = resp.Header.Get("Content-Type")
        res.Location = resp.Header.Get("Location")
        return res
}

func countBodyLines(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	lines := bytes.Count(body, []byte{'\n'})
	if body[len(body)-1] != '\n' {
		lines++
	}
	return lines
}

// calibrateSoft404 probes random paths to fingerprint catch-all responses.
func calibrateSoft404(client *http.Client, base string, exts []string, cfg Config, limiter *rateLimiter) (Soft404Info, []soft404Sig) {
	probes := []string{randLabel(16), randLabel(18), randLabel(14) + "/"}
	if len(exts) > 0 && !cfg.NoExtension {
		probes = append(probes, randLabel(15)+"."+exts[0])
        }
        var sigs []soft404Sig
	softStatuses := make(map[int]int)
	for _, p := range probes {
		r := probeWithRetry(client, joinURL(base, p), cfg, limiter)
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

func intInSet(n int, set map[int]bool) bool {
	return set[n]
}

func int64InSet(n int64, set map[int]bool) bool {
	if n < 0 {
		return false
	}
	maxInt := int64(^uint(0) >> 1)
	if n > maxInt {
		return false
	}
	return set[int(n)]
}

func shouldShow(r dirResult, cfg Config) bool {
        if len(cfg.MatchSizes) > 0 && !int64InSet(r.Size, cfg.MatchSizes) {
                return false
        }
        if len(cfg.MatchWords) > 0 && !intInSet(r.Words, cfg.MatchWords) {
                return false
        }
        if len(cfg.MatchLines) > 0 && !intInSet(r.Lines, cfg.MatchLines) {
                return false
        }
        if cfg.MatchRegex != nil && !r.matchRegex {
                return false
        }
        if len(cfg.FilterSizes) > 0 && int64InSet(r.Size, cfg.FilterSizes) {
                return false
        }
        if len(cfg.FilterWords) > 0 && intInSet(r.Words, cfg.FilterWords) {
                return false
        }
        if len(cfg.FilterLines) > 0 && intInSet(r.Lines, cfg.FilterLines) {
                return false
        }
        if cfg.FilterRegex != nil && r.filterRegex {
                return false
        }
        if len(cfg.Codes) > 0 {
                return cfg.Codes[r.Status]
        }
        return !cfg.HideCodes[r.Status]
}
