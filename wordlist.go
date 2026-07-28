package main

import (
	"bufio"
	"os"
	"strings"
)

// ---------------------------------------------------------------------------
// Wordlist / candidate builders
// ---------------------------------------------------------------------------

type pathBuildOptions struct {
	ExtMode     string
	NoExtension bool
	Prefixes    []string
	Suffixes    []string
}

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

func pathBuildOptionsFromConfig(cfg Config) pathBuildOptions {
	return pathBuildOptions{
		ExtMode:     cfg.ExtMode,
		NoExtension: cfg.NoExtension,
		Prefixes:    cfg.Prefixes,
		Suffixes:    cfg.Suffixes,
	}
}

// buildPaths joins each word with the requested extensions, de-dupes.
func buildPaths(words []string, exts []string, options ...pathBuildOptions) []string {
        opt := pathBuildOptions{ExtMode: "append"}
        if len(options) > 0 {
                opt = options[0]
        }
        if opt.ExtMode == "" {
                opt.ExtMode = "append"
        }
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
                var built []string
                if opt.NoExtension {
                        built = append(built, w)
                } else if opt.ExtMode == "replace" {
                        if strings.Contains(w, "%EXT%") {
                                for _, e := range exts {
                                        built = append(built, strings.ReplaceAll(w, "%EXT%", e))
                                }
                        } else {
                                built = append(built, w)
                        }
                } else {
                        built = append(built, w)
                        for _, e := range exts {
                                built = append(built, w+"."+e)
                        }
                }
                for _, p := range built {
                        add(p)
                        for _, prefix := range opt.Prefixes {
                                add(prefix + p)
                        }
                        for _, suffix := range opt.Suffixes {
                                add(p + suffix)
                        }
                }
        }
        return out
}
