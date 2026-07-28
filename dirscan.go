package main

import (
	"fmt"
	"net/http"
	"os"
	pathpkg "path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

func normalizeDirPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.Trim(p, "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if p == "." {
		return ""
	}
	return p
}

func joinDirPath(prefix, child string) string {
	prefix = normalizeDirPath(prefix)
	child = normalizeDirPath(child)
	if prefix == "" {
		return child
	}
	if child == "" {
		return prefix
	}
	return prefix + "/" + child
}

func pathHasExcludedSubdir(p string, excludes []string) bool {
	p = normalizeDirPath(p)
	if p == "" || len(excludes) == 0 {
		return false
	}
	parts := strings.Split(p, "/")
	for _, exclude := range excludes {
		exclude = normalizeDirPath(exclude)
		if exclude == "" {
			continue
		}
		exParts := strings.Split(exclude, "/")
		if len(exParts) > len(parts) {
			continue
		}
		for i := 0; i <= len(parts)-len(exParts); i++ {
			match := true
			for j := range exParts {
				if parts[i+j] != exParts[j] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

func isRecursiveDir(cfg Config, r dirResult, depth int) bool {
	if !cfg.Recursive || depth >= cfg.MaxDepth {
		return false
	}
	p := normalizeDirPath(r.Path)
	if p == "" {
		return false
	}
	if pathHasExcludedSubdir(p, cfg.ExcludeSubdirs) {
		return false
	}
	if cfg.RecursionStrategy == "greedy" {
		return true
	}
	if r.Status != http.StatusOK && r.Status != http.StatusMovedPermanently && r.Status != http.StatusFound {
		return false
	}
	noExt := pathpkg.Ext(p) == ""
	htmlNoDot := strings.Contains(strings.ToLower(shortCT(r.ContentType)), "text/html") && !strings.Contains(p, ".")
	return noExt || htmlNoDot
}

// ---------------------------------------------------------------------------
// Directory scan
// ---------------------------------------------------------------------------

func runDirScanLegacy(cfg Config, client *http.Client, resume *ResumeStore) ([]dirResult, Soft404Info) {
        words, err := loadWordlist(cfg.DirWL)
        if err != nil {
                fmt.Fprintf(os.Stderr, "  [!] cannot read dir wordlist: %v\n", err)
                return nil, Soft404Info{}
        }
        paths := buildPaths(words, cfg.Exts, pathBuildOptionsFromConfig(cfg))

        limiter := newRateLimiter(cfg.Rate)
        defer limiter.Stop()

        soft, sigs := calibrateSoft404(client, cfg.BaseURL, cfg.Exts, cfg, limiter)
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
                printMu  sync.Mutex
                results  []dirResult
                filtered int
        )
        donePtr, stop := startProgress("directories", len(paths), cfg.NoColor, &printMu)
        sem := make(chan struct{}, cfg.Threads)
        var wg sync.WaitGroup
        for _, p := range paths {
                wg.Add(1)
                sem <- struct{}{}
                go func(path string) {
                        defer wg.Done()
                        defer func() { <-sem }()
                        defer atomic.AddInt64(donePtr, 1)

                        r := probeWithRetry(client, joinURL(cfg.BaseURL, path), cfg, limiter)
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
                        if !shouldShow(r, cfg) {
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

func countDepth(cands []dirCandidate, depth int) int {
	n := 0
	for _, c := range cands {
		if c.Depth == depth {
			n++
		}
	}
	return n
}

func runDirScan(cfg Config, client *http.Client, resume *ResumeStore) ([]dirResult, Soft404Info) {
	words, err := loadWordlist(cfg.DirWL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [!] cannot read dir wordlist: %v\n", err)
		return nil, Soft404Info{}
	}
	paths := buildPaths(words, cfg.Exts, pathBuildOptionsFromConfig(cfg))

	limiter := newRateLimiter(cfg.Rate)
	defer limiter.Stop()

	soft, sigs := calibrateSoft404(client, cfg.BaseURL, cfg.Exts, cfg, limiter)
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
	recNote := "off"
	if cfg.Recursive {
		recNote = fmt.Sprintf("on depth:%d", cfg.MaxDepth)
	}
	info := fmt.Sprintf("candidates: %d   exts: %s   recursive: %s   wordlist: %s\nbase: %s   soft-404: %s",
		len(paths), extNote, recNote, tail(cfg.DirWL, 40), cfg.BaseURL, softNote)
	sectionHeader(cfg.NoColor, "DIRECTORY SCAN", info)

	var (
		mu             sync.Mutex
		printMu        sync.Mutex
		scheduleMu     sync.Mutex
		sigMu          sync.Mutex
		results        []dirResult
		filtered       int
		dedupFiltered  int
		scheduled      = make(map[string]bool)
		dirSigs        = make(map[string][]soft404Sig)
		hashCounts     = make(map[string]int)
		totalScheduled int64
	)
	if old, oldFiltered := resume.DirResults(); len(old) > 0 || oldFiltered > 0 {
		results = append(results, old...)
		filtered += oldFiltered
	}

	ensureDirSigs := func(parent string) []soft404Sig {
		parent = normalizeDirPath(parent)
		if parent == "" {
			return nil
		}
		sigMu.Lock()
		if sigs, ok := dirSigs[parent]; ok {
			sigMu.Unlock()
			return sigs
		}
		sigMu.Unlock()

		_, local := calibrateSoft404(client, joinURL(cfg.BaseURL, parent), cfg.Exts, cfg, limiter)

		sigMu.Lock()
		if sigs, ok := dirSigs[parent]; ok {
			sigMu.Unlock()
			return sigs
		}
		dirSigs[parent] = local
		sigMu.Unlock()
		return local
	}

	for _, r := range results {
		if r.BodyHash != "" {
			hashCounts[r.BodyHash]++
		}
	}

	addResult := func(r dirResult) bool {
		mu.Lock()
		defer mu.Unlock()
		if cfg.NoDedup || r.BodyHash == "" {
			results = append(results, r)
			return true
		}
		threshold := cfg.DedupThreshold
		if threshold < 1 {
			threshold = 3
		}
		hashCounts[r.BodyHash]++
		if hashCounts[r.BodyHash] < threshold {
			results = append(results, r)
			return true
		}

		// Body-hash dedup is effective from the moment the threshold is reached.
		// Because rows are printed live, rows already printed cannot be erased
		// from the terminal; they are only removed from final results/report.
		removed := 0
		kept := results[:0]
		for _, old := range results {
			if old.BodyHash == r.BodyHash {
				removed++
				continue
			}
			kept = append(kept, old)
		}
		results = kept
		dedupFiltered += removed + 1
		return false
	}

	addCandidate := func(dst *[]dirCandidate, cand dirCandidate) bool {
		cand.Path = normalizeDirPath(cand.Path)
		cand.Parent = normalizeDirPath(cand.Parent)
		if cand.Path == "" || resume.IsDirProcessed(cand.Path) {
			return false
		}
		scheduleMu.Lock()
		defer scheduleMu.Unlock()
		if scheduled[cand.Path] {
			return false
		}
		scheduled[cand.Path] = true
		*dst = append(*dst, cand)
		atomic.AddInt64(&totalScheduled, 1)
		return true
	}

	var current []dirCandidate
	for _, p := range paths {
		addCandidate(&current, dirCandidate{Path: p, Depth: 0})
	}
	if cfg.Recursive {
		for _, r := range results {
			depth := resume.DirDepth(r.Path)
			if !isRecursiveDir(cfg, r, depth) {
				continue
			}
			ensureDirSigs(r.Path)
			for _, child := range paths {
				addCandidate(&current, dirCandidate{Path: joinDirPath(r.Path, child), Depth: depth + 1, Parent: r.Path})
			}
		}
		for _, root := range resume.DirRecurseRoots() {
			if root.Depth >= cfg.MaxDepth {
				continue
			}
			ensureDirSigs(root.Path)
			for _, child := range paths {
				addCandidate(&current, dirCandidate{Path: joinDirPath(root.Path, child), Depth: root.Depth + 1, Parent: root.Path})
			}
		}
	}
	if skipped := len(paths) - countDepth(current, 0); skipped > 0 {
		fmt.Println(colorize(cfg.NoColor, cGray, fmt.Sprintf("  resume: skipped %d completed top-level candidates", skipped)))
	}

	printDirHeader(cfg)
	for _, r := range results {
		printDirRow(cfg, r)
	}

	donePtr, stop := startProgressDynamic("directories", &totalScheduled, cfg.NoColor, &printMu)
	sem := make(chan struct{}, cfg.Threads)
	for len(current) > 0 {
		var (
			wg   sync.WaitGroup
			next []dirCandidate
		)
		for _, cand := range current {
			wg.Add(1)
			sem <- struct{}{}
			go func(c dirCandidate) {
				defer wg.Done()
				defer func() { <-sem }()
				defer atomic.AddInt64(donePtr, 1)

				r := probeWithRetry(client, joinURL(cfg.BaseURL, c.Path), cfg, limiter)
				r.Path = c.Path
				if r.Err != "" {
					resume.UpdateDir(c, nil, false)
					return
				}
				parentSigs := ensureDirSigs(c.Parent)
				if (softActive && isSoft404(r, sigs)) || isSoft404(r, parentSigs) {
					mu.Lock()
					filtered++
					mu.Unlock()
					resume.UpdateDir(c, nil, true)
					return
				}

				show := shouldShow(r, cfg)
				added := false
				if show {
					added = addResult(r)
					if added {
						resume.UpdateDir(c, &r, false)

						printMu.Lock()
						clearProgressLine()
						printDirRow(cfg, r)
						printMu.Unlock()
					} else {
						resume.UpdateDir(c, nil, false)
					}
				} else {
					resume.UpdateDir(c, nil, false)
				}

				recurse := false
				if cfg.RecursionStrategy == "greedy" {
					if added {
						recurse = isRecursiveDir(cfg, r, c.Depth)
					}
				} else {
					recurse = isRecursiveDir(cfg, r, c.Depth)
				}
				if recurse {
					resume.AddDirRecurseRoot(r.Path, c.Depth)
					ensureDirSigs(r.Path)
				}

				if recurse {
					var children []dirCandidate
					for _, child := range paths {
						children = append(children, dirCandidate{Path: joinDirPath(r.Path, child), Depth: c.Depth + 1, Parent: r.Path})
					}
					if len(children) > 0 {
						mu.Lock()
						for _, child := range children {
							addCandidate(&next, child)
						}
						mu.Unlock()
					}
				}
			}(cand)
		}
		wg.Wait()
		current = next
	}
	stop()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Status != results[j].Status {
			return results[i].Status < results[j].Status
		}
		return results[i].Path < results[j].Path
	})
	soft.Filtered = filtered

	if len(results) == 0 {
		fmt.Println(colorize(cfg.NoColor, cGray, "  (no paths matched filters)"))
	}
	foot := fmt.Sprintf("  → %d paths", len(results))
	if filtered > 0 {
		foot += fmt.Sprintf("  (filtered %d soft-404 noise)", filtered)
	}
	if dedupFiltered > 0 {
		foot += fmt.Sprintf("  (dedup filtered %d body-hash noise; live rows already printed are not erased)", dedupFiltered)
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
