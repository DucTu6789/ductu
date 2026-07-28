package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

type ResumeMeta struct {
	Domain    string   `json:"domain,omitempty"`
	BaseURL   string   `json:"base_url,omitempty"`
	SubWL     string   `json:"sub_wordlist,omitempty"`
	DirWL     string   `json:"dir_wordlist,omitempty"`
	Exts      []string `json:"exts,omitempty"`
	Recursive bool     `json:"recursive,omitempty"`
	MaxDepth  int      `json:"max_depth,omitempty"`
}

type ResumeState struct {
	Version           int            `json:"version"`
	UpdatedAt         string         `json:"updated_at"`
	Meta              ResumeMeta     `json:"meta"`
	SubProcessed      map[string]bool `json:"sub_processed,omitempty"`
	DirProcessed      map[string]int  `json:"dir_processed,omitempty"`
	SubProcessedCount int            `json:"sub_processed_count"`
	DirProcessedCount int            `json:"dir_processed_count"`
	SubResults        []SubResult    `json:"sub_results,omitempty"`
	DirResults        []dirResult    `json:"dir_results,omitempty"`
	DirRecurseRoots   map[string]int  `json:"dir_recurse_roots,omitempty"`
	SubFiltered       int            `json:"sub_filtered,omitempty"`
	DirFiltered       int            `json:"dir_filtered,omitempty"`
}

type ResumeStore struct {
	path          string
	state         ResumeState
	mu            sync.Mutex
	loaded        bool
	lastSave      time.Time
	changes       int
	subResultKeys map[string]bool
	dirResultKeys map[string]bool
}

func resumeMetaFromConfig(cfg Config) ResumeMeta {
	return ResumeMeta{
		Domain:    cfg.Domain,
		BaseURL:   cfg.BaseURL,
		SubWL:     cfg.SubWL,
		DirWL:     cfg.DirWL,
		Exts:      append([]string(nil), cfg.Exts...),
		Recursive: cfg.Recursive,
		MaxDepth:  cfg.MaxDepth,
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func resumeMetaCompatible(saved, want ResumeMeta) bool {
	if want.Domain != "" && saved.Domain != "" && saved.Domain != want.Domain {
		return false
	}
	if want.BaseURL != "" && saved.BaseURL != "" && saved.BaseURL != want.BaseURL {
		return false
	}
	if want.SubWL != "" && saved.SubWL != "" && saved.SubWL != want.SubWL {
		return false
	}
	if want.DirWL != "" && saved.DirWL != "" && saved.DirWL != want.DirWL {
		return false
	}
	if want.DirWL != "" {
		if !sameStrings(saved.Exts, want.Exts) {
			return false
		}
		if saved.Recursive != want.Recursive || saved.MaxDepth != want.MaxDepth {
			return false
		}
	}
	return true
}

func newResumeStore(path string, cfg Config) *ResumeStore {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	rs := &ResumeStore{
		path: path,
		state: ResumeState{
			Version:      1,
			Meta:         resumeMetaFromConfig(cfg),
			SubProcessed: make(map[string]bool),
			DirProcessed: make(map[string]int),
			DirRecurseRoots: make(map[string]int),
		},
		lastSave:      time.Now(),
		subResultKeys: make(map[string]bool),
		dirResultKeys: make(map[string]bool),
	}

	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		var st ResumeState
		if json.Unmarshal(b, &st) == nil && st.Version == 1 && resumeMetaCompatible(st.Meta, rs.state.Meta) {
			rs.state = st
			rs.loaded = true
		}
	}
	rs.ensureLocked()
	rs.rebuildKeysLocked()
	return rs
}

func (rs *ResumeStore) ensureLocked() {
	if rs.state.Version == 0 {
		rs.state.Version = 1
	}
	if rs.state.SubProcessed == nil {
		rs.state.SubProcessed = make(map[string]bool)
	}
	if rs.state.DirProcessed == nil {
		rs.state.DirProcessed = make(map[string]int)
	}
	if rs.state.DirRecurseRoots == nil {
		rs.state.DirRecurseRoots = make(map[string]int)
	}
	if rs.state.Meta.Domain == "" && rs.state.Meta.BaseURL == "" {
		rs.state.Meta = resumeMetaFromConfig(Config{})
	}
	for _, r := range rs.state.SubResults {
		if r.FQDN != "" {
			rs.state.SubProcessed[r.FQDN] = true
		}
	}
	for _, r := range rs.state.DirResults {
		p := normalizeDirPath(r.Path)
		if p != "" {
			if _, ok := rs.state.DirProcessed[p]; !ok {
				rs.state.DirProcessed[p] = 0
			}
		}
	}
}

func (rs *ResumeStore) rebuildKeysLocked() {
	if rs.subResultKeys == nil {
		rs.subResultKeys = make(map[string]bool)
	}
	if rs.dirResultKeys == nil {
		rs.dirResultKeys = make(map[string]bool)
	}
	for _, r := range rs.state.SubResults {
		if r.FQDN != "" {
			rs.subResultKeys[r.FQDN] = true
		}
	}
	for _, r := range rs.state.DirResults {
		if p := normalizeDirPath(r.Path); p != "" {
			rs.dirResultKeys[p] = true
		}
	}
}

func (rs *ResumeStore) Loaded() bool {
	return rs != nil && rs.loaded
}

func (rs *ResumeStore) SubResults() ([]SubResult, int) {
	if rs == nil {
		return nil, 0
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := append([]SubResult(nil), rs.state.SubResults...)
	return out, rs.state.SubFiltered
}

func (rs *ResumeStore) DirResults() ([]dirResult, int) {
	if rs == nil {
		return nil, 0
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := append([]dirResult(nil), rs.state.DirResults...)
	return out, rs.state.DirFiltered
}

func (rs *ResumeStore) IsSubProcessed(host string) bool {
	if rs == nil {
		return false
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.state.SubProcessed[host]
}

func (rs *ResumeStore) IsDirProcessed(p string) bool {
	if rs == nil {
		return false
	}
	p = normalizeDirPath(p)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	_, ok := rs.state.DirProcessed[p]
	return ok
}

func (rs *ResumeStore) DirDepth(p string) int {
	if rs == nil {
		return 0
	}
	p = normalizeDirPath(p)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.state.DirProcessed[p]
}

func (rs *ResumeStore) DirRecurseRoots() []dirCandidate {
	if rs == nil {
		return nil
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var out []dirCandidate
	for p, depth := range rs.state.DirRecurseRoots {
		out = append(out, dirCandidate{Path: p, Depth: depth})
	}
	return out
}

func (rs *ResumeStore) AddDirRecurseRoot(p string, depth int) {
	if rs == nil {
		return
	}
	p = normalizeDirPath(p)
	if p == "" {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.ensureLocked()
	rs.state.DirRecurseRoots[p] = depth
	rs.changes++
	rs.maybeSaveLocked()
}

func (rs *ResumeStore) UpdateSub(host string, result *SubResult, filtered bool) {
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.ensureLocked()
	rs.state.SubProcessed[host] = true
	if result != nil && result.FQDN != "" && !rs.subResultKeys[result.FQDN] {
		rs.state.SubResults = append(rs.state.SubResults, *result)
		rs.subResultKeys[result.FQDN] = true
	}
	if filtered {
		rs.state.SubFiltered++
	}
	rs.changes++
	rs.maybeSaveLocked()
}

func (rs *ResumeStore) UpdateDir(c dirCandidate, result *dirResult, filtered bool) {
	if rs == nil {
		return
	}
	p := normalizeDirPath(c.Path)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.ensureLocked()
	rs.state.DirProcessed[p] = c.Depth
	if result != nil && result.Path != "" {
		key := normalizeDirPath(result.Path)
		if key != "" && !rs.dirResultKeys[key] {
			rs.state.DirResults = append(rs.state.DirResults, *result)
			rs.dirResultKeys[key] = true
		}
	}
	if filtered {
		rs.state.DirFiltered++
	}
	rs.changes++
	rs.maybeSaveLocked()
}

func (rs *ResumeStore) maybeSaveLocked() {
	if rs.changes < 100 && time.Since(rs.lastSave) < 5*time.Second {
		return
	}
	_ = rs.saveLocked()
}

func (rs *ResumeStore) saveLocked() error {
	rs.ensureLocked()
	now := time.Now()
	rs.state.UpdatedAt = now.Format(time.RFC3339)
	rs.state.SubProcessedCount = len(rs.state.SubProcessed)
	rs.state.DirProcessedCount = len(rs.state.DirProcessed)
	b, err := json.MarshalIndent(rs.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(rs.path, b, 0644); err != nil {
		return err
	}
	rs.lastSave = now
	rs.changes = 0
	return nil
}

func (rs *ResumeStore) SaveNow() error {
	if rs == nil {
		return nil
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.saveLocked()
}

func (rs *ResumeStore) Delete() error {
	if rs == nil {
		return nil
	}
	if err := os.Remove(rs.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func installResumeSignalHandler(rs *ResumeStore) {
	if rs == nil {
		return
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n  [!] interrupted; saving resume state before exit...")
		if err := rs.SaveNow(); err != nil {
			fmt.Fprintf(os.Stderr, "  [!] failed to save resume state: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "  resume state saved: %s\n", rs.path)
		}
		os.Exit(130)
	}()
}
