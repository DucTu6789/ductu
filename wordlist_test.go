package main

import (
	"reflect"
	"strings"
	"testing"
)

func oldBuildPathsForTest(words []string, exts []string) []string {
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

func TestBuildPathsDefaultMatchesOldBehavior(t *testing.T) {
	words := []string{"admin", " login ", "#comment", "", "/api", "admin", "assets/%EXT%"}
	exts := []string{"php", "txt"}

	want := oldBuildPathsForTest(words, exts)
	got := buildPaths(words, exts)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default buildPaths changed old behavior\nwant: %#v\n got: %#v", want, got)
	}
}
