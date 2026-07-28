package main

import (
	"fmt"
	"math/rand"
	"strings"
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

        wCode  = 4
        wSize  = 8
        wWords = 6
        wLines = 6
        wPath  = 38
        wNote  = 34

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

func randLabel(n int) string {
        const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
        b := make([]byte, n)
        for i := range b {
                b[i] = letters[rand.Intn(len(letters))]
        }
        return "zzq" + string(b) // improbable prefix
}
