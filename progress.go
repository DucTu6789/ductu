package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Progress (transient, on stderr so stdout tables stay clean)
// ---------------------------------------------------------------------------

// mu is the same lock used by the caller when it prints result rows to
// stdout while the scan is running. Sharing the lock (and clearing the
// progress line before every write) is what keeps "scanning ... x/y" on
// its own line instead of bleeding into the next result row.
func startProgress(label string, total int, noColor bool, mu *sync.Mutex) (*int64, func()) {
        var done int64
        stop := make(chan struct{})
        finished := make(chan struct{})
        started := time.Now()
        go func() {
                defer close(finished)
                t := time.NewTicker(150 * time.Millisecond)
                defer t.Stop()
                for {
                        select {
                        case <-stop:
                                mu.Lock()
                                fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 120))
                                mu.Unlock()
                                return
                        case <-t.C:
                                doneNow := atomic.LoadInt64(&done)
                                elapsed := time.Since(started).Seconds()
                                speed := 0.0
                                if elapsed > 0 {
                                        speed = float64(doneNow) / elapsed
                                }
                                mu.Lock()
                                fmt.Fprintf(os.Stderr, "\r  scanning %s ... %d/%d  %.1f/s", label, doneNow, total, speed)
                                mu.Unlock()
                        }
                }
        }()
        return &done, func() { close(stop); <-finished }
}

func startProgressDynamic(label string, total *int64, noColor bool, mu *sync.Mutex) (*int64, func()) {
        var done int64
        stop := make(chan struct{})
        finished := make(chan struct{})
        started := time.Now()
        go func() {
                defer close(finished)
                t := time.NewTicker(150 * time.Millisecond)
                defer t.Stop()
                for {
                        select {
                        case <-stop:
                                mu.Lock()
                                fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 120))
                                mu.Unlock()
                                return
                        case <-t.C:
                                doneNow := atomic.LoadInt64(&done)
                                elapsed := time.Since(started).Seconds()
                                speed := 0.0
                                if elapsed > 0 {
                                        speed = float64(doneNow) / elapsed
                                }
                                mu.Lock()
                                fmt.Fprintf(os.Stderr, "\r  scanning %s ... %d/%d  %.1f/s", label, doneNow, atomic.LoadInt64(total), speed)
                                mu.Unlock()
                        }
                }
        }()
        return &done, func() { close(stop); <-finished }
}

// clearProgressLine wipes whatever "scanning ..." text is currently sitting
// on the terminal line so the next thing printed (a result row) starts
// clean on its own line instead of getting appended after it.
func clearProgressLine() {
        fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 120))
}
