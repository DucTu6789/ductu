package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

type rateLimiter struct {
	ticker *time.Ticker
	ch     <-chan time.Time
}

func newRateLimiter(rate int) *rateLimiter {
	if rate <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(rate)
	if interval < time.Nanosecond {
		interval = time.Nanosecond
	}
	ticker := time.NewTicker(interval)
	return &rateLimiter{ticker: ticker, ch: ticker.C}
}

func (rl *rateLimiter) Wait() {
	if rl == nil {
		return
	}
	<-rl.ch
}

func (rl *rateLimiter) Stop() {
	if rl == nil {
		return
	}
	rl.ticker.Stop()
}

func retrySleep(cfg Config, attempt int) {
	if cfg.RetryDelay <= 0 {
		return
	}
	time.Sleep(cfg.RetryDelay * time.Duration(attempt+1))
}

func probeWithRetry(client *http.Client, rawURL string, cfg Config, limiter *rateLimiter) dirResult {
	attempts := cfg.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	var r dirResult
	for i := 0; i < attempts; i++ {
		limiter.Wait()
		r = probe(client, rawURL, cfg)
		if r.Err == "" {
			return r
		}
		if i < attempts-1 {
			retrySleep(cfg, i)
		}
	}
	return r
}

func shouldRetryResolve(err error, ips []string) bool {
	if err == nil {
		return len(ips) == 0
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return false
		}
		return dnsErr.IsTimeout || dnsErr.IsTemporary
	}
	return true
}

func resolveHostWithRetry(ctx context.Context, resolver *net.Resolver, host string, cfg Config, limiter *rateLimiter) ([]string, string, error) {
	attempts := cfg.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	var (
		ips   []string
		cname string
		err   error
	)
	for i := 0; i < attempts; i++ {
		limiter.Wait()
		ips, cname, err = resolveHost(ctx, resolver, host, cfg.Timeout)
		if err == nil && len(ips) > 0 {
			return ips, cname, nil
		}
		if !shouldRetryResolve(err, ips) {
			return ips, cname, err
		}
		if i < attempts-1 {
			retrySleep(cfg, i)
		}
	}
	return ips, cname, err
}
