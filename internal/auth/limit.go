// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"sync"
	"time"
)

// Limiter counts failed attempts per key (an IP, or an address) in a fixed
// window. Memory is capped: when full, the oldest windows are dropped.
type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	cap    int
	m      map[string]*entry
	now    func() time.Time
}

type entry struct {
	n     int
	start time.Time
}

// NewLimiter allows max failures per key per window.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, cap: 100_000, m: map[string]*entry{}, now: time.Now}
}

// Allowed reports whether key may try again.
func (l *Limiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	if e == nil {
		return true
	}
	if l.now().Sub(e.start) > l.window {
		delete(l.m, key)
		return true
	}
	return e.n < l.max
}

// Fail records a failure for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.m[key]
	if e == nil || now.Sub(e.start) > l.window {
		if len(l.m) >= l.cap {
			l.sweep(now)
		}
		e = &entry{start: now}
		l.m[key] = e
	}
	e.n++
}

// Reset clears key after a success.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

func (l *Limiter) sweep(now time.Time) {
	for k, e := range l.m {
		if now.Sub(e.start) > l.window {
			delete(l.m, k)
		}
	}
	// Still full: drop arbitrary entries (map order is random).
	for k := range l.m {
		if len(l.m) < l.cap*9/10 {
			break
		}
		delete(l.m, k)
	}
}
