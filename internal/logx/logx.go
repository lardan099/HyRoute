// Package logx holds the log ring buffers and the secret redactor shared by
// the engine log and the Hysteria log.
package logx

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Redactor replaces known secrets (auth, obfs password, SOCKS credentials,
// subscription URLs) with "***" in every log line. Secrets are kept in
// groups (one per profile or subscription) so each owner replaces only its
// own set.
type Redactor struct {
	mu       sync.RWMutex
	groups   map[string][]string
	replacer *strings.Replacer
}

// minSecretLen avoids redacting trivially short strings that would mangle
// ordinary text.
const minSecretLen = 4

// Set replaces the default group.
func (r *Redactor) Set(secrets ...string) { r.SetGroup("", secrets...) }

// SetGroup replaces one group's secrets. Raw, URL-escaped, JSON- and
// Go-quoted forms are redacted. No secrets removes the group.
func (r *Redactor) SetGroup(group string, secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groups == nil {
		r.groups = map[string][]string{}
	}
	if len(secrets) == 0 {
		delete(r.groups, group)
	} else {
		r.groups[group] = append([]string(nil), secrets...)
	}
	seen := map[string]bool{}
	var list []string
	add := func(s string) {
		if len(s) >= minSecretLen && !seen[s] {
			seen[s] = true
			list = append(list, s)
		}
	}
	for _, g := range r.groups {
		for _, s := range g {
			add(s)
			add(url.QueryEscape(s))
			add(url.PathEscape(s))
			// JSON (Hysteria's log format) and Go %q escape quotes,
			// backslashes and control characters.
			if j, err := json.Marshal(s); err == nil {
				add(string(j[1 : len(j)-1]))
			}
			if q := strconv.Quote(s); len(q) >= 2 {
				add(q[1 : len(q)-1])
			}
		}
	}
	// Longest first so a secret that contains another is fully replaced.
	sort.Slice(list, func(i, j int) bool {
		return len(list[i]) > len(list[j]) || (len(list[i]) == len(list[j]) && list[i] < list[j])
	})
	var pairs []string
	for _, s := range list {
		pairs = append(pairs, s, "***")
	}
	r.replacer = nil
	if len(pairs) > 0 {
		r.replacer = strings.NewReplacer(pairs...)
	}
}

func (r *Redactor) Redact(s string) string {
	if r == nil {
		return s
	}
	r.mu.RLock()
	rep := r.replacer
	r.mu.RUnlock()
	if rep == nil {
		return s
	}
	return rep.Replace(s)
}

// Ring is a fixed-size ring buffer.
type Ring[T any] struct {
	mu   sync.Mutex
	buf  []T
	next int
	full bool
}

func NewRing[T any](n int) *Ring[T] { return &Ring[T]{buf: make([]T, n)} }

func (r *Ring[T]) Clear() {
	r.mu.Lock()
	clear(r.buf)
	r.next, r.full = 0, false
	r.mu.Unlock()
}

func (r *Ring[T]) Add(v T) {
	r.mu.Lock()
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

// FindLast returns the newest element for which match is true, without
// copying the ring.
func (r *Ring[T]) FindLast(match func(*T) bool) (T, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	for k := 1; k <= n; k++ {
		i := (r.next - k + len(r.buf)) % len(r.buf)
		if match(&r.buf[i]) {
			return r.buf[i], true
		}
	}
	var zero T
	return zero, false
}

// Snapshot returns the contents oldest first.
func (r *Ring[T]) Snapshot() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]T(nil), r.buf[:r.next]...)
	}
	out := make([]T, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	return append(out, r.buf[:r.next]...)
}
