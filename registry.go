package caddyja4

import (
	"sync"
	"time"
)

// registry bridges the listener wrapper (which computes JA4 at TLS-handshake time)
// and the HTTP handler (which reads it back, keyed by the client's remote address).
//
// A connection's RemoteAddr (ip:port) is unique while it is open, and an HTTP request
// served over that connection carries the same value in r.RemoteAddr — so it's a stable
// join key for the lifetime of the conn. Entries are swept by TTL so a dropped handshake
// (no HTTP request ever follows) can't leak memory.
type entry struct {
	ja4 string
	ts  time.Time
}

type registry struct {
	mu  sync.Mutex
	m   map[string]entry
	ttl time.Duration
}

func newRegistry(ttl time.Duration) *registry {
	r := &registry{m: make(map[string]entry), ttl: ttl}
	go r.sweepLoop()
	return r
}

func (r *registry) put(addr, ja4 string) {
	r.mu.Lock()
	r.m[addr] = entry{ja4: ja4, ts: time.Now()}
	r.mu.Unlock()
}

// take returns the JA4 for an address and removes it.
func (r *registry) take(addr string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[addr]
	if ok {
		delete(r.m, addr)
	}
	return e.ja4, ok
}

// peek returns the JA4 for an address without removing it, so every request on a kept-alive
// or multiplexed (HTTP/2) connection sees the same fingerprint. The TTL sweep handles cleanup.
func (r *registry) peek(addr string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[addr]
	return e.ja4, ok
}

func (r *registry) sweepLoop() {
	t := time.NewTicker(r.ttl)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-r.ttl)
		r.mu.Lock()
		for k, e := range r.m {
			if e.ts.Before(cutoff) {
				delete(r.m, k)
			}
		}
		r.mu.Unlock()
	}
}

// shared across the listener wrapper + handler in this plugin. 30s comfortably covers
// the handshake→first-byte gap without retaining fingerprints for idle/abandoned conns.
var shared = newRegistry(30 * time.Second)
