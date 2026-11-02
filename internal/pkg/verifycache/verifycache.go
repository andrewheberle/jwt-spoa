// Package verifycache remembers the results of JWT verification for JWTs
// that passed, so a repeat request with the same JWT returns the same claim
// values without verifying again.
//
// Entries are keyed by the SHA-256 of the JWT, so the cache holds no usable
// tokens. An entry lives until the earlier of the JWT's expiry (exp) and a
// maximum age, which limits how long a cached JWT keeps passing after its
// signing key is withdrawn from the JWKS. When the cache is full, the least
// recently used entry is evicted.
package verifycache

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Verifier performs JWT verification, returning the claim values of a JWT
// that passes.
type Verifier interface {
	Verify(ctx context.Context, signed string) (map[string]any, error)
}

// Cache is a Verifier that remembers the claim values of JWTs that passed
// verification by the Verifier it wraps. It is safe for concurrent use.
type Cache struct {
	next       Verifier
	maxEntries int
	maxAge     time.Duration
	now        func() time.Time
	lookups    *prometheus.CounterVec
	evictions  *prometheus.CounterVec
	size       prometheus.Gauge

	mu      sync.Mutex
	entries map[[sha256.Size]byte]*list.Element
	order   *list.List // most recently used at the front
}

type entry struct {
	key     [sha256.Size]byte
	claims  map[string]any
	expires time.Time
}

// Option configures a Cache.
type Option func(*Cache)

// WithMetrics sets the counter for lookups, labelled by a "result" of "hit"
// or "miss", the counter for evictions, labelled by a "reason" of
// "capacity" or "expired", and the gauge for the number of entries. By
// default nothing is counted.
func WithMetrics(lookups, evictions *prometheus.CounterVec, size prometheus.Gauge) Option {
	return func(c *Cache) {
		c.lookups = lookups
		c.evictions = evictions
		c.size = size
	}
}

// WithClock sets the function used to get the current time. The default is
// time.Now.
func WithClock(now func() time.Time) Option {
	return func(c *Cache) {
		c.now = now
	}
}

// New returns a Cache in front of next holding at most maxEntries entries,
// each for at most maxAge. Both must be greater than 0.
func New(next Verifier, maxEntries int, maxAge time.Duration, opts ...Option) (*Cache, error) {
	if maxEntries <= 0 {
		return nil, fmt.Errorf("maximum verification cache entries must be greater than 0, got %d", maxEntries)
	}
	if maxAge <= 0 {
		return nil, fmt.Errorf("maximum verification cache age must be greater than 0, got %s", maxAge)
	}

	c := &Cache{
		next:       next,
		maxEntries: maxEntries,
		maxAge:     maxAge,
		now:        time.Now,
		entries:    make(map[[sha256.Size]byte]*list.Element),
		order:      list.New(),
	}

	for _, o := range opts {
		o(c)
	}

	return c, nil
}

// Verify returns the claim values for signed, from the cache when it holds
// an unexpired entry and otherwise from the wrapped Verifier. The returned
// map is the caller's own.
func (c *Cache) Verify(ctx context.Context, signed string) (map[string]any, error) {
	claims, _, err := c.VerifyCached(ctx, signed)
	return claims, err
}

// VerifyCached is Verify, also reporting whether the claim values came from
// the cache.
func (c *Cache) VerifyCached(ctx context.Context, signed string) (map[string]any, bool, error) {
	key := sha256.Sum256([]byte(signed))

	if claims, ok := c.get(key); ok {
		c.countLookup("hit")
		return claims, true, nil
	}
	c.countLookup("miss")

	claims, err := c.next.Verify(ctx, signed)
	if err != nil {
		return nil, false, err
	}

	// the JWT has passed verification, so its expiry can be trusted
	if exp, ok := expiry(signed); ok {
		c.add(key, claims, exp)
	}

	return claims, false, nil
}

// get returns a copy of the claim values for key if there is an unexpired
// entry, removing it if it has expired.
func (c *Cache) get(key [sha256.Size]byte) (map[string]any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	e := el.Value.(*entry)
	if !c.now().Before(e.expires) {
		c.remove(el, "expired")
		return nil, false
	}

	c.order.MoveToFront(el)

	return maps.Clone(e.claims), true
}

// add stores a copy of claims for key until the earlier of exp and the
// maximum age, evicting the least recently used entry if the cache is full.
func (c *Cache) add(key [sha256.Size]byte, claims map[string]any, exp time.Time) {
	now := c.now()
	expires := now.Add(c.maxAge)
	if exp.Before(expires) {
		expires = exp
	}
	if !now.Before(expires) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// a concurrent miss for the same JWT may have added it already
	if el, ok := c.entries[key]; ok {
		el.Value = &entry{key: key, claims: maps.Clone(claims), expires: expires}
		c.order.MoveToFront(el)
		return
	}

	for len(c.entries) >= c.maxEntries {
		oldest := c.order.Back()
		reason := "capacity"
		if !now.Before(oldest.Value.(*entry).expires) {
			reason = "expired"
		}
		c.remove(oldest, reason)
	}

	c.entries[key] = c.order.PushFront(&entry{key: key, claims: maps.Clone(claims), expires: expires})
	c.setSize()
}

// remove deletes el from the cache, counting its eviction for reason. The
// caller must hold c.mu.
func (c *Cache) remove(el *list.Element, reason string) {
	c.order.Remove(el)
	delete(c.entries, el.Value.(*entry).key)
	if c.evictions != nil {
		c.evictions.WithLabelValues(reason).Inc()
	}
	c.setSize()
}

// setSize updates the entries gauge. The caller must hold c.mu.
func (c *Cache) setSize() {
	if c.size != nil {
		c.size.Set(float64(len(c.entries)))
	}
}

func (c *Cache) countLookup(result string) {
	if c.lookups != nil {
		c.lookups.WithLabelValues(result).Inc()
	}
}

// expiry returns the expiry (exp) from the payload of the compact JWT
// signed, without checking its signature.
func expiry(signed string) (time.Time, bool) {
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}

	var claims struct {
		Exp *float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == nil {
		return time.Time{}, false
	}

	sec := int64(*claims.Exp)
	nsec := int64((*claims.Exp - float64(sec)) * float64(time.Second))

	return time.Unix(sec, nsec), true
}
