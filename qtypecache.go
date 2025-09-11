package recursive

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// cacheEntry represents a single cached DNS response with expiration
type cacheEntry struct {
	message   *dns.Msg
	expiresAt time.Time
}

// isExpired checks if the cache entry has expired
func (ce *cacheEntry) isExpired(now time.Time) bool {
	return now.After(ce.expiresAt)
}

// qtypeCache manages cached responses for a specific DNS query type
type qtypeCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

// newQtypeCache creates a new cache for a specific query type
func newQtypeCache() *qtypeCache {
	return &qtypeCache{
		entries: make(map[string]*cacheEntry),
	}
}

// size returns the number of entries in the cache
func (qc *qtypeCache) size() int {
	qc.mu.RLock()
	defer qc.mu.RUnlock()
	return len(qc.entries)
}

// set stores a DNS message with the given TTL
func (qc *qtypeCache) set(qname string, msg *dns.Msg, ttl time.Duration) {
	if msg == nil || ttl <= 0 {
		return
	}

	entry := &cacheEntry{
		message:   msg,
		expiresAt: time.Now().Add(ttl),
	}

	qc.mu.Lock()
	qc.entries[qname] = entry
	qc.mu.Unlock()
}

// get retrieves a cached DNS message, removing it if expired
func (qc *qtypeCache) get(qname string) *dns.Msg {
	now := time.Now()

	qc.mu.RLock()
	entry, exists := qc.entries[qname]
	qc.mu.RUnlock()

	if !exists {
		return nil
	}

	if entry.isExpired(now) {
		// Remove expired entry
		qc.mu.Lock()
		// Double-check it's still expired and exists
		if entry, exists := qc.entries[qname]; exists && entry.isExpired(now) {
			delete(qc.entries, qname)
		}
		qc.mu.Unlock()
		return nil
	}

	return entry.message
}

// clear removes all entries from the cache
func (qc *qtypeCache) clear() {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	// Create new map to ensure complete cleanup
	qc.entries = make(map[string]*cacheEntry)
}

// clean removes expired entries from the cache
func (qc *qtypeCache) clean(now time.Time) {
	if now.IsZero() {
		// If no time provided, clear everything
		qc.clear()
		return
	}

	qc.mu.Lock()
	defer qc.mu.Unlock()

	// Collect expired keys to avoid modification during iteration
	expiredKeys := make([]string, 0)
	for qname, entry := range qc.entries {
		if entry.isExpired(now) {
			expiredKeys = append(expiredKeys, qname)
		}
	}

	// Remove expired entries
	for _, qname := range expiredKeys {
		delete(qc.entries, qname)
	}
}

// pruneOldest removes the oldest entries when cache is too large
func (qc *qtypeCache) pruneOldest(maxEntries int) {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if len(qc.entries) <= maxEntries {
		return
	}

	// Create slice of entries with expiration times for sorting
	type entryInfo struct {
		qname     string
		expiresAt time.Time
	}

	entryInfos := make([]entryInfo, 0, len(qc.entries))
	for qname, entry := range qc.entries {
		entryInfos = append(entryInfos, entryInfo{
			qname:     qname,
			expiresAt: entry.expiresAt,
		})
	}

	// Sort by expiration time (oldest first)
	for i := 0; i < len(entryInfos)-1; i++ {
		for j := i + 1; j < len(entryInfos); j++ {
			if entryInfos[i].expiresAt.After(entryInfos[j].expiresAt) {
				entryInfos[i], entryInfos[j] = entryInfos[j], entryInfos[i]
			}
		}
	}

	// Remove excess entries (keeping the newest ones)
	entriesToRemove := len(entryInfos) - maxEntries
	for i := 0; i < entriesToRemove; i++ {
		delete(qc.entries, entryInfos[i].qname)
	}
}

// getStats returns statistics for this qtype cache
func (qc *qtypeCache) getStats() (total, expired int) {
	now := time.Now()

	qc.mu.RLock()
	defer qc.mu.RUnlock()

	total = len(qc.entries)
	for _, entry := range qc.entries {
		if now.After(entry.expiresAt) {
			expired++
		}
	}

	return total, expired
}
