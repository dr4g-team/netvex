package protocol

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxProxyAddressesPerHost = 16

type proxyHostResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type proxyDNSCacheEntry struct {
	done    chan struct{}
	addrs   []netip.Addr
	err     error
	expires time.Time
	next    atomic.Uint64
}

// ProxyDNSCache coalesces concurrent gateway lookups and rotates cached
// addresses. It is bounded independently of input size and never caches
// failed lookups.
type ProxyDNSCache struct {
	TTL        time.Duration
	MaxEntries int
	Resolver   proxyHostResolver

	mu      sync.Mutex
	entries map[string]*proxyDNSCacheEntry
}

func NewProxyDNSCache(ttl time.Duration, maxEntries int) *ProxyDNSCache {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &ProxyDNSCache{TTL: ttl, MaxEntries: maxEntries, Resolver: net.DefaultResolver, entries: make(map[string]*proxyDNSCacheEntry)}
}

func (c *ProxyDNSCache) Address(ctx context.Context, host string, port uint16) (string, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(address.Unmap(), port).String(), nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	entry, err := c.resolve(ctx, host)
	if err != nil {
		return "", err
	}
	index := entry.next.Add(1) - 1
	address := entry.addrs[index%uint64(len(entry.addrs))]
	return netip.AddrPortFrom(address, port).String(), nil
}

func (c *ProxyDNSCache) resolve(ctx context.Context, host string) (*proxyDNSCacheEntry, error) {
	now := time.Now()
	c.mu.Lock()
	if entry := c.entries[host]; entry != nil {
		if entry.expires.IsZero() {
			done := entry.done
			c.mu.Unlock()
			select {
			case <-done:
				return entry, entry.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if now.Before(entry.expires) {
			c.mu.Unlock()
			return entry, nil
		}
		delete(c.entries, host)
	}
	if len(c.entries) >= c.MaxEntries {
		c.evictLocked(now)
	}
	entry := &proxyDNSCacheEntry{done: make(chan struct{})}
	cached := len(c.entries) < c.MaxEntries
	if cached {
		c.entries[host] = entry
	}
	c.mu.Unlock()

	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	resolved, err := resolver.LookupNetIP(ctx, "ip", host)
	addresses := make([]netip.Addr, 0, min(len(resolved), maxProxyAddressesPerHost))
	if err == nil {
		for _, address := range resolved {
			address = address.Unmap()
			if !address.IsValid() || address.Zone() != "" {
				continue
			}
			duplicate := false
			for _, existing := range addresses {
				if existing == address {
					duplicate = true
					break
				}
			}
			if !duplicate {
				addresses = append(addresses, address)
				if len(addresses) == maxProxyAddressesPerHost {
					break
				}
			}
		}
		if len(addresses) == 0 {
			err = &net.DNSError{Err: "no usable addresses", Name: host}
		}
	}

	c.mu.Lock()
	entry.addrs = addresses
	entry.err = err
	if err == nil {
		entry.expires = time.Now().Add(c.TTL)
	} else if cached && c.entries[host] == entry {
		delete(c.entries, host)
	}
	close(entry.done)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func (c *ProxyDNSCache) evictLocked(now time.Time) {
	var oldestHost string
	var oldestExpiry time.Time
	for host, entry := range c.entries {
		if entry.expires.IsZero() {
			continue
		}
		if !now.Before(entry.expires) {
			delete(c.entries, host)
			if len(c.entries) < c.MaxEntries {
				return
			}
			continue
		}
		if oldestHost == "" || entry.expires.Before(oldestExpiry) {
			oldestHost, oldestExpiry = host, entry.expires
		}
	}
	if len(c.entries) >= c.MaxEntries && oldestHost != "" {
		delete(c.entries, oldestHost)
	}
}
