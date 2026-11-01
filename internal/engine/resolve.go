package engine

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/dr4g-team/netvex/internal/model"
	"github.com/dr4g-team/netvex/internal/policy"
	"github.com/dr4g-team/netvex/internal/protocol"
)

type resolveEntry struct {
	done    chan struct{}
	dest    policy.Destination
	err     error
	expires time.Time
}

func destinationForProtocol(dest policy.Destination, protoName model.Protocol) policy.Destination {
	if protoName != model.ProtocolSOCKS4 || dest.IP.Is4() {
		return dest
	}
	for _, ip := range dest.Resolved {
		ip = ip.Unmap()
		if ip.Is4() {
			dest.IP = ip
			break
		}
	}
	return dest
}

const maxDestinationAddresses = 4

func destinationCandidates(dest policy.Destination, protoName model.Protocol, remoteDNS bool) []policy.Destination {
	if remoteDNS && protoName != model.ProtocolSOCKS4 {
		return []policy.Destination{destinationForProtocol(dest, protoName)}
	}
	addresses := make([]netip.Addr, 0, min(len(dest.Resolved)+1, maxDestinationAddresses))
	add := func(address netip.Addr) {
		address = address.Unmap()
		if !address.IsValid() || protoName == model.ProtocolSOCKS4 && !address.Is4() {
			return
		}
		for _, existing := range addresses {
			if existing == address {
				return
			}
		}
		if len(addresses) < maxDestinationAddresses {
			addresses = append(addresses, address)
		}
	}
	add(dest.IP)
	for _, address := range dest.Resolved {
		add(address)
	}
	if len(addresses) == 0 {
		return []policy.Destination{destinationForProtocol(dest, protoName)}
	}
	result := make([]policy.Destination, len(addresses))
	for index, address := range addresses {
		result[index] = dest
		result[index].IP = address
	}
	return result
}

func retryDestinationAddress(err error) bool {
	var protocolError *protocol.Error
	if !errors.As(err, &protocolError) {
		return false
	}
	switch protocolError.Code {
	case "connect_upstream_error",
		"socks4_request_rejected",
		"socks5_general_failure",
		"socks5_network_unreachable",
		"socks5_host_unreachable",
		"socks5_connection_refused",
		"socks5_ttl_expired",
		"tls_handshake":
		return true
	default:
		return false
	}
}

func (c *Checker) resolve(ctx context.Context, target string) (policy.Destination, error) {
	if c.Config.DNSCacheTTL == 0 {
		return c.Policy.Resolve(ctx, target)
	}
	if err := ctx.Err(); err != nil {
		return policy.Destination{}, err
	}
	for {
		c.resolveMu.Lock()
		entry := c.resolved[target]
		if entry != nil && !entry.expires.IsZero() && time.Now().After(entry.expires) {
			delete(c.resolved, target)
			entry = nil
		}
		if entry == nil {
			entry = &resolveEntry{done: make(chan struct{})}
			c.resolved[target] = entry
			c.resolveMu.Unlock()
			lookupCtx, cancel := c.detachedResolveContext(ctx)
			go c.resolveTarget(lookupCtx, cancel, target, entry)
			select {
			case <-entry.done:
				return entry.dest, entry.err
			case <-ctx.Done():
				return policy.Destination{}, ctx.Err()
			}
		}
		done := entry.done
		c.resolveMu.Unlock()
		select {
		case <-done:
			return entry.dest, entry.err
		case <-ctx.Done():
			return policy.Destination{}, ctx.Err()
		}
	}
}

func (c *Checker) detachedResolveContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(base, deadline)
	}
	timeout := c.Config.RequestTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(base, timeout)
}

func (c *Checker) resolveTarget(ctx context.Context, cancel context.CancelFunc, target string, entry *resolveEntry) {
	defer cancel()
	dest, err := c.Policy.Resolve(ctx, target)
	c.resolveMu.Lock()
	entry.dest, entry.err = dest, err
	entry.expires = time.Now().Add(c.Config.DNSCacheTTL)
	close(entry.done)
	if err != nil && c.resolved[target] == entry {
		delete(c.resolved, target)
	}
	c.resolveMu.Unlock()
}
