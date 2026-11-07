package protocol

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/drag-team/netvex-go/internal/model"
)

// GatewayCache coalesces concurrent failures for the same gateway and keeps
// only short-lived, deterministic failures. Successful sockets are never shared.
type GatewayCache struct {
	ttl     time.Duration
	max     int
	mu      sync.Mutex
	entries map[string]gatewayFailure
	flights map[string]*gatewayFlight
}

type gatewayFailure struct {
	err     error
	expires time.Time
}

type gatewayFlight struct {
	done chan struct{}
	err  error
}

func NewGatewayCache(ttl time.Duration, maxEntries int) *GatewayCache {
	return &GatewayCache{ttl: ttl, max: max(1, maxEntries), entries: make(map[string]gatewayFailure), flights: make(map[string]*gatewayFlight)}
}

// Do lets one caller probe a gateway. Waiters reuse a cacheable failure, while
// a successful leader wakes them to establish their own independent sockets.
func (g *GatewayCache) Do(ctx context.Context, key string, dial func() (Dialed, error)) (Dialed, error) {
	g.mu.Lock()
	if cached, ok := g.entries[key]; ok {
		if time.Now().Before(cached.expires) {
			g.mu.Unlock()
			return Dialed{}, cached.err
		}
		delete(g.entries, key)
	}
	if flight, ok := g.flights[key]; ok {
		g.mu.Unlock()
		select {
		case <-flight.done:
			if cacheableGatewayFailure(flight.err) {
				return Dialed{}, flight.err
			}
			// A successful TCP socket belongs to the leader. Waiters fan out
			// directly instead of serializing healthy gateways behind new flights.
			return dial()
		case <-ctx.Done():
			return Dialed{}, classifyNet(model.StageConnect, "proxy_connect", ctx.Err())
		}
	}
	flight := &gatewayFlight{done: make(chan struct{})}
	g.flights[key] = flight
	g.mu.Unlock()

	dialed, err := dial()
	g.mu.Lock()
	delete(g.flights, key)
	flight.err = err
	if cacheableGatewayFailure(err) {
		if len(g.entries) >= g.max {
			for oldKey := range g.entries {
				delete(g.entries, oldKey)
				break
			}
		}
		g.entries[key] = gatewayFailure{err: err, expires: time.Now().Add(g.ttl)}
	}
	close(flight.done)
	g.mu.Unlock()
	return dialed, err
}

func cacheableGatewayFailure(err error) bool {
	var classified *Error
	if !errors.As(err, &classified) {
		return false
	}
	switch classified.Code {
	case "connection_refused", "network_unreachable", "host_unreachable", "proxy_gateway_blocked":
		return true
	case "proxy_dns":
		var dns interface{ Temporary() bool }
		return !errors.As(err, &dns) || !dns.Temporary()
	default:
		return false
	}
}
