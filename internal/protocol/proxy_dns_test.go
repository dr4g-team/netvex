package protocol

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dr4g-team/netvex/internal/model"
)

type controlledProxyResolver struct {
	calls   atomic.Int64
	addrs   []netip.Addr
	err     error
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *controlledProxyResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	r.calls.Add(1)
	if r.started != nil {
		r.once.Do(func() { close(r.started) })
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r.addrs, r.err
}

func TestProxyDNSCacheCoalescesAndRotates(t *testing.T) {
	resolver := &controlledProxyResolver{
		addrs:   []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")},
		started: make(chan struct{}), release: make(chan struct{}),
	}
	cache := NewProxyDNSCache(time.Minute, 8)
	cache.Resolver = resolver
	const callers = 32
	results := make(chan string, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			address, err := cache.Address(context.Background(), "GATEWAY.TEST.", 8080)
			if err != nil {
				results <- err.Error()
				return
			}
			results <- address
		}()
	}
	<-resolver.started
	close(resolver.release)
	wg.Wait()
	close(results)
	counts := map[string]int{}
	for result := range results {
		counts[result]++
	}
	if resolver.calls.Load() != 1 || counts["1.1.1.1:8080"] != callers/2 || counts["8.8.8.8:8080"] != callers/2 {
		t.Fatalf("calls=%d results=%v", resolver.calls.Load(), counts)
	}
}

func TestProxyDNSCacheExpiryFailureAndBounds(t *testing.T) {
	resolver := &controlledProxyResolver{addrs: []netip.Addr{netip.MustParseAddr("9.9.9.9")}}
	cache := NewProxyDNSCache(time.Minute, 1)
	cache.Resolver = resolver
	if got, err := cache.Address(context.Background(), "one.test", 80); err != nil || got != "9.9.9.9:80" {
		t.Fatalf("address=%q err=%v", got, err)
	}
	cache.mu.Lock()
	cache.entries["one.test"].expires = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	if _, err := cache.Address(context.Background(), "one.test", 80); err != nil || resolver.calls.Load() != 2 {
		t.Fatalf("expired lookup calls=%d err=%v", resolver.calls.Load(), err)
	}
	if _, err := cache.Address(context.Background(), "two.test", 80); err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	entries := len(cache.entries)
	cache.mu.Unlock()
	if entries != 1 {
		t.Fatalf("entries=%d", entries)
	}

	failing := &controlledProxyResolver{err: errors.New("temporary DNS failure")}
	failedCache := NewProxyDNSCache(time.Minute, 1)
	failedCache.Resolver = failing
	for range 2 {
		if _, err := failedCache.Address(context.Background(), "failure.test", 80); err == nil {
			t.Fatal("failed lookup unexpectedly succeeded")
		}
	}
	if failing.calls.Load() != 2 {
		t.Fatalf("failure was cached: calls=%d", failing.calls.Load())
	}
}

func TestProxyDNSCacheBypassesLiteralAndConnectorUsesResolvedAddress(t *testing.T) {
	resolver := &controlledProxyResolver{addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	cache := NewProxyDNSCache(time.Minute, 8)
	cache.Resolver = resolver
	if got, err := cache.Address(context.Background(), "2001:4860:4860::8888", 443); err != nil || got != "[2001:4860:4860::8888]:443" || resolver.calls.Load() != 0 {
		t.Fatalf("literal=%q calls=%d err=%v", got, resolver.calls.Load(), err)
	}
	var dialed string
	connector := Connector{
		ConnectTimeout: time.Second,
		ProxyDNS:       cache,
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, syscall.ECONNREFUSED
		},
	}
	_, err := connector.Open(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "gateway.test", Port: 3128}, destination())
	var protocolError *Error
	if !errors.As(err, &protocolError) || protocolError.Code != "connection_refused" || dialed != "1.1.1.1:3128" {
		t.Fatalf("dialed=%q err=%v", dialed, err)
	}
}

func TestProxyDNSCacheHonorsCancellation(t *testing.T) {
	resolver := &controlledProxyResolver{started: make(chan struct{}), release: make(chan struct{})}
	cache := NewProxyDNSCache(time.Minute, 8)
	cache.Resolver = resolver
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := cache.Address(ctx, "slow.test", 80)
		done <- err
	}()
	<-resolver.started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	close(resolver.release)
}

func TestProxyDNSCacheLeaderCancellationDoesNotFailWaiters(t *testing.T) {
	resolver := &controlledProxyResolver{
		addrs:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		started: make(chan struct{}), release: make(chan struct{}),
	}
	cache := NewProxyDNSCache(time.Minute, 8)
	cache.Resolver = resolver
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := cache.Address(leaderCtx, "shared.test", 80)
		leaderDone <- err
	}()
	<-resolver.started
	waiterDone := make(chan error, 1)
	go func() {
		address, err := cache.Address(context.Background(), "shared.test", 80)
		if err == nil && address != "1.1.1.1:80" {
			err = errors.New("unexpected resolved address: " + address)
		}
		waiterDone <- err
	}()
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err=%v", err)
	}
	close(resolver.release)
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter err=%v", err)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("resolver calls=%d", resolver.calls.Load())
	}
}

func TestProxyDNSUsesConnectDeadline(t *testing.T) {
	resolver := &controlledProxyResolver{started: make(chan struct{}), release: make(chan struct{})}
	cache := NewProxyDNSCache(time.Minute, 8)
	cache.Resolver = resolver
	connector := Connector{ConnectTimeout: 20 * time.Millisecond, ProxyDNS: cache}
	started := time.Now()
	_, err := connector.Open(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "slow.test", Port: 80}, destination())
	close(resolver.release)
	var protocolError *Error
	if !errors.As(err, &protocolError) || protocolError.Status != model.StatusTimeout || time.Since(started) > time.Second {
		t.Fatalf("elapsed=%s err=%v", time.Since(started), err)
	}
}

func BenchmarkProxyDNSCacheHit(b *testing.B) {
	resolver := &controlledProxyResolver{addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}}
	cache := NewProxyDNSCache(time.Hour, 8)
	cache.Resolver = resolver
	if _, err := cache.Address(context.Background(), "gateway.test", 8080); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := cache.Address(context.Background(), "gateway.test", 8080); err != nil {
			b.Fatal(err)
		}
	}
	if resolver.calls.Load() != 1 {
		b.Fatalf("resolver calls=%d", resolver.calls.Load())
	}
}

func BenchmarkProxyDNSCacheHitParallel(b *testing.B) {
	resolver := &controlledProxyResolver{addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}}
	cache := NewProxyDNSCache(time.Hour, 8)
	cache.Resolver = resolver
	if _, err := cache.Address(context.Background(), "gateway.test", 8080); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := cache.Address(context.Background(), "gateway.test", 8080); err != nil {
				b.Fatal(err)
			}
		}
	})
}
