package protocol

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/drag-team/netvex-go/internal/model"
)

func TestGatewayCacheCoalescesDeterministicFailures(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	connector := Connector{
		GatewayCache: NewGatewayCache(time.Minute, 16),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			<-release
			return nil, syscall.ECONNREFUSED
		},
	}
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "dead.test", Port: 80}
	var group sync.WaitGroup
	group.Add(16)
	for range 16 {
		go func() { defer group.Done(); _, _ = connector.Dial(context.Background(), proxy) }()
	}
	time.Sleep(10 * time.Millisecond)
	close(release)
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("dials=%d, want 1", calls.Load())
	}
}

func TestGatewayCacheDoesNotRetainSuccessOrTimeout(t *testing.T) {
	cache := NewGatewayCache(time.Minute, 2)
	var successes atomic.Int64
	for range 2 {
		dialed, err := cache.Do(context.Background(), "healthy", func() (Dialed, error) {
			successes.Add(1)
			client, server := net.Pipe()
			_ = server.Close()
			return Dialed{Conn: client}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		dialed.Close()
	}
	if successes.Load() != 2 {
		t.Fatalf("successful dial was cached: %d", successes.Load())
	}
	var timeouts atomic.Int64
	for range 2 {
		_, _ = cache.Do(context.Background(), "timeout", func() (Dialed, error) {
			timeouts.Add(1)
			return Dialed{}, &Error{Stage: model.StageConnect, Status: model.StatusTimeout, Code: "network_timeout", Err: syscall.ETIMEDOUT}
		})
	}
	if timeouts.Load() != 2 {
		t.Fatalf("timeout was cached: %d", timeouts.Load())
	}
}

func TestGatewayCacheExpiresFailure(t *testing.T) {
	cache := NewGatewayCache(time.Millisecond, 1)
	var calls atomic.Int64
	dial := func() (Dialed, error) {
		calls.Add(1)
		return Dialed{}, &Error{Stage: model.StageConnect, Status: model.StatusFailed, Code: "connection_refused", Err: syscall.ECONNREFUSED}
	}
	_, _ = cache.Do(context.Background(), "dead", dial)
	time.Sleep(2 * time.Millisecond)
	_, _ = cache.Do(context.Background(), "dead", dial)
	if calls.Load() != 2 {
		t.Fatalf("expired failure calls=%d", calls.Load())
	}
}
