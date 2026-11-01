package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dr4g-team/netvex/internal/config"
	"github.com/dr4g-team/netvex/internal/model"
)

// simulationScale compresses real time so large dead lists finish in seconds.
const simulationScale = 50

// TestDeadGatewaySimulation reproduces the figures in docs/BENCHMARKS.md. Every
// dial blocks until its timeout, the worst case of a host that drops packets. It
// is skipped by default because it measures throughput rather than behavior.
func TestDeadGatewaySimulation(t *testing.T) {
	if os.Getenv("NETVEX_SIMULATE") == "" {
		t.Skip("set NETVEX_SIMULATE=1 to run")
	}
	scaled := func(seconds float64) time.Duration {
		return time.Duration(seconds * float64(time.Second) / simulationScale)
	}
	for _, scenario := range []struct {
		name      string
		protocol  model.Protocol
		count     int
		prescreen bool
		configure func(*config.Config)
	}{
		{"defaults, http", model.ProtocolHTTP, 1200, false, nil},
		{"defaults, auto", model.ProtocolAuto, 1200, false, nil},
		{"--no-connect-retry, auto", model.ProtocolAuto, 1200, false, func(c *config.Config) { c.SkipConnectRetry = true }},
		{"--prescreen", model.ProtocolHTTP, 30000, true, nil},
		{"--prescreen, no retry, 3s", model.ProtocolAuto, 30000, true, func(c *config.Config) {
			c.PrescreenRetries = 0
			c.PrescreenTimeout = scaled(3)
		}},
		{"--prescreen, 16384 workers, no retry, 3s", model.ProtocolAuto, 80000, true, func(c *config.Config) {
			c.PrescreenRetries = 0
			c.PrescreenWorkers = 16384
			c.PrescreenTimeout = scaled(3)
		}},
	} {
		cfg := config.Defaults()
		cfg.ConnectTimeout = scaled(5)
		cfg.RequestTimeout = scaled(12)
		cfg.AutoProbeTimeout = scaled(3)
		cfg.RetryBackoff = scaled(0.1)
		if scenario.configure != nil {
			scenario.configure(&cfg)
		}
		checker := NewChecker(cfg)
		checker.Policy.AllowedHosts = map[string]struct{}{"example.com": {}}
		checker.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
		var dials atomic.Int64
		checker.Connector.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		jobs := make(chan model.Proxy, scenario.count)
		for index := range scenario.count {
			jobs <- model.Proxy{Protocol: scenario.protocol, Host: fmt.Sprintf("192.0.%d.%d", index/250, index%250+1), Port: 8080}
		}
		close(jobs)
		started := time.Now()
		ctx := context.Background()
		var input <-chan model.Proxy = jobs
		var rejected <-chan model.Result
		if scenario.prescreen {
			input, rejected = checker.Prescreen(ctx, jobs, cfg.PrescreenWorkers, 256)
		}
		results := Engine{Workers: cfg.Concurrency, QueueSize: 256, Processor: checker}.Run(ctx, input)
		if rejected != nil {
			results = Merge(results, rejected, 256)
		}
		for range results {
		}
		rate := float64(scenario.count) / (time.Since(started).Seconds() * simulationScale)
		t.Logf("%-42s %4.1f dials/proxy %8.1f proxies/s %6.2f h per million", scenario.name, float64(dials.Load())/float64(scenario.count), rate, 1e6/rate/3600)
	}
}
