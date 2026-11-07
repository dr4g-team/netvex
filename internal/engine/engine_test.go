package engine

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/drag-team/netvex-go/internal/model"
)

type immediateProcessor struct{}

func (immediateProcessor) Check(_ context.Context, p model.Proxy) model.Result {
	return model.Result{ID: p.Key(), Status: model.StatusOK}
}

func BenchmarkEngineScheduler(b *testing.B) {
	for _, workers := range []int{1, 16, 128} {
		b.Run(workerName(workers), func(b *testing.B) {
			jobs := make(chan model.Proxy, workers*2)
			e := Engine{Workers: workers, QueueSize: workers * 2, Processor: immediateProcessor{}}
			go func() {
				defer close(jobs)
				for i := 0; i < b.N; i++ {
					jobs <- model.Proxy{Protocol: model.ProtocolHTTP, Host: "bench.invalid", Port: uint16(1000 + i%64000)}
				}
			}()
			b.ResetTimer()
			n := 0
			for range e.Run(context.Background(), jobs) {
				n++
			}
			if n != b.N {
				b.Fatalf("got %d", n)
			}
		})
	}
}
func workerName(n int) string {
	if n == 1 {
		return "workers_1"
	}
	if n == 16 {
		return "workers_16"
	}
	return "workers_128"
}

func TestAdaptiveControllerAIMD(t *testing.T) {
	controller := NewAdaptiveController(2, 8, 8)
	for range 8 {
		if !controller.Acquire(context.Background()) {
			t.Fatal("acquire failed")
		}
		controller.Release(model.Result{Status: model.StatusOK})
	}
	if controller.Limit() != 3 {
		t.Fatalf("additive limit=%d, want 3", controller.Limit())
	}
	failure := model.Result{Observations: []model.Observation{{Code: "local_resource_exhausted"}}}
	for i := 0; i < 8; i++ {
		if !controller.Acquire(context.Background()) {
			t.Fatal("acquire failed")
		}
		if i == 0 {
			controller.Release(failure)
		} else {
			controller.Release(model.Result{Status: model.StatusOK})
		}
	}
	if controller.Limit() != 2 {
		t.Fatalf("multiplicative limit=%d, want floor 2", controller.Limit())
	}
	controller.SetMaximum(1)
	if controller.Limit() != 1 {
		t.Fatalf("reduced stage maximum=%d", controller.Limit())
	}
}

func TestDurationEstimatorRequiresEvidenceAndClamps(t *testing.T) {
	var estimator durationEstimator
	if got := estimator.Timeout(100*time.Millisecond, 5*time.Second); got != 5*time.Second {
		t.Fatalf("cold timeout=%s", got)
	}
	for range 32 {
		estimator.Observe(20 * time.Millisecond)
	}
	if got := estimator.Timeout(100*time.Millisecond, 5*time.Second); got != 100*time.Millisecond {
		t.Fatalf("floor timeout=%s", got)
	}
	estimator.Reset()
	if got := estimator.Timeout(100*time.Millisecond, 5*time.Second); got != 5*time.Second {
		t.Fatalf("reset timeout=%s", got)
	}
}

// BenchmarkCheckLiveProxy measures one complete validation over an in-memory
// proxy, so allocation changes in the request path show up without network noise.
func BenchmarkCheckLiveProxy(b *testing.B) {
	checker := baseChecker("http://target.test/")
	checker.Config.Repeat = 1
	checker.Connector.DialContext = pipeDial(func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 46\r\n\r\n{\"origin\":\"203.0.113.9\",\"headers\":{\"Host\":\"x\"}}")
	})
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080}
	b.ReportAllocs()
	for b.Loop() {
		if result := checker.Check(context.Background(), proxy); result.Status != model.StatusOK {
			b.Fatalf("result=%+v", result)
		}
	}
}

func BenchmarkPrescreenConnectionReuse(b *testing.B) {
	for _, reuse := range []bool{false, true} {
		name := "redial"
		if reuse {
			name = "reuse"
		}
		b.Run(name, func(b *testing.B) {
			checker := baseChecker("http://target.test/")
			checker.Config.PrescreenRetries = 0
			checker.Connector.DialContext = pipeDial(func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				if _, err := http.ReadRequest(reader); err != nil {
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				_, _ = http.ReadRequest(reader)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			})
			proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080}
			b.ReportAllocs()
			for b.Loop() {
				_, dialed, alive := checker.screen(context.Background(), checker.Connector, proxy)
				if !alive {
					b.Fatal("prescreen failed")
				}
				var result model.Result
				if reuse {
					result = checker.CheckPrepared(context.Background(), PreparedProxy{Proxy: proxy, Dialed: dialed})
				} else {
					dialed.Close()
					result = checker.Check(context.Background(), proxy)
				}
				if result.Status != model.StatusOK {
					b.Fatalf("result=%+v", result)
				}
			}
		})
	}
}
