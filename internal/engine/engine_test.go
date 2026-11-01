package engine

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/drag-team/netvex/internal/model"
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
