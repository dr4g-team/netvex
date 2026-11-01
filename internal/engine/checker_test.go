package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/drag-team/netvex/internal/config"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/policy"
	"github.com/drag-team/netvex/internal/protocol"
)

type fixedResolver struct {
	ips   []netip.Addr
	calls *atomic.Int64
}

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if r.calls != nil {
		r.calls.Add(1)
	}
	return r.ips, nil
}

type failingResolver struct{}

func (failingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("resolver unavailable")
}

type blockingResolver struct {
	calls   atomic.Int64
	started chan struct{}
	release chan struct{}
}

func (r *blockingResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	r.calls.Add(1)
	select {
	case r.started <- struct{}{}:
	default:
	}
	select {
	case <-r.release:
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type fixedMetadata struct{}

func (fixedMetadata) Lookup(ip string) (model.ExitMetadata, bool) {
	if ip == "8.8.8.8" {
		return model.ExitMetadata{CountryCode: "US", ASN: "AS15169", NetworkType: "datacenter"}, true
	}
	return model.ExitMetadata{}, false
}

func pipeDial(script func(net.Conn)) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { defer server.Close(); script(server) }()
		return client, nil
	}
}

func baseChecker(target string) *Checker {
	cfg := config.Defaults()
	cfg.Targets = []string{target}
	cfg.AllowedHosts = []string{"target.test"}
	cfg.Repeat = 1
	cfg.RequestTimeout = time.Second
	cfg.ConnectTimeout = 500 * time.Millisecond
	cfg.RetryBackoff = 0
	c := NewChecker(cfg)
	c.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	return c
}

func TestHTTPValidationAndIntelligence(t *testing.T) {
	c := baseChecker("http://target.test/echo")
	c.baseline = netip.MustParseAddr("192.0.2.1")
	c.Metadata = fixedMetadata{}
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		connectReq, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if connectReq.Method != "CONNECT" || connectReq.Host != "1.1.1.1:80" {
			t.Errorf("CONNECT host=%q", connectReq.Host)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Host != "target.test" || req.URL.Path != "/echo" {
			t.Errorf("host=%q url=%q", req.Host, req.URL.String())
		}
		body := `{"origin":"8.8.8.8","headers":{"X-Forwarded-For":"192.0.2.1"}}`
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body)
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if r.Status != model.StatusOK || r.Successes != 1 {
		t.Fatalf("%+v", r)
	}
	o := r.Observations[0]
	if o.ExitIP != "8.8.8.8" || o.Anonymity != "transparent" || len(o.ForwardingEvidence) != 1 || o.ForwardingEvidence[0] != "X-Forwarded-For" || o.Metadata == nil || o.Metadata.ASN != "AS15169" {
		t.Fatalf("%+v", o)
	}
}

func TestCredentialBearingInputProxyIsExplicit(t *testing.T) {
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080, Credentials: &model.Credentials{Username: "user", Password: "s%cret"}}
	check := func(include bool) model.Result {
		c := baseChecker("http://target.test/")
		c.IncludeInputProxy = include
		c.Connector.DialContext = pipeDial(func(conn net.Conn) {
			reader := bufio.NewReader(conn)
			_, _ = http.ReadRequest(reader)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = http.ReadRequest(reader)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		})
		return c.Check(context.Background(), proxy)
	}
	if result := check(false); result.Validated != nil {
		t.Fatalf("credentials retained without export: %v", result.Validated.SafeURI())
	}
	if result := check(true); result.Validated == nil || !strings.Contains(result.Validated.FullURI(), "user:s%25cret@proxy.test:8080") {
		t.Fatalf("credentials missing for explicit export: %+v", result.Validated)
	}
	failed := baseChecker("http://target.test/")
	failed.IncludeInputProxy = true
	failed.Connector.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("offline") }
	if result := failed.Check(context.Background(), proxy); result.Validated != nil {
		t.Fatalf("failed proxy retained credentials: %v", result.Validated.SafeURI())
	}
}

func TestDestinationAddressFallback(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}}
	var calls atomic.Int64
	c.Connector.DialContext = func(context.Context, string, string) (net.Conn, error) {
		attempt := calls.Add(1)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			connectRequest, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			if attempt == 1 {
				if connectRequest.Host != "1.1.1.1:80" {
					t.Errorf("first CONNECT host=%q", connectRequest.Host)
				}
				_, _ = io.WriteString(server, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
				return
			}
			if connectRequest.Host != "8.8.8.8:80" {
				t.Errorf("fallback CONNECT host=%q", connectRequest.Host)
			}
			_, _ = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n")
			if _, err := http.ReadRequest(reader); err != nil {
				return
			}
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}()
		return client, nil
	}
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if result.Status != model.StatusOK || calls.Load() != 2 || result.Observations[0].ResolvedIP != "8.8.8.8" || result.Observations[0].DestinationAttempts != 2 {
		t.Fatalf("calls=%d result=%+v", calls.Load(), result)
	}
}

func TestDestinationCandidatesAreBoundedAndProtocolAware(t *testing.T) {
	resolved := []netip.Addr{
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("208.67.222.222"),
	}
	destination := policy.Destination{IP: resolved[0], Resolved: resolved}
	if got := destinationCandidates(destination, model.ProtocolSOCKS5, false); len(got) != maxDestinationAddresses || !got[0].IP.Is6() {
		t.Fatalf("SOCKS5 candidates=%v", got)
	}
	if got := destinationCandidates(destination, model.ProtocolSOCKS4, false); len(got) != maxDestinationAddresses || !got[0].IP.Is4() {
		t.Fatalf("SOCKS4 candidates=%v", got)
	}
	if got := destinationCandidates(destination, model.ProtocolSOCKS5, true); len(got) != 1 {
		t.Fatalf("remote DNS candidates=%v", got)
	}
	if got := destinationCandidates(destination, model.ProtocolSOCKS4, true); len(got) != maxDestinationAddresses {
		t.Fatalf("SOCKS4 local-DNS candidates=%v", got)
	}
	if retryDestinationAddress(&protocol.Error{Code: "proxy_auth_rejected"}) {
		t.Fatal("authentication failure triggered address fallback")
	}
}

func TestAnonymityEvidenceLevels(t *testing.T) {
	baseline := netip.MustParseAddr("192.0.2.1")
	tests := []struct {
		body string
		want string
	}{
		{`{"origin":"8.8.8.8","headers":{}}`, "elite"},
		{`{"origin":"8.8.8.8","headers":{"Via":"proxy"}}`, "anonymous"},
		{`{"origin":"8.8.8.8","headers":{"X-Forwarded-For":"192.0.2.1"}}`, "transparent"},
		{`{"origin":"192.0.2.1","headers":{}}`, "transparent"},
	}
	for _, tc := range tests {
		_, got, evidence := extractIntelligence([]byte(tc.body), baseline)
		if got != tc.want {
			t.Fatalf("body=%s got=%s want=%s evidence=%v", tc.body, got, tc.want, evidence)
		}
	}
	_, got, _ := extractIntelligence([]byte(tests[0].body), netip.Addr{})
	if got != "undetermined" {
		t.Fatalf("without baseline got=%s", got)
	}
	if !containsIP(`for="[2001:db8::1]:443"`, netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("IPv6 forwarded address was not detected")
	}
}

func TestReadBodyEvidenceStreamsAndCapsCapture(t *testing.T) {
	payload := bytes.Repeat([]byte("netvex"), 200000)
	wantDigest := sha256.Sum256(payload)
	body, count, digest, err := readBodyEvidence(bytes.NewReader(payload), int64(len(payload)), 4096, int64(len(payload)), nil)
	if err != nil || count != int64(len(payload)) || len(body) != 4096 || digest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("count=%d captured=%d digest=%s err=%v", count, len(body), digest, err)
	}
	body, count, _, err = readBodyEvidence(bytes.NewReader(payload), 65536, 4096, int64(len(payload)), nil)
	if err != nil || count != 65537 || len(body) != 4096 {
		t.Fatalf("limited count=%d captured=%d err=%v", count, len(body), err)
	}
}

type emptyBodyReader struct{ reads int }

func (r *emptyBodyReader) Read([]byte) (int, error) {
	r.reads++
	return 0, nil
}

type shortEvidenceWriter struct{}

func (shortEvidenceWriter) Write(value []byte) (int, error) { return len(value) - 1, nil }

func TestReadBodyEvidencePropagatesStreamingFailures(t *testing.T) {
	empty := &emptyBodyReader{}
	if _, _, _, err := readBodyEvidence(empty, 1024, 1024, 0, nil); !errors.Is(err, io.ErrNoProgress) || empty.reads != 100 {
		t.Fatalf("empty reads=%d err=%v", empty.reads, err)
	}
	if _, count, _, err := readBodyEvidence(strings.NewReader("payload"), 1024, 1024, 0, shortEvidenceWriter{}); !errors.Is(err, io.ErrShortWrite) || count != 7 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestTextMatcherStreamsAcrossChunks(t *testing.T) {
	plan := compileTextMatchPlan([]string{"cloudflare", "access denied"}, []string{"captcha", "turnstile"})
	if plan == nil {
		t.Fatal("ASCII rules did not produce a streaming matcher")
	}
	matcher := plan.matcher()
	for _, chunk := range []string{"CLOUD", "Flare says access ", "DENIED and cap", "TCHA"} {
		if _, err := matcher.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	want := []bool{true, true, true, false}
	if !slices.Equal(matcher.found, want) {
		t.Fatalf("matches=%v want=%v", matcher.found, want)
	}
	if got := compileTextMatchPlan([]string{"café"}, nil); got != nil {
		t.Fatal("Unicode rule must use the compatibility capture path")
	}
	if got := compileTextMatchPlan([]string{""}, nil); got != nil {
		t.Fatal("empty rule must use validated compatibility handling")
	}
}

func TestTextMatcherEquivalentAcrossBoundaries(t *testing.T) {
	patterns := []string{"alpha", "access denied", "403!", "aaaaab", "x-y_z"}
	plan := compileTextMatchPlan(patterns, nil)
	bodies := []string{
		"nothing relevant here",
		"prefix ALPHA suffix",
		"mixed Access DENIED response",
		strings.Repeat("a", 80) + "b",
		"status=403! x-Y_Z",
	}
	for _, body := range bodies {
		lower := bytes.ToLower([]byte(body))
		want := make([]bool, len(patterns))
		for index, pattern := range patterns {
			want[index] = bytes.Contains(lower, []byte(pattern))
		}
		for chunkSize := 1; chunkSize <= 17; chunkSize++ {
			matcher := plan.matcher()
			for offset := 0; offset < len(body); offset += chunkSize {
				end := min(offset+chunkSize, len(body))
				_, _ = matcher.Write([]byte(body[offset:end]))
			}
			if !slices.Equal(matcher.found, want) {
				t.Fatalf("body=%q chunk=%d matches=%v want=%v", body, chunkSize, matcher.found, want)
			}
		}
	}
}

func TestLargeResponseRetainsBoundedIntelligenceBody(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 128<<10)
	copy(payload[100<<10:], []byte("REQUIRED-MARKER"))
	wantDigest := sha256.Sum256(payload)
	c := baseChecker("http://target.test/payload")
	c.Config.MaxResponseBytes = int64(len(payload))
	c.Config.IntelligenceBytes = 4096
	c.Config.RequireText = []string{"required-marker"}
	c.requireText = []string{"required-marker"}
	c.effectiveRules = nil
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: "+itoa(len(payload))+"\r\n\r\n")
		_, _ = conn.Write(payload)
	})
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080})
	observation := result.Observations[0]
	if result.Status != model.StatusOK || observation.BodyBytes != int64(len(payload)) || observation.BodyCapturedBytes != 4096 || observation.BodySHA256 != hex.EncodeToString(wantDigest[:]) || observation.Anonymity != "unavailable" {
		t.Fatalf("result=%+v", result)
	}
}

func BenchmarkReadBodyEvidence(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1<<20)
	b.Run("legacy_read_all", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		for range b.N {
			body, err := io.ReadAll(io.LimitReader(bytes.NewReader(payload), int64(len(payload))+1))
			digest := sha256.Sum256(body)
			if err != nil || len(body) != len(payload) || digest == [32]byte{} {
				b.Fatal(err, len(body))
			}
		}
	})
	for _, capture := range []int64{64 << 10, 1 << 20} {
		name := "capture_64KiB"
		if capture == 1<<20 {
			name = "capture_full"
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for range b.N {
				body, count, _, err := readBodyEvidence(bytes.NewReader(payload), int64(len(payload)), capture, int64(len(payload)), nil)
				if err != nil || count != int64(len(payload)) || len(body) != int(capture) {
					b.Fatal(err, count, len(body))
				}
			}
		})
	}
	b.Run("legacy_text_assertion", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		pattern := []byte("access denied")
		for range b.N {
			body, err := io.ReadAll(io.LimitReader(bytes.NewReader(payload), int64(len(payload))+1))
			matched := bytes.Contains(bytes.ToLower(body), pattern)
			if err != nil || matched {
				b.Fatal(err, matched)
			}
		}
	})
	b.Run("stream_text_assertion", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		plan := compileTextMatchPlan([]string{"access denied"}, nil)
		for range b.N {
			matcher := plan.matcher()
			body, count, _, err := readBodyEvidence(bytes.NewReader(payload), int64(len(payload)), 64<<10, int64(len(payload)), matcher)
			if err != nil || count != int64(len(payload)) || len(body) != 64<<10 || matcher.found[0] {
				b.Fatal(err, count, len(body), matcher.found)
			}
		}
	})
}

func TestAutoProtocolOrderUsesPortHints(t *testing.T) {
	assertOrder := func(port uint16, want ...model.Protocol) {
		t.Helper()
		got := autoProtocols(port, false)
		if len(got) != len(want) {
			t.Fatalf("port=%d got=%v want=%v", port, got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("port=%d got=%v want=%v", port, got, want)
			}
		}
	}
	assertOrder(1080, model.ProtocolSOCKS5, model.ProtocolSOCKS4, model.ProtocolHTTP, model.ProtocolHTTPS)
	assertOrder(443, model.ProtocolHTTPS, model.ProtocolHTTP, model.ProtocolSOCKS5, model.ProtocolSOCKS4)
	assertOrder(8080, model.ProtocolHTTP, model.ProtocolHTTPS, model.ProtocolSOCKS5, model.ProtocolSOCKS4)
	if got := autoProtocols(1080, true); got[len(got)-1] != model.ProtocolSOCKS4A {
		t.Fatalf("remote DNS order=%v", got)
	}
}

func TestAutoStopsAtTheFirstTCPFailure(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 1
	c.Config.AutoProbeTimeout = 40 * time.Millisecond
	var dials atomic.Int64
	c.Connector.ConnectTimeout = 40 * time.Millisecond
	c.Connector.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolAuto, Host: "proxy.test", Port: 8080})
	if dials.Load() != 1 {
		t.Fatalf("dead host dialed %d times", dials.Load())
	}
	if result.Status != model.StatusTimeout || result.Observations[0].Stage != model.StageConnect {
		t.Fatalf("result=%+v", result)
	}
}

func TestAutoProbeTimeoutLeavesTimeForOtherCandidates(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 1
	c.Config.RequestTimeout = 240 * time.Millisecond
	c.Config.AutoProbeTimeout = 40 * time.Millisecond
	var dials atomic.Int64
	c.Connector.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
		}()
		return client, nil
	}
	started := time.Now()
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolAuto, Host: "proxy.test", Port: 8080})
	if elapsed := time.Since(started); elapsed > 400*time.Millisecond {
		t.Fatalf("auto detection exceeded bound: %s", elapsed)
	}
	if dials.Load() < 4 {
		t.Fatalf("only %d connections for a silent server; every candidate must get a turn", dials.Load())
	}
	if len(result.Observations) != 1 || result.Status != model.StatusTimeout {
		t.Fatalf("result=%+v", result)
	}
}

func TestSniffHintSkipsWrongProtocols(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 1
	var dials atomic.Int64
	c.Connector.DialContext = func(context.Context, string, string) (net.Conn, error) {
		first := dials.Add(1) == 1
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if first {
				probe := make([]byte, 8)
				if _, err := io.ReadFull(server, probe); err != nil {
					return
				}
				_, _ = server.Write([]byte{5, 0})
				_, _ = io.Copy(io.Discard, server)
				return
			}
			greeting := make([]byte, 3)
			if _, err := io.ReadFull(server, greeting); err != nil {
				return
			}
			_, _ = server.Write([]byte{5, 0})
			head := make([]byte, 10)
			if _, err := io.ReadFull(server, head); err != nil {
				return
			}
			_, _ = server.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			reader := bufio.NewReader(server)
			if _, err := http.ReadRequest(reader); err != nil {
				return
			}
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}()
		return client, nil
	}
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolAuto, Host: "proxy.test", Port: 8080})
	if result.Status != model.StatusOK || result.Protocol != model.ProtocolSOCKS5 {
		t.Fatalf("result=%+v", result)
	}
	if dials.Load() != 2 {
		t.Fatalf("expected one sniff and one validation, got %d connections", dials.Load())
	}
}

func TestNarrowProtocols(t *testing.T) {
	all := []model.Protocol{model.ProtocolHTTP, model.ProtocolHTTPS, model.ProtocolSOCKS5, model.ProtocolSOCKS4, model.ProtocolSOCKS4A}
	if got := narrowProtocols(all, ""); len(got) != len(all) {
		t.Fatalf("no hint changed candidates: %v", got)
	}
	if got := narrowProtocols(all, model.ProtocolSOCKS5); len(got) != 1 || got[0] != model.ProtocolSOCKS5 {
		t.Fatalf("got=%v", got)
	}
	if got := narrowProtocols(all, model.ProtocolSOCKS4); len(got) != 2 {
		t.Fatalf("got=%v", got)
	}
	if got := narrowProtocols([]model.Protocol{model.ProtocolHTTP}, model.ProtocolSOCKS5); len(got) != 1 {
		t.Fatalf("a hint outside the candidates must not empty them: %v", got)
	}
}

func TestDeadGatewayNeverOccupiesTargetSlot(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 1
	c.Config.PerTarget = 1
	c.Config.Concurrency = 8
	c.Connector.ConnectTimeout = 80 * time.Millisecond
	var active, peak atomic.Int64
	c.Connector.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		now := active.Add(1)
		defer active.Add(-1)
		for {
			current := peak.Load()
			if now <= current || peak.CompareAndSwap(current, now) {
				break
			}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var group sync.WaitGroup
	for index := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: uint16(8000 + index)})
		}()
	}
	group.Wait()
	if peak.Load() != 8 {
		t.Fatalf("per-target limit throttled dead gateways to %d of 8", peak.Load())
	}
}

func TestQueueWaitIsChargedToNeitherLatencyNorTimeout(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 1
	c.Config.PerTarget = 1
	c.Config.Concurrency = 2
	c.Config.RequestTimeout = 300 * time.Millisecond
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	release := c.acquireTarget(context.Background(), "target.test")
	time.AfterFunc(400*time.Millisecond, release)
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if result.Status != model.StatusOK {
		t.Fatalf("queue wait consumed the timeout: %+v", result)
	}
	timings := result.Observations[0].Timings
	if timings.QueueMS < 300 || timings.TotalMS > 200 {
		t.Fatalf("timings=%+v", timings)
	}
}

func TestStaleQueuedConnectionIsRedialed(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 1
	var dials atomic.Int64
	c.Connector.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			if _, err := http.ReadRequest(reader); err != nil {
				return
			}
			_, _ = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = http.ReadRequest(reader)
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}()
		return client, nil
	}
	c.Config.PerTarget = 1
	release := c.acquireTarget(context.Background(), "target.test")
	time.AfterFunc(maxQueuedConnAge+50*time.Millisecond, release)
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if result.Status != model.StatusOK || dials.Load() != 2 {
		t.Fatalf("status=%s dials=%d", result.Status, dials.Load())
	}
}

func TestSkipConnectRetryStopsAfterTCPFailure(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 3
	c.Config.MinSuccessRate = 0.3
	c.Config.RetryBackoff = 0
	var dials atomic.Int64
	c.Connector.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, syscall.ECONNREFUSED
	}
	c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if dials.Load() != 3 {
		t.Fatalf("default retries changed: %d", dials.Load())
	}
	dials.Store(0)
	c.Config.SkipConnectRetry = true
	c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if dials.Load() != 1 {
		t.Fatalf("connect failure retried: %d", dials.Load())
	}
}

func TestPrescreenRoutesAndRetries(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.PrescreenRetries = 1
	c.Config.RetryBackoff = 0
	dials := map[string]*atomic.Int64{"alive.test:80": {}, "flaky.test:80": {}, "dead.test:80": {}}
	c.Connector.DialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		attempt := dials[address].Add(1)
		if address == "dead.test:80" || (address == "flaky.test:80" && attempt == 1) {
			return nil, syscall.ECONNREFUSED
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	input := make(chan model.Proxy, 3)
	for _, host := range []string{"alive.test", "flaky.test", "dead.test"} {
		input <- model.Proxy{Protocol: model.ProtocolHTTP, Host: host, Port: 80}
	}
	close(input)
	reachable, rejected := c.Prescreen(context.Background(), input, 2, 4)
	var alive []string
	var dead []model.Result
	for reachable != nil || rejected != nil {
		select {
		case proxy, ok := <-reachable:
			if !ok {
				reachable = nil
				continue
			}
			alive = append(alive, proxy.Host)
		case result, ok := <-rejected:
			if !ok {
				rejected = nil
				continue
			}
			dead = append(dead, result)
		}
	}
	if len(alive) != 2 || len(dead) != 1 {
		t.Fatalf("alive=%v dead=%+v", alive, dead)
	}
	result := dead[0]
	if result.Endpoint != "dead.test:80" || result.Status != model.StatusFailed || result.Attempts != 1 || result.Observations[0].Code != "connection_refused" || result.ID == "" || result.Rotation.Classification == "" {
		t.Fatalf("result=%+v", result)
	}
	if dials["dead.test:80"].Load() != 2 {
		t.Fatalf("dead dials=%d", dials["dead.test:80"].Load())
	}
}

func TestPrescreenStopsOnCancellation(t *testing.T) {
	c := baseChecker("http://target.test/")
	ctx, cancel := context.WithCancel(context.Background())
	input := make(chan model.Proxy)
	reachable, rejected := c.Prescreen(ctx, input, 3, 1)
	cancel()
	deadline := time.After(2 * time.Second)
	for reachable != nil || rejected != nil {
		select {
		case _, ok := <-reachable:
			if !ok {
				reachable = nil
			}
		case _, ok := <-rejected:
			if !ok {
				rejected = nil
			}
		case <-deadline:
			t.Fatal("prescreen did not stop")
		}
	}
}

func TestMergeForwardsBothStreams(t *testing.T) {
	first, second := make(chan model.Result, 2), make(chan model.Result, 2)
	first <- model.Result{ID: "a"}
	second <- model.Result{ID: "b"}
	second <- model.Result{ID: "c"}
	close(first)
	close(second)
	count := 0
	for range Merge(first, second, 1) {
		count++
	}
	if count != 3 {
		t.Fatalf("count=%d", count)
	}
}

func TestClassicalKeyExchangeIsOptIn(t *testing.T) {
	c := baseChecker("https://target.test/")
	if preferences := c.destinationTLS("target.test").CurvePreferences; preferences != nil {
		t.Fatalf("default curves changed: %v", preferences)
	}
	c.Config.TLSClassicalKEX = true
	config := c.destinationTLS("target.test")
	if len(config.CurvePreferences) != 1 || config.CurvePreferences[0] != tls.X25519 || config.ServerName != "target.test" || config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("config=%+v", config)
	}
}

func TestContentAssertionsAndThroughputEvidence(t *testing.T) {
	body := "required-marker" + strings.Repeat("x", 20<<10)
	newChecker := func() *Checker {
		c := baseChecker("http://target.test/payload")
		c.Config.MinResponseBytes = 16 << 10
		c.Config.MinThroughputKBPS = 1
		c.Config.RequireText = []string{"REQUIRED-MARKER"}
		c.requireText = []string{"required-marker"}
		c.effectiveRules = nil
		c.Connector.DialContext = pipeDial(func(conn net.Conn) {
			br := bufio.NewReader(conn)
			_, _ = http.ReadRequest(br)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = http.ReadRequest(br)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body)
		})
		return c
	}
	c := newChecker()
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080})
	if r.Status != model.StatusOK || r.Observations[0].BodyBytes != int64(len(body)) || r.Observations[0].ThroughputKBPS <= 0 {
		t.Fatalf("result=%+v", r)
	}
	c = newChecker()
	c.Config.RejectText = []string{"required-marker"}
	c.rejectText = []string{"required-marker"}
	c.effectiveRules = nil
	r = c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080})
	if r.Status != model.StatusFailed || r.Observations[0].Code != "rejected_content_present" || r.Observations[0].BodyBytes != int64(len(body)) {
		t.Fatalf("result=%+v", r)
	}
}

func TestJSONResponseAssertions(t *testing.T) {
	body := `{"status":"ok","nested":{"value":2}}`
	newChecker := func(expected string) *Checker {
		c := baseChecker("http://target.test/json")
		c.expectJSON = []jsonExpectation{{path: []string{"nested", "value"}, expected: expected}}
		c.effectiveRules = nil
		c.Connector.DialContext = pipeDial(func(conn net.Conn) {
			br := bufio.NewReader(conn)
			_, _ = http.ReadRequest(br)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = http.ReadRequest(br)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body)
		})
		return c
	}
	if result := newChecker("2").Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080}); result.Status != model.StatusOK {
		t.Fatalf("matching assertion failed: %+v", result)
	}
	result := newChecker("3").Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080})
	if result.Status != model.StatusFailed || result.Observations[0].Code != "json_assertion_failed" {
		t.Fatalf("mismatch result=%+v", result)
	}
}

func TestOptInForwardHTTP(t *testing.T) {
	c := baseChecker("http://target.test/path")
	c.Config.AllowRemoteDNS = true
	c.Connector.AllowRemoteDNS = true
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		if req.Method != "GET" || req.URL.Host != "target.test" {
			t.Errorf("not absolute-form: %s %s", req.Method, req.URL.String())
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080})
	if r.Status != model.StatusOK {
		t.Fatalf("%+v", r.Observations)
	}
}

func TestHTTPSConnectAndVerifiedTLS(t *testing.T) {
	cert, roots := testCertificate(t)
	c := baseChecker("https://target.test/")
	c.TLSConfig = &tls.Config{RootCAs: roots}
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != "CONNECT" {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if server.Handshake() != nil {
			return
		}
		r, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		if r.Host != "target.test" {
			t.Errorf("unexpected SNI request host %s", r.Host)
		}
		_, _ = io.WriteString(server, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080})
	if r.Status != model.StatusOK {
		t.Fatalf("%+v", r.Observations)
	}
}

func TestRedirectToUnapprovedHostBlocked(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	o := r.Observations[0]
	if o.Status != model.StatusPolicyBlock || o.Code != "redirect_blocked" {
		t.Fatalf("%+v", o)
	}
}

func TestRedirectWithoutLocationIsRejected(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if observation := r.Observations[0]; observation.Status != model.StatusFailed || observation.Code != "invalid_redirect" {
		t.Fatalf("%+v", observation)
	}
}

func TestConnectTimeoutClassification(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.RequestTimeout = 30 * time.Millisecond
	c.Connector.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if r.Status != model.StatusTimeout {
		t.Fatalf("%+v", r)
	}
}

func TestDestinationDNSClassification(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Policy.Resolver = failingResolver{}
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	o := r.Observations[0]
	if o.Status != model.StatusInconclusive || o.Stage != model.StageResolve || o.Code != "destination_dns" {
		t.Fatalf("%+v", o)
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "target.test"}, DNSNames: []string{"target.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 10)
	for n > 0 {
		b = append(b, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

type countingProcessor struct {
	active, max atomic.Int64
	gate        chan struct{}
}

func (p *countingProcessor) Check(ctx context.Context, x model.Proxy) model.Result {
	n := p.active.Add(1)
	for {
		m := p.max.Load()
		if n <= m || p.max.CompareAndSwap(m, n) {
			break
		}
	}
	select {
	case <-p.gate:
	case <-ctx.Done():
	}
	p.active.Add(-1)
	return model.Result{Status: model.StatusOK}
}
func TestEngineBoundsConcurrencyAndCancellation(t *testing.T) {
	p := &countingProcessor{gate: make(chan struct{})}
	jobs := make(chan model.Proxy, 20)
	for i := 0; i < 20; i++ {
		jobs <- model.Proxy{}
	}
	close(jobs)
	ctx, cancel := context.WithCancel(context.Background())
	out := Engine{Workers: 3, QueueSize: 2, Processor: p}.Run(ctx, jobs)
	time.Sleep(10 * time.Millisecond)
	if p.max.Load() != 3 {
		t.Fatalf("max=%d", p.max.Load())
	}
	cancel()
	for range out {
	}
	if p.active.Load() != 0 {
		t.Fatal("workers did not exit")
	}
}

func TestRateLimiter(t *testing.T) {
	c := NewChecker(config.Defaults())
	c.Config.RateLimit = 100
	start := time.Now()
	for i := 0; i < 3; i++ {
		if !c.waitRate(context.Background()) {
			t.Fatal("unexpected cancellation")
		}
	}
	if time.Since(start) < 18*time.Millisecond {
		t.Fatalf("rate limiter ran too quickly: %s", time.Since(start))
	}
}

func TestCanceledRateWaitDoesNotReserveFutureSlots(t *testing.T) {
	c := NewChecker(config.Defaults())
	c.Config.RateLimit = 1
	if !c.waitRate(context.Background()) {
		t.Fatal("initial token failed")
	}
	reserved := c.nextStart
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 20; i++ {
		if c.waitRate(ctx) {
			t.Fatal("canceled waiter received a token")
		}
	}
	if !c.nextStart.Equal(reserved) {
		t.Fatalf("canceled waiters moved next slot: %s -> %s", reserved, c.nextStart)
	}
}

func TestDestinationResolutionCachedAcrossAttempts(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 4
	var calls atomic.Int64
	c.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, calls: &calls}
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	})
	c.Config.RetryPermanent = true
	_ = c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if calls.Load() != 1 {
		t.Fatalf("DNS calls=%d want 1", calls.Load())
	}
}

func TestDestinationResolutionLeaderCancellationDoesNotFailWaiters(t *testing.T) {
	c := baseChecker("http://target.test/")
	resolver := &blockingResolver{started: make(chan struct{}, 1), release: make(chan struct{})}
	c.Policy.Resolver = resolver
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := c.resolve(leaderCtx, "http://target.test/")
		leaderDone <- err
	}()
	<-resolver.started
	waiterDone := make(chan error, 1)
	go func() {
		destination, err := c.resolve(context.Background(), "http://target.test/")
		if err == nil && destination.IP.String() != "1.1.1.1" {
			err = errors.New("unexpected resolved destination")
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

func TestPermanentFailuresStopEarlyUnlessRequested(t *testing.T) {
	for _, retry := range []bool{false, true} {
		c := baseChecker("http://target.test/")
		c.Config.Repeat = 4
		c.Config.RetryPermanent = retry
		c.Connector.DialContext = pipeDial(func(conn net.Conn) {
			_, _ = http.ReadRequest(bufio.NewReader(conn))
			_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		})
		r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
		want := 1
		if retry {
			want = 3
		}
		if r.Attempts != want || r.Status != model.StatusAuthFailed {
			t.Fatalf("retry=%v attempts=%d status=%s", retry, r.Attempts, r.Status)
		}
	}
}

func TestStopOnSuccess(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 5
	c.Config.StopOnSuccess = true
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if r.Attempts != 3 || r.Successes != 3 || r.RequiredSuccesses != 3 || r.Status != model.StatusOK {
		t.Fatalf("%+v", r)
	}
}

func TestReliabilityThresholdAndEarlyImpossibility(t *testing.T) {
	c := baseChecker("http://target.test/private?token=secret")
	c.Config.Repeat = 5
	c.Config.MinSuccessRate = 0.8
	c.Config.RetryPermanent = true
	var calls atomic.Int64
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = http.ReadRequest(br)
			_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if r.Status != model.StatusUnreliable || r.Successes != 1 || r.RequiredSuccesses != 4 || r.Attempts != 3 {
		t.Fatalf("%+v", r)
	}
	for _, ob := range r.Observations {
		if ob.Target != "http://target.test/" || strings.Contains(ob.Target, "secret") {
			t.Fatalf("unsafe target persisted: %q", ob.Target)
		}
	}
}

func TestTargetMatrixQuorumAndLabels(t *testing.T) {
	cfg := config.Defaults()
	one, two := "http://one.test/health", "http://two.test/health"
	cfg.Targets = []string{one, two}
	cfg.AllowedHosts = []string{"one.test", "two.test"}
	cfg.TargetLabels = map[string]string{one: "primary", two: "secondary"}
	cfg.TargetMatrix = true
	cfg.TargetQuorum = 1
	cfg.Repeat = 2
	cfg.MinSuccessRate = 1
	cfg.RetryBackoff = 0
	cfg.RequestTimeout = time.Second
	checker := NewChecker(cfg)
	checker.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	checker.Connector.DialContext = pipeDial(func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		request, _ := http.ReadRequest(reader)
		status := "204 No Content"
		if request != nil && request.Host == "two.test" {
			status = "503 Service Unavailable"
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\n\r\n")
	})
	result := checker.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if result.Status != model.StatusOK || result.Attempts != 4 || len(result.TargetResults) != 2 {
		t.Fatalf("result=%+v", result)
	}
	if result.TargetResults[0].Target != "primary" || !result.TargetResults[0].Qualified || result.TargetResults[1].Target != "secondary" || result.TargetResults[1].Qualified {
		t.Fatalf("targets=%+v", result.TargetResults)
	}
}

func TestRateLimiterSustainsHighRates(t *testing.T) {
	c := NewChecker(config.Defaults())
	c.Config.RateLimit = 5000
	const permits = 2000
	start := time.Now()
	for range permits {
		if !c.waitRate(context.Background()) {
			t.Fatal("unexpected cancellation")
		}
	}
	elapsed := time.Since(start)
	real := permits / elapsed.Seconds()
	// The floor leaves room for loaded CI runners; the defect this guards against
	// capped the real rate near 900/s.
	if real < 2000 || real > 5500 {
		t.Fatalf("configured 5000/s, measured %.0f/s", real)
	}
}

func TestRateLimiterSharesScheduleAcrossWorkers(t *testing.T) {
	c := NewChecker(config.Defaults())
	c.Config.RateLimit = 200
	var group sync.WaitGroup
	start := time.Now()
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 5 {
				c.waitRate(context.Background())
			}
		}()
	}
	group.Wait()
	if elapsed := time.Since(start); elapsed < 180*time.Millisecond {
		t.Fatalf("40 permits at 200/s finished in %s", elapsed)
	}
}

func TestRateLimiterKeepsScheduleThroughCoarseTimers(t *testing.T) {
	c := NewChecker(config.Defaults())
	c.Config.RateLimit = 1000
	if !c.waitRate(context.Background()) {
		t.Fatal("unexpected cancellation")
	}
	scheduled := c.nextStart
	time.Sleep(rateCatchUp / 2)
	if !c.waitRate(context.Background()) {
		t.Fatal("unexpected cancellation")
	}
	if want := scheduled.Add(time.Millisecond); !c.nextStart.Equal(want) {
		t.Fatalf("overshoot lost the schedule: next=%s want=%s", c.nextStart, want)
	}
	time.Sleep(2 * rateCatchUp)
	before := time.Now()
	if !c.waitRate(context.Background()) {
		t.Fatal("unexpected cancellation")
	}
	if c.nextStart.Before(before) {
		t.Fatal("an idle gap earned burst credit")
	}
}

func TestPlainTextEchoProvidesExitIP(t *testing.T) {
	baseline := netip.MustParseAddr("198.51.100.1")
	for _, test := range []struct {
		body, exit, anonymity string
	}{
		{"203.0.113.9\n", "203.0.113.9", "undetermined"},
		{"  2001:db8::1\r\n", "2001:db8::1", "undetermined"},
		{"198.51.100.1", "198.51.100.1", "transparent"},
		{"<html>not an address</html>", "", "unavailable"},
		{strings.Repeat("1", 200), "", "unavailable"},
		{`{"ip_addr":"203.0.113.9"}`, "203.0.113.9", "undetermined"},
	} {
		exit, anonymity, _ := extractIntelligence([]byte(test.body), baseline)
		if exit != test.exit || anonymity != test.anonymity {
			t.Fatalf("%q: exit=%q anonymity=%q", test.body, exit, anonymity)
		}
	}
}

func TestEliteRequiresEchoedHeaders(t *testing.T) {
	baseline := netip.MustParseAddr("198.51.100.1")
	if _, anonymity, _ := extractIntelligence([]byte(`{"ip":"203.0.113.9"}`), baseline); anonymity != "undetermined" {
		t.Fatalf("address-only body classified as %q", anonymity)
	}
	if _, anonymity, _ := extractIntelligence([]byte(`{"origin":"203.0.113.9","headers":{"Host":"x"}}`), baseline); anonymity != "elite" {
		t.Fatalf("clean header echo classified as %q", anonymity)
	}
	for _, header := range []string{"X-Client-IP", "True-Client-IP", "Proxy-Connection", "CF-Connecting-IP", "X-Proxy-ID"} {
		body := fmt.Sprintf(`{"origin":"203.0.113.9","headers":{%q:"1"}}`, header)
		if _, anonymity, evidence := extractIntelligence([]byte(body), baseline); anonymity != "anonymous" || len(evidence) != 1 {
			t.Fatalf("%s: anonymity=%q evidence=%v", header, anonymity, evidence)
		}
	}
}

func TestCancelledProxyHasNoVerdict(t *testing.T) {
	cfg := config.Defaults()
	cfg.Repeat = 3
	cfg.RetryBackoff = time.Minute
	cfg.Targets = []string{"https://example.com/"}
	c := NewChecker(cfg)
	c.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	ctx, cancel := context.WithCancel(context.Background())
	c.Connector.DialContext = func(context.Context, string, string) (net.Conn, error) {
		time.AfterFunc(10*time.Millisecond, cancel)
		return nil, errors.New("refused")
	}
	result := c.Check(ctx, model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if result.Status != model.StatusInterrupted {
		t.Fatalf("status=%s attempts=%d", result.Status, result.Attempts)
	}
}

func TestPrivateGatewayBlockedByDefault(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := config.Defaults()
	cfg.Repeat = 3
	c := NewChecker(cfg)
	c.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	address := listener.Addr().(*net.TCPAddr)
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "127.0.0.1", Port: uint16(address.Port)})
	if result.Status != model.StatusPolicyBlock || result.Attempts != 1 || result.Observations[0].Code != "proxy_gateway_blocked" {
		t.Fatalf("status=%s attempts=%d observations=%+v", result.Status, result.Attempts, result.Observations)
	}
}

func TestOversizedRemoteDiagnosticIsBounded(t *testing.T) {
	observation := finishError(model.Observation{}, time.Now(), &protocol.Error{Code: "x", Detail: strings.Repeat("y", 8192)})
	if len(observation.Message) > model.MaxMessageBytes {
		t.Fatalf("message has %d bytes", len(observation.Message))
	}
}

func TestCanaryPausesAndWithholdsJudgmentDuringOutage(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 1
	c.Config.CanaryInterval = time.Hour
	var healthy atomic.Bool
	c.canaryProbe = func(context.Context, string) model.TargetHealth {
		if healthy.Load() {
			return model.TargetHealth{Status: "ok"}
		}
		return model.TargetHealth{Status: "failed"}
	}
	c.Config.CanaryInterval = 20 * time.Millisecond
	c.probeTargets(context.Background())
	if !c.targetDown("http://target.test/") {
		t.Fatal("outage not detected")
	}
	failing := func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	c.Connector.DialContext = failing
	started := time.Now()
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if elapsed := time.Since(started); elapsed < 50*time.Millisecond {
		t.Fatalf("worker did not pause: %s", elapsed)
	}
	if result.Status != model.StatusInconclusive || result.Observations[0].Code != "target_unhealthy" {
		t.Fatalf("result=%+v", result)
	}
	report := c.CanaryReport()
	if report.Outages != 1 || report.Reclassified != 1 || report.Failures != 1 || report.Checks != 2 {
		t.Fatalf("report=%+v", report)
	}
	healthy.Store(true)
	c.probeTargets(context.Background())
	if c.targetDown("http://target.test/") {
		t.Fatal("recovery not detected")
	}
	if result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080}); result.Status != model.StatusFailed {
		t.Fatalf("healthy target must not reclassify: %+v", result)
	}
}

func TestCanaryIgnoresSingleFailureAndKeepsAuthResults(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.CanaryInterval = 5 * time.Millisecond
	var calls atomic.Int64
	c.canaryProbe = func(context.Context, string) model.TargetHealth {
		if calls.Add(1) == 1 {
			return model.TargetHealth{Status: "failed"}
		}
		return model.TargetHealth{Status: "ok"}
	}
	c.probeTargets(context.Background())
	if c.targetDown("http://target.test/") {
		t.Fatal("one failed probe paused the run")
	}
	down := map[string]struct{}{"http://target.test/": {}}
	c.canaryDown.Store(&down)
	observation := model.Observation{Status: model.StatusAuthFailed, Code: "proxy_auth_rejected"}
	c.reclassifyDuringOutage(&observation, "http://target.test/")
	if observation.Status != model.StatusAuthFailed {
		t.Fatalf("authentication verdict changed: %+v", observation)
	}
}

func TestRunCanaryStopsWithContext(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.CanaryInterval = 5 * time.Millisecond
	c.canaryProbe = func(context.Context, string) model.TargetHealth { return model.TargetHealth{Status: "ok"} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.RunCanary(ctx)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canary did not stop")
	}
	if c.CanaryReport().Checks == 0 {
		t.Fatal("canary never ran")
	}
	idle := baseChecker("http://target.test/")
	if idle.CanaryReport() != nil {
		t.Fatal("disabled canary produced a report")
	}
}

func TestExpectCountryRejectsOtherExits(t *testing.T) {
	newChecker := func(countries ...string) *Checker {
		c := baseChecker("http://target.test/")
		c.Config.Repeat = 1
		c.Metadata = fixedMetadata{}
		c.expectCountries = map[string]struct{}{}
		for _, country := range countries {
			c.expectCountries[country] = struct{}{}
		}
		c.Connector.DialContext = pipeDial(func(conn net.Conn) {
			reader := bufio.NewReader(conn)
			_, _ = http.ReadRequest(reader)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = http.ReadRequest(reader)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"ip\":\"8.8.8.8\"}")
		})
		return c
	}
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080}
	expected, _ := fixedMetadata{}.Lookup("8.8.8.8")
	if result := newChecker(expected.CountryCode).Check(context.Background(), proxy); result.Status != model.StatusOK {
		t.Fatalf("result=%+v", result)
	}
	result := newChecker("ZZ").Check(context.Background(), proxy)
	if result.Status != model.StatusFailed || result.Observations[0].Code != "country_mismatch" {
		t.Fatalf("result=%+v", result)
	}
}

func TestExitFamilyCapabilities(t *testing.T) {
	capabilities := observedCapabilities([]model.Observation{{ExitIP: "203.0.113.9"}, {ExitIP: "2001:db8::1"}, {ExitIP: ""}})
	if capabilities == nil || !capabilities.ExitIPv4 || !capabilities.ExitIPv6 {
		t.Fatalf("capabilities=%+v", capabilities)
	}
	if observedCapabilities([]model.Observation{{}}) != nil {
		t.Fatal("no evidence must mean no capabilities")
	}
}

func TestThroughputSurvivesCoarseClocks(t *testing.T) {
	if got := throughputKBPS(20_000, 0); got != 20_000 {
		t.Fatalf("zero duration: %v", got)
	}
	if got := throughputKBPS(20_000, 2*time.Second); got != 10 {
		t.Fatalf("measured duration: %v", got)
	}
	if got := throughputKBPS(0, 0); got != 0 {
		t.Fatalf("empty body: %v", got)
	}
}

func TestLocalExhaustionPausesNewAttempts(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 2
	c.Config.MinSuccessRate = 0.5
	c.Config.RetryBackoff = 0
	var times []time.Time
	c.Connector.DialContext = func(context.Context, string, string) (net.Conn, error) {
		times = append(times, time.Now())
		return nil, syscall.EMFILE
	}
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if result.Status != model.StatusInconclusive || len(times) != 2 {
		t.Fatalf("status=%s dials=%d", result.Status, len(times))
	}
	if gap := times[1].Sub(times[0]); gap < localBackoff-20*time.Millisecond {
		t.Fatalf("attempts only %s apart", gap)
	}
	if c.localPauses.Load() != 2 {
		t.Fatalf("pauses=%d", c.localPauses.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.noteLocalExhaustion(model.Observation{Code: "local_resource_exhausted"})
	if c.waitTurn(ctx) {
		t.Fatal("cancelled wait succeeded")
	}
}

func TestRedirectsShareOneDNSLookupPerOrigin(t *testing.T) {
	c := baseChecker("http://target.test/start")
	c.Config.Repeat = 1
	c.Config.MaxRedirects = 3
	var calls atomic.Int64
	c.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, calls: &calls}
	var served atomic.Int64
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(reader)
		if step := served.Add(1); step < 3 {
			fmt.Fprintf(conn, "HTTP/1.1 302 Found\r\nLocation: /next/%d?token=x\r\nContent-Length: 0\r\n\r\n", step)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if result.Status != model.StatusOK {
		t.Fatalf("result=%+v", result)
	}
	if calls.Load() > 2 {
		t.Fatalf("%d lookups for one origin", calls.Load())
	}
	c.resolveMu.Lock()
	entries := len(c.resolved)
	c.resolveMu.Unlock()
	if entries > 2 {
		t.Fatalf("redirect paths grew the cache to %d entries", entries)
	}
}

func TestRedirectWithCredentialsStaysBlocked(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 1
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 302 Found\r\nLocation: http://user:pw@target.test/\r\nContent-Length: 0\r\n\r\n")
	})
	result := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if result.Status != model.StatusPolicyBlock || result.Observations[0].Code != "redirect_blocked" {
		t.Fatalf("result=%+v", result)
	}
}

func TestJSONPathSupportsArrayIndexes(t *testing.T) {
	var document any
	if err := json.Unmarshal([]byte(`{"items":[{"id":7},{"id":8}],"name":"x"}`), &document); err != nil {
		t.Fatal(err)
	}
	if value, ok := jsonPath(document, []string{"items", "1", "id"}); !ok || fmt.Sprint(value) != "8" {
		t.Fatalf("value=%v ok=%v", value, ok)
	}
	for _, path := range [][]string{{"items", "2"}, {"items", "-1"}, {"items", "first"}, {"name", "0"}, {"missing"}} {
		if _, ok := jsonPath(document, path); ok {
			t.Fatalf("path %v matched", path)
		}
	}
}

func TestCertificatePinDetectsInterception(t *testing.T) {
	certificate, pool := testCertificate(t)
	run := func(pins ...string) model.Result {
		c := baseChecker("https://target.test/")
		c.Config.Repeat = 1
		c.TLSConfig = &tls.Config{RootCAs: pool}
		if len(pins) > 0 {
			c.certificatePins = map[string]struct{}{}
			for _, pin := range pins {
				c.certificatePins[pin] = struct{}{}
			}
		}
		c.Connector.DialContext = pipeDial(func(conn net.Conn) {
			reader := bufio.NewReader(conn)
			_, _ = http.ReadRequest(reader)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
			if server.Handshake() != nil {
				return
			}
			_, _ = http.ReadRequest(bufio.NewReader(server))
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			_ = server.Close()
		})
		return c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	}
	baseline := run()
	if baseline.Status != model.StatusOK {
		t.Fatalf("result=%+v", baseline)
	}
	fingerprint := baseline.Observations[0].DestinationTLS.PeerCertificateSHA
	if result := run(strings.Repeat("0", 64), fingerprint); result.Status != model.StatusOK {
		t.Fatalf("a rotated pin set must accept any listed certificate: %+v", result)
	}
	result := run(strings.Repeat("0", 64))
	observation := result.Observations[0]
	if result.Status != model.StatusFailed || observation.Code != "certificate_pin_mismatch" || observation.Stage != model.StageTLS || observation.DestinationTLS == nil {
		t.Fatalf("result=%+v", result)
	}
}

func TestHTTPSRedirectToHTTPIsRefused(t *testing.T) {
	certificate, pool := testCertificate(t)
	run := func(allow bool) model.Result {
		c := baseChecker("https://target.test/")
		c.Config.Repeat = 1
		c.Config.AllowDowngrade = allow
		c.TLSConfig = &tls.Config{RootCAs: pool}
		var step atomic.Int64
		c.Connector.DialContext = pipeDial(func(conn net.Conn) {
			reader := bufio.NewReader(conn)
			_, _ = http.ReadRequest(reader)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			if step.Add(1) == 1 {
				server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
				if server.Handshake() != nil {
					return
				}
				_, _ = http.ReadRequest(bufio.NewReader(server))
				_, _ = io.WriteString(server, "HTTP/1.1 302 Found\r\nLocation: http://target.test/plain\r\nContent-Length: 0\r\n\r\n")
				_ = server.Close()
				return
			}
			_, _ = http.ReadRequest(reader)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		})
		return c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	}
	refused := run(false)
	if refused.Status != model.StatusPolicyBlock || refused.Observations[0].Code != "redirect_downgrade" {
		t.Fatalf("result=%+v", refused)
	}
	if allowed := run(true); allowed.Status != model.StatusOK {
		t.Fatalf("explicit exception ignored: %+v", allowed)
	}
}
