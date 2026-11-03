package protocol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/drag-team/netvex-go/internal/model"
	"github.com/drag-team/netvex-go/internal/policy"
)

type memoryConn struct{ *bytes.Reader }

func (c *memoryConn) Write(data []byte) (int, error) { return len(data), nil }
func (c *memoryConn) Close() error                   { return nil }
func (c *memoryConn) LocalAddr() net.Addr            { return memoryAddr("local") }
func (c *memoryConn) RemoteAddr() net.Addr           { return memoryAddr("remote") }
func (c *memoryConn) SetDeadline(time.Time) error    { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *memoryConn) SetWriteDeadline(time.Time) error {
	return nil
}

type chunkWriter struct {
	buffer bytes.Buffer
	limit  int
	zero   bool
}

func (w *chunkWriter) Write(value []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	if len(value) > w.limit {
		value = value[:w.limit]
	}
	return w.buffer.Write(value)
}

type countingCloseConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countingCloseConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type memoryAddr string

func (a memoryAddr) Network() string { return "memory" }
func (a memoryAddr) String() string  { return string(a) }

func destination() policy.Destination {
	u, _ := url.Parse("https://target.test/")
	return policy.Destination{URL: u, Host: "target.test", Port: "443", IP: netip.MustParseAddr("1.1.1.1")}
}

func TestFullWritesHandleShortWriters(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(io.Writer) error
	}{
		{name: "bytes", run: func(w io.Writer) error { return writeFull(w, []byte("complete handshake")) }},
		{name: "string", run: func(w io.Writer) error { return writeStringFull(w, "complete handshake") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := &chunkWriter{limit: 3}
			if err := test.run(writer); err != nil || writer.buffer.String() != "complete handshake" {
				t.Fatalf("value=%q err=%v", writer.buffer.String(), err)
			}
			writer = &chunkWriter{limit: 3, zero: true}
			if err := test.run(writer); !errors.Is(err, io.ErrNoProgress) {
				t.Fatalf("zero-progress error=%v", err)
			}
		})
	}
}

func TestSOCKS5RejectsMalformedReplyFields(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		code string
	}{
		{name: "reserved", data: []byte{5, 0, 5, 0, 1, 1}, code: "socks5_bad_reserved"},
		{name: "empty domain", data: []byte{5, 0, 5, 0, 0, 3, 0}, code: "socks5_bad_address"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &memoryConn{Reader: bytes.NewReader(test.data)}
			_, err := socks5Connect(conn, model.Proxy{Protocol: model.ProtocolSOCKS5}, destination(), false)
			var protocolErr *Error
			if !errors.As(err, &protocolErr) || protocolErr.Code != test.code {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestSOCKS5ReplyClassification(t *testing.T) {
	for reply := byte(1); reply <= 9; reply++ {
		data := []byte{5, 0, 5, reply, 0, 1}
		conn := &memoryConn{Reader: bytes.NewReader(data)}
		_, err := socks5Connect(conn, model.Proxy{Protocol: model.ProtocolSOCKS5}, destination(), false)
		var protocolErr *Error
		if !errors.As(err, &protocolErr) {
			t.Fatalf("reply=%d err=%v", reply, err)
		}
		want := model.StatusFailed
		if reply >= 3 && reply <= 6 {
			want = model.StatusInconclusive
		}
		if protocolErr.Status != want {
			t.Fatalf("reply=%d status=%s want=%s", reply, protocolErr.Status, want)
		}
	}
}

func pipeConnector(handler func(net.Conn)) Connector {
	return Connector{ConnectTimeout: time.Second, AllowRemoteDNS: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { defer server.Close(); handler(server) }()
		return client, nil
	}}
}

func echo(c net.Conn) {
	b := make([]byte, 32)
	for {
		n, err := c.Read(b)
		if n > 0 {
			_, _ = c.Write(b[:n])
		}
		if err != nil {
			return
		}
	}
}

func httpScript(c net.Conn) {
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	echo(c)
}

func socks4Script(c net.Conn) {
	br := bufio.NewReader(c)
	h := make([]byte, 8)
	if _, err := io.ReadFull(br, h); err != nil {
		return
	}
	for {
		b, err := br.ReadByte()
		if err != nil {
			return
		}
		if b == 0 {
			break
		}
	}
	if h[4] == 0 && h[5] == 0 && h[6] == 0 {
		for {
			b, err := br.ReadByte()
			if err != nil {
				return
			}
			if b == 0 {
				break
			}
		}
	}
	_, _ = c.Write([]byte{0, 90, h[2], h[3], h[4], h[5], h[6], h[7]})
	echo(c)
}

func socks5Script(user, pass string) func(net.Conn) {
	return func(c net.Conn) {
		br := bufio.NewReader(c)
		h := make([]byte, 2)
		if _, err := io.ReadFull(br, h); err != nil {
			return
		}
		methods := make([]byte, int(h[1]))
		_, _ = io.ReadFull(br, methods)
		method := byte(0)
		if user != "" {
			method = 2
		}
		offered := false
		for _, m := range methods {
			if m == method {
				offered = true
			}
		}
		if !offered {
			_, _ = c.Write([]byte{5, 0xff})
			return
		}
		_, _ = c.Write([]byte{5, method})
		if method == 2 {
			v, _ := br.ReadByte()
			ul, _ := br.ReadByte()
			ub := make([]byte, int(ul))
			_, _ = io.ReadFull(br, ub)
			pl, _ := br.ReadByte()
			pb := make([]byte, int(pl))
			_, _ = io.ReadFull(br, pb)
			status := byte(0)
			if v != 1 || string(ub) != user || string(pb) != pass {
				status = 1
			}
			_, _ = c.Write([]byte{1, status})
			if status != 0 {
				return
			}
		}
		req := make([]byte, 4)
		if _, err := io.ReadFull(br, req); err != nil {
			return
		}
		n := 0
		switch req[3] {
		case 1:
			n = 4
		case 4:
			n = 16
		case 3:
			b, _ := br.ReadByte()
			n = int(b)
		}
		tail := make([]byte, n+2)
		_, _ = io.ReadFull(br, tail)
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		echo(c)
	}
}

func TestConnectorsRelay(t *testing.T) {
	tests := []struct {
		name   string
		proto  model.Protocol
		script func(net.Conn)
	}{{"http", model.ProtocolHTTP, httpScript}, {"socks4", model.ProtocolSOCKS4, socks4Script}, {"socks4a", model.ProtocolSOCKS4A, socks4Script}, {"socks5", model.ProtocolSOCKS5, socks5Script("", "")}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			con := pipeConnector(tc.script)
			p := model.Proxy{Protocol: tc.proto, Host: "proxy.test", Port: 1080}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := con.Open(ctx, p, destination())
			if err != nil {
				t.Fatal(err)
			}
			if got.AuthMethod != "none" {
				t.Fatalf("auth method=%q", got.AuthMethod)
			}
			defer got.Conn.Close()
			_, _ = got.Conn.Write([]byte("ping"))
			b := make([]byte, 4)
			if _, err := io.ReadFull(got.Conn, b); err != nil || string(b) != "ping" {
				t.Fatalf("relay %q: %v", b, err)
			}
		})
	}
}

func TestHTTPSProxyTransportAndCertificateValidation(t *testing.T) {
	cert, roots := proxyCertificate(t)
	script := func(conn net.Conn) {
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if secure.Handshake() != nil {
			return
		}
		httpScript(secure)
	}
	connector := pipeConnector(script)
	connector.TLSConfig = &tls.Config{RootCAs: roots}
	p := model.Proxy{Protocol: model.ProtocolHTTPS, Host: "proxy.test", Port: 8443}
	got, err := connector.Open(context.Background(), p, destination())
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthMethod != "none" {
		t.Fatalf("auth method=%q", got.AuthMethod)
	}
	defer got.Conn.Close()
	if _, err := got.Conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(got.Conn, b); err != nil || string(b) != "ping" {
		t.Fatalf("relay=%q err=%v", b, err)
	}

	untrusted := pipeConnector(script)
	_, err = untrusted.Open(context.Background(), p, destination())
	var pe *Error
	if !errors.As(err, &pe) || pe.Stage != model.StageProxyTLS || pe.Code != "proxy_tls_handshake" {
		t.Fatalf("unexpected certificate error: %v", err)
	}
}

func proxyCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proxy.test"}, DNSNames: []string{"proxy.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return cert, roots
}

func TestSOCKS5Authentication(t *testing.T) {
	p := model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy.test", Port: 1080}
	if _, err := pipeConnector(socks5Script("user", "secret")).Open(context.Background(), p, destination()); err == nil {
		t.Fatal("expected missing credentials failure")
	} else if pe, ok := err.(*Error); !ok || pe.Status != model.StatusAuthFailed {
		t.Fatalf("wrong classification: %v", err)
	}
	p.Credentials = &model.Credentials{Username: "user", Password: "wrong"}
	if _, err := pipeConnector(socks5Script("user", "secret")).Open(context.Background(), p, destination()); err == nil {
		t.Fatal("expected bad credentials failure")
	} else if pe, ok := err.(*Error); !ok || pe.Status != model.StatusAuthFailed {
		t.Fatalf("wrong classification: %v", err)
	}
	p.Credentials.Password = "secret"
	got, err := pipeConnector(socks5Script("user", "secret")).Open(context.Background(), p, destination())
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthMethod != "username_password" {
		t.Fatalf("auth method=%q", got.AuthMethod)
	}
	got.Conn.Close()
}

func TestHTTPAuthenticationFailure(t *testing.T) {
	script := func(c net.Conn) {
		req, _ := http.ReadRequest(bufio.NewReader(c))
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
		if req.Header.Get("Proxy-Authorization") != want {
			_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	}
	p := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080}
	_, err := pipeConnector(script).Open(context.Background(), p, destination())
	if err == nil {
		t.Fatal("expected auth failure")
	}
	p.Credentials = &model.Credentials{Username: "u", Password: "p"}
	got, err := pipeConnector(script).Open(context.Background(), p, destination())
	if err != nil {
		t.Fatal(err)
	}
	got.Conn.Close()
}

func TestHTTPAuthenticationClassification(t *testing.T) {
	response := func(challenge string) *http.Response {
		h := make(http.Header)
		if challenge != "" {
			h.Add("Proxy-Authenticate", challenge)
		}
		return &http.Response{StatusCode: http.StatusProxyAuthRequired, Header: h}
	}
	tests := []struct {
		name      string
		supplied  bool
		challenge string
		code      string
	}{
		{"missing", false, "Basic realm=provider", "proxy_auth_required"},
		{"rejected", true, "Basic realm=provider", "proxy_auth_rejected"},
		{"mixed", true, `Digest realm="provider,a", nonce=x, Basic realm=provider`, "proxy_auth_rejected"},
		{"unsupported", true, "Digest realm=provider", "proxy_auth_unsupported"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var pe *Error
			if !errors.As(HTTPProxyAuthError(response(tc.challenge), tc.supplied), &pe) || pe.Code != tc.code {
				t.Fatalf("got %+v", pe)
			}
			if strings.Contains(pe.Detail, "realm") {
				t.Fatalf("challenge details leaked: %q", pe.Detail)
			}
		})
	}
}

func TestSOCKS4ARemoteDNSBlockedByDefault(t *testing.T) {
	c := pipeConnector(socks4Script)
	c.AllowRemoteDNS = false
	p := model.Proxy{Protocol: model.ProtocolSOCKS4A, Host: "proxy", Port: 1080}
	_, err := c.Open(context.Background(), p, destination())
	pe, ok := err.(*Error)
	if !ok || pe.Code != "remote_dns_disabled" {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCancellationInterruptsHandshake(t *testing.T) {
	c := pipeConnector(func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Open(ctx, model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy", Port: 1080}, destination())
		done <- err
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cancellation did not interrupt handshake")
	}
}

func TestNormalCloseUnregistersCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	base := &countingCloseConn{Conn: &memoryConn{Reader: bytes.NewReader(nil)}}
	conn := watchContext(ctx, base)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if got := base.closes.Load(); got != 1 {
		t.Fatalf("underlying close count=%d want=1", got)
	}
}

func BenchmarkWatchContextClose(b *testing.B) {
	base := &memoryConn{Reader: bytes.NewReader(nil)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.ReportAllocs()
	for range b.N {
		_ = watchContext(ctx, base).Close()
	}
}

func TestMalformedAndRejectedReplies(t *testing.T) {
	p := model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy", Port: 1080}
	bad := pipeConnector(func(c net.Conn) { b := make([]byte, 3); _, _ = io.ReadFull(c, b); _, _ = c.Write([]byte{4, 0}) })
	_, err := bad.Open(context.Background(), p, destination())
	pe, ok := err.(*Error)
	if !ok || pe.Code != "socks5_bad_version" {
		t.Fatalf("unexpected %v", err)
	}
	p.Protocol = model.ProtocolHTTP
	rejected := pipeConnector(func(c net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(c))
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	})
	_, err = rejected.Open(context.Background(), p, destination())
	pe, ok = err.(*Error)
	if !ok || pe.Code != "connect_upstream_error" || pe.Status != model.StatusInconclusive {
		t.Fatalf("unexpected %v", err)
	}
}

func TestConnectPreservesPrefetchedTunnelBytes(t *testing.T) {
	script := func(c net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(c))
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\nprefetch")
	}
	p := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80}
	got, err := pipeConnector(script).Open(context.Background(), p, destination())
	if err != nil {
		t.Fatal(err)
	}
	defer got.Conn.Close()
	b := make([]byte, 8)
	if _, err := io.ReadFull(got.Conn, b); err != nil || string(b) != "prefetch" {
		t.Fatalf("got=%q err=%v", b, err)
	}
}

func TestConnectRejectsOversizedHeaders(t *testing.T) {
	script := func(c net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(c))
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("x", 70<<10)+"\r\n\r\n")
	}
	p := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80}
	_, err := pipeConnector(script).Open(context.Background(), p, destination())
	pe, ok := err.(*Error)
	if !ok || pe.Code != "invalid_connect_response" {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestProxyDNSClassification(t *testing.T) {
	c := Connector{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "not found", Name: "proxy.invalid"}
	}}
	_, err := c.Open(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.invalid", Port: 80}, destination())
	pe, ok := err.(*Error)
	if !ok || pe.Code != "proxy_dns" {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestNetworkErrorClassification(t *testing.T) {
	tests := []struct {
		err    error
		status model.Status
		code   string
	}{
		{context.Canceled, model.StatusInterrupted, "interrupted"},
		{syscall.ECONNREFUSED, model.StatusFailed, "connection_refused"},
		{syscall.ECONNRESET, model.StatusFailed, "connection_reset"},
		{syscall.EPIPE, model.StatusFailed, "broken_pipe"},
		{syscall.ENETUNREACH, model.StatusFailed, "network_unreachable"},
		{syscall.EHOSTUNREACH, model.StatusFailed, "host_unreachable"},
		{syscall.ETIMEDOUT, model.StatusTimeout, "network_timeout"},
		{net.ErrClosed, model.StatusFailed, "connection_closed"},
		{io.ErrUnexpectedEOF, model.StatusFailed, "unexpected_eof"},
	}
	for _, tc := range tests {
		var pe *Error
		if !errors.As(classifyNet(model.StageConnect, "proxy_connect", tc.err), &pe) || pe.Status != tc.status || pe.Code != tc.code {
			t.Fatalf("err=%v got=%+v", tc.err, pe)
		}
	}
}

func TestHTTPConnectAuthorityMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote bool
		want   string
	}{{"pinned", false, "1.1.1.1:443"}, {"proxy_dns", true, "target.test:443"}} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 1)
			script := func(c net.Conn) {
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				seen <- req.Host
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
			}
			connector := pipeConnector(script)
			connector.AllowRemoteDNS = tc.remote
			p := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80}
			got, err := connector.Open(context.Background(), p, destination())
			if err != nil {
				t.Fatal(err)
			}
			got.Conn.Close()
			if authority := <-seen; authority != tc.want {
				t.Fatalf("got %q want %q", authority, tc.want)
			}
		})
	}
}

func TestSOCKS5DestinationAddressMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote bool
		atyp   byte
		value  string
	}{{"pinned", false, 1, "1.1.1.1"}, {"proxy_dns", true, 3, "target.test"}} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 1)
			script := func(c net.Conn) {
				br := bufio.NewReader(c)
				greeting := make([]byte, 3)
				_, _ = io.ReadFull(br, greeting)
				_, _ = c.Write([]byte{5, 0})
				head := make([]byte, 4)
				_, _ = io.ReadFull(br, head)
				if head[3] != tc.atyp {
					seen <- "wrong-atyp"
					return
				}
				var host string
				if head[3] == 1 {
					b := make([]byte, 4)
					_, _ = io.ReadFull(br, b)
					host = net.IP(b).String()
				} else {
					n, _ := br.ReadByte()
					b := make([]byte, int(n))
					_, _ = io.ReadFull(br, b)
					host = string(b)
				}
				port := make([]byte, 2)
				_, _ = io.ReadFull(br, port)
				seen <- host
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
			}
			connector := pipeConnector(script)
			connector.AllowRemoteDNS = tc.remote
			got, err := connector.Open(context.Background(), model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy", Port: 1080}, destination())
			if err != nil {
				t.Fatal(err)
			}
			_ = got.Conn.Close()
			if value := <-seen; value != tc.value {
				t.Fatalf("got %q want %q", value, tc.value)
			}
		})
	}
}

func FuzzReadResponseLimited(f *testing.F) {
	for _, data := range [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
		[]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
		[]byte("not http"),
		bytes.Repeat([]byte("x"), 5000),
	} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		conn := &memoryConn{Reader: bytes.NewReader(data)}
		response, _, err := ReadResponseLimited(conn, &http.Request{Method: http.MethodGet}, 4096)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
	})
}

func TestReadResponseLimitedRejectsLFOnlyHeaders(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK\nContent-Length: 2\n\nok")
	conn := &memoryConn{Reader: bytes.NewReader(data)}
	if response, _, err := ReadResponseLimited(conn, &http.Request{Method: http.MethodGet}, 4096); err == nil {
		_ = response.Body.Close()
		t.Fatal("accepted LF-only response headers")
	}
}

func BenchmarkReadResponseLimited(b *testing.B) {
	payload := []byte("HTTP/1.1 200 OK\r\nServer: netvex-fixture\r\nContent-Type: application/json\r\nContent-Length: 15\r\nX-Request-ID: benchmark\r\n\r\n{\"status\":\"ok\"}")
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	request := &http.Request{Method: http.MethodGet}
	for range b.N {
		conn := &memoryConn{Reader: bytes.NewReader(payload)}
		response, _, err := ReadResponseLimited(conn, request, 64<<10)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
}

func TestProxyAuthDiagnosticIsBounded(t *testing.T) {
	challenges := []string{}
	for index := range 40 {
		challenges = append(challenges, fmt.Sprintf("%s%d realm=x", strings.Repeat("a", 4000), index))
	}
	response := &http.Response{Header: http.Header{"Proxy-Authenticate": challenges}}
	err := HTTPProxyAuthError(response, true)
	if len(err.Error()) > 512 {
		t.Fatalf("diagnostic has %d bytes", len(err.Error()))
	}
}

func TestLocalResourceExhaustionIsNotAProxyFailure(t *testing.T) {
	for _, cause := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.EADDRNOTAVAIL} {
		var classified *Error
		if !errors.As(classifyNet(model.StageConnect, "proxy_connect", fmt.Errorf("dial: %w", cause)), &classified) {
			t.Fatal("unclassified error")
		}
		if classified.Status != model.StatusInconclusive || classified.Code != "local_resource_exhausted" {
			t.Fatalf("%v classified as %+v", cause, classified)
		}
	}
}

func TestGatewayGuardChecksConnectedAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "10.0.0.1:80", "169.254.169.254:80", "[::1]:1080", "[fe80::1]:80", "100.64.0.1:3128", "[::ffff:192.168.0.1]:80"} {
		if err := GatewayGuard(context.Background(), "tcp4", address, nil); !errors.Is(err, policy.ErrGatewayBlocked) {
			t.Fatalf("%s: %v", address, err)
		}
	}
	if err := GatewayGuard(context.Background(), "tcp4", "8.8.8.8:8080", nil); err != nil {
		t.Fatal(err)
	}
	if err := GatewayGuard(context.Background(), "tcp4", "not-an-address", nil); err == nil {
		t.Fatal("unparseable address accepted")
	}
	var classified *Error
	if !errors.As(classifyNet(model.StageConnect, "proxy_connect", fmt.Errorf("dial: %w", policy.ErrGatewayBlocked)), &classified) || classified.Status != model.StatusPolicyBlock || classified.Stage != model.StagePolicy {
		t.Fatalf("classified=%+v", classified)
	}
}

func TestSniffClassifiesReplies(t *testing.T) {
	for _, test := range []struct {
		reply []byte
		want  model.Protocol
	}{
		{[]byte{5, 0}, model.ProtocolSOCKS5},
		{[]byte{5, 2}, model.ProtocolSOCKS5},
		{[]byte{5, 0xff}, model.ProtocolSOCKS5},
		{[]byte("HTTP/1.1 400 Bad Request\r\n\r\n"), model.ProtocolHTTP},
		{[]byte{0x15, 3, 3, 0, 2, 2, 50}, model.ProtocolHTTPS},
		{[]byte{0, 91, 0, 0, 0, 0, 0, 0}, model.ProtocolSOCKS4},
		{[]byte{0xde, 0xad}, ""},
		{[]byte{5}, ""},
		{nil, ""},
	} {
		client, server := net.Pipe()
		go func() {
			probe := make([]byte, len(sniffProbe))
			_, _ = io.ReadFull(server, probe)
			_, _ = server.Write(test.reply)
			_ = server.Close()
		}()
		if got := Sniff(client, time.Second); got != test.want {
			t.Fatalf("reply %x: got %q want %q", test.reply, got, test.want)
		}
		_ = client.Close()
	}
}

func TestSniffHonorsTimeoutOnSilentServers(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	started := time.Now()
	if got := Sniff(client, 50*time.Millisecond); got != "" {
		t.Fatalf("got=%q", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("sniff ignored its timeout: %s", elapsed)
	}
}

func TestOpenDialedConsumesPreparedConnectionOnce(t *testing.T) {
	var dials atomic.Int64
	script := func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}
	connector := pipeConnector(script)
	base := connector.DialContext
	connector.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return base(ctx, network, address)
	}
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080}
	dialed, err := connector.Dial(context.Background(), proxy)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := connector.OpenDialed(context.Background(), proxy, destination(), &dialed)
	if err != nil {
		t.Fatal(err)
	}
	_ = opened.Conn.Close()
	if dialed.Conn != nil || dials.Load() != 1 {
		t.Fatalf("prepared connection not consumed: dials=%d", dials.Load())
	}
	opened, err = connector.OpenDialed(context.Background(), proxy, destination(), &dialed)
	if err != nil {
		t.Fatal(err)
	}
	_ = opened.Conn.Close()
	if dials.Load() != 2 {
		t.Fatalf("spent connection reused: dials=%d", dials.Load())
	}
	(&Dialed{}).Close()
	(*Dialed)(nil).Close()
}

func FuzzSOCKS5Reply(f *testing.F) {
	f.Add([]byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{5, 2, 1, 0, 5, 0, 0, 3, 4, 'h', 'o', 's', 't', 0, 80})
	f.Add([]byte{5, 0, 5, 1, 0, 1})
	f.Add([]byte{5, 0, 5, 0, 0, 3, 0})
	f.Add([]byte{})
	proxy := model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy", Port: 1080, Credentials: &model.Credentials{Username: "u", Password: "p"}}
	f.Fuzz(func(t *testing.T, reply []byte) {
		client, server := net.Pipe()
		defer client.Close()
		go func() {
			defer server.Close()
			go func() { _, _ = io.Copy(io.Discard, server) }()
			_, _ = server.Write(reply)
		}()
		_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
		method, err := socks5Connect(client, proxy, destination(), false)
		if err == nil && method != "none" && method != "username_password" {
			t.Fatalf("unknown method %q", method)
		}
	})
}

func FuzzSOCKS4Reply(f *testing.F) {
	f.Add([]byte{0, 90, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{4, 91, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0})
	proxy := model.Proxy{Protocol: model.ProtocolSOCKS4, Host: "proxy", Port: 1080}
	f.Fuzz(func(t *testing.T, reply []byte) {
		client, server := net.Pipe()
		defer client.Close()
		go func() {
			defer server.Close()
			go func() { _, _ = io.Copy(io.Discard, server) }()
			_, _ = server.Write(reply)
		}()
		_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
		err := socks4Connect(client, proxy, destination(), false)
		if err == nil && (len(reply) < 8 || reply[1] != 90) {
			t.Fatalf("accepted reply %x", reply)
		}
	})
}

func FuzzProxyAuthChallenge(f *testing.F) {
	f.Add(`Basic realm="x"`)
	f.Add(`Negotiate, NTLM, Digest realm="a,b", qop="auth"`)
	f.Add(`"unterminated`)
	f.Fuzz(func(t *testing.T, challenge string) {
		err := HTTPProxyAuthError(&http.Response{Header: http.Header{"Proxy-Authenticate": {challenge}}}, true)
		if len(err.Error()) > 4096 {
			t.Fatalf("unbounded diagnostic: %d bytes", len(err.Error()))
		}
	})
}

func TestProbeUDPClassifiesReplies(t *testing.T) {
	proxy := model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy", Port: 1080}
	for _, test := range []struct {
		reply byte
		want  string
	}{{0, UDPSupported}, {7, UDPUnsupported}, {2, UDPUnsupported}, {1, UDPUnavailable}} {
		connector := pipeConnector(func(conn net.Conn) {
			greeting := make([]byte, 3)
			_, _ = io.ReadFull(conn, greeting)
			_, _ = conn.Write([]byte{5, 0})
			request := make([]byte, 10)
			_, _ = io.ReadFull(conn, request)
			if request[1] != 3 {
				return
			}
			_, _ = conn.Write([]byte{5, test.reply, 0, 1, 0, 0, 0, 0, 0, 0})
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if got := connector.ProbeUDP(ctx, proxy); got != test.want {
			t.Fatalf("reply %d: got %q want %q", test.reply, got, test.want)
		}
		cancel()
	}
	refused := Connector{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }}
	if got := refused.ProbeUDP(context.Background(), proxy); got != UDPUnavailable {
		t.Fatalf("got %q", got)
	}
}
