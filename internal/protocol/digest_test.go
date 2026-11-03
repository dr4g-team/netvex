package protocol

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/drag-team/netvex-go/internal/model"
)

func TestDigestMatchesRFC7616Vectors(t *testing.T) {
	credentials := &model.Credentials{Username: "Mufasa", Password: "Circle of Life"}
	for algorithm, want := range map[string]string{
		"MD5":     "8ca523f5e9506fed4657c9700eebdbec",
		"SHA-256": "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
	} {
		challenge := &digestChallenge{realm: "http-auth@example.org", nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", algorithm: algorithm, qopAuth: true}
		header := challenge.answerWith(credentials, http.MethodGet, "/dir/index.html", "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ")
		if !strings.Contains(header, `response="`+want+`"`) {
			t.Fatalf("%s: %s", algorithm, header)
		}
	}
}

func TestParseDigestChallenge(t *testing.T) {
	parsed := parseDigestChallenge([]string{`Negotiate, Digest realm="a,b", nonce="n1", qop="auth,auth-int", opaque="o", algorithm=MD5, NTLM`})
	if parsed == nil || parsed.realm != "a,b" || parsed.nonce != "n1" || parsed.opaque != "o" || !parsed.qopAuth {
		t.Fatalf("parsed=%+v", parsed)
	}
	strongest := parseDigestChallenge([]string{`Digest realm="r", nonce="md5", algorithm=MD5`, `Digest realm="r", nonce="sha", algorithm=SHA-256`})
	if strongest == nil || strongest.nonce != "sha" {
		t.Fatalf("strongest=%+v", strongest)
	}
	if legacy := parseDigestChallenge([]string{`Digest realm="r", nonce="n"`}); legacy == nil || !legacy.noQop || legacy.algorithm != "MD5" {
		t.Fatalf("legacy=%+v", legacy)
	}
	for _, rejected := range []string{
		`Basic realm="r"`,
		`Digest realm="r"`,
		`Digest realm="r", nonce="n", algorithm=SHA-512`,
		`Digest realm="r", nonce="n", qop="auth-int"`,
		"Digest realm=\"r\", nonce=\"bad\rvalue\"",
		`Digest realm="r", nonce="` + strings.Repeat("n", maxDigestParameterBytes+1) + `"`,
	} {
		if parsed := parseDigestChallenge([]string{rejected}); parsed != nil {
			t.Fatalf("%q accepted: %+v", rejected, parsed)
		}
	}
}

func TestDigestAnswerEscapesAndCarriesOpaque(t *testing.T) {
	challenge := &digestChallenge{realm: `re"alm`, nonce: "n", opaque: "o", algorithm: "SHA-256-SESS", noQop: true}
	header := challenge.answerWith(&model.Credentials{Username: `us"er`, Password: "p"}, http.MethodConnect, "1.2.3.4:443", "c")
	for _, want := range []string{`username="us\"er"`, `realm="re\"alm"`, `opaque="o"`, "algorithm=SHA-256-SESS"} {
		if !strings.Contains(header, want) {
			t.Fatalf("%q missing from %s", want, header)
		}
	}
	if strings.Contains(header, "qop=") {
		t.Fatalf("qop sent to a legacy challenge: %s", header)
	}
	if _, err := challenge.answer(nil, http.MethodConnect, "x"); err == nil {
		t.Fatal("answer without credentials")
	}
}

// digestProxy answers like a real proxy: it challenges, closes, and only accepts a
// response it computed independently of the code under test.
func digestProxy(algorithm string, password string, connections *atomic.Int64) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		connections.Add(1)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			request, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			header := request.Header.Get("Proxy-Authorization")
			if !strings.HasPrefix(header, "Digest ") {
				fmt.Fprintf(server, "HTTP/1.1 407 Auth\r\nProxy-Authenticate: Digest realm=\"r\", nonce=\"abc\", qop=\"auth\", algorithm=%s\r\nContent-Length: 0\r\n\r\n", algorithm)
				return
			}
			fields := map[string]string{}
			for _, part := range splitChallenge(strings.TrimPrefix(header, "Digest ")) {
				name, value, _ := strings.Cut(part, "=")
				fields[name] = strings.Trim(value, `"`)
			}
			sum := func(value string) string {
				if algorithm == "MD5" {
					digest := md5.Sum([]byte(value))
					return hex.EncodeToString(digest[:])
				}
				digest := sha256.Sum256([]byte(value))
				return hex.EncodeToString(digest[:])
			}
			expected := sum(sum("user:r:"+password) + ":abc:" + fields["nc"] + ":" + fields["cnonce"] + ":auth:" + sum("CONNECT:"+fields["uri"]))
			if fields["response"] != expected {
				_, _ = io.WriteString(server, "HTTP/1.1 407 Auth\r\nProxy-Authenticate: Digest realm=\"r\", nonce=\"abc\"\r\nContent-Length: 0\r\n\r\n")
				return
			}
			_, _ = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = io.Copy(io.Discard, reader)
		}()
		return client, nil
	}
}

func TestConnectAnswersDigestOnNewConnection(t *testing.T) {
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080, Credentials: &model.Credentials{Username: "user", Password: "right"}}
	for _, algorithm := range []string{"MD5", "SHA-256"} {
		var connections atomic.Int64
		connector := Connector{DialContext: digestProxy(algorithm, "right", &connections)}
		opened, err := connector.Open(context.Background(), proxy, destination())
		if err != nil {
			t.Fatalf("%s: %v", algorithm, err)
		}
		if opened.AuthMethod != "digest" || connections.Load() != 2 {
			t.Fatalf("%s: method=%q connections=%d", algorithm, opened.AuthMethod, connections.Load())
		}
		_ = opened.Conn.Close()
	}
}

func TestWrongDigestPasswordFailsOnceWithoutLooping(t *testing.T) {
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080, Credentials: &model.Credentials{Username: "user", Password: "wrong"}}
	var connections atomic.Int64
	connector := Connector{DialContext: digestProxy("SHA-256", "right", &connections)}
	_, err := connector.Open(context.Background(), proxy, destination())
	var classified *Error
	if !errors.As(err, &classified) || classified.Status != model.StatusAuthFailed {
		t.Fatalf("err=%v", err)
	}
	if connections.Load() != 2 {
		t.Fatalf("connections=%d", connections.Load())
	}
}

func FuzzDigestChallenge(f *testing.F) {
	f.Add(`Digest realm="r", nonce="n", qop="auth"`)
	f.Add(`Negotiate, Digest realm="a,b", nonce="\"", algorithm=SHA-256-sess`)
	f.Add(`Digest nonce`)
	f.Add(`"`)
	credentials := &model.Credentials{Username: "u", Password: "p"}
	f.Fuzz(func(t *testing.T, value string) {
		challenge := parseDigestChallenge([]string{value})
		if challenge == nil {
			return
		}
		header := challenge.answerWith(credentials, http.MethodConnect, "1.2.3.4:443", "c")
		if strings.ContainsAny(header, "\r\n") {
			t.Fatalf("header injection: %q", header)
		}
	})
}

// recordingProxy keeps every request so a test can prove what was never sent.
func recordingProxy(reply string, requests chan<- *http.Request) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			request, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			requests <- request
			_, _ = io.WriteString(server, reply)
			_, _ = io.Copy(io.Discard, reader)
		}()
		return client, nil
	}
}

func TestProtectedCredentialsNeverReachBasicProxy(t *testing.T) {
	requests := make(chan *http.Request, 4)
	connector := Connector{ProtectCredentials: true, DialContext: recordingProxy("HTTP/1.1 407 Auth\r\nProxy-Authenticate: Basic realm=\"r\"\r\nContent-Length: 0\r\n\r\n", requests)}
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080, Credentials: &model.Credentials{Username: "user", Password: "secret"}}
	_, err := connector.Open(context.Background(), proxy, destination())
	var classified *Error
	if !errors.As(err, &classified) || classified.Code != "cleartext_credentials_refused" || classified.Status != model.StatusPolicyBlock {
		t.Fatalf("err=%v", err)
	}
	if request := <-requests; request.Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("credentials were sent: %v", request.Header)
	}
	if len(requests) != 0 {
		t.Fatal("proxy received a second request")
	}
}

func TestProtectedCredentialsStillUseDigest(t *testing.T) {
	var connections atomic.Int64
	connector := Connector{ProtectCredentials: true, DialContext: digestProxy("SHA-256", "right", &connections)}
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080, Credentials: &model.Credentials{Username: "user", Password: "right"}}
	opened, err := connector.Open(context.Background(), proxy, destination())
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Conn.Close()
	if opened.AuthMethod != "digest" {
		t.Fatalf("method=%q", opened.AuthMethod)
	}
}

func TestProtectedCredentialsAllowOpenProxies(t *testing.T) {
	requests := make(chan *http.Request, 1)
	connector := Connector{ProtectCredentials: true, DialContext: recordingProxy("HTTP/1.1 200 Connection Established\r\n\r\n", requests)}
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080, Credentials: &model.Credentials{Username: "user", Password: "secret"}}
	opened, err := connector.Open(context.Background(), proxy, destination())
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Conn.Close()
	if opened.AuthMethod != "none" || (<-requests).Header.Get("Proxy-Authorization") != "" {
		t.Fatalf("method=%q", opened.AuthMethod)
	}
}

func TestProtectedCredentialsRefuseSOCKSBeforeSendingThem(t *testing.T) {
	for _, protocolName := range []model.Protocol{model.ProtocolSOCKS5, model.ProtocolSOCKS4} {
		connector := pipeConnector(func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
		connector.ProtectCredentials = true
		proxy := model.Proxy{Protocol: protocolName, Host: "proxy", Port: 1080, Credentials: &model.Credentials{Username: "user"}}
		_, err := connector.Open(context.Background(), proxy, destination())
		var classified *Error
		if !errors.As(err, &classified) || classified.Code != "cleartext_credentials_refused" {
			t.Fatalf("%s: err=%v", protocolName, err)
		}
	}
}

func TestBytesAfterConnectReplyAreNotLost(t *testing.T) {
	connector := pipeConnector(func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nearly")
		_, _ = io.Copy(io.Discard, reader)
	})
	proxy := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080}
	opened, err := connector.Open(context.Background(), proxy, destination())
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Conn.Close()
	received := make([]byte, 5)
	if _, err := io.ReadFull(opened.Conn, received); err != nil || string(received) != "early" {
		t.Fatalf("received=%q err=%v", received, err)
	}
}

func TestPooledReaderDoesNotLeakBetweenResponses(t *testing.T) {
	for _, body := range []string{"first-response", "second"} {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		}()
		response, release, err := ReadResponseReleased(client, &http.Request{Method: http.MethodGet}, 4096)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(response.Body)
		if err != nil || string(payload) != body {
			t.Fatalf("payload=%q err=%v", payload, err)
		}
		_ = response.Body.Close()
		release()
		_ = client.Close()
	}
}
