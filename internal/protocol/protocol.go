package protocol

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/drag-team/netvex/internal/buildinfo"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/policy"
)

type Error struct {
	Stage  model.Stage
	Status model.Status
	Code   string
	Detail string
	Err    error
	// digest carries a challenge the connector can answer on a fresh connection.
	digest *digestChallenge
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Code
}
func (e *Error) Unwrap() error { return e.Err }

type TimedConn struct {
	Conn         net.Conn
	Connect      time.Duration
	ProxyTLS     time.Duration
	Negotiate    time.Duration
	ProxyTLSInfo *model.TLSInfo
	AuthMethod   string
}

type Connector struct {
	ConnectTimeout time.Duration
	AllowRemoteDNS bool
	ClassicalKEX   bool
	DialContext    func(context.Context, string, string) (net.Conn, error)
	Dialer         *net.Dialer
	ProxyDNS       *ProxyDNSCache
	TLSConfig      *tls.Config
	// ProtectCredentials refuses to send a password a passive observer could read.
	ProtectCredentials bool
}

// withoutCredentials asks httpConnect for an unauthenticated CONNECT, used to learn
// what a plaintext proxy accepts before anything secret is sent.
const withoutCredentials = "-"

// CleartextRefused is the error for credentials that would travel unprotected.
func CleartextRefused() error {
	return &Error{Stage: model.StageNegotiate, Status: model.StatusPolicyBlock, Code: "cleartext_credentials_refused", Detail: "this proxy would receive the password without encryption; --no-cleartext-credentials refused to send it"}
}

// Dialed is a proxy connection opened before any protocol negotiation.
type Dialed struct {
	Conn    net.Conn
	Connect time.Duration
}

// Close releases a connection that was not handed to OpenDialed.
func (d *Dialed) Close() {
	if d != nil && d.Conn != nil {
		_ = d.Conn.Close()
		d.Conn = nil
	}
}

func (c Connector) Open(ctx context.Context, proxy model.Proxy, dest policy.Destination) (TimedConn, error) {
	return c.OpenDialed(ctx, proxy, dest, nil)
}

// Dial performs only proxy DNS and the TCP handshake. Separating it lets callers
// reject dead gateways before they occupy any destination capacity.
func (c Connector) Dial(ctx context.Context, proxy model.Proxy) (Dialed, error) {
	start := time.Now()
	connectCtx := ctx
	cancelConnect := func() {}
	if c.ConnectTimeout > 0 {
		connectCtx, cancelConnect = context.WithTimeout(ctx, c.ConnectTimeout)
	}
	defer cancelConnect()
	address := proxy.Address()
	if c.ProxyDNS != nil {
		var err error
		address, err = c.ProxyDNS.Address(connectCtx, proxy.Host, proxy.Port)
		if err != nil {
			return Dialed{}, classifyNet(model.StageConnect, "proxy_dns", err)
		}
	}
	var conn net.Conn
	var err error
	switch {
	case c.DialContext != nil:
		conn, err = c.DialContext(connectCtx, "tcp", address)
	case c.Dialer != nil:
		conn, err = c.Dialer.DialContext(connectCtx, "tcp", address)
	default:
		dialer := net.Dialer{KeepAlive: -1}
		conn, err = dialer.DialContext(connectCtx, "tcp", address)
	}
	if err != nil {
		return Dialed{}, classifyNet(model.StageConnect, "proxy_connect", err)
	}
	return Dialed{Conn: conn, Connect: time.Since(start)}, nil
}

// OpenDialed negotiates the proxy protocol, consuming pre when it still holds a
// connection and dialing otherwise.
func (c Connector) OpenDialed(ctx context.Context, proxy model.Proxy, dest policy.Destination, pre *Dialed) (TimedConn, error) {
	return c.open(ctx, proxy, dest, pre, "")
}

// open negotiates one connection. A non-empty authorization replaces Basic, which
// is how the retry after a Digest challenge presents its answer.
func (c Connector) open(ctx context.Context, proxy model.Proxy, dest policy.Destination, pre *Dialed, authorization string) (TimedConn, error) {
	var dialed Dialed
	if pre != nil && pre.Conn != nil {
		dialed, *pre = *pre, Dialed{}
	} else {
		var err error
		if dialed, err = c.Dial(ctx, proxy); err != nil {
			return TimedConn{}, err
		}
	}
	connectTime := dialed.Connect
	conn := watchContext(ctx, dialed.Conn)
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if deadline, yes := ctx.Deadline(); yes {
		_ = conn.SetDeadline(deadline)
	}
	var proxyTLSTime time.Duration
	var proxyTLSInfo *model.TLSInfo
	authMethod := "none"
	if proxy.Protocol == model.ProtocolHTTPS {
		proxyTLSStart := time.Now()
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: proxy.Host}
		if c.TLSConfig != nil {
			tlsConfig = c.TLSConfig.Clone()
			if tlsConfig.MinVersion == 0 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
			tlsConfig.ServerName = proxy.Host
		}
		if c.ClassicalKEX {
			tlsConfig.CurvePreferences = []tls.CurveID{tls.X25519}
		}
		secure := tls.Client(conn, tlsConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return TimedConn{}, &Error{Stage: model.StageProxyTLS, Status: statusFromNet(err), Code: "proxy_tls_handshake", Detail: "TLS handshake or certificate validation with proxy failed", Err: err}
		}
		proxyTLSTime = time.Since(proxyTLSStart)
		proxyTLSInfo = model.TLSInfoFromState(secure.ConnectionState())
		conn = secure
	}
	negStart := time.Now()
	guarded := c.ProtectCredentials && proxy.Credentials != nil && proxy.Protocol != model.ProtocolHTTPS
	if guarded && proxy.Protocol != model.ProtocolHTTP {
		return TimedConn{}, CleartextRefused()
	}
	switch proxy.Protocol {
	case model.ProtocolHTTP, model.ProtocolHTTPS:
		if proxy.Credentials != nil {
			authMethod = "basic"
		}
		if dest.URL.Scheme == "https" || !c.AllowRemoteDNS {
			probing := guarded && authorization == ""
			if probing {
				authorization = withoutCredentials
			}
			tunnel, tunnelErr := httpConnect(conn, proxy, dest, c.AllowRemoteDNS, authorization)
			var classified *Error
			retryable := authorization == "" || probing
			if retryable && errors.As(tunnelErr, &classified) && classified.digest != nil {
				// A proxy usually closes after a 407, so the answer needs a new connection.
				answer, answerErr := classified.digest.answer(proxy.Credentials, http.MethodConnect, connectAuthority(dest, c.AllowRemoteDNS))
				if answerErr != nil {
					return TimedConn{}, classified
				}
				_ = conn.Close()
				ok = true
				return c.open(ctx, proxy, dest, nil, answer)
			}
			if probing && errors.As(tunnelErr, &classified) && classified.Status == model.StatusAuthFailed {
				return TimedConn{}, CleartextRefused()
			}
			if tunnelErr != nil {
				return TimedConn{}, tunnelErr
			}
			conn = tunnel
			switch {
			case probing:
				authMethod = "none"
			case authorization != "":
				authMethod = "digest"
			}
		}
	case model.ProtocolSOCKS4:
		if proxy.Credentials != nil {
			authMethod = "userid"
		}
		if err := socks4Connect(conn, proxy, dest, false); err != nil {
			return TimedConn{}, err
		}
	case model.ProtocolSOCKS4A:
		if proxy.Credentials != nil {
			authMethod = "userid"
		}
		if !c.AllowRemoteDNS {
			return TimedConn{}, &Error{Stage: model.StagePolicy, Status: model.StatusPolicyBlock, Code: "remote_dns_disabled", Detail: "SOCKS4a remote DNS is disabled by destination policy"}
		}
		if err := socks4Connect(conn, proxy, dest, true); err != nil {
			return TimedConn{}, err
		}
	case model.ProtocolSOCKS5:
		var authErr error
		authMethod, authErr = socks5Connect(conn, proxy, dest, c.AllowRemoteDNS)
		if authErr != nil {
			return TimedConn{}, authErr
		}
	default:
		return TimedConn{}, &Error{Stage: model.StageNegotiate, Status: model.StatusInvalid, Code: "unsupported_protocol", Detail: "unsupported proxy protocol"}
	}
	ok = true
	return TimedConn{Conn: conn, Connect: connectTime, ProxyTLS: proxyTLSTime, Negotiate: time.Since(negStart), ProxyTLSInfo: proxyTLSInfo, AuthMethod: authMethod}, nil
}

func statusFromNet(err error) model.Status {
	var classified *Error
	if errors.As(classifyNet(model.StageProxyTLS, "proxy_tls_handshake", err), &classified) {
		return classified.Status
	}
	return model.StatusFailed
}

func connectAuthority(dest policy.Destination, remoteDNS bool) string {
	host := dest.IP.String()
	if remoteDNS {
		host = dest.Host
	}
	return net.JoinHostPort(host, dest.Port)
}

func httpConnect(conn net.Conn, proxy model.Proxy, dest policy.Destination, remoteDNS bool, authorization string) (net.Conn, error) {
	authority := connectAuthority(dest, remoteDNS)
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n", authority, authority, buildinfo.UserAgent())
	if authorization == withoutCredentials {
		// Nothing secret goes out; the reply reveals what the proxy requires.
	} else if authorization != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", authorization)
	} else if proxy.Credentials != nil {
		token := base64.StdEncoding.EncodeToString([]byte(proxy.Credentials.Username + ":" + proxy.Credentials.Password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", token)
	}
	b.WriteString("\r\n")
	if err := writeStringFull(conn, b.String()); err != nil {
		return nil, classifyNet(model.StageTunnel, "connect_write", err)
	}
	resp, source, err := readResponse(conn, &http.Request{Method: http.MethodConnect}, 64<<10)
	if err != nil {
		return nil, &Error{Stage: model.StageTunnel, Status: model.StatusFailed, Code: "invalid_connect_response", Detail: "HTTP proxy returned an invalid or oversized CONNECT response", Err: err}
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	// A proxy that sends tunnel bytes with its reply needs the reader kept. Almost
	// none do, so the usual tunnel is the plain connection.
	var tunnel net.Conn = conn
	if source.Buffered() > 0 {
		tunnel = &readerConn{Conn: conn, r: source}
	} else {
		putResponseReader(source)
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return nil, HTTPProxyAuthError(resp, proxy.Credentials != nil)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		status, code := model.StatusFailed, "connect_rejected"
		if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
			status, code = model.StatusInconclusive, "connect_upstream_error"
		}
		return nil, &Error{Stage: model.StageTunnel, Status: status, Code: code, Detail: fmt.Sprintf("HTTP CONNECT rejected with status %d", resp.StatusCode)}
	}
	return tunnel, nil
}

func HTTPProxyAuthError(resp *http.Response, supplied bool) error {
	if !supplied {
		return &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "proxy_auth_required", Detail: "HTTP proxy requires credentials"}
	}
	digest := parseDigestChallenge(resp.Header.Values("Proxy-Authenticate"))
	challenges := resp.Header.Values("Proxy-Authenticate")
	schemes := proxyAuthSchemes(challenges)
	if len(schemes) > 0 {
		if _, basic := schemes["basic"]; !basic {
			names := make([]string, 0, len(schemes))
			for name := range schemes {
				names = append(names, name)
			}
			sort.Strings(names)
			names = boundedSchemes(names)
			return &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "proxy_auth_unsupported", Detail: "HTTP proxy requires unsupported authentication scheme(s): " + strings.Join(names, ","), digest: digest}
		}
	}
	return &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "proxy_auth_rejected", Detail: "HTTP proxy rejected the supplied credentials", digest: digest}
}

// boundedSchemes limits text chosen by the remote proxy. One oversized scheme
// must not be able to fail history persistence for an entire run.
func boundedSchemes(names []string) []string {
	if len(names) > maxReportedAuthSchemes {
		names = names[:maxReportedAuthSchemes]
	}
	for index, name := range names {
		if len(name) > maxAuthSchemeBytes {
			names[index] = name[:maxAuthSchemeBytes] + "..."
		}
	}
	return names
}

func proxyAuthSchemes(challenges []string) map[string]struct{} {
	schemes := make(map[string]struct{})
	for _, challenge := range challenges {
		start, quoted, escaped := 0, false, false
		for index := 0; index <= len(challenge); index++ {
			if index < len(challenge) {
				character := challenge[index]
				if escaped {
					escaped = false
					continue
				}
				if quoted && character == '\\' {
					escaped = true
					continue
				}
				if character == '"' {
					quoted = !quoted
					continue
				}
				if character != ',' || quoted {
					continue
				}
			}
			segment := strings.TrimSpace(challenge[start:index])
			start = index + 1
			if fields := strings.Fields(segment); len(fields) > 0 && !strings.ContainsRune(fields[0], '=') {
				schemes[strings.ToLower(fields[0])] = struct{}{}
			}
		}
	}
	return schemes
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

var errHeaderLimit = errors.New("HTTP response headers exceed limit")

const (
	maxReportedAuthSchemes = 8
	maxAuthSchemeBytes     = 32
)

type headerLimitReader struct {
	r         io.Reader
	remaining int
	matched   int
	done      bool
}

func (r *headerLimitReader) Read(data []byte) (int, error) {
	if r.done {
		return r.r.Read(data)
	}
	if r.remaining == 0 {
		return 0, errHeaderLimit
	}
	if len(data) > r.remaining {
		data = data[:r.remaining]
	}
	n, err := r.r.Read(data)
	r.remaining -= n
	terminator := [...]byte{'\r', '\n', '\r', '\n'}
	for _, value := range data[:n] {
		if value == terminator[r.matched] {
			r.matched++
			if r.matched == len(terminator) {
				r.done = true
				break
			}
		} else if value == terminator[0] {
			r.matched = 1
		} else {
			r.matched = 0
		}
	}
	return n, err
}

// responseReaders reuses the buffered reader of every proxy response. Allocating
// these was about a third of the memory used by a validation.
var responseReaders = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, 4096) }}

// readResponse returns the response and the reader holding any bytes after its
// headers. The caller owns the reader until it calls putResponseReader.
func readResponse(conn net.Conn, req *http.Request, maxHeader int) (*http.Response, *bufio.Reader, error) {
	if maxHeader < 1 {
		maxHeader = 64 << 10
	}
	limited := &headerLimitReader{r: conn, remaining: maxHeader}
	source := responseReaders.Get().(*bufio.Reader)
	source.Reset(limited)
	resp, err := http.ReadResponse(source, req)
	if err != nil {
		putResponseReader(source)
		return nil, nil, err
	}
	if !limited.done {
		_ = resp.Body.Close()
		putResponseReader(source)
		return nil, nil, errors.New("HTTP response headers require CRLF line endings")
	}
	return resp, source, nil
}

// putResponseReader drops the connection reference before pooling, so an idle
// buffer can never keep a socket or a stale proxy response alive.
func putResponseReader(source *bufio.Reader) {
	source.Reset(nil)
	responseReaders.Put(source)
}

// ReadResponseLimited keeps the reader for the life of the returned connection,
// which is required when bytes may already be buffered behind the headers.
func ReadResponseLimited(conn net.Conn, req *http.Request, maxHeader int) (*http.Response, net.Conn, error) {
	resp, source, err := readResponse(conn, req, maxHeader)
	if err != nil {
		return nil, nil, err
	}
	return resp, &readerConn{Conn: conn, r: source}, nil
}

// ReadResponseReleased is for callers that finish with the response before the
// connection. release must run after the body is no longer read.
func ReadResponseReleased(conn net.Conn, req *http.Request, maxHeader int) (*http.Response, func(), error) {
	resp, source, err := readResponse(conn, req, maxHeader)
	if err != nil {
		return nil, nil, err
	}
	return resp, func() { putResponseReader(source) }, nil
}

// sniffProbe is a SOCKS5 greeting offering no-auth and username/password, followed
// by a blank line. SOCKS5 servers answer the greeting and HTTP servers reject the
// malformed request line, so one round trip separates the families without
// sending credentials or contacting any destination.
var sniffProbe = []byte{5, 2, 0, 2, '\r', '\n', '\r', '\n'}

// Sniff identifies the protocol spoken on conn, or returns "" when the reply is
// silent or unrecognized. The result is a hint and the connection is spent.
func Sniff(conn net.Conn, timeout time.Duration) model.Protocol {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	if err := writeFull(conn, sniffProbe); err != nil {
		return ""
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return ""
	}
	return classifySniff(reply[0], reply[1])
}

func classifySniff(first, second byte) model.Protocol {
	switch {
	case first == 5 && (second == 0 || second == 2 || second == 0xff):
		return model.ProtocolSOCKS5
	case first == 'H' && second == 'T':
		return model.ProtocolHTTP
	case first == 0x15 && second == 3:
		return model.ProtocolHTTPS
	case first == 0 && second >= 90 && second <= 93:
		return model.ProtocolSOCKS4
	default:
		return ""
	}
}

func socks4Connect(conn net.Conn, proxy model.Proxy, dest policy.Destination, remote bool) error {
	if proxy.Credentials != nil && proxy.Credentials.Password != "" {
		return &Error{Stage: model.StageNegotiate, Status: model.StatusInvalid, Code: "socks4_password_unsupported", Detail: "SOCKS4 supports a user ID but not password authentication"}
	}
	port, _ := strconv.ParseUint(dest.Port, 10, 16)
	req := []byte{4, 1, byte(port >> 8), byte(port)}
	if remote {
		req = append(req, 0, 0, 0, 1)
	} else {
		if !dest.IP.Is4() {
			return &Error{Stage: model.StageNegotiate, Status: model.StatusFailed, Code: "socks4_ipv6_unsupported", Detail: "SOCKS4 requires an IPv4 destination"}
		}
		ip4 := dest.IP.As4()
		req = append(req, ip4[:]...)
	}
	if proxy.Credentials != nil {
		req = append(req, []byte(proxy.Credentials.Username)...)
	}
	req = append(req, 0)
	if remote {
		req = append(req, []byte(dest.Host)...)
		req = append(req, 0)
	}
	if err := writeFull(conn, req); err != nil {
		return classifyNet(model.StageNegotiate, "socks4_write", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return classifyNet(model.StageNegotiate, "socks4_read", err)
	}
	if reply[0] != 0 && reply[0] != 4 {
		return &Error{Stage: model.StageNegotiate, Status: model.StatusFailed, Code: "socks4_bad_version", Detail: "invalid SOCKS4 response version"}
	}
	if reply[1] != 90 {
		code := "unknown_reply"
		switch reply[1] {
		case 91:
			code = "request_rejected"
		case 92:
			code = "ident_unreachable"
		case 93:
			code = "ident_mismatch"
		}
		status := model.StatusFailed
		if reply[1] == 92 || reply[1] == 93 {
			status = model.StatusAuthFailed
		}
		return &Error{Stage: model.StageTunnel, Status: status, Code: "socks4_" + code, Detail: "SOCKS4 proxy rejected CONNECT: " + code}
	}
	return nil
}

func socks5Connect(conn net.Conn, proxy model.Proxy, dest policy.Destination, remoteDNS bool) (string, error) {
	authMethod, err := socks5Negotiate(conn, proxy)
	if err != nil {
		return "", err
	}
	port, _ := strconv.ParseUint(dest.Port, 10, 16)
	req := []byte{5, 1, 0}
	if remoteDNS {
		if len(dest.Host) == 0 || len(dest.Host) > 255 {
			return "", &Error{Stage: model.StageNegotiate, Status: model.StatusInvalid, Code: "socks5_domain_length", Detail: "SOCKS5 destination hostname is outside protocol limits"}
		}
		req = append(req, 3, byte(len(dest.Host)))
		req = append(req, dest.Host...)
	} else if dest.IP.Is4() {
		a := dest.IP.As4()
		req = append(req, 1)
		req = append(req, a[:]...)
	} else {
		a := dest.IP.As16()
		req = append(req, 4)
		req = append(req, a[:]...)
	}
	req = append(req, byte(port>>8), byte(port))
	if err := writeFull(conn, req); err != nil {
		return "", classifyNet(model.StageTunnel, "socks5_connect_write", err)
	}
	if err := socks5ReadReply(conn); err != nil {
		return "", err
	}
	return authMethod, nil
}

// Results of a SOCKS5 UDP ASSOCIATE probe.
const (
	UDPSupported   = "supported"
	UDPUnsupported = "unsupported"
	UDPUnavailable = "unavailable"
)

// ProbeUDP asks a SOCKS5 proxy for a UDP relay. It exercises only the control
// channel: a "supported" answer means the proxy accepts the command, not that
// datagrams were relayed end to end.
func (c Connector) ProbeUDP(ctx context.Context, proxy model.Proxy) string {
	dialed, err := c.Dial(ctx, proxy)
	if err != nil {
		return UDPUnavailable
	}
	conn := watchContext(ctx, dialed.Conn)
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := socks5Negotiate(conn, proxy); err != nil {
		return UDPUnavailable
	}
	if err := writeFull(conn, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return UDPUnavailable
	}
	var classified *Error
	switch err := socks5ReadReply(conn); {
	case err == nil:
		return UDPSupported
	case errors.As(err, &classified) && (classified.Code == "socks5_command_unsupported" || classified.Code == "socks5_ruleset_denied"):
		return UDPUnsupported
	default:
		return UDPUnavailable
	}
}

func socks5Negotiate(conn net.Conn, proxy model.Proxy) (string, error) {
	methods := []byte{0}
	if proxy.Credentials != nil {
		methods = append(methods, 2)
	}
	if err := writeFull(conn, append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return "", classifyNet(model.StageNegotiate, "socks5_greeting_write", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return "", classifyNet(model.StageNegotiate, "socks5_greeting_read", err)
	}
	if resp[0] != 5 {
		return "", &Error{Stage: model.StageNegotiate, Status: model.StatusFailed, Code: "socks5_bad_version", Detail: "invalid SOCKS5 response version"}
	}
	authMethod := "none"
	switch resp[1] {
	case 0:
	case 2:
		authMethod = "username_password"
		if proxy.Credentials == nil {
			return "", &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "socks5_auth_required", Detail: "SOCKS5 proxy requires username/password"}
		}
		user, pass := []byte(proxy.Credentials.Username), []byte(proxy.Credentials.Password)
		auth := append([]byte{1, byte(len(user))}, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if err := writeFull(conn, auth); err != nil {
			return "", classifyNet(model.StageNegotiate, "socks5_auth_write", err)
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			return "", classifyNet(model.StageNegotiate, "socks5_auth_read", err)
		}
		if ar[0] != 1 || ar[1] != 0 {
			return "", &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "socks5_auth_failed", Detail: "SOCKS5 username/password authentication failed"}
		}
	case 0xff:
		return "", &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "socks5_no_acceptable_auth", Detail: "SOCKS5 proxy accepts none of the offered authentication methods"}
	default:
		return "", &Error{Stage: model.StageNegotiate, Status: model.StatusFailed, Code: "socks5_unsupported_auth", Detail: fmt.Sprintf("SOCKS5 proxy selected unsupported authentication method 0x%02x", resp[1])}
	}
	return authMethod, nil
}

// socks5ReadReply consumes one command reply, including its bound address.
func socks5ReadReply(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return classifyNet(model.StageTunnel, "socks5_connect_read", err)
	}
	if head[0] != 5 {
		return &Error{Stage: model.StageTunnel, Status: model.StatusFailed, Code: "socks5_bad_reply", Detail: "invalid SOCKS5 CONNECT response"}
	}
	if head[2] != 0 {
		return &Error{Stage: model.StageTunnel, Status: model.StatusFailed, Code: "socks5_bad_reserved", Detail: "invalid SOCKS5 reserved response byte"}
	}
	if head[1] != 0 {
		code := socks5Reply(head[1])
		return &Error{Stage: model.StageTunnel, Status: socks5ReplyStatus(head[1]), Code: "socks5_" + code, Detail: "SOCKS5 CONNECT failed: " + code}
	}
	var n int
	switch head[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return classifyNet(model.StageTunnel, "socks5_bound_read", err)
		}
		n = int(l[0])
		if n == 0 {
			return &Error{Stage: model.StageTunnel, Status: model.StatusFailed, Code: "socks5_bad_address", Detail: "SOCKS5 returned an empty bound hostname"}
		}
	default:
		return &Error{Stage: model.StageTunnel, Status: model.StatusFailed, Code: "socks5_bad_address", Detail: "invalid SOCKS5 bound address type"}
	}
	tail := make([]byte, n+2)
	if _, err := io.ReadFull(conn, tail); err != nil {
		return classifyNet(model.StageTunnel, "socks5_bound_read", err)
	}
	return nil
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if written < 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func writeStringFull(writer io.Writer, value string) error {
	for len(value) > 0 {
		written, err := io.WriteString(writer, value)
		if written < 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func socks5Reply(b byte) string {
	switch b {
	case 1:
		return "general_failure"
	case 2:
		return "ruleset_denied"
	case 3:
		return "network_unreachable"
	case 4:
		return "host_unreachable"
	case 5:
		return "connection_refused"
	case 6:
		return "ttl_expired"
	case 7:
		return "command_unsupported"
	case 8:
		return "address_unsupported"
	default:
		return "unknown_reply"
	}
}

func socks5ReplyStatus(reply byte) model.Status {
	switch reply {
	case 3, 4, 5, 6:
		return model.StatusInconclusive
	default:
		return model.StatusFailed
	}
}

func classifyNet(stage model.Stage, code string, err error) error {
	if errors.Is(err, policy.ErrGatewayBlocked) {
		return &Error{Stage: model.StagePolicy, Status: model.StatusPolicyBlock, Code: "proxy_gateway_blocked", Detail: "proxy gateway uses a private or special-purpose address; authorize it with --allow-private-proxies", Err: err}
	}
	if localResourceExhausted(err) {
		return &Error{Stage: stage, Status: model.StatusInconclusive, Code: "local_resource_exhausted", Detail: "this host ran out of sockets or file descriptors; lower concurrency or raise limits", Err: err}
	}
	status := model.StatusFailed
	if errors.Is(err, context.Canceled) {
		status = model.StatusInterrupted
		code = "interrupted"
	} else if errors.Is(err, context.DeadlineExceeded) {
		status = model.StatusTimeout
		code = "deadline_exceeded"
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		code = "connection_refused"
	} else if errors.Is(err, syscall.ECONNRESET) {
		code = "connection_reset"
	} else if errors.Is(err, syscall.EPIPE) {
		code = "broken_pipe"
	} else if errors.Is(err, syscall.ENETUNREACH) {
		code = "network_unreachable"
	} else if errors.Is(err, syscall.EHOSTUNREACH) {
		code = "host_unreachable"
	} else if errors.Is(err, syscall.ETIMEDOUT) {
		status = model.StatusTimeout
		code = "network_timeout"
	} else if errors.Is(err, net.ErrClosed) {
		code = "connection_closed"
	} else if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		code = "unexpected_eof"
	}
	var ne net.Error
	if status == model.StatusFailed && errors.As(err, &ne) && ne.Timeout() {
		status = model.StatusTimeout
		code = "network_timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		code = "proxy_dns"
	}
	return &Error{Stage: stage, Status: status, Code: code, Detail: safeNetMessage(err), Err: err}
}

// localResourceExhausted separates failures of this host from failures of the
// proxy, so exhausted descriptors are never reported as a dead proxy.
func localResourceExhausted(err error) bool {
	for _, target := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.EADDRNOTAVAIL} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// GatewayGuard is a dialer control hook. It inspects the address actually being
// connected, so hostnames cannot resolve around the check.
func GatewayGuard(_ context.Context, _, address string, _ syscall.RawConn) error {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("parse gateway address: %w", err)
	}
	if policy.IsUnsafe(endpoint.Addr()) {
		return policy.ErrGatewayBlocked
	}
	return nil
}

func safeNetMessage(err error) string {
	if errors.Is(err, context.Canceled) {
		return "operation interrupted"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "operation timed out"
	}
	var op *net.OpError
	if errors.As(err, &op) {
		if op.Timeout() {
			return "network operation timed out"
		}
		return "network operation failed: " + op.Op
	}
	return "network operation failed"
}

func IsIPLiteral(host string) bool {
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}

type watchedConn struct {
	net.Conn
	stop func() bool
	once sync.Once
}

func watchContext(ctx context.Context, conn net.Conn) net.Conn {
	w := &watchedConn{Conn: conn}
	w.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	return w
}
func (w *watchedConn) Close() error {
	w.once.Do(func() { w.stop() })
	return w.Conn.Close()
}
