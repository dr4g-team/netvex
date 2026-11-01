package model

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialIdentityAndSafeURI(t *testing.T) {
	a := Proxy{Protocol: ProtocolHTTP, Host: "host", Port: 80, Credentials: &Credentials{Username: "u", Password: "one"}}
	b := a
	b.Credentials = &Credentials{Username: "u", Password: "two"}
	if a.Key() != b.Key() {
		t.Fatal("public endpoint identity must not depend on credentials")
	}
	if strings.Contains(a.SafeURI(), "one") || strings.Contains(a.SafeURI(), "u") || !strings.Contains(a.SafeURI(), "***:***") {
		t.Fatal("password exposed")
	}
}
func TestProtocolValidation(t *testing.T) {
	if _, err := ParseProtocol("SOCKS5"); err != nil {
		t.Fatal(err)
	}
	if p, err := ParseProtocol("HTTPS"); err != nil || p != ProtocolHTTPS {
		t.Fatalf("HTTPS parse: %q %v", p, err)
	}
	if _, err := ParseProtocol("ftp"); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
}

func TestCredentialExportIsExplicitOnly(t *testing.T) {
	p := Proxy{Protocol: ProtocolHTTP, Host: "host", Port: 80, Credentials: &Credentials{Username: "u", Password: "p@ss"}}
	if got := p.FullURI(); !strings.Contains(got, "p%40ss") {
		t.Fatalf("bad full URI: %s", got)
	}
	b, err := json.Marshal(Result{Proxy: p.SafeURI(), InputProxy: p.FullURI()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "p%40ss") {
		t.Fatalf("transient secret marshaled: %s", b)
	}
}

func TestBinaryIdentityMatchesPublicKey(t *testing.T) {
	p := Proxy{Protocol: ProtocolHTTP, Host: "proxy.test", Port: 8080, Credentials: &Credentials{Username: "u", Password: "p"}}
	id := p.Identity()
	if p.Key() != hex.EncodeToString(id[:]) {
		t.Fatal("key and identity differ")
	}
	q := p
	q.Credentials = &Credentials{Username: "u", Password: "different"}
	if p.Identity() != q.Identity() {
		t.Fatal("public identity leaked credential-dependent information")
	}
}

func TestResultIDSeparatesAccountsOnOneGateway(t *testing.T) {
	key := func() []byte { return []byte("local secret") }
	base := Proxy{Protocol: ProtocolHTTP, Host: "gateway.test", Port: 8000}
	first, second := base, base
	first.Credentials = &Credentials{Username: "session-1", Password: "pw"}
	second.Credentials = &Credentials{Username: "session-2", Password: "pw"}
	if first.ResultID(key) == second.ResultID(key) {
		t.Fatal("two accounts on one gateway share a result ID")
	}
	if first.ResultID(key) != first.ResultID(key) {
		t.Fatal("result ID is not stable")
	}
	if base.ResultID(key) != base.Key() {
		t.Fatal("credential-free proxies must keep their endpoint identity")
	}
	if first.ResultID(nil) != first.Key() {
		t.Fatal("a missing key must fall back to the endpoint identity")
	}
	if first.ResultID(func() []byte { return []byte("other secret") }) == first.ResultID(key) {
		t.Fatal("result ID does not depend on the local key")
	}
}

func TestBoundedMessageLimitsAndCleans(t *testing.T) {
	long := BoundedMessage(strings.Repeat("é", MaxMessageBytes))
	if len(long) > MaxMessageBytes || strings.ContainsRune(long, '�') {
		t.Fatalf("oversized or split rune: %d bytes", len(long))
	}
	if cleaned := BoundedMessage("a\x1b]0;x\x07b\r\nc"); strings.ContainsAny(cleaned, "\x1b\x07\r\n") {
		t.Fatalf("control characters survived: %q", cleaned)
	}
	if short := BoundedMessage("plain text"); short != "plain text" {
		t.Fatalf("short message changed: %q", short)
	}
}
