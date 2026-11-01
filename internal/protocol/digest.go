package protocol

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"unicode"

	"github.com/dr4g-team/netvex/internal/model"
)

const maxDigestParameterBytes = 1024

// digestChallenge is one Proxy-Authenticate: Digest challenge from RFC 7616.
type digestChallenge struct {
	realm, nonce, opaque, algorithm string
	qopAuth, noQop                  bool
}

// parseDigestChallenge returns the strongest usable challenge. Every value comes
// from the proxy and is echoed into a request, so control characters are refused
// and sizes are bounded rather than trusted.
func parseDigestChallenge(challenges []string) *digestChallenge {
	var best *digestChallenge
	for _, value := range challenges {
		var current map[string]string
		finish := func() {
			if candidate := newDigestChallenge(current); candidate != nil && (best == nil || digestRank(candidate.algorithm) > digestRank(best.algorithm)) {
				best = candidate
			}
			current = nil
		}
		for _, segment := range splitChallenge(value) {
			fields := strings.Fields(segment)
			if len(fields) == 0 {
				continue
			}
			parameter := segment
			if !strings.ContainsRune(fields[0], '=') {
				finish()
				if !strings.EqualFold(fields[0], "digest") {
					continue
				}
				current = map[string]string{}
				parameter = strings.TrimSpace(segment[len(fields[0]):])
			}
			if current == nil {
				continue
			}
			if name, content, ok := strings.Cut(parameter, "="); ok {
				current[strings.ToLower(strings.TrimSpace(name))] = unquoteDigest(strings.TrimSpace(content))
			}
		}
		finish()
	}
	return best
}

func newDigestChallenge(parameters map[string]string) *digestChallenge {
	if parameters == nil || parameters["nonce"] == "" {
		return nil
	}
	for _, value := range parameters {
		if len(value) > maxDigestParameterBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil
		}
	}
	challenge := &digestChallenge{realm: parameters["realm"], nonce: parameters["nonce"], opaque: parameters["opaque"], algorithm: strings.ToUpper(parameters["algorithm"])}
	if challenge.algorithm == "" {
		challenge.algorithm = "MD5"
	}
	if digestRank(challenge.algorithm) == 0 {
		return nil
	}
	qop, present := parameters["qop"]
	challenge.noQop = !present
	for _, option := range strings.FieldsFunc(qop, func(r rune) bool { return r == ',' || r == ' ' }) {
		challenge.qopAuth = challenge.qopAuth || strings.EqualFold(option, "auth")
	}
	if !challenge.qopAuth && !challenge.noQop {
		return nil
	}
	return challenge
}

func digestRank(algorithm string) int {
	switch algorithm {
	case "SHA-256-SESS":
		return 4
	case "SHA-256":
		return 3
	case "MD5-SESS":
		return 2
	case "MD5":
		return 1
	default:
		return 0
	}
}

func unquoteDigest(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	value = value[1 : len(value)-1]
	var unescaped strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+1 < len(value) {
			index++
		}
		unescaped.WriteByte(value[index])
	}
	return unescaped.String()
}

func quoteDigest(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

// splitChallenge separates comma-delimited segments outside quoted strings.
func splitChallenge(value string) []string {
	var segments []string
	start, quoted, escaped := 0, false, false
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case escaped:
			escaped = false
		case quoted && character == '\\':
			escaped = true
		case character == '"':
			quoted = !quoted
		case character == ',' && !quoted:
			segments = append(segments, strings.TrimSpace(value[start:index]))
			start = index + 1
		}
	}
	return append(segments, strings.TrimSpace(value[start:]))
}

func (d *digestChallenge) answer(credentials *model.Credentials, method, uri string) (string, error) {
	if credentials == nil {
		return "", errors.New("digest authentication requires credentials")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return d.answerWith(credentials, method, uri, hex.EncodeToString(nonce[:])), nil
}

func (d *digestChallenge) answerWith(credentials *model.Credentials, method, uri, clientNonce string) string {
	newHash := sha256.New
	if strings.HasPrefix(d.algorithm, "MD5") {
		// RFC 7616 requires MD5 for compatibility; it authenticates to a proxy that
		// chose it and protects nothing else. SHA-256 is preferred when offered.
		newHash = md5.New
	}
	sum := func(parts ...string) string { return digestSum(newHash, strings.Join(parts, ":")) }
	ha1 := sum(credentials.Username, d.realm, credentials.Password)
	if strings.HasSuffix(d.algorithm, "-SESS") {
		ha1 = sum(ha1, d.nonce, clientNonce)
	}
	ha2 := sum(method, uri)
	var header strings.Builder
	fmt.Fprintf(&header, `Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s`, quoteDigest(credentials.Username), quoteDigest(d.realm), quoteDigest(d.nonce), quoteDigest(uri), d.algorithm)
	if d.qopAuth {
		const count = "00000001"
		fmt.Fprintf(&header, `, qop=auth, nc=%s, cnonce="%s", response="%s"`, count, clientNonce, sum(ha1, d.nonce, count, clientNonce, "auth", ha2))
	} else {
		fmt.Fprintf(&header, `, response="%s"`, sum(ha1, d.nonce, ha2))
	}
	if d.opaque != "" {
		fmt.Fprintf(&header, `, opaque="%s"`, quoteDigest(d.opaque))
	}
	return header.String()
}

func digestSum(newHash func() hash.Hash, value string) string {
	digest := newHash()
	digest.Write([]byte(value))
	return hex.EncodeToString(digest.Sum(nil))
}
