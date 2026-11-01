package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/dr4g-team/netvex/internal/model"
)

const responseReadBufferSize = 32 << 10

var responseReadBuffers = sync.Pool{New: func() any {
	buffer := make([]byte, responseReadBufferSize)
	return &buffer
}}

type cappedCapture struct {
	buffer bytes.Buffer
	limit  int64
}

func (c *cappedCapture) Write(value []byte) (int, error) {
	written := len(value)
	remaining := c.limit - int64(c.buffer.Len())
	if remaining <= 0 {
		return written, nil
	}
	if int64(len(value)) > remaining {
		value = value[:remaining]
	}
	_, _ = c.buffer.Write(value)
	return written, nil
}

func readBodyEvidence(reader io.Reader, maxBytes, captureBytes, expectedBytes int64, evidence io.Writer) ([]byte, int64, string, error) {
	if captureBytes > maxBytes+1 {
		captureBytes = maxBytes + 1
	}
	capture := cappedCapture{limit: captureBytes}
	if expectedBytes > 0 {
		growth := min(expectedBytes, captureBytes)
		if growth <= int64(^uint(0)>>1) {
			capture.buffer.Grow(int(growth))
		}
	}
	digest := sha256.New()
	buffer := responseReadBuffers.Get().(*[]byte)
	limit := maxBytes + 1
	var total int64
	var readErr error
	emptyReads := 0
	for total < limit {
		chunk := *buffer
		if remaining := limit - total; int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		n, err := reader.Read(chunk)
		if n > 0 {
			emptyReads = 0
			value := chunk[:n]
			_, _ = digest.Write(value)
			_, _ = capture.Write(value)
			total += int64(n)
			if evidence != nil {
				written, evidenceErr := evidence.Write(value)
				if evidenceErr != nil {
					readErr = evidenceErr
					break
				}
				if written != len(value) {
					readErr = io.ErrShortWrite
					break
				}
			}
		} else if err == nil {
			emptyReads++
			if emptyReads >= 100 {
				readErr = io.ErrNoProgress
				break
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	responseReadBuffers.Put(buffer)
	var sum [sha256.Size]byte
	return capture.buffer.Bytes(), total, hex.EncodeToString(digest.Sum(sum[:0])), readErr
}

func observedCapabilities(observations []model.Observation) *model.Capabilities {
	var capabilities *model.Capabilities
	for _, observation := range observations {
		address, err := netip.ParseAddr(observation.ExitIP)
		if err != nil {
			continue
		}
		if capabilities == nil {
			capabilities = &model.Capabilities{}
		}
		if address.Unmap().Is4() {
			capabilities.ExitIPv4 = true
		} else {
			capabilities.ExitIPv6 = true
		}
	}
	return capabilities
}

func selectedHeaders(h http.Header) map[string]string {
	var out map[string]string
	for _, k := range []string{"Server", "Via", "Content-Type", "Content-Length"} {
		if v := h.Get(k); v != "" {
			if out == nil {
				out = make(map[string]string, 4)
			}
			out[k] = model.BoundedMessage(v)
		}
	}
	return out
}

// forwardingHeaders names request headers that reveal a proxy to the echo
// target. Any of them rules out the elite classification.
var forwardingHeaders = map[string]struct{}{
	"via": {}, "forwarded": {}, "forwarded-for": {}, "x-forwarded-for": {}, "x-forwarded-host": {},
	"x-forwarded-proto": {}, "x-forwarded-server": {}, "x-real-ip": {}, "client-ip": {}, "x-client-ip": {},
	"x-cluster-client-ip": {}, "true-client-ip": {}, "cf-connecting-ip": {}, "fastly-client-ip": {},
	"x-originating-ip": {}, "x-remote-ip": {}, "x-remote-addr": {}, "x-proxy-id": {}, "proxy-connection": {},
	"x-bluecoat-via": {}, "x-squid-error": {}, "xroxy-connection": {},
}

// maxPlainIPBytes admits the longest IPv6 text form plus surrounding whitespace.
const maxPlainIPBytes = 64

func extractIntelligence(body []byte, baseline netip.Addr) (string, string, []string) {
	var v map[string]any
	if json.Unmarshal(body, &v) != nil {
		// Echo services such as ipify and icanhazip answer with a bare address.
		if len(body) <= maxPlainIPBytes {
			if address, err := netip.ParseAddr(strings.TrimSpace(string(body))); err == nil {
				return address.Unmap().String(), plainBodyAnonymity(address, baseline), nil
			}
		}
		return "", "unavailable", nil
	}
	exit := ""
	for _, k := range []string{"ip", "origin", "query", "ip_addr", "address", "client_ip"} {
		if s, ok := v[k].(string); ok {
			part, _, _ := strings.Cut(s, ",")
			part = strings.TrimSpace(part)
			if address, err := netip.ParseAddr(part); err == nil {
				exit = address.Unmap().String()
				break
			}
		}
	}
	evidence := []string{}
	baselineForwarded := false
	headers, headersEchoed := v["headers"].(map[string]any)
	if headersEchoed {
		for k, val := range headers {
			lk := strings.ToLower(k)
			if _, forwarding := forwardingHeaders[lk]; forwarding {
				evidence = append(evidence, http.CanonicalHeaderKey(k))
				if baseline.IsValid() && containsIP(fmt.Sprint(val), baseline) {
					baselineForwarded = true
				}
			}
		}
	}
	sort.Strings(evidence)
	anon := "undetermined"
	if exit == "" && len(evidence) == 0 {
		anon = "unavailable"
	} else if baseline.IsValid() {
		exitAddr, _ := netip.ParseAddr(exit)
		switch {
		case baselineForwarded || exitAddr.IsValid() && exitAddr.Unmap() == baseline.Unmap():
			anon = "transparent"
		case len(evidence) > 0:
			anon = "anonymous"
		case exitAddr.IsValid() && headersEchoed:
			// Elite requires seeing the request headers. A body with only an
			// address cannot show that forwarding headers were absent.
			anon = "elite"
		}
	}
	return exit, anon, evidence
}

func plainBodyAnonymity(exit, baseline netip.Addr) string {
	if baseline.IsValid() && exit.Unmap() == baseline.Unmap() {
		return "transparent"
	}
	return "undetermined"
}

func containsIP(value string, expected netip.Addr) bool {
	for _, field := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '=' || r == '"'
	}) {
		if addr, err := netip.ParseAddr(strings.Trim(field, "[]")); err == nil && addr.Unmap() == expected.Unmap() {
			return true
		}
		if addrPort, err := netip.ParseAddrPort(field); err == nil && addrPort.Addr().Unmap() == expected.Unmap() {
			return true
		}
	}
	return false
}

func jsonPath(value any, path []string) (any, bool) {
	current := value
	for _, key := range path {
		switch container := current.(type) {
		case map[string]any:
			next, ok := container[key]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(key)
			if err != nil || index < 0 || index >= len(container) {
				return nil, false
			}
			current = container[index]
		default:
			return nil, false
		}
	}
	return current, true
}
