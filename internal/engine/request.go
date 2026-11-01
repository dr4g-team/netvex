package engine

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/drag-team/netvex/internal/buildinfo"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/policy"
	"github.com/drag-team/netvex/internal/protocol"
)

func (c *Checker) request(ctx context.Context, p model.Proxy, dest policy.Destination, rules compiledResponseRules, dialed *protocol.Dialed) (model.Observation, error) {
	return c.requestWithRedirects(ctx, p, dest, c.Config.MaxRedirects, rules, dialed)
}

func (c *Checker) requestWithRedirects(ctx context.Context, p model.Proxy, dest policy.Destination, redirectsLeft int, rules compiledResponseRules, dialed *protocol.Dialed) (model.Observation, error) {
	obs := model.Observation{Protocol: p.Protocol, ResolvedIP: dest.IP.String(), Status: model.StatusFailed, Stage: model.StageConnect, Anonymity: "unavailable"}
	timed, err := c.Connector.OpenDialed(ctx, p, dest, dialed)
	if err != nil {
		return obs, err
	}
	defer timed.Conn.Close()
	obs.Timings.ConnectMS = ms(timed.Connect)
	obs.Timings.ProxyTLSMS = ms(timed.ProxyTLS)
	obs.ProxyTLS = timed.ProxyTLSInfo
	obs.ProxyAuthentication = timed.AuthMethod
	obs.Timings.TunnelMS = ms(timed.Negotiate)
	conn := timed.Conn
	if dest.URL.Scheme == "https" {
		tlsStart := time.Now()
		tc := tls.Client(conn, c.destinationTLS(dest.Host))
		if err := tc.HandshakeContext(ctx); err != nil {
			status := statusFor(err)
			if status == model.StatusFailed {
				status = model.StatusInconclusive
			}
			return obs, &protocol.Error{Stage: model.StageTLS, Status: status, Code: "tls_handshake", Detail: "TLS handshake or certificate validation failed", Err: err}
		}
		obs.Timings.TLSMS = ms(time.Since(tlsStart))
		obs.DestinationTLS = model.TLSInfoFromState(tc.ConnectionState())
		conn = tc
	}
	reqURL := *dest.URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return obs, err
	}
	req.Host = dest.URL.Host
	req.Header.Set("User-Agent", buildinfo.UserAgent())
	req.Header.Set("Accept", "application/json, text/plain;q=0.8, */*;q=0.1")
	req.Header.Set("Accept-Encoding", "identity")
	req.Close = true
	forwardMode := (p.Protocol == model.ProtocolHTTP || p.Protocol == model.ProtocolHTTPS) && dest.URL.Scheme == "http" && c.Config.AllowRemoteDNS
	if forwardMode && p.Credentials != nil {
		req.Header.Set("Proxy-Authorization", "Basic "+basicToken(p.Credentials.Username, p.Credentials.Password))
	}
	writeStart := time.Now()
	if forwardMode {
		err = req.WriteProxy(conn)
	} else {
		err = req.Write(conn)
	}
	if err != nil {
		return obs, &protocol.Error{Stage: model.StageRequest, Status: statusFor(err), Code: "request_write", Detail: "failed to send request", Err: err}
	}
	resp, _, err := protocol.ReadResponseLimited(conn, req, 64<<10)
	if err != nil {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: statusFor(err), Code: "response_read", Detail: "failed to read HTTP response", Err: err}
	}
	obs.Timings.TTFBMS = ms(time.Since(writeStart))
	defer resp.Body.Close()
	obs.HTTPStatus = resp.StatusCode
	obs.ResponseHeaders = selectedHeaders(resp.Header)
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return obs, protocol.HTTPProxyAuthError(resp, p.Credentials != nil)
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		if redirectsLeft <= 0 {
			return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "redirect_limit", Detail: "redirect limit exceeded"}
		}
		location := resp.Header.Get("Location")
		if location == "" {
			return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "invalid_redirect", Detail: "destination redirect did not include a Location header"}
		}
		loc, locErr := dest.URL.Parse(location)
		if locErr != nil {
			return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "invalid_redirect", Detail: "destination returned an invalid redirect"}
		}
		_ = resp.Body.Close()
		_ = timed.Conn.Close()
		return c.followRedirect(ctx, p, loc, redirectsLeft-1, obs, rules)
	}
	if err := c.inspectResponse(&obs, resp, rules); err != nil {
		return obs, err
	}
	return obs, nil
}

// inspectResponse reads the body and applies every assertion. Evidence is written
// to obs even on failure, because a rejected response is still a measurement.
func (c *Checker) inspectResponse(obs *model.Observation, resp *http.Response, rules compiledResponseRules) error {
	bodyStart := time.Now()
	captureBytes := min(c.Config.IntelligenceBytes, c.Config.MaxResponseBytes)
	if len(rules.expectJSON) > 0 || (rules.textPlan == nil && (len(rules.requireText) > 0 || len(rules.rejectText) > 0)) {
		captureBytes = c.Config.MaxResponseBytes + 1
	}
	bodyMatcher := rules.textPlan.matcher()
	var textEvidence io.Writer
	if bodyMatcher != nil {
		textEvidence = bodyMatcher
	}
	body, bodyBytes, bodySHA, readErr := readBodyEvidence(resp.Body, c.Config.MaxResponseBytes, captureBytes, resp.ContentLength, textEvidence)
	bodyDuration := time.Since(bodyStart)
	obs.Timings.BodyMS = ms(bodyDuration)
	obs.BodyBytes = bodyBytes
	bodyComplete := int64(len(body)) == bodyBytes
	if !bodyComplete {
		obs.BodyCapturedBytes = int64(len(body))
	}
	obs.BodySHA256 = bodySHA
	obs.ThroughputKBPS = throughputKBPS(obs.BodyBytes, bodyDuration)
	if readErr != nil {
		return &protocol.Error{Stage: model.StageResponse, Status: statusFor(readErr), Code: "body_read", Detail: "failed to read response body", Err: readErr}
	}
	if obs.BodyBytes > c.Config.MaxResponseBytes {
		return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "response_too_large", Detail: "response exceeded configured byte limit"}
	}
	if resp.StatusCode < rules.minHTTPStatus || resp.StatusCode > rules.maxHTTPStatus {
		return &protocol.Error{Stage: model.StageResponse, Status: model.StatusInconclusive, Code: "http_status", Detail: fmt.Sprintf("destination returned HTTP status %d", resp.StatusCode)}
	}
	if err := checkTextRules(resp.Header, body, bodyMatcher, rules); err != nil {
		return err
	}
	if err := checkJSONRules(body, rules); err != nil {
		return err
	}
	if rules.expectedBodySHA != "" && obs.BodySHA256 != rules.expectedBodySHA {
		return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "body_integrity_mismatch", Detail: "response body SHA-256 did not match the configured value"}
	}
	if obs.BodyBytes < rules.minResponseBytes {
		return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "response_too_small", Detail: "response body is smaller than the configured measurement size"}
	}
	if rules.minThroughputKBPS > 0 && obs.ThroughputKBPS < rules.minThroughputKBPS {
		return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "throughput_below_minimum", Detail: "response throughput is below the configured minimum"}
	}
	obs.Status = model.StatusOK
	obs.Stage = model.StageComplete
	if bodyComplete {
		obs.ExitIP, obs.Anonymity, obs.ForwardingEvidence = extractIntelligence(body, c.baseline)
	}
	if c.Metadata != nil && obs.ExitIP != "" {
		if metadata, ok := c.Metadata.Lookup(obs.ExitIP); ok {
			obs.Metadata = &metadata
		}
	}
	if c.expectCountries != nil {
		country := ""
		if obs.Metadata != nil {
			country = strings.ToUpper(obs.Metadata.CountryCode)
		}
		if _, expected := c.expectCountries[country]; !expected {
			return &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "country_mismatch", Detail: "exit country is unknown or outside the expected set"}
		}
	}
	return nil
}

// throughputKBPS treats a zero duration as one coarse clock tick. Windows clocks
// can report no elapsed time for a fast transfer, and calling that zero throughput
// would fail --min-throughput-kbps on the fastest proxies. The tick gives a lower
// bound, so the result never overstates what was measured.
func throughputKBPS(bytes int64, duration time.Duration) float64 {
	if bytes <= 0 {
		return 0
	}
	if duration <= 0 {
		duration = time.Millisecond
	}
	return float64(bytes) / 1000 / duration.Seconds()
}

func (c *Checker) followRedirect(ctx context.Context, p model.Proxy, u *url.URL, left int, prior model.Observation, rules compiledResponseRules) (model.Observation, error) {
	dest, err := c.Policy.Resolve(ctx, u.String())
	if err != nil {
		if errors.Is(err, policy.ErrBlocked) {
			return prior, &protocol.Error{Stage: model.StagePolicy, Status: model.StatusPolicyBlock, Code: "redirect_blocked", Detail: "redirect destination blocked: " + err.Error(), Err: err}
		}
		return prior, &protocol.Error{Stage: model.StageResolve, Status: model.StatusInconclusive, Code: "redirect_dns", Detail: "redirect destination DNS resolution failed", Err: err}
	}
	next, err := c.requestWithRedirects(ctx, p, dest, left, rules, nil)
	if err == nil {
		next.Timings.ConnectMS += prior.Timings.ConnectMS
		next.Timings.ProxyTLSMS += prior.Timings.ProxyTLSMS
		next.Timings.TunnelMS += prior.Timings.TunnelMS
		next.Timings.TLSMS += prior.Timings.TLSMS
		next.Timings.BodyMS += prior.Timings.BodyMS
	}
	return next, err
}

func basicToken(u, p string) string {
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
}
