package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/drag-team/netvex/internal/buildinfo"
	"github.com/drag-team/netvex/internal/config"
	"github.com/drag-team/netvex/internal/intel"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/policy"
	"github.com/drag-team/netvex/internal/protocol"
	"github.com/drag-team/netvex/internal/score"
)

type Checker struct {
	Config            config.Config
	Policy            *policy.Policy
	Connector         protocol.Connector
	mu                sync.Mutex
	targetSem         map[string]chan struct{}
	TLSConfig         *tls.Config
	rateMu            sync.Mutex
	nextStart         time.Time
	resolveMu         sync.Mutex
	resolved          map[string]*resolveEntry
	baseline          netip.Addr
	Metadata          MetadataLookup
	requireText       []string
	rejectText        []string
	expectJSON        []jsonExpectation
	Label             string
	targetRules       map[string]compiledResponseRules
	effectiveRules    map[string]compiledResponseRules
	targetNames       map[string]string
	expectedTargets   []string
	IncludeInputProxy bool
	IdentityKey       func() []byte
}

type jsonExpectation struct {
	path     []string
	expected string
}

type compiledResponseRules struct {
	minHTTPStatus     int
	maxHTTPStatus     int
	minResponseBytes  int64
	minThroughputKBPS float64
	requireText       []string
	rejectText        []string
	expectJSON        []jsonExpectation
	expectedBodySHA   string
	textPlan          *textMatchPlan
}

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

type textMatchPlan struct {
	patterns  []textPattern
	maxLength int
}

type textPattern struct {
	value  []byte
	anchor int
}

type textMatcher struct {
	plan      *textMatchPlan
	found     []bool
	remaining int
	tail      []byte
	boundary  []byte
}

func compileTextMatchPlan(required, rejected []string) *textMatchPlan {
	patterns := append(append([]string{}, required...), rejected...)
	if len(patterns) == 0 {
		return nil
	}
	for _, pattern := range patterns {
		if pattern == "" {
			return nil
		}
		for index := range len(pattern) {
			if pattern[index] >= 0x80 {
				return nil
			}
		}
	}
	plan := &textMatchPlan{patterns: make([]textPattern, len(patterns))}
	for index, pattern := range patterns {
		value := []byte(pattern)
		plan.patterns[index] = textPattern{value: value, anchor: textPatternAnchor(value)}
		if len(pattern) > plan.maxLength {
			plan.maxLength = len(pattern)
		}
	}
	return plan
}

func (p *textMatchPlan) matcher() *textMatcher {
	if p == nil {
		return nil
	}
	return &textMatcher{plan: p, found: make([]bool, len(p.patterns)), remaining: len(p.patterns), tail: make([]byte, 0, p.maxLength-1)}
}

func (m *textMatcher) Write(value []byte) (int, error) {
	if len(value) == 0 || m.remaining == 0 {
		return len(value), nil
	}
	tailLength := m.plan.maxLength - 1
	boundaryLength := 0
	if len(m.tail) > 0 && tailLength > 0 {
		boundaryLength = len(m.tail) + min(len(value), tailLength)
		if cap(m.boundary) < boundaryLength {
			m.boundary = make([]byte, boundaryLength)
		} else {
			m.boundary = m.boundary[:boundaryLength]
		}
		copy(m.boundary, m.tail)
		copy(m.boundary[len(m.tail):], value[:boundaryLength-len(m.tail)])
	}
	for index, pattern := range m.plan.patterns {
		if !m.found[index] && (containsASCIIFold(value, pattern) || boundaryLength > 0 && containsASCIIFold(m.boundary, pattern)) {
			m.found[index] = true
			m.remaining--
		}
	}
	if m.remaining == 0 || tailLength == 0 {
		m.tail = m.tail[:0]
		return len(value), nil
	}
	if len(value) >= tailLength {
		m.tail = append(m.tail[:0], value[len(value)-tailLength:]...)
	} else if boundaryLength == 0 {
		m.tail = append(m.tail[:0], value...)
	} else {
		keep := min(tailLength, boundaryLength)
		m.tail = append(m.tail[:0], m.boundary[boundaryLength-keep:]...)
	}
	return len(value), nil
}

func textPatternAnchor(pattern []byte) int {
	// Prefer a less common ASCII byte when possible. The matcher only uses the
	// anchor to locate candidates; EqualFold still verifies the full pattern.
	best, bestRank := 0, 0
	for index, value := range pattern {
		rank := strings.IndexByte("etaoinshrdlucmfwypvbgkjqxz", asciiLower(value))
		if rank > bestRank {
			best, bestRank = index, rank
		}
	}
	return best
}

func containsASCIIFold(data []byte, pattern textPattern) bool {
	anchor := pattern.value[pattern.anchor]
	if containsAnchoredFold(data, pattern.value, pattern.anchor, anchor) {
		return true
	}
	upper := anchor
	if anchor >= 'a' && anchor <= 'z' {
		upper = anchor - ('a' - 'A')
	}
	return upper != anchor && containsAnchoredFold(data, pattern.value, pattern.anchor, upper)
}

func containsAnchoredFold(data, pattern []byte, anchor int, character byte) bool {
	for offset := 0; offset < len(data); {
		index := bytes.IndexByte(data[offset:], character)
		if index < 0 {
			return false
		}
		position := offset + index
		start := position - anchor
		if start >= 0 && start+len(pattern) <= len(data) && bytes.EqualFold(data[start:start+len(pattern)], pattern) {
			return true
		}
		offset = position + 1
	}
	return false
}

func asciiLower(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

type MetadataLookup interface {
	Lookup(string) (model.ExitMetadata, bool)
}

type resolveEntry struct {
	done    chan struct{}
	dest    policy.Destination
	err     error
	expires time.Time
}

func NewChecker(c config.Config) *Checker {
	baseline, _ := netip.ParseAddr(c.AnonymityBaseline)
	dialer := &net.Dialer{KeepAlive: -1}
	if !c.AllowPrivateProxy {
		dialer.ControlContext = protocol.GatewayGuard
	}
	connector := protocol.Connector{ConnectTimeout: c.ConnectTimeout, AllowRemoteDNS: c.AllowRemoteDNS, ClassicalKEX: c.TLSClassicalKEX, Dialer: dialer}
	if c.ProxyDNSCacheTTL > 0 {
		connector.ProxyDNS = protocol.NewProxyDNSCache(c.ProxyDNSCacheTTL, min(c.MaxInputEntries, 4096))
	}
	checker := &Checker{Config: c, Policy: policy.New(c.AllowPrivate, c.AllowedHosts), Connector: connector, targetSem: make(map[string]chan struct{}), resolved: make(map[string]*resolveEntry), baseline: baseline.Unmap(), targetRules: make(map[string]compiledResponseRules), effectiveRules: make(map[string]compiledResponseRules, len(c.Targets)), targetNames: make(map[string]string, len(c.Targets)), expectedTargets: make([]string, 0, len(c.Targets))}
	for _, rule := range c.RequireText {
		checker.requireText = append(checker.requireText, strings.ToLower(rule))
	}
	for _, rule := range c.RejectText {
		checker.rejectText = append(checker.rejectText, strings.ToLower(rule))
	}
	for _, rule := range c.ExpectJSON {
		path, expected, _ := strings.Cut(rule, "=")
		checker.expectJSON = append(checker.expectJSON, jsonExpectation{path: strings.Split(path, "."), expected: expected})
	}
	for target, rules := range c.TargetRules {
		checker.targetRules[target] = compileResponseRules(rules)
	}
	for _, target := range c.Targets {
		name := c.TargetLabels[target]
		if name == "" {
			name = targetOrigin(target)
		}
		checker.targetNames[target] = name
		checker.expectedTargets = append(checker.expectedTargets, name)
	}
	for _, target := range c.Targets {
		checker.effectiveRules[target] = checker.buildRules(target)
	}
	return checker
}

func compileResponseRules(rules config.ResponseRules) compiledResponseRules {
	compiled := compiledResponseRules{
		minHTTPStatus: rules.MinHTTPStatus, maxHTTPStatus: rules.MaxHTTPStatus,
		minResponseBytes: rules.MinResponseBytes, minThroughputKBPS: rules.MinThroughputKBPS,
		expectedBodySHA: strings.ToLower(rules.ExpectedBodySHA),
	}
	for _, rule := range rules.RequireText {
		compiled.requireText = append(compiled.requireText, strings.ToLower(rule))
	}
	for _, rule := range rules.RejectText {
		compiled.rejectText = append(compiled.rejectText, strings.ToLower(rule))
	}
	for _, rule := range rules.ExpectJSON {
		path, expected, _ := strings.Cut(rule, "=")
		compiled.expectJSON = append(compiled.expectJSON, jsonExpectation{path: strings.Split(path, "."), expected: expected})
	}
	return compiled
}

func (c *Checker) buildRules(target string) compiledResponseRules {
	rules := compiledResponseRules{
		minHTTPStatus: 200, maxHTTPStatus: 399,
		minResponseBytes: c.Config.MinResponseBytes, minThroughputKBPS: c.Config.MinThroughputKBPS,
		requireText: c.requireText, rejectText: c.rejectText, expectJSON: c.expectJSON,
		expectedBodySHA: strings.ToLower(c.Config.ExpectedBodySHA),
	}
	if targetRules, ok := c.targetRules[target]; ok {
		if targetRules.minHTTPStatus > 0 {
			rules.minHTTPStatus = targetRules.minHTTPStatus
		}
		if targetRules.maxHTTPStatus > 0 {
			rules.maxHTTPStatus = targetRules.maxHTTPStatus
		}
		if targetRules.minResponseBytes > 0 {
			rules.minResponseBytes = targetRules.minResponseBytes
		}
		if targetRules.minThroughputKBPS > 0 {
			rules.minThroughputKBPS = targetRules.minThroughputKBPS
		}
		if targetRules.expectedBodySHA != "" {
			rules.expectedBodySHA = targetRules.expectedBodySHA
		}
		rules.requireText = append(append([]string{}, rules.requireText...), targetRules.requireText...)
		rules.rejectText = append(append([]string{}, rules.rejectText...), targetRules.rejectText...)
		rules.expectJSON = append(append([]jsonExpectation{}, rules.expectJSON...), targetRules.expectJSON...)
	}
	rules.textPlan = compileTextMatchPlan(rules.requireText, rules.rejectText)
	return rules
}

func (c *Checker) rulesFor(target string) compiledResponseRules {
	if rules, ok := c.effectiveRules[target]; ok {
		return rules
	}
	return c.buildRules(target)
}

// attemptPlan holds the measurement counts implied by the configuration.
type attemptPlan struct {
	repeats  int
	attempts int
	required int
	quorum   int
}

func (c *Checker) plan() attemptPlan {
	plan := attemptPlan{repeats: max(c.Config.Repeat, c.Config.RotationSamples)}
	plan.attempts = plan.repeats
	plan.required = int(math.Ceil(float64(plan.repeats) * c.Config.MinSuccessRate))
	if c.Config.TargetMatrix {
		plan.attempts *= len(c.Config.Targets)
		plan.quorum = c.Config.TargetQuorum
		if plan.quorum == 0 {
			plan.quorum = len(c.Config.Targets)
		}
		plan.required *= plan.quorum
	}
	return plan
}

func (c *Checker) newResult(p model.Proxy, plan attemptPlan) model.Result {
	return model.Result{SchemaVersion: model.SchemaVersion, ID: p.ResultID(c.IdentityKey), Proxy: p.SafeURI(), Endpoint: p.Address(), Protocol: p.Protocol, Label: c.Label, RequiredSuccesses: plan.required, TargetQuorum: plan.quorum, CheckedAt: time.Now().UTC()}
}

func (c *Checker) Check(ctx context.Context, p model.Proxy) model.Result {
	plan := c.plan()
	r := c.newResult(p, plan)
	for i := 0; i < plan.attempts; i++ {
		target := c.Config.Targets[i%len(c.Config.Targets)]
		intervalDue := i > 0 && (!c.Config.TargetMatrix || i%len(c.Config.Targets) == 0)
		if intervalDue && !c.waitInterval(ctx) {
			break
		}
		if !c.waitRate(ctx) {
			break
		}
		obs := c.attempt(ctx, p, target, i+1)
		if r.Observations == nil {
			r.Observations = make([]model.Observation, 0, min(plan.attempts, 8))
		}
		r.Observations = append(r.Observations, obs)
		r.Attempts++
		if obs.Status == model.StatusOK {
			r.Successes++
			r.Protocol = obs.Protocol
		}
		if !c.Config.TargetMatrix && obs.Status == model.StatusOK && c.Config.StopOnSuccess && r.Successes >= plan.required {
			break
		}
		globalPermanent := obs.Status == model.StatusAuthFailed || obs.Status == model.StatusInvalid || obs.Code == "proxy_gateway_blocked" || (!c.Config.TargetMatrix && obs.Status == model.StatusPolicyBlock)
		if !c.Config.RetryPermanent && globalPermanent {
			break
		}
		if ctx.Err() != nil {
			break
		}
		if c.Config.SkipConnectRetry && obs.Status != model.StatusOK && obs.Stage == model.StageConnect {
			break
		}
		remaining := plan.attempts - (i + 1)
		if !c.Config.TargetMatrix && r.Successes+remaining < plan.required {
			break
		}
		if obs.Status != model.StatusOK && i+1 < plan.attempts && !c.waitBackoff(ctx, p, i) {
			break
		}
	}
	c.conclude(ctx, &r, p, plan)
	return r
}

// conclude derives the verdict and every aggregate from the observations.
func (c *Checker) conclude(ctx context.Context, r *model.Result, p model.Proxy, plan attemptPlan) {
	expectedPerTarget := 0
	if c.Config.TargetMatrix {
		expectedPerTarget = plan.repeats
	}
	r.TargetResults = intel.TargetResults(r.Observations, c.Config.MinSuccessRate, expectedPerTarget, c.expectedTargets...)
	r.Rotation = intel.Rotation(r.Observations)
	qualified := r.Successes >= plan.required
	if c.Config.TargetMatrix {
		passing := 0
		for _, targetResult := range r.TargetResults {
			if targetResult.Qualified {
				passing++
			}
		}
		qualified = passing >= plan.quorum
	}
	switch {
	case qualified:
		r.Status = model.StatusOK
	case r.Successes > 0:
		r.Status = model.StatusUnreliable
	case len(r.Observations) > 0:
		r.Status = r.Observations[len(r.Observations)-1].Status
	default:
		r.Status = model.StatusInterrupted
	}
	if ctx.Err() != nil && r.Status != model.StatusOK {
		// A cancelled proxy has no verdict. Recording its last failure would make
		// resume treat an unfinished proxy as finished.
		r.Status = model.StatusInterrupted
	}
	if r.Status == model.StatusOK && c.IncludeInputProxy {
		exportProxy := p
		if p.Protocol == model.ProtocolAuto {
			exportProxy.Protocol = r.Protocol
		}
		r.InputProxy = exportProxy.FullURI()
	}
	r.Score = score.Calculate(r.Observations)
}

func (c *Checker) waitInterval(ctx context.Context) bool {
	if c.Config.RotationInterval <= 0 {
		return true
	}
	timer := time.NewTimer(c.Config.RotationInterval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Checker) waitBackoff(ctx context.Context, p model.Proxy, retry int) bool {
	base := c.Config.RetryBackoff
	if base <= 0 {
		return true
	}
	delay := base
	for n := 1; n < retry && delay < 5*time.Second; n++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}
	id := p.Identity()
	factor := 0.75 + float64(id[0])/255*0.5
	delay = time.Duration(float64(delay) * factor)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

const (
	// maxQueuedConnAge limits how long an idle tunnel may wait for a destination
	// slot. Older connections are redialed because proxies drop idle clients, and
	// that drop would otherwise be reported as a proxy failure.
	maxQueuedConnAge = time.Second
	sniffTimeout     = 1500 * time.Millisecond
)

// attempt orders its work around one rule: a gateway must prove it is reachable
// before it occupies destination capacity. Most entries in a real list are dead,
// and holding a slot through their connect timeout halves throughput. Time spent
// queueing is reported separately and charged to neither latency nor the timeout.
func (c *Checker) attempt(parent context.Context, p model.Proxy, target string, n int) model.Observation {
	start := time.Now()
	obs := model.Observation{Attempt: n, StartedAt: start.UTC(), Protocol: p.Protocol, Target: c.targetName(target), Status: model.StatusFailed, Stage: model.StageResolve, Anonymity: "unavailable"}
	prepareCtx, cancelPrepare := context.WithTimeout(parent, c.Config.RequestTimeout)
	defer cancelPrepare()
	dest, err := c.resolve(prepareCtx, target)
	obs.Timings.DNSMS = ms(dest.DNSDuration)
	if err != nil {
		if errors.Is(err, policy.ErrBlocked) {
			return finishError(obs, start, &protocol.Error{Stage: model.StagePolicy, Status: model.StatusPolicyBlock, Code: "destination_blocked", Detail: err.Error(), Err: err})
		}
		return finishError(obs, start, &protocol.Error{Stage: model.StageResolve, Status: model.StatusInconclusive, Code: "destination_dns", Detail: "destination DNS resolution failed", Err: err})
	}
	obs.ResolvedIP = dest.IP.String()
	dialed, err := c.Connector.Dial(prepareCtx, p)
	if err != nil {
		// No protocol can succeed without TCP, so auto mode stops here too.
		return finishError(obs, start, err)
	}
	defer dialed.Close()
	protos := []model.Protocol{p.Protocol}
	if p.Protocol == model.ProtocolAuto {
		protos = narrowProtocols(autoProtocols(p.Port, c.Config.AllowRemoteDNS), protocol.Sniff(dialed.Conn, min(sniffTimeout, c.Config.AutoProbeTimeout)))
		dialed.Close()
	}
	queueStart := time.Now()
	release := c.acquireTarget(parent, dest.Host)
	queued := time.Since(queueStart)
	if release == nil {
		return finishError(obs, start, parent.Err())
	}
	defer release()
	obs.Timings.QueueMS = ms(queued)
	if queued > maxQueuedConnAge {
		dialed.Close()
	}
	// From here on, elapsed time is measured as if the queue wait never happened.
	measured := start.Add(queued)
	ctx, cancel := context.WithTimeout(parent, c.Config.RequestTimeout-time.Since(measured))
	defer cancel()
	var best error
	bestProtocol := p.Protocol
	bestObservation := obs
	rules := c.rulesFor(target)
	for index, protoName := range protos {
		candidate := p
		candidate.Protocol = protoName
		obs.Protocol = protoName
		candidateCtx := ctx
		cancelCandidate := func() {}
		if p.Protocol == model.ProtocolAuto {
			budget := c.Config.AutoProbeTimeout
			if deadline, ok := ctx.Deadline(); ok {
				fairShare := time.Until(deadline) / time.Duration(len(protos)-index)
				if fairShare < budget {
					budget = fairShare
				}
			}
			if budget <= 0 {
				best = &protocol.Error{Stage: model.StageConnect, Status: model.StatusTimeout, Code: "attempt_timeout", Detail: "overall validation attempt timed out", Err: context.DeadlineExceeded}
				break
			}
			candidateCtx, cancelCandidate = context.WithTimeout(ctx, budget)
		}
		var got model.Observation
		var e error
		addresses := destinationCandidates(dest, protoName, c.Config.AllowRemoteDNS)
		for addressIndex, candidateDest := range addresses {
			got, e = c.request(candidateCtx, candidate, candidateDest, rules, &dialed)
			if addressIndex > 0 {
				got.DestinationAttempts = addressIndex + 1
			}
			if e == nil || addressIndex+1 == len(addresses) || candidateCtx.Err() != nil || !retryDestinationAddress(e) {
				break
			}
		}
		candidateErr := candidateCtx.Err()
		cancelCandidate()
		if p.Protocol == model.ProtocolAuto && ctx.Err() == nil && errors.Is(candidateErr, context.DeadlineExceeded) {
			e = &protocol.Error{Stage: got.Stage, Status: model.StatusTimeout, Code: "auto_probe_timeout", Detail: "protocol candidate exceeded the auto-detection time budget", Err: candidateErr}
		}
		got.Attempt = n
		got.StartedAt = obs.StartedAt
		got.Target = obs.Target
		got.Timings.DNSMS = obs.Timings.DNSMS
		got.Timings.QueueMS = obs.Timings.QueueMS
		if e == nil {
			got.Timings.TotalMS = ms(time.Since(measured))
			return got
		}
		if best == nil || errorPriority(e) > errorPriority(best) {
			best = e
			bestProtocol = protoName
			bestObservation = got
		}
		if ctx.Err() != nil {
			code, detail := "attempt_timeout", "overall validation attempt timed out"
			if errors.Is(ctx.Err(), context.Canceled) {
				code, detail = "interrupted", "validation attempt was interrupted"
			}
			stage := got.Stage
			if stage == "" {
				stage = model.StageConnect
			}
			best = &protocol.Error{Stage: stage, Status: statusFor(ctx.Err()), Code: code, Detail: detail, Err: ctx.Err()}
			bestProtocol = protoName
			bestObservation = got
			break
		}
	}
	bestObservation.Protocol = bestProtocol
	return finishError(bestObservation, measured, best)
}

// narrowProtocols applies a sniffing hint. A proxy that clearly answered in one
// family cannot succeed in another, so the remaining probes are skipped. Without
// a hint every candidate stays, preserving detection for silent servers.
func narrowProtocols(candidates []model.Protocol, hint model.Protocol) []model.Protocol {
	if hint == "" {
		return candidates
	}
	narrowed := make([]model.Protocol, 0, 2)
	for _, candidate := range candidates {
		if candidate == hint || (hint == model.ProtocolSOCKS4 && candidate == model.ProtocolSOCKS4A) {
			narrowed = append(narrowed, candidate)
		}
	}
	if len(narrowed) == 0 {
		return candidates
	}
	return narrowed
}

func autoProtocols(port uint16, remoteDNS bool) []model.Protocol {
	var protocols []model.Protocol
	switch port {
	case 1080, 1081, 1085, 9050, 9150:
		protocols = []model.Protocol{model.ProtocolSOCKS5, model.ProtocolSOCKS4, model.ProtocolHTTP, model.ProtocolHTTPS}
	case 443, 8443, 9443:
		protocols = []model.Protocol{model.ProtocolHTTPS, model.ProtocolHTTP, model.ProtocolSOCKS5, model.ProtocolSOCKS4}
	default:
		protocols = []model.Protocol{model.ProtocolHTTP, model.ProtocolHTTPS, model.ProtocolSOCKS5, model.ProtocolSOCKS4}
	}
	if remoteDNS {
		protocols = append(protocols, model.ProtocolSOCKS4A)
	}
	return protocols
}

func targetOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "unavailable"
	}
	u.User = nil
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/", "", "", ""
	return u.String()
}

func (c *Checker) targetName(raw string) string {
	if name := c.targetNames[raw]; name != "" {
		return name
	}
	return targetOrigin(raw)
}

func destinationForProtocol(dest policy.Destination, protoName model.Protocol) policy.Destination {
	if protoName != model.ProtocolSOCKS4 || dest.IP.Is4() {
		return dest
	}
	for _, ip := range dest.Resolved {
		ip = ip.Unmap()
		if ip.Is4() {
			dest.IP = ip
			break
		}
	}
	return dest
}

const maxDestinationAddresses = 4

func destinationCandidates(dest policy.Destination, protoName model.Protocol, remoteDNS bool) []policy.Destination {
	if remoteDNS && protoName != model.ProtocolSOCKS4 {
		return []policy.Destination{destinationForProtocol(dest, protoName)}
	}
	addresses := make([]netip.Addr, 0, min(len(dest.Resolved)+1, maxDestinationAddresses))
	add := func(address netip.Addr) {
		address = address.Unmap()
		if !address.IsValid() || protoName == model.ProtocolSOCKS4 && !address.Is4() {
			return
		}
		for _, existing := range addresses {
			if existing == address {
				return
			}
		}
		if len(addresses) < maxDestinationAddresses {
			addresses = append(addresses, address)
		}
	}
	add(dest.IP)
	for _, address := range dest.Resolved {
		add(address)
	}
	if len(addresses) == 0 {
		return []policy.Destination{destinationForProtocol(dest, protoName)}
	}
	result := make([]policy.Destination, len(addresses))
	for index, address := range addresses {
		result[index] = dest
		result[index].IP = address
	}
	return result
}

func retryDestinationAddress(err error) bool {
	var protocolError *protocol.Error
	if !errors.As(err, &protocolError) {
		return false
	}
	switch protocolError.Code {
	case "connect_upstream_error",
		"socks4_request_rejected",
		"socks5_general_failure",
		"socks5_network_unreachable",
		"socks5_host_unreachable",
		"socks5_connection_refused",
		"socks5_ttl_expired",
		"tls_handshake":
		return true
	default:
		return false
	}
}

func (c *Checker) resolve(ctx context.Context, target string) (policy.Destination, error) {
	if c.Config.DNSCacheTTL == 0 {
		return c.Policy.Resolve(ctx, target)
	}
	if err := ctx.Err(); err != nil {
		return policy.Destination{}, err
	}
	for {
		c.resolveMu.Lock()
		entry := c.resolved[target]
		if entry != nil && !entry.expires.IsZero() && time.Now().After(entry.expires) {
			delete(c.resolved, target)
			entry = nil
		}
		if entry == nil {
			entry = &resolveEntry{done: make(chan struct{})}
			c.resolved[target] = entry
			c.resolveMu.Unlock()
			lookupCtx, cancel := c.detachedResolveContext(ctx)
			go c.resolveTarget(lookupCtx, cancel, target, entry)
			select {
			case <-entry.done:
				return entry.dest, entry.err
			case <-ctx.Done():
				return policy.Destination{}, ctx.Err()
			}
		}
		done := entry.done
		c.resolveMu.Unlock()
		select {
		case <-done:
			return entry.dest, entry.err
		case <-ctx.Done():
			return policy.Destination{}, ctx.Err()
		}
	}
}

func (c *Checker) detachedResolveContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(base, deadline)
	}
	timeout := c.Config.RequestTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(base, timeout)
}

func (c *Checker) resolveTarget(ctx context.Context, cancel context.CancelFunc, target string, entry *resolveEntry) {
	defer cancel()
	dest, err := c.Policy.Resolve(ctx, target)
	c.resolveMu.Lock()
	entry.dest, entry.err = dest, err
	entry.expires = time.Now().Add(c.Config.DNSCacheTTL)
	close(entry.done)
	if err != nil && c.resolved[target] == entry {
		delete(c.resolved, target)
	}
	c.resolveMu.Unlock()
}

func errorPriority(err error) int {
	var pe *protocol.Error
	if !errors.As(err, &pe) {
		return 0
	}
	switch pe.Status {
	case model.StatusPolicyBlock:
		return 4
	case model.StatusAuthFailed:
		return 3
	case model.StatusTimeout:
		return 2
	default:
		return 1
	}
}

func (c *Checker) waitRate(ctx context.Context) bool {
	if c.Config.RateLimit <= 0 {
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	spacing := time.Duration(float64(time.Second) / c.Config.RateLimit)
	// Slots are reserved on a virtual schedule and slept on outside the lock.
	// Timer overshoot therefore cannot accumulate, which previously capped the
	// real rate near 900/s whatever was configured.
	now := time.Now()
	c.rateMu.Lock()
	slot := c.nextStart
	if slot.Before(now.Add(-rateCatchUp)) {
		// Idle time earns no credit; only a schedule in progress may catch up.
		slot = now
	}
	c.nextStart = slot.Add(spacing)
	c.rateMu.Unlock()
	wait := slot.Sub(now)
	if wait <= 0 {
		return true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		c.rateMu.Lock()
		if c.nextStart.Equal(slot.Add(spacing)) {
			c.nextStart = slot
		}
		c.rateMu.Unlock()
		return false
	}
}

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
	if obs.BodyBytes > 0 && bodyDuration > 0 {
		obs.ThroughputKBPS = float64(obs.BodyBytes) / 1000 / bodyDuration.Seconds()
	}
	if readErr != nil {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: statusFor(readErr), Code: "body_read", Detail: "failed to read response body", Err: readErr}
	}
	if obs.BodyBytes > c.Config.MaxResponseBytes {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "response_too_large", Detail: "response exceeded configured byte limit"}
	}
	if resp.StatusCode < rules.minHTTPStatus || resp.StatusCode > rules.maxHTTPStatus {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusInconclusive, Code: "http_status", Detail: fmt.Sprintf("destination returned HTTP status %d", resp.StatusCode)}
	}
	if len(rules.requireText) > 0 || len(rules.rejectText) > 0 {
		var headerText strings.Builder
		headerText.Grow(1024)
		for name, values := range resp.Header {
			headerText.WriteByte('\n')
			headerText.WriteString(strings.ToLower(name))
			headerText.WriteByte(':')
			headerText.WriteString(strings.ToLower(strings.Join(values, ",")))
		}
		headersLower := headerText.String()
		var headerMatches []bool
		if rules.textPlan != nil {
			headerMatcher := rules.textPlan.matcher()
			_, _ = headerMatcher.Write([]byte(headersLower))
			headerMatches = headerMatcher.found
		}
		var bodyLower []byte
		if rules.textPlan == nil {
			bodyLower = bytes.ToLower(body)
		}
		for i, required := range rules.requireText {
			matched := rules.textPlan != nil && (bodyMatcher.found[i] || headerMatches[i])
			if rules.textPlan == nil {
				matched = bytes.Contains(bodyLower, []byte(required)) || strings.Contains(headersLower, required)
			}
			if !matched {
				return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "required_content_missing", Detail: fmt.Sprintf("response did not satisfy required content rule %d", i+1)}
			}
		}
		for i, rejected := range rules.rejectText {
			patternIndex := len(rules.requireText) + i
			matched := rules.textPlan != nil && (bodyMatcher.found[patternIndex] || headerMatches[patternIndex])
			if rules.textPlan == nil {
				matched = bytes.Contains(bodyLower, []byte(rejected)) || strings.Contains(headersLower, rejected)
			}
			if matched {
				return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "rejected_content_present", Detail: fmt.Sprintf("response matched rejected content rule %d", i+1)}
			}
		}
	}
	if len(rules.expectJSON) > 0 {
		var document any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		decodeErr := decoder.Decode(&document)
		var trailing any
		if decodeErr != nil || decoder.Decode(&trailing) != io.EOF {
			return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "expected_json_invalid", Detail: "response is not valid JSON required by configured assertions"}
		}
		for i, expectation := range rules.expectJSON {
			value, found := jsonPath(document, expectation.path)
			if !found || fmt.Sprint(value) != expectation.expected {
				return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "json_assertion_failed", Detail: fmt.Sprintf("response did not satisfy JSON assertion %d", i+1)}
			}
		}
	}
	if rules.expectedBodySHA != "" && obs.BodySHA256 != rules.expectedBodySHA {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "body_integrity_mismatch", Detail: "response body SHA-256 did not match the configured value"}
	}
	if obs.BodyBytes < rules.minResponseBytes {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "response_too_small", Detail: "response body is smaller than the configured measurement size"}
	}
	if rules.minThroughputKBPS > 0 && obs.ThroughputKBPS < rules.minThroughputKBPS {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "throughput_below_minimum", Detail: "response throughput is below the configured minimum"}
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
	return obs, nil
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

func (c *Checker) acquireTarget(ctx context.Context, host string) func() {
	c.mu.Lock()
	sem := c.targetSem[host]
	if sem == nil {
		limit := c.Config.PerTarget
		if limit > c.Config.Concurrency {
			limit = c.Config.Concurrency
		}
		sem = make(chan struct{}, limit)
		c.targetSem[host] = sem
	}
	c.mu.Unlock()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }
	case <-ctx.Done():
		return nil
	}
}

// rateCatchUp is how far the schedule may lag before unused capacity is
// forfeited. It absorbs timer overshoot without allowing a meaningful burst.
const rateCatchUp = 5 * time.Millisecond

func finishError(obs model.Observation, start time.Time, err error) model.Observation {
	obs.Timings.TotalMS = ms(time.Since(start))
	if err == nil {
		obs.Status = model.StatusFailed
		obs.Code = "unknown"
		obs.Message = "unknown validation error"
		return obs
	}
	var pe *protocol.Error
	if errors.As(err, &pe) {
		obs.Stage = pe.Stage
		obs.Status = pe.Status
		obs.Code = pe.Code
		obs.Message = model.BoundedMessage(pe.Error())
	} else {
		obs.Status = statusFor(err)
		obs.Code = "operation_failed"
		obs.Message = "operation failed"
	}
	return obs
}

func statusFor(err error) model.Status {
	if errors.Is(err, context.Canceled) {
		return model.StatusInterrupted
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.StatusTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return model.StatusTimeout
	}
	return model.StatusFailed
}
func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
func basicToken(u, p string) string {
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
}

func selectedHeaders(h http.Header) map[string]string {
	var out map[string]string
	for _, k := range []string{"Server", "Via", "Content-Type", "Content-Length"} {
		if v := h.Get(k); v != "" {
			if out == nil {
				out = make(map[string]string, 4)
			}
			if len(v) > 512 {
				v = v[:512]
			}
			out[k] = v
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
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}
