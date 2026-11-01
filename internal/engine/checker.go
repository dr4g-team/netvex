package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

	expectCountries    map[string]struct{}
	certificatePins    map[string]struct{}
	canaryProbe        func(context.Context, string) model.TargetHealth
	canaryDown         atomic.Pointer[map[string]struct{}]
	localPauseUntil    atomic.Int64
	localPauses        atomic.Int64
	canaryChecks       atomic.Int64
	canaryFailures     atomic.Int64
	canaryOutages      atomic.Int64
	canaryReclassified atomic.Int64
}

type MetadataLookup interface {
	Lookup(string) (model.ExitMetadata, bool)
}

func NewChecker(c config.Config) *Checker {
	baseline, _ := netip.ParseAddr(c.AnonymityBaseline)
	dialer := &net.Dialer{KeepAlive: -1}
	if !c.AllowPrivateProxy {
		dialer.ControlContext = protocol.GatewayGuard
	}
	connector := protocol.Connector{ConnectTimeout: c.ConnectTimeout, AllowRemoteDNS: c.AllowRemoteDNS, ClassicalKEX: c.TLSClassicalKEX, ProtectCredentials: c.NoCleartextCredentials, Dialer: dialer}
	if c.ProxyDNSCacheTTL > 0 {
		connector.ProxyDNS = protocol.NewProxyDNSCache(c.ProxyDNSCacheTTL, min(c.MaxInputEntries, 4096))
	}
	checker := &Checker{
		Config:          c,
		Policy:          policy.New(c.AllowPrivate, c.AllowedHosts),
		Connector:       connector,
		targetSem:       make(map[string]chan struct{}),
		resolved:        make(map[string]*resolveEntry),
		baseline:        baseline.Unmap(),
		targetRules:     make(map[string]compiledResponseRules),
		effectiveRules:  make(map[string]compiledResponseRules, len(c.Targets)),
		targetNames:     make(map[string]string, len(c.Targets)),
		expectedTargets: make([]string, 0, len(c.Targets)),
	}
	if len(c.ExpectCountries) > 0 {
		checker.expectCountries = make(map[string]struct{}, len(c.ExpectCountries))
		for _, country := range c.ExpectCountries {
			checker.expectCountries[strings.ToUpper(country)] = struct{}{}
		}
	}
	if len(c.PinSHA256) > 0 {
		checker.certificatePins = make(map[string]struct{}, len(c.PinSHA256))
		for _, pin := range c.PinSHA256 {
			checker.certificatePins[strings.ToLower(pin)] = struct{}{}
		}
	}
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
		if !c.waitTargetHealthy(ctx, target) || !c.waitTurn(ctx) {
			break
		}
		obs := c.attempt(ctx, p, target, i+1)
		c.noteLocalExhaustion(obs)
		c.reclassifyDuringOutage(&obs, target)
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
		globalPermanent := obs.Status == model.StatusAuthFailed || obs.Status == model.StatusInvalid || obs.Code == "proxy_gateway_blocked" || obs.Code == "cleartext_credentials_refused" || (!c.Config.TargetMatrix && obs.Status == model.StatusPolicyBlock)
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
	c.probeCapabilities(ctx, &r, p)
	return r
}

func (c *Checker) probeCapabilities(ctx context.Context, r *model.Result, p model.Proxy) {
	if !c.Config.ProbeUDP || r.Successes == 0 || r.Protocol != model.ProtocolSOCKS5 {
		return
	}
	p.Protocol = model.ProtocolSOCKS5
	probeCtx, cancel := context.WithTimeout(ctx, c.Config.RequestTimeout)
	defer cancel()
	if r.Capabilities == nil {
		r.Capabilities = &model.Capabilities{}
	}
	r.Capabilities.UDPAssociate = c.Connector.ProbeUDP(probeCtx, p)
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
		r.Validated = &exportProxy
	}
	r.Capabilities = observedCapabilities(r.Observations)
	r.Score = score.Calculate(r.Observations)
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
