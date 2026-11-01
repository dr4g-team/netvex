package cli

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/drag-team/netvex/internal/config"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/output"
	"github.com/drag-team/netvex/internal/scenario"
)

type checkOptions struct {
	configPath, profile, format, inputFormat, protocol, color   string
	concurrency                                                 string
	queueSize, perTarget, repeat, maxInputEntries               int
	connectTimeout, requestTimeout, autoProbeTimeout            string
	dnsCacheTTL, proxyDNSCacheTTL, retryBackoff                 string
	progressInterval                                            string
	targets, allowHosts, requireText, rejectText, expectJSON    stringsFlag
	allowPrivate, allowRemoteDNS, save, requireSuccess, verbose bool
	allowPrivateProxies, prescreen, noConnectRetry              bool
	tlsClassicalKEX                                             bool
	prescreenWorkers, prescreenRetries                          int
	prescreenTimeout, canaryInterval                            string
	workingDir, workingTemplate, saveStatus                     string
	cpuProfile, memProfile                                      string
	noProgress, resumeAnyConfig, probeUDP, saveGzip             bool
	expectCountries                                             stringsFlag
	dataDir                                                     string
	maxRedirects                                                int
	requireCount                                                int
	minResponseBytes, maxResponseBytes, intelligenceBytes       int64
	maxInputBytes                                               int64
	rate, minSuccessRate, minThroughput                         float64
	baselineIP, metadataFile, expectedBodySHA                   string
	caBundle, proxyCABundle, scenarioPath, label                string
	rotationInterval, preflight                                 string
	rotationSamples, targetQuorum                               int
	targetMatrix                                                bool
	plain                                                       bool
	workingOutput                                               string
	summaryOutput                                               string
	metricsOutput                                               string
	checkpointOutput, resumeCheckpoint                          string
	qualityPolicy, junitOutput                                  string
	checkpointSync                                              int
	forceWorking, keepPartial                                   bool
	noDeduplicate, retryPermanent, stopOnSuccess, quiet         bool
	outputStatus                                                string
	explicit                                                    map[string]bool
}

func (c CLI) addCheckFlags(fs *flag.FlagSet, o *checkOptions) {
	fs.StringVar(&o.configPath, "config", "", "JSON configuration file")
	fs.StringVar(&o.profile, "profile", "", "execution profile: fast, balanced, thorough")
	fs.StringVar(&o.format, "format", "table", "output: table, json, jsonl, csv, txt")
	fs.StringVar(&o.inputFormat, "input-format", "auto", "input: auto, text, csv, json, jsonl")
	fs.StringVar(&o.protocol, "protocol", "http", "default protocol: http, https, socks4, socks4a, socks5, auto")
	fs.StringVar(&o.color, "color", "auto", "color: auto, always, never")
	fs.BoolVar(&o.plain, "plain", false, "disable ANSI styling for plain terminal output")
	fs.StringVar(&o.concurrency, "concurrency", "", "global concurrency (1..4096 or auto)")
	fs.IntVar(&o.queueSize, "queue-size", 0, "bounded input/result queue size (1..65536)")
	fs.IntVar(&o.perTarget, "per-target", 0, "per-target concurrency")
	fs.Float64Var(&o.rate, "rate", -1, "maximum validation attempts per second; 0 disables")
	fs.IntVar(&o.repeat, "repeat", 0, "measurements per proxy (1..20)")
	fs.Int64Var(&o.maxInputBytes, "max-input-bytes", -1, "maximum aggregate decompressed input bytes")
	fs.IntVar(&o.maxInputEntries, "max-input-entries", -1, "maximum aggregate input records")
	fs.Int64Var(&o.maxResponseBytes, "max-response-bytes", -1, "maximum response body bytes per attempt")
	fs.Int64Var(&o.intelligenceBytes, "intelligence-bytes", -1, "maximum response bytes retained for exit-IP intelligence")
	fs.Float64Var(&o.minSuccessRate, "min-success-rate", -1, "minimum successful measurement ratio (0..1]")
	fs.Int64Var(&o.minResponseBytes, "min-response-bytes", -1, "minimum response body size for a successful measurement")
	fs.Float64Var(&o.minThroughput, "min-throughput-kbps", -1, "minimum measured response-body throughput in decimal KB/s")
	fs.Var(&o.requireText, "require-text", "case-insensitive response substring required for success (repeatable)")
	fs.Var(&o.rejectText, "reject-text", "case-insensitive response substring that fails validation (repeatable)")
	fs.Var(&o.expectJSON, "expect-json", "required dot.path=value JSON assertion; numeric segments index arrays (repeatable)")
	fs.StringVar(&o.expectedBodySHA, "expect-sha256", "", "required SHA-256 of the final response body")
	fs.StringVar(&o.baselineIP, "baseline-ip", "", "local public IP used for evidence-based anonymity classification")
	fs.StringVar(&o.metadataFile, "metadata-file", "", "offline exit-IP metadata CSV or CSV.gz database")
	fs.StringVar(&o.caBundle, "ca-bundle", "", "additional PEM CA bundle for HTTPS destinations")
	fs.StringVar(&o.proxyCABundle, "proxy-ca-bundle", "", "additional PEM CA bundle for TLS-encrypted proxies")
	fs.StringVar(&o.scenarioPath, "scenario", "", "declarative validation scenario JSON file")
	fs.StringVar(&o.label, "label", "", "safe pool label stored with results")
	fs.BoolVar(&o.targetMatrix, "target-matrix", false, "run the configured repeat count against every target")
	fs.IntVar(&o.targetQuorum, "target-quorum", -1, "required qualified targets in matrix mode; 0 means all")
	fs.IntVar(&o.rotationSamples, "rotation-samples", -1, "minimum exit-IP samples per proxy (2..50; 0 disables)")
	fs.StringVar(&o.rotationInterval, "rotation-interval", "", "delay between rotation samples")
	fs.StringVar(&o.preflight, "preflight", "", "direct target health check: off, report, or strict")
	fs.StringVar(&o.connectTimeout, "connect-timeout", "", "TCP connect timeout")
	fs.StringVar(&o.requestTimeout, "request-timeout", "", "overall attempt timeout")
	fs.StringVar(&o.autoProbeTimeout, "auto-probe-timeout", "", "maximum time for each protocol candidate in auto mode")
	fs.StringVar(&o.dnsCacheTTL, "dns-cache-ttl", "", "cache approved target DNS answers (0 disables)")
	fs.StringVar(&o.proxyDNSCacheTTL, "proxy-dns-cache-ttl", "", "cache proxy gateway DNS answers (0 disables)")
	fs.StringVar(&o.retryBackoff, "retry-backoff", "", "initial exponential backoff after transient failure")
	fs.StringVar(&o.progressInterval, "progress-interval", "", "verbose progress refresh interval (50ms..1m)")
	fs.Var(&o.targets, "target", "validation URL (repeatable)")
	fs.Var(&o.allowHosts, "allow-host", "additional redirect hostname (repeatable)")
	fs.BoolVar(&o.allowPrivate, "allow-private-targets", false, "allow private/loopback validation destinations (dangerous)")
	fs.BoolVar(&o.allowRemoteDNS, "allow-remote-dns", false, "allow proxy-side DNS for SOCKS4a/SOCKS5 and HTTP CONNECT/forwarding (reduces rebinding protection)")
	fs.BoolVar(&o.allowPrivateProxies, "allow-private-proxies", false, "allow proxy gateways on private, loopback, or special-purpose addresses")
	fs.BoolVar(&o.prescreen, "prescreen", false, "reject unreachable gateways with a wide TCP-only stage before validation")
	fs.IntVar(&o.prescreenWorkers, "prescreen-concurrency", 0, "concurrent prescreen connects (1..65536)")
	fs.IntVar(&o.prescreenRetries, "prescreen-retries", -1, "extra prescreen connects before a gateway is rejected (0..3)")
	fs.StringVar(&o.prescreenTimeout, "prescreen-timeout", "", "prescreen connect timeout; 0 uses connect-timeout")
	fs.BoolVar(&o.noConnectRetry, "no-connect-retry", false, "do not repeat measurements after a TCP connect failure")
	fs.BoolVar(&o.tlsClassicalKEX, "tls-classical-kex", false, "use X25519 only for validation TLS, trading post-quantum key exchange for CPU")
	fs.BoolVar(&o.retryPermanent, "retry-permanent", false, "repeat authentication, policy, and invalid-protocol failures")
	fs.BoolVar(&o.stopOnSuccess, "stop-on-success", false, "stop remaining measurements once the reliability threshold is reached")
	fs.BoolVar(&o.noDeduplicate, "no-deduplicate", false, "disable exact deduplication to use bounded parser memory")
	fs.BoolVar(&o.quiet, "quiet", false, "suppress per-proxy stdout; summaries and errors remain on stderr")
	fs.StringVar(&o.outputStatus, "output-status", "all", "stdout results: all, or a comma-separated list of ok, failed, timeout, auth_failed, policy_blocked, invalid, inconclusive, unreliable, interrupted")
	fs.StringVar(&o.workingOutput, "working-output", "", "write validated proxies with credentials to a mode-0600 file")
	fs.StringVar(&o.workingDir, "working-dir", "", "write validated proxies to one mode-0600 file per protocol in this directory")
	fs.StringVar(&o.workingTemplate, "working-template", "", "working line format: uri, hostport, colon, or a template using {protocol} {user} {pass} {host} {port} {hostport} {uri}")
	fs.StringVar(&o.saveStatus, "save-status", "", "comma-separated statuses persisted by --save; default all")
	fs.BoolVar(&o.saveGzip, "save-gzip", false, "compress saved runs; every command reads both formats")
	fs.StringVar(&o.cpuProfile, "cpu-profile", "", "write a pprof CPU profile of this run")
	fs.StringVar(&o.memProfile, "mem-profile", "", "write a pprof allocation profile when this run ends")
	fs.BoolVar(&o.noProgress, "no-progress", false, "disable the live progress line on terminals")
	fs.BoolVar(&o.resumeAnyConfig, "resume-any-config", false, "resume even if the checkpoint used different validation rules")
	fs.BoolVar(&o.probeUDP, "probe-udp", false, "ask working SOCKS5 proxies for UDP ASSOCIATE (control channel only)")
	fs.Var(&o.expectCountries, "expect-country", "required exit country code from the metadata file (repeatable)")
	fs.StringVar(&o.canaryInterval, "canary-interval", "", "check targets directly at this interval during the run; 0 disables")
	fs.BoolVar(&o.keepPartial, "keep-partial", false, "atomically publish validated working output when interrupted")
	fs.StringVar(&o.summaryOutput, "summary-output", "", "atomically write the run summary as JSON")
	fs.StringVar(&o.metricsOutput, "metrics-output", "", "atomically write aggregate Prometheus textfile metrics")
	fs.StringVar(&o.checkpointOutput, "checkpoint", "", "append completed results to a resumable JSONL checkpoint")
	fs.StringVar(&o.resumeCheckpoint, "resume", "", "resume and append an existing checkpoint JSONL file")
	fs.IntVar(&o.checkpointSync, "checkpoint-sync", 100, "synchronize a checkpoint after this many results")
	fs.StringVar(&o.qualityPolicy, "policy", "", "JSON quality-gate policy evaluated after the run")
	fs.StringVar(&o.junitOutput, "junit-output", "", "atomically write a JUnit XML quality report")
	fs.BoolVar(&o.forceWorking, "force", false, "replace existing output and report files")
	fs.BoolVar(&o.save, "save", false, "persist run results locally")
	fs.StringVar(&o.dataDir, "data-dir", "", "history directory")
	fs.IntVar(&o.maxRedirects, "max-redirects", -1, "safe redirects to follow (0..10)")
	fs.BoolVar(&o.requireSuccess, "require-success", false, "exit 5 when no proxy validates")
	fs.IntVar(&o.requireCount, "require-count", 0, "exit 5 unless at least this many proxies validate")
	fs.BoolVar(&o.verbose, "verbose", false, "show rejected inputs and progress on stderr")
}

// override applies a flag on top of the configuration when it was supplied.
func override[T any](target *T, value T, supplied bool) {
	if supplied {
		*target = value
	}
}

// loadCheck resolves precedence: configuration file and environment, then the
// scenario, then the profile, and finally explicit flags.
func (c CLI) loadCheck(o checkOptions) (config.Config, model.Protocol, output.Format, bool, error) {
	cfg, err := loadBaseConfig(o)
	if err != nil {
		return cfg, "", "", false, err
	}
	if err := applyConcurrencyFlag(&cfg, o); err != nil {
		return cfg, "", "", false, err
	}
	applySchedulingFlags(&cfg, o)
	applyResponseFlags(&cfg, o)
	applyEvidenceFlags(&cfg, o)
	applyTimingFlags(&cfg, o)
	applyPolicyFlags(&cfg, o)
	if err := cfg.ParseDurations(); err != nil {
		return cfg, "", "", false, err
	}
	cfg.AllowedHosts = allowedHosts(cfg, o)
	if err := cfg.Validate(); err != nil {
		return cfg, "", "", false, err
	}
	protocol, format, color, err := c.outputSettings(o)
	if err != nil {
		return cfg, "", "", false, err
	}
	return cfg, protocol, format, color, nil
}

func loadBaseConfig(o checkOptions) (config.Config, error) {
	cfg, err := config.Load(o.configPath)
	if err != nil {
		return cfg, err
	}
	if o.scenarioPath != "" {
		document, err := scenario.Load(o.scenarioPath)
		if err != nil {
			return cfg, err
		}
		if err := scenario.Apply(document, &cfg); err != nil {
			return cfg, err
		}
	}
	return cfg, applyProfile(&cfg, o.profile)
}

func applyConcurrencyFlag(cfg *config.Config, o checkOptions) error {
	if o.concurrency != "" {
		if strings.EqualFold(o.concurrency, "auto") {
			cfg.Concurrency = recommendedConcurrency()
			cfg.AutoConcurrency = true
			if !o.explicit["queue-size"] {
				cfg.QueueSize = min(cfg.Concurrency*2, 65536)
			}
			if !o.explicit["per-target"] {
				cfg.PerTarget = max(1, cfg.Concurrency/2)
			}
		} else {
			value, parseErr := strconv.Atoi(o.concurrency)
			if parseErr != nil {
				return errors.New("concurrency must be an integer or auto")
			}
			cfg.Concurrency = value
		}
	}
	return nil
}

func applySchedulingFlags(cfg *config.Config, o checkOptions) {
	override(&cfg.QueueSize, o.queueSize, o.queueSize != 0)
	override(&cfg.PerTarget, o.perTarget, o.perTarget != 0)
	override(&cfg.RateLimit, o.rate, o.rate != -1)
	override(&cfg.Repeat, o.repeat, o.repeat != 0)
	override(&cfg.MinSuccessRate, o.minSuccessRate, o.minSuccessRate != -1 && o.minSuccessRate != 0)
	override(&cfg.TargetMatrix, o.targetMatrix, o.targetMatrix || o.explicit["target-matrix"])
	override(&cfg.TargetQuorum, o.targetQuorum, o.targetQuorum >= 0)
	override(&cfg.RotationSamples, o.rotationSamples, o.rotationSamples >= 0)
	override(&cfg.Prescreen, o.prescreen, o.prescreen || o.explicit["prescreen"])
	override(&cfg.PrescreenWorkers, o.prescreenWorkers, o.prescreenWorkers != 0)
	override(&cfg.PrescreenRetries, o.prescreenRetries, o.prescreenRetries >= 0)
	override(&cfg.SkipConnectRetry, o.noConnectRetry, o.noConnectRetry || o.explicit["no-connect-retry"])
	override(&cfg.RetryPermanent, o.retryPermanent, o.retryPermanent || o.explicit["retry-permanent"])
	override(&cfg.StopOnSuccess, o.stopOnSuccess, o.stopOnSuccess || o.explicit["stop-on-success"])
}

func applyResponseFlags(cfg *config.Config, o checkOptions) {
	override(&cfg.MaxInputBytes, o.maxInputBytes, o.maxInputBytes > 0 || o.explicit["max-input-bytes"])
	override(&cfg.MaxInputEntries, o.maxInputEntries, o.maxInputEntries > 0 || o.explicit["max-input-entries"])
	override(&cfg.MaxResponseBytes, o.maxResponseBytes, o.maxResponseBytes > 0 || o.explicit["max-response-bytes"])
	override(&cfg.IntelligenceBytes, o.intelligenceBytes, o.intelligenceBytes > 0 || o.explicit["intelligence-bytes"])
	override(&cfg.MinResponseBytes, o.minResponseBytes, o.minResponseBytes > 0 || o.explicit["min-response-bytes"])
	override(&cfg.MinThroughputKBPS, o.minThroughput, o.minThroughput > 0 || o.explicit["min-throughput-kbps"])
	override(&cfg.RequireText, append([]string(nil), o.requireText...), len(o.requireText) > 0)
	override(&cfg.RejectText, append([]string(nil), o.rejectText...), len(o.rejectText) > 0)
	override(&cfg.ExpectJSON, append([]string(nil), o.expectJSON...), len(o.expectJSON) > 0)
	override(&cfg.ExpectedBodySHA, strings.ToLower(strings.TrimSpace(o.expectedBodySHA)), o.expectedBodySHA != "" || o.explicit["expect-sha256"])
	override(&cfg.ExpectCountries, []string(o.expectCountries), len(o.expectCountries) > 0)
}

func applyEvidenceFlags(cfg *config.Config, o checkOptions) {
	override(&cfg.AnonymityBaseline, o.baselineIP, o.baselineIP != "" || o.explicit["baseline-ip"])
	override(&cfg.MetadataFile, o.metadataFile, o.metadataFile != "" || o.explicit["metadata-file"])
	override(&cfg.CABundle, o.caBundle, o.caBundle != "" || o.explicit["ca-bundle"])
	override(&cfg.ProxyCABundle, o.proxyCABundle, o.proxyCABundle != "" || o.explicit["proxy-ca-bundle"])
	override(&cfg.Preflight, strings.ToLower(o.preflight), o.preflight != "")
	override(&cfg.DataDir, o.dataDir, o.dataDir != "")
	override(&cfg.ProbeUDP, o.probeUDP, o.probeUDP || o.explicit["probe-udp"])
	override(&cfg.TLSClassicalKEX, o.tlsClassicalKEX, o.tlsClassicalKEX || o.explicit["tls-classical-kex"])
	override(&cfg.Save, o.save, o.save || o.explicit["save"])
	override(&cfg.SaveGzip, o.saveGzip, o.saveGzip || o.explicit["save-gzip"])
}

func applyTimingFlags(cfg *config.Config, o checkOptions) {
	override(&cfg.RotationRaw, o.rotationInterval, o.rotationInterval != "")
	override(&cfg.ConnectTimeoutRaw, o.connectTimeout, o.connectTimeout != "")
	override(&cfg.RequestTimeoutRaw, o.requestTimeout, o.requestTimeout != "")
	override(&cfg.AutoProbeRaw, o.autoProbeTimeout, o.autoProbeTimeout != "")
	override(&cfg.DNSCacheTTLRaw, o.dnsCacheTTL, o.dnsCacheTTL != "")
	override(&cfg.ProxyDNSCacheRaw, o.proxyDNSCacheTTL, o.proxyDNSCacheTTL != "")
	override(&cfg.RetryBackoffRaw, o.retryBackoff, o.retryBackoff != "")
	override(&cfg.ProgressRaw, o.progressInterval, o.progressInterval != "")
	override(&cfg.CanaryRaw, o.canaryInterval, o.canaryInterval != "")
	override(&cfg.PrescreenRaw, o.prescreenTimeout, o.prescreenTimeout != "")
}

func applyPolicyFlags(cfg *config.Config, o checkOptions) {
	override(&cfg.MaxRedirects, o.maxRedirects, o.maxRedirects >= 0)
	override(&cfg.AllowPrivate, o.allowPrivate, o.allowPrivate || o.explicit["allow-private-targets"])
	override(&cfg.AllowRemoteDNS, o.allowRemoteDNS, o.allowRemoteDNS || o.explicit["allow-remote-dns"])
	override(&cfg.AllowPrivateProxy, o.allowPrivateProxies, o.allowPrivateProxies || o.explicit["allow-private-proxies"])
	if len(o.targets) > 0 {
		cfg.Targets = []string(o.targets)
		cfg.TargetRules = nil
		cfg.TargetLabels = nil
	}
}

// allowedHosts builds the redirect allowlist. Explicit targets replace the
// configured hosts, because those were approved for different destinations.
func allowedHosts(cfg config.Config, o checkOptions) []string {
	allowed := map[string]struct{}{}
	if len(o.targets) == 0 {
		for _, host := range cfg.AllowedHosts {
			allowed[strings.ToLower(strings.TrimSuffix(host, "."))] = struct{}{}
		}
	}
	for _, target := range cfg.Targets {
		if parsed, err := url.Parse(target); err == nil {
			allowed[strings.ToLower(parsed.Hostname())] = struct{}{}
		}
	}
	for _, host := range o.allowHosts {
		allowed[strings.ToLower(strings.TrimSuffix(host, "."))] = struct{}{}
	}
	hosts := make([]string, 0, len(allowed))
	for host := range allowed {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func (c CLI) outputSettings(o checkOptions) (model.Protocol, output.Format, bool, error) {
	protocol, err := model.ParseProtocol(o.protocol)
	if err != nil {
		return "", "", false, err
	}
	format, err := output.ParseFormat(o.format)
	if err != nil {
		return "", "", false, err
	}
	if o.color != "auto" && o.color != "always" && o.color != "never" {
		return "", "", false, errors.New("color must be auto, always, or never")
	}
	color := !o.plain && format == output.FormatTable && (o.color == "always" || (o.color == "auto" && c.IsTerminal && os.Getenv("NO_COLOR") == ""))
	if o.outputStatus != "" && o.outputStatus != "all" {
		if _, err := parseStatusList(o.outputStatus); err != nil {
			return "", "", false, errors.New("output-status is invalid")
		}
	}
	if len(o.label) > 64 || strings.IndexFunc(o.label, unicode.IsControl) >= 0 {
		return "", "", false, errors.New("label must contain at most 64 safe characters")
	}
	return protocol, format, color, nil
}

func applyProfile(cfg *config.Config, name string) error {
	switch name {
	case "":
		return nil
	case "fast":
		cfg.Repeat = 1
		cfg.MinSuccessRate = 1
		cfg.StopOnSuccess = true
		cfg.RetryPermanent = false
		cfg.ConnectTimeoutRaw = "3s"
		cfg.RequestTimeoutRaw = "8s"
		cfg.RetryBackoffRaw = "0s"
		cfg.ProxyDNSCacheRaw = "1m"
		cfg.Prescreen = true
	case "balanced":
		cfg.Repeat = 2
		cfg.MinSuccessRate = 0.5
		cfg.StopOnSuccess = false
		cfg.RetryPermanent = false
		cfg.ConnectTimeoutRaw = "5s"
		cfg.RequestTimeoutRaw = "12s"
		cfg.RetryBackoffRaw = "100ms"
	case "thorough":
		cfg.Repeat = 5
		cfg.MinSuccessRate = 0.8
		cfg.StopOnSuccess = false
		cfg.RetryPermanent = false
		cfg.ConnectTimeoutRaw = "8s"
		cfg.RequestTimeoutRaw = "20s"
		cfg.RetryBackoffRaw = "250ms"
	default:
		return fmt.Errorf("profile must be fast, balanced, or thorough")
	}
	return nil
}

func runConfiguration(cfg config.Config, proto model.Protocol, o checkOptions) model.RunConfiguration {
	targets := make([]string, 0, len(cfg.Targets))
	for _, raw := range cfg.Targets {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		u.RawQuery = ""
		u.Fragment = ""
		u.Path = "/"
		u.RawPath = ""
		targets = append(targets, u.String())
	}
	return model.RunConfiguration{
		Profile: o.profile, Protocol: proto, Concurrency: cfg.Concurrency,
		QueueSize: cfg.QueueSize, PerTarget: cfg.PerTarget, RateLimit: cfg.RateLimit,
		Repeat: cfg.Repeat, MinSuccessRate: cfg.MinSuccessRate, ConnectTimeout: cfg.ConnectTimeout.String(), RequestTimeout: cfg.RequestTimeout.String(), AutoProbeTimeout: cfg.AutoProbeTimeout.String(),
		RetryBackoff: cfg.RetryBackoff.String(), StopOnSuccess: cfg.StopOnSuccess,
		RetryPermanent: cfg.RetryPermanent, AllowRemoteDNS: cfg.AllowRemoteDNS, AllowPrivateProxy: cfg.AllowPrivateProxy,
		ProbeUDP: cfg.ProbeUDP, ExpectCountries: cfg.ExpectCountries, CanaryInterval: canaryInterval(cfg), SaveStatus: o.saveStatus, SaveGzip: cfg.Save && cfg.SaveGzip,
		SkipConnectRetry: cfg.SkipConnectRetry, TLSClassicalKEX: cfg.TLSClassicalKEX, Prescreen: cfg.Prescreen, PrescreenWorkers: prescreenWorkers(cfg), PrescreenRetries: cfg.PrescreenRetries, ProxyDNSCacheTTL: cfg.ProxyDNSCacheTTL.String(),
		MaxResponseBytes: cfg.MaxResponseBytes, IntelligenceBytes: min(cfg.IntelligenceBytes, cfg.MaxResponseBytes), MinResponseBytes: cfg.MinResponseBytes, MinThroughput: cfg.MinThroughputKBPS,
		ContentRules:    len(cfg.RequireText) + len(cfg.RejectText) + len(cfg.ExpectJSON),
		MetadataEnabled: cfg.MetadataFile != "",
		TargetMatrix:    cfg.TargetMatrix, TargetQuorum: cfg.TargetQuorum,
		RotationSamples: cfg.RotationSamples, RotationInterval: cfg.RotationInterval.String(),
		Preflight: cfg.Preflight, AutoConcurrency: cfg.AutoConcurrency,
		KeepPartial: o.keepPartial, Scenario: cfg.ScenarioName, Label: o.label,
		Deduplicate: !o.noDeduplicate, MaxInputEntries: cfg.MaxInputEntries, ValidationTarget: targets,
	}
}

func canaryInterval(cfg config.Config) string {
	if cfg.CanaryInterval > 0 {
		return cfg.CanaryInterval.String()
	}
	return ""
}

func parseStatusList(value string) (map[model.Status]bool, error) {
	statuses := map[model.Status]bool{}
	if value == "" {
		return statuses, nil
	}
	for _, name := range strings.Split(value, ",") {
		status := model.Status(strings.TrimSpace(name))
		switch status {
		case model.StatusOK, model.StatusFailed, model.StatusTimeout, model.StatusAuthFailed, model.StatusPolicyBlock, model.StatusInvalid, model.StatusInconclusive, model.StatusUnreliable, model.StatusInterrupted:
			statuses[status] = true
		default:
			return nil, fmt.Errorf("unknown status %q", name)
		}
	}
	return statuses, nil
}

func prescreenWorkers(cfg config.Config) int {
	if cfg.Prescreen {
		return cfg.PrescreenWorkers
	}
	return 0
}
