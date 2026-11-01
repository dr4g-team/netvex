package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Concurrency = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected concurrency error")
	}
	c = Defaults()
	c.RateLimit = 0.01
	if err := c.Validate(); err == nil {
		t.Fatal("accepted unsafe tiny rate")
	}
	c.RateLimit = math.NaN()
	if err := c.Validate(); err == nil {
		t.Fatal("accepted NaN rate")
	}
	c = Defaults()
	c.MinSuccessRate = math.NaN()
	if err := c.Validate(); err == nil {
		t.Fatal("accepted NaN success rate")
	}
	c = Defaults()
	c.MinThroughputKBPS = 100
	if err := c.Validate(); err == nil {
		t.Fatal("accepted throughput threshold without a meaningful response size")
	}
	c.MinResponseBytes = 16 << 10
	c.AnonymityBaseline = "not-an-ip"
	if err := c.Validate(); err == nil {
		t.Fatal("accepted invalid anonymity baseline")
	}
	c = Defaults()
	c.ExpectJSON = []string{"missing-separator"}
	if err := c.Validate(); err == nil {
		t.Fatal("accepted invalid JSON assertion")
	}
	c = Defaults()
	c.IntelligenceBytes = 0
	if err := c.Validate(); err == nil {
		t.Fatal("accepted zero intelligence capture limit")
	}
	c = Defaults()
	c.AutoProbeTimeout = 0
	if err := c.Validate(); err == nil {
		t.Fatal("accepted zero auto probe timeout")
	}
	c = Defaults()
	c.ProxyDNSCacheTTL = 25 * time.Hour
	if err := c.Validate(); err == nil {
		t.Fatal("accepted excessive proxy DNS cache TTL")
	}
	c = Defaults()
	c.Concurrency = 1024
	c.IntelligenceBytes = 1 << 20
	if err := c.Validate(); err == nil {
		t.Fatal("accepted excessive concurrent capture budget")
	}
}

func TestResponseCaptureLimitIncludesTargetAssertions(t *testing.T) {
	c := Defaults()
	c.IntelligenceBytes = 1024
	if got := c.ResponseCaptureLimit(); got != 1024 {
		t.Fatalf("ordinary capture=%d", got)
	}
	c.TargetRules = map[string]ResponseRules{"https://example.com/": {ExpectJSON: []string{"status=ok"}}}
	if got := c.ResponseCaptureLimit(); got != c.MaxResponseBytes {
		t.Fatalf("assertion capture=%d want=%d", got, c.MaxResponseBytes)
	}
	c.TargetRules = map[string]ResponseRules{"https://example.com/": {RequireText: []string{"access denied"}}}
	if got := c.ResponseCaptureLimit(); got != 1024 {
		t.Fatalf("streaming text assertion capture=%d", got)
	}
	c.TargetRules = map[string]ResponseRules{"https://example.com/": {RequireText: []string{"café"}}}
	if got := c.ResponseCaptureLimit(); got != c.MaxResponseBytes {
		t.Fatalf("Unicode text assertion capture=%d want=%d", got, c.MaxResponseBytes)
	}
}
func TestLoadPrecedenceEnvironment(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "c.json")
	if err := os.WriteFile(p, []byte(`{"concurrency":12,"connect_timeout":"2s","request_timeout":"3s","progress_interval":"1s"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETVEX_CONCURRENCY", "7")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Concurrency != 7 {
		t.Fatalf("got %d", c.Concurrency)
	}
	if c.QueueSize != Defaults().QueueSize || c.DNSCacheTTL != Defaults().DNSCacheTTL {
		t.Fatalf("defaults lost while decoding: %+v", c)
	}
}

func TestLoadRejectsUnknownAndBadEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte(`{"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("unknown field accepted")
	}
	t.Setenv("NETVEX_CONCURRENCY", "not-a-number")
	if _, err := Load(""); err == nil {
		t.Fatal("bad environment accepted")
	}
}

func TestCompleteEnvironmentConfiguration(t *testing.T) {
	values := map[string]string{
		"NETVEX_CONCURRENCY":              "9",
		"NETVEX_QUEUE_SIZE":               "18",
		"NETVEX_PER_TARGET_CONCURRENCY":   "3",
		"NETVEX_REQUESTS_PER_SECOND":      "12.5",
		"NETVEX_REPEAT":                   "4",
		"NETVEX_MIN_SUCCESS_RATE":         "0.75",
		"NETVEX_MAX_REDIRECTS":            "1",
		"NETVEX_MAX_INPUT_BYTES":          "4096",
		"NETVEX_MAX_INPUT_ENTRIES":        "1234",
		"NETVEX_MAX_RESPONSE_BYTES":       "2048",
		"NETVEX_INTELLIGENCE_BODY_BYTES":  "1536",
		"NETVEX_MIN_RESPONSE_BYTES":       "1024",
		"NETVEX_MIN_THROUGHPUT_KBPS":      "0",
		"NETVEX_ALLOW_PRIVATE_TARGETS":    "true",
		"NETVEX_ALLOW_REMOTE_DNS":         "true",
		"NETVEX_RETRY_PERMANENT_FAILURES": "true",
		"NETVEX_STOP_ON_SUCCESS":          "true",
		"NETVEX_SAVE":                     "true",
		"NETVEX_TARGETS":                  "https://one.test/, http://two.test/",
		"NETVEX_ALLOWED_TARGET_HOSTS":     "one.test, two.test",
		"NETVEX_PROGRESS_INTERVAL":        "750ms",
		"NETVEX_PROXY_DNS_CACHE_TTL":      "45s",
		"NETVEX_AUTO_PROBE_TIMEOUT":       "1500ms",
		"NETVEX_ANONYMITY_BASELINE_IP":    "198.51.100.10",
		"NETVEX_METADATA_FILE":            "/tmp/netvex-metadata.csv",
		"NETVEX_REQUIRE_TEXT":             "expected marker,application/json",
		"NETVEX_REJECT_TEXT":              "access denied,captcha",
		"NETVEX_EXPECT_JSON":              "status=ok,data.region=eu",
		"NETVEX_EXPECTED_BODY_SHA256":     strings.Repeat("a", 64),
		"NETVEX_CA_BUNDLE":                "/tmp/destination-ca.pem",
		"NETVEX_PROXY_CA_BUNDLE":          "/tmp/proxy-ca.pem",
		"NETVEX_TARGET_MATRIX":            "true",
		"NETVEX_TARGET_QUORUM":            "1",
		"NETVEX_ROTATION_SAMPLES":         "3",
		"NETVEX_ROTATION_INTERVAL":        "2s",
		"NETVEX_PREFLIGHT":                "report",
	}
	for name, value := range values {
		t.Setenv(name, value)
	}
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Concurrency != 9 || c.QueueSize != 18 || c.PerTarget != 3 || c.RateLimit != 12.5 || c.Repeat != 4 || c.MinSuccessRate != 0.75 {
		t.Fatalf("numeric environment not applied: %+v", c)
	}
	if c.MaxRedirects != 1 || c.MaxInputBytes != 4096 || c.MaxInputEntries != 1234 || c.MaxResponseBytes != 2048 || c.IntelligenceBytes != 1536 || c.MinResponseBytes != 1024 || c.ProgressInterval != 750*time.Millisecond || c.AutoProbeTimeout != 1500*time.Millisecond || c.ProxyDNSCacheTTL != 45*time.Second {
		t.Fatalf("limits not applied: %+v", c)
	}
	if !c.AllowPrivate || !c.AllowRemoteDNS || !c.RetryPermanent || !c.StopOnSuccess || !c.Save {
		t.Fatalf("boolean environment not applied: %+v", c)
	}
	if len(c.Targets) != 2 || c.Targets[1] != "http://two.test/" || len(c.AllowedHosts) != 2 {
		t.Fatalf("lists not applied: targets=%v allowed=%v", c.Targets, c.AllowedHosts)
	}
	if c.AnonymityBaseline != "198.51.100.10" {
		t.Fatalf("baseline=%q", c.AnonymityBaseline)
	}
	if c.MetadataFile != "/tmp/netvex-metadata.csv" {
		t.Fatalf("metadata_file=%q", c.MetadataFile)
	}
	if len(c.RequireText) != 2 || len(c.RejectText) != 2 || len(c.ExpectJSON) != 2 {
		t.Fatalf("content rules not applied: require=%v reject=%v json=%v", c.RequireText, c.RejectText, c.ExpectJSON)
	}
	if !c.TargetMatrix || c.TargetQuorum != 1 || c.RotationSamples != 3 || c.RotationInterval != 2*time.Second || c.Preflight != "report" {
		t.Fatalf("advanced environment not applied: %+v", c)
	}
	if c.ExpectedBodySHA != strings.Repeat("a", 64) || c.CABundle == "" || c.ProxyCABundle == "" {
		t.Fatalf("TLS or integrity environment not applied: %+v", c)
	}
}

func TestRejectsInvalidBooleanEnvironment(t *testing.T) {
	t.Setenv("NETVEX_ALLOW_REMOTE_DNS", "sometimes")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "NETVEX_ALLOW_REMOTE_DNS") {
		t.Fatalf("err=%v", err)
	}
}

func TestRejectsExcessiveTargetMatrix(t *testing.T) {
	c := Defaults()
	c.TargetMatrix = true
	c.RotationSamples = 50
	c.Targets = make([]string, 21)
	c.AllowedHosts = make([]string, 21)
	for index := range c.Targets {
		c.Targets[index] = fmt.Sprintf("https://target-%d.test/", index)
		c.AllowedHosts[index] = fmt.Sprintf("target-%d.test", index)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "1000-attempt") {
		t.Fatalf("err=%v", err)
	}
}

func TestDataDirEnvironmentAppliesToDefaults(t *testing.T) {
	t.Setenv("NETVEX_DATA_DIR", "/tmp/netvex-env-dir")
	if dir := Defaults().DataDir; dir != "/tmp/netvex-env-dir" {
		t.Fatalf("dir=%q", dir)
	}
}

func TestValidateRejectsEachUnsafeSetting(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"concurrency", func(c *Config) { c.Concurrency = 0 }, "concurrency"},
		{"queue", func(c *Config) { c.QueueSize = 70000 }, "queue_size"},
		{"per target", func(c *Config) { c.PerTarget = 0 }, "per_target"},
		{"repeat", func(c *Config) { c.Repeat = 21 }, "repeat"},
		{"success rate", func(c *Config) { c.MinSuccessRate = 1.5 }, "min_success_rate"},
		{"rate", func(c *Config) { c.RateLimit = 0.01 }, "requests_per_second"},
		{"connect", func(c *Config) { c.ConnectTimeout = time.Millisecond }, "connect_timeout"},
		{"request", func(c *Config) { c.RequestTimeout = time.Second; c.ConnectTimeout = 2 * time.Second }, "request_timeout"},
		{"auto probe", func(c *Config) { c.AutoProbeTimeout = time.Millisecond }, "auto_probe_timeout"},
		{"dns cache", func(c *Config) { c.DNSCacheTTL = -1 }, "dns_cache_ttl"},
		{"proxy dns", func(c *Config) { c.ProxyDNSCacheTTL = 48 * time.Hour }, "proxy_dns_cache_ttl"},
		{"backoff", func(c *Config) { c.RetryBackoff = time.Minute }, "retry_backoff"},
		{"rotation interval", func(c *Config) { c.RotationInterval = 2 * time.Hour }, "rotation_interval"},
		{"canary", func(c *Config) { c.CanaryInterval = time.Millisecond }, "canary_interval"},
		{"country code", func(c *Config) { c.ExpectCountries = []string{"USA"}; c.MetadataFile = "m" }, "two-letter"},
		{"country needs metadata", func(c *Config) { c.ExpectCountries = []string{"US"} }, "metadata"},
		{"prescreen workers", func(c *Config) { c.PrescreenWorkers = 0 }, "prescreen_concurrency"},
		{"prescreen retries", func(c *Config) { c.PrescreenRetries = 9 }, "prescreen_retries"},
		{"prescreen timeout", func(c *Config) { c.PrescreenTimeout = time.Millisecond }, "prescreen_timeout"},
		{"rotation samples", func(c *Config) { c.RotationSamples = 1 }, "rotation_samples"},
		{"progress", func(c *Config) { c.ProgressInterval = time.Millisecond }, "progress_interval"},
		{"redirects", func(c *Config) { c.MaxRedirects = 11 }, "max_redirects"},
		{"input bytes", func(c *Config) { c.MaxInputBytes = 0 }, "max_input_bytes"},
		{"input entries", func(c *Config) { c.MaxInputEntries = 0 }, "max_input_entries"},
		{"response bytes", func(c *Config) { c.MaxResponseBytes = 1 }, "max_response_bytes"},
		{"intelligence bytes", func(c *Config) { c.IntelligenceBytes = 1 }, "intelligence_body_bytes"},
		{"memory budget", func(c *Config) { c.Concurrency = 4096; c.IntelligenceBytes = 1 << 20 }, "512MiB"},
		{"min response", func(c *Config) { c.MinResponseBytes = c.MaxResponseBytes + 1 }, "min_response_bytes"},
		{"throughput needs size", func(c *Config) { c.MinThroughputKBPS = 1 }, "16384"},
		{"body hash", func(c *Config) { c.ExpectedBodySHA = "zz" }, "expected_body_sha256"},
		{"too many rules", func(c *Config) { c.RequireText = make([]string, 17) }, "at most 16"},
		{"empty text rule", func(c *Config) { c.RejectText = []string{""} }, "content assertion"},
		{"json rule", func(c *Config) { c.ExpectJSON = []string{"novalue"} }, "path=value"},
		{"json path", func(c *Config) { c.ExpectJSON = []string{"a..b=1"} }, "dot-separated"},
		{"baseline", func(c *Config) { c.AnonymityBaseline = "not-ip" }, "anonymity_baseline_ip"},
		{"no targets", func(c *Config) { c.Targets = nil }, "at least one"},
		{"too many targets", func(c *Config) { c.Targets = make([]string, 33) }, "at most 32"},
		{"quorum", func(c *Config) { c.TargetQuorum = 5 }, "target_quorum"},
		{"quorum needs matrix", func(c *Config) { c.TargetQuorum = 1 }, "requires target_matrix"},
		{"matrix size", func(c *Config) {
			c.TargetMatrix, c.RotationSamples = true, 50
			c.Targets = nil
			for index := range 32 {
				c.Targets = append(c.Targets, "https://host"+strconv.Itoa(index)+".test/")
			}
		}, "1000-attempt"},
		{"preflight", func(c *Config) { c.Preflight = "maybe" }, "preflight"},
		{"bundle path", func(c *Config) { c.CABundle = "a\nb" }, "CA bundle"},
		{"target scheme", func(c *Config) { c.Targets = []string{"ftp://example.com/"} }, "invalid URL"},
		{"target credentials", func(c *Config) { c.Targets = []string{"https://u:p@example.com/"} }, "credentials"},
		{"target port", func(c *Config) { c.Targets = []string{"https://example.com:0/"} }, "invalid port"},
		{"unknown rule target", func(c *Config) { c.TargetRules = map[string]ResponseRules{"https://other.test/": {}} }, "target_rules"},
		{"unknown label target", func(c *Config) { c.TargetLabels = map[string]string{"https://other.test/": "x"} }, "target_labels"},
		{"too many hosts", func(c *Config) { c.AllowedHosts = make([]string, 65) }, "allowed target hosts"},
		{"bad host", func(c *Config) { c.AllowedHosts = []string{"a/b"} }, "invalid allowed target host"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := Defaults()
			if err := c.ParseDurations(); err != nil {
				t.Fatal(err)
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("defaults are invalid: %v", err)
			}
			test.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want %q", err, test.want)
			}
		})
	}
}

func TestCertificatePinBounds(t *testing.T) {
	c := Defaults()
	if err := c.ParseDurations(); err != nil {
		t.Fatal(err)
	}
	c.PinSHA256 = []string{"abc"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "certificate pins") {
		t.Fatalf("err=%v", err)
	}
	c.PinSHA256 = []string{strings.Repeat("z", 64)}
	if err := c.Validate(); err == nil {
		t.Fatal("non-hexadecimal pin accepted")
	}
	c.PinSHA256 = make([]string, 17)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "at most 16") {
		t.Fatalf("err=%v", err)
	}
	c.PinSHA256 = []string{strings.Repeat("a", 64)}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentReportsEveryInvalidValue(t *testing.T) {
	t.Setenv("NETVEX_REPEAT", "many")
	t.Setenv("NETVEX_STOP_ON_SUCCESS", "perhaps")
	t.Setenv("NETVEX_PIN_SHA256", " a , b ,, ")
	t.Setenv("NETVEX_PREFLIGHT", " REPORT ")
	c := Defaults()
	err := applyEnv(&c)
	if err == nil || !strings.Contains(err.Error(), "NETVEX_REPEAT") || !strings.Contains(err.Error(), "NETVEX_STOP_ON_SUCCESS") {
		t.Fatalf("err=%v", err)
	}
	if len(c.PinSHA256) != 2 || c.PinSHA256[1] != "b" || c.Preflight != "report" {
		t.Fatalf("pins=%v preflight=%q", c.PinSHA256, c.Preflight)
	}
}
