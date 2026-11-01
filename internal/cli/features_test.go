package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dr4g-team/netvex/internal/config"
	historypkg "github.com/dr4g-team/netvex/internal/history"
	"github.com/dr4g-team/netvex/internal/model"
)

func checkArgs(target string, extra ...string) []string {
	base := []string{"check", "--quiet", "--repeat", "1", "--allow-private-targets", "--allow-private-proxies", "--target", target}
	return append(base, extra...)
}

func writeProxies(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWorkingTemplates(t *testing.T) {
	proxy := model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "gw.test", Port: 1080, Credentials: &model.Credentials{Username: "user", Password: "p@ss"}}
	for _, test := range []struct{ input, want string }{
		{"", "socks5://user:p%40ss@gw.test:1080"},
		{"uri", "socks5://user:p%40ss@gw.test:1080"},
		{"hostport", "gw.test:1080"},
		{"colon", "gw.test:1080:user:p@ss"},
		{"{protocol} {host} {port} {user} {pass}", "socks5 gw.test 1080 user p@ss"},
	} {
		template, err := parseWorkingTemplate(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if got := renderWorking(template, proxy); got != test.want {
			t.Fatalf("%q: got %q want %q", test.input, got, test.want)
		}
	}
	for _, invalid := range []string{"plain text", "{unknown}", "{host}\n{port}", "{host} {nope}"} {
		if _, err := parseWorkingTemplate(invalid); err == nil {
			t.Fatalf("%q accepted", invalid)
		}
	}
	unsafe := proxy
	unsafe.Credentials = &model.Credentials{Username: "user", Password: "a\nb"}
	if line := renderWorking("{user}:{pass}", unsafe); strings.ContainsAny(line, "\r\n") {
		t.Fatalf("decoded credential split a record: %q", line)
	}
}

func TestWorkingDirSplitsByProtocol(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := filepath.Join(t.TempDir(), "out")
	input := writeProxies(t, "http://user:secret@"+proxy)
	if code, _, diag := run(checkArgs(target, "--working-dir", dir, "--working-template", "colon", input), ""); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	payload, err := os.ReadFile(filepath.Join(dir, "http.txt"))
	host, port, _ := net.SplitHostPort(proxy)
	if err != nil || string(payload) != fmt.Sprintf("%s:%s:user:secret\n", host, port) {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
	assertPrivateMode(t, filepath.Join(dir, "http.txt"))
	if _, err := os.Stat(filepath.Join(dir, "socks5.txt")); !os.IsNotExist(err) {
		t.Fatalf("empty protocol file created: %v", err)
	}
	if code, _, diag := run(checkArgs(target, "--working-dir", dir, input), ""); code != ExitOperational {
		t.Fatalf("existing output accepted late: code=%d diag=%q", code, diag)
	}
	if code, _, diag := run(checkArgs(target, "--working-dir", dir, "--force", input), ""); code != ExitOK {
		t.Fatalf("force code=%d diag=%q", code, diag)
	}
}

func TestWorkingFlagValidation(t *testing.T) {
	for _, args := range [][]string{
		{"check", "--working-dir", "a", "--working-output", "b"},
		{"check", "--working-template", "colon"},
		{"check", "--working-output", "b", "--working-template", "{nope}"},
		{"check", "--save-status", "ok"},
		{"check", "--save", "--save-status", "nonsense"},
	} {
		if code, _, _ := run(args, ""); code != ExitUsage {
			t.Fatalf("%v code=%d", args, code)
		}
	}
}

func TestResumeRebuildsWorkingOutputFromInput(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "proxies.txt")
	if err := os.WriteFile(input, []byte(fmt.Sprintf("http://alpha:one@%[1]s\nhttp://bravo:two@%[1]s\n", proxy)), 0600); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(dir, "run.jsonl")
	if code, _, diag := run(checkArgs(target, "--checkpoint", checkpoint, input), ""); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	payload, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	first := payload[:strings.IndexByte(string(payload), '\n')+1]
	if err := os.WriteFile(checkpoint, first, 0600); err != nil {
		t.Fatal(err)
	}
	working := filepath.Join(dir, "working.txt")
	if code, _, diag := run(checkArgs(target, "--resume", checkpoint, "--working-output", working, input), ""); code != ExitOK {
		t.Fatalf("resume code=%d diag=%q", code, diag)
	}
	exported, err := os.ReadFile(working)
	if err != nil || strings.Count(string(exported), "\n") != 2 || !strings.Contains(string(exported), "alpha:one") || !strings.Contains(string(exported), "bravo:two") {
		t.Fatalf("exported=%q err=%v", exported, err)
	}
}

func TestCheckpointRejectsChangedValidationRules(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	checkpoint := filepath.Join(dir, "run.jsonl")
	input := writeProxies(t, proxy)
	if code, _, diag := run(checkArgs(target, "--checkpoint", checkpoint, input), ""); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	assertPrivateMode(t, checkpoint+checkpointConfigSuffix)
	changed := checkArgs(target, "--resume", checkpoint, "--require-text", "other", input)
	if code, _, diag := run(changed, ""); code != ExitUsage || !strings.Contains(diag, "different validation rules") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	if code, _, diag := run(append(changed, "--resume-any-config"), ""); code != ExitOK {
		t.Fatalf("override code=%d diag=%q", code, diag)
	}
	if code, _, diag := run(checkArgs(target, "--resume", checkpoint, "--concurrency", "3", input), ""); code != ExitOK {
		t.Fatalf("tuning change refused: code=%d diag=%q", code, diag)
	}
	if err := os.Remove(checkpoint + checkpointConfigSuffix); err != nil {
		t.Fatal(err)
	}
	if code, _, diag := run(checkArgs(target, "--resume", checkpoint, input), ""); code != ExitOK || !strings.Contains(diag, "no configuration fingerprint") {
		t.Fatalf("legacy checkpoint code=%d diag=%q", code, diag)
	}
}

func TestSaveStatusLimitsPersistenceAndKeepsCounts(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	dead := listener.Addr().String()
	_ = listener.Close()
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	args := checkArgs(target, "--save", "--save-status", "ok", "--data-dir", dir, "--summary-output", summaryPath)
	if code, _, diag := run(args, proxy+"\n"+dead+"\n"); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	code, out, diag := run([]string{"results", "--data-dir", dir, "--format", "txt"}, "")
	if code != ExitOK || strings.Count(out, "\n") != 1 || !strings.Contains(out, proxy) {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	payload, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	var summary model.RunSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Processed != 2 || summary.Configuration.SaveStatus != "ok" {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestDiffComparesTwoSavedRuns(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	flaky := connectProxy(t)
	dir := t.TempDir()
	if code, _, diag := run([]string{"diff", "--data-dir", dir}, ""); code != ExitOperational || !strings.Contains(diag, "two saved runs") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	args := checkArgs(target, "--save", "--data-dir", dir)
	if code, _, diag := run(args, proxy+"\n"+flaky+"\n"); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	time.Sleep(5 * time.Millisecond)
	if code, _, diag := run(args, proxy+"\n"); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	code, out, diag := run([]string{"diff", "--data-dir", dir, "--json", "--only", "removed"}, "")
	if code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	var report historypkg.DiffReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Counts[historypkg.ChangeRemoved] != 1 || len(report.Entries) != 1 || report.Entries[0].Endpoint != flaky {
		t.Fatalf("report=%+v", report)
	}
	code, out, _ = run([]string{"diff", "--data-dir", dir}, "")
	if code != ExitOK || !strings.Contains(out, "removed=1") || !strings.Contains(out, flaky) {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if code, _, _ := run([]string{"diff", "--only", "exploded"}, ""); code != ExitUsage {
		t.Fatalf("bad filter code=%d", code)
	}
}

func TestDiffUsesPersistedRunsWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	if err := os.MkdirAll(runs, 0700); err != nil {
		t.Fatal(err)
	}
	baseID := "20261101T120000.000000000Z-base"
	currentID := "20261101T120001.000000000Z-current"
	writeRun := func(id string, results []model.Result) {
		t.Helper()
		var records bytes.Buffer
		encoder := json.NewEncoder(&records)
		for _, result := range results {
			if err := encoder.Encode(result); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(runs, id+".jsonl"), records.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		summary, err := json.Marshal(model.RunSummary{RunID: id})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runs, id+".summary.json"), summary, 0600); err != nil {
			t.Fatal(err)
		}
	}
	result := func(id, endpoint string, status model.Status, latency float64) model.Result {
		return model.Result{ID: id, Endpoint: endpoint, Protocol: model.ProtocolHTTP, Status: status, Score: model.Score{MedianMS: latency}}
	}
	writeRun(baseID, []model.Result{
		result("died", "died.test:80", model.StatusOK, 100),
		result("revived", "revived.test:80", model.StatusFailed, 0),
		result("slower", "slower.test:80", model.StatusOK, 100),
		result("faster", "faster.test:80", model.StatusOK, 100),
		result("removed", "removed.test:80", model.StatusOK, 100),
		result("same", "same.test:80", model.StatusFailed, 0),
	})
	writeRun(currentID, []model.Result{
		result("died", "died.test:80", model.StatusFailed, 0),
		result("revived", "revived.test:80", model.StatusOK, 100),
		result("slower", "slower.test:80", model.StatusOK, 200),
		result("faster", "faster.test:80", model.StatusOK, 50),
		result("added", "added.test:80", model.StatusOK, 100),
		result("same", "same.test:80", model.StatusFailed, 0),
	})

	code, out, diag := run([]string{"diff", "--data-dir", dir, "--json", baseID, currentID}, "")
	if code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	var report historypkg.DiffReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	for _, change := range []historypkg.Change{historypkg.ChangeDied, historypkg.ChangeRevived, historypkg.ChangeSlower, historypkg.ChangeFaster, historypkg.ChangeAdded, historypkg.ChangeRemoved} {
		if report.Counts[change] != 1 {
			t.Fatalf("%s count=%d report=%+v", change, report.Counts[change], report)
		}
	}
	if report.Unchanged != 1 || len(report.Entries) != 6 {
		t.Fatalf("report=%+v", report)
	}

	code, out, diag = run([]string{"diff", "--data-dir", dir, "--only", "died, revived", "--limit", "1"}, "")
	if code != ExitOK || !strings.Contains(out, "died.test:80") || strings.Contains(out, "revived.test:80") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	code, out, diag = run([]string{"diff", "--data-dir", dir, "--json", baseID}, "")
	if code != ExitOK || !strings.Contains(out, `"died"`) {
		t.Fatalf("one-argument diff code=%d out=%q diag=%q", code, out, diag)
	}
	if code, _, diag := run([]string{"diff", "--data-dir", dir, "--max-load", "1", baseID, currentID}, ""); code != ExitOperational || !strings.Contains(diag, "load limit") {
		t.Fatalf("load limit code=%d diag=%q", code, diag)
	}
	for _, args := range [][]string{
		{"diff", "--limit", "0"},
		{"diff", "--max-load", "0"},
		{"diff", "--latency-change", "0"},
		{"diff", "one", "two", "three"},
	} {
		if code, _, _ := run(args, ""); code != ExitUsage {
			t.Fatalf("%v code=%d", args, code)
		}
	}
}

func TestProgressLine(t *testing.T) {
	line := progressLine(progressState{processed: 500, scheduled: 1000, ingestDone: true, ok: 40, failed: 460, elapsed: 10 * time.Second})
	for _, want := range []string{"500/1000", "50.0%", "ok=40", "failed=460", "50/s", "ETA 10s"} {
		if !strings.Contains(line, want) {
			t.Fatalf("%q missing %q", line, want)
		}
	}
	streaming := progressLine(progressState{processed: 5, scheduled: 9, elapsed: time.Second})
	if !strings.Contains(streaming, "5/9+") || strings.Contains(streaming, "ETA") {
		t.Fatalf("streaming line %q", streaming)
	}
	if line := progressLine(progressState{}); strings.Contains(line, "NaN") || strings.Contains(line, "Inf") {
		t.Fatalf("empty line %q", line)
	}
}

func TestProgressGoesToTerminalOnly(t *testing.T) {
	var out, diag strings.Builder
	cli := CLI{Stdout: &out, Stderr: &diag, Stdin: strings.NewReader("proxy.test:8080\n"), ErrorTerminal: true}
	if code := cli.Run([]string{"check", "--quiet", "--progress-interval", "50ms", "--target", "http://127.0.0.1:9/", "--repeat", "1"}); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag.String())
	}
	if strings.Contains(out.String(), clearLine) {
		t.Fatal("progress control sequence reached stdout")
	}
}

func TestProfilesAreWrittenAndNeverOverwrittenWithoutForce(t *testing.T) {
	dir := t.TempDir()
	cpu, mem := filepath.Join(dir, "cpu.pprof"), filepath.Join(dir, "mem.pprof")
	args := []string{"check", "--quiet", "--repeat", "1", "--target", "http://127.0.0.1:9/", "--cpu-profile", cpu, "--mem-profile", mem}
	if code, _, diag := run(args, "proxy.test:8080\n"); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	for _, path := range []string{cpu, mem} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("%s: %v", path, err)
		}
		assertPrivateMode(t, path)
	}
	if code, _, diag := run(args, "proxy.test:8080\n"); code != ExitOperational || !strings.Contains(diag, "cpu profile") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
}

func TestProfilesAndCheckpointSidecarCannotCollide(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "proxies.txt")
	original := []byte("proxy.test:8080\n")
	if err := os.WriteFile(input, original, 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, diag := run([]string{"check", "--cpu-profile", input, "--force", input}, ""); code != ExitUsage || !strings.Contains(diag, "must not overwrite an input") {
		t.Fatalf("profile/input collision code=%d diag=%q", code, diag)
	}
	if payload, err := os.ReadFile(input); err != nil || !bytes.Equal(payload, original) {
		t.Fatalf("input changed: %q err=%v", payload, err)
	}
	profile := filepath.Join(dir, "profile.pprof")
	if code, _, _ := run([]string{"check", "--cpu-profile", profile, "--mem-profile", profile}, "proxy.test:8080\n"); code != ExitUsage {
		t.Fatalf("profile collision code=%d", code)
	}
	checkpoint := filepath.Join(dir, "run.jsonl")
	if code, _, _ := run([]string{"check", "--checkpoint", checkpoint, "--summary-output", checkpoint + checkpointConfigSuffix}, "proxy.test:8080\n"); code != ExitUsage {
		t.Fatalf("checkpoint sidecar collision code=%d", code)
	}
}

func TestProfileFinalizationFailureIsOperational(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "mem.pprof")
	code, _, diag := run([]string{"check", "--quiet", "--repeat", "1", "--target", "http://127.0.0.1:9/", "--mem-profile", path}, "proxy.test:8080\n")
	if code != ExitOperational || !strings.Contains(diag, "memory profile") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
}

func TestSchemaCommand(t *testing.T) {
	code, out, _ := run([]string{"schema", "result"}, "")
	var document map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &document) != nil || document["$schema"] == nil {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if code, _, _ := run([]string{"schema", "nope"}, ""); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	if code, _, _ := run([]string{"schema"}, ""); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
}

func TestFastProfileUsesPrescreen(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	code, _, diag := run([]string{"check", "--quiet", "--profile", "fast", "--allow-private-targets", "--allow-private-proxies", "--target", target, "--summary-output", summaryPath}, proxy+"\n")
	if code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	payload, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	var summary model.RunSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		t.Fatal(err)
	}
	if !summary.Configuration.Prescreen || summary.Successful != 1 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestMaxLatencyFiltersSingleMeasurementRuns(t *testing.T) {
	slow := model.Result{Status: model.StatusOK, Successes: 1, Score: model.Score{MedianMS: 900}}
	if matchResult(slow, resultFilter{maxLatency: 100}) {
		t.Fatal("slow proxy passed the latency filter")
	}
}

func TestFlagsOverrideConfigurationAndProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"concurrency":12,"allow_remote_dns":true,"repeat":4,"targets":["https://configured.test/"],"allowed_target_hosts":["configured.test","extra.test"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	load := func(o checkOptions) config.Config {
		t.Helper()
		o.configPath, o.protocol, o.format, o.color = path, "http", "table", "auto"
		o.rate, o.minSuccessRate, o.maxInputBytes, o.maxInputEntries, o.maxResponseBytes, o.intelligenceBytes, o.minResponseBytes, o.minThroughput = -1, -1, -1, -1, -1, -1, -1, -1
		o.targetQuorum, o.rotationSamples, o.maxRedirects, o.prescreenRetries = -1, -1, -1, -1
		if o.explicit == nil {
			o.explicit = map[string]bool{}
		}
		cfg, _, _, _, err := CLI{}.loadCheck(o)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg := load(checkOptions{})
	if cfg.Concurrency != 12 || cfg.Repeat != 4 || !cfg.AllowRemoteDNS || !slices.Contains(cfg.AllowedHosts, "extra.test") {
		t.Fatalf("configuration lost: %+v", cfg)
	}
	cfg = load(checkOptions{profile: "fast"})
	if cfg.Repeat != 1 || !cfg.Prescreen {
		t.Fatalf("profile not applied: %+v", cfg)
	}
	cfg = load(checkOptions{profile: "fast", repeat: 3, concurrency: "9", prescreenRetries: 2})
	if cfg.Repeat != 3 || cfg.Concurrency != 9 {
		t.Fatalf("flags did not win: %+v", cfg)
	}
	cfg = load(checkOptions{explicit: map[string]bool{"allow-remote-dns": true}})
	if cfg.AllowRemoteDNS {
		t.Fatal("an explicit false flag must disable a configured boolean")
	}
	cfg = load(checkOptions{targets: stringsFlag{"https://flag.test/"}})
	if slices.Contains(cfg.AllowedHosts, "extra.test") || !slices.Contains(cfg.AllowedHosts, "flag.test") || len(cfg.Targets) != 1 {
		t.Fatalf("explicit targets must replace configured hosts: %+v", cfg.AllowedHosts)
	}
}

func TestOutputStatusAcceptsLists(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	args := []string{"check", "--repeat", "1", "--format", "txt", "--allow-private-targets", "--allow-private-proxies", "--target", target}
	if code, out, diag := run(append(args, "--output-status", "failed,ok"), proxy+"\n"); code != ExitOK || !strings.Contains(out, proxy) {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	if code, out, _ := run(append(args, "--output-status", "failed"), proxy+"\n"); code != ExitOK || strings.Contains(out, proxy) {
		t.Fatalf("filtered status printed: code=%d out=%q", code, out)
	}
	if code, _, _ := run(append(args, "--output-status", "nope"), proxy+"\n"); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
}

func TestInspectLeavesNoFileAndReadsStandardInput(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	flags := []string{"--allow-private-targets", "--allow-private-proxies", "--target", target}
	for _, args := range [][]string{
		append([]string{"inspect", proxy}, flags...),
		append(append([]string{"inspect"}, flags...), proxy),
	} {
		code, out, diag := run(args, "")
		if code != ExitOK || !strings.Contains(out, proxy) {
			t.Fatalf("args=%v code=%d out=%q diag=%q", args, code, out, diag)
		}
	}
	code, out, diag := run(append([]string{"inspect", "-"}, flags...), "http://user:secret@"+proxy+"\nignored:1\n")
	if code != ExitOK || !strings.Contains(out, proxy) || strings.Contains(out, "secret") || strings.Contains(out, "ignored") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary files=%v err=%v", entries, err)
	}
	for _, args := range [][]string{{"inspect"}, {"inspect", "a:1", "b:2"}} {
		if code, _, _ := run(args, ""); code != ExitUsage {
			t.Fatalf("%v code=%d", args, code)
		}
	}
}

func TestDoctorReportsPrescreenWorkers(t *testing.T) {
	code, out, diag := run([]string{"doctor"}, "")
	if code != ExitOK || !strings.Contains(out, "prescreen      OK") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
}

func TestSaveGzipWorksWithEveryReader(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	if code, _, diag := run(checkArgs(target, "--save", "--save-gzip", "--data-dir", dir), proxy+"\n"); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "runs", "*.jsonl.gz"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("matches=%v err=%v", matches, err)
	}
	assertPrivateMode(t, matches[0])
	for _, args := range [][]string{
		{"results", "--data-dir", dir, "--format", "txt"},
		{"export", "--data-dir", dir, "--format", "txt"},
		{"stats", "--data-dir", dir},
		{"pool", "--data-dir", dir},
		{"history", "--data-dir", dir},
	} {
		if code, out, diag := run(args, ""); code != ExitOK || out == "" {
			t.Fatalf("%v code=%d out=%q diag=%q", args, code, out, diag)
		}
	}
	if code, _, _ := run(checkArgs(target, "--save-gzip"), proxy+"\n"); code != ExitUsage {
		t.Fatalf("save-gzip without save code=%d", code)
	}
}

func TestSaveStatusAcceptsSavingFromEnvironment(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	t.Setenv("NETVEX_SAVE", "true")
	t.Setenv("NETVEX_DATA_DIR", dir)
	if code, _, diag := run(checkArgs(target, "--save-status", "ok"), proxy+"\n"); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
}

func TestCheckHelpGroupsEveryFlagOnce(t *testing.T) {
	fs, _ := CLI{}.newFlagSet("check")
	var options checkOptions
	CLI{}.addCheckFlags(fs, &options)
	seen := map[string]string{}
	for _, group := range checkFlagGroups {
		for _, name := range group.names {
			if previous, duplicate := seen[name]; duplicate {
				t.Fatalf("%s is in %q and %q", name, previous, group.title)
			}
			if fs.Lookup(name) == nil {
				t.Fatalf("%s in %q is not a flag", name, group.title)
			}
			seen[name] = group.title
		}
	}
	fs.VisitAll(func(option *flag.Flag) {
		if _, grouped := seen[option.Name]; !grouped {
			t.Fatalf("--%s has no help group", option.Name)
		}
	})
	code, out, _ := run([]string{"check", "--help"}, "")
	if code != ExitOK || !strings.Contains(out, "Speed and concurrency:") || !strings.Contains(out, "-prescreen-concurrency") || !strings.Contains(out, `(default "all")`) {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestCheckpointRejectsChangedCertificatePins(t *testing.T) {
	first := checkpointFingerprint(config.Config{Targets: []string{"https://a.test/"}}, model.ProtocolHTTP)
	second := checkpointFingerprint(config.Config{Targets: []string{"https://a.test/"}, PinSHA256: []string{strings.Repeat("a", 64)}}, model.ProtocolHTTP)
	if first == second {
		t.Fatal("certificate pins must be part of the verdict fingerprint")
	}
}

func TestUnknownCommandSuggestsTheClosestOne(t *testing.T) {
	code, _, diag := run([]string{"chek"}, "")
	if code != ExitUsage || !strings.Contains(diag, `did you mean "check"`) {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	if code, _, diag := run([]string{"INSPECT"}, ""); code != ExitUsage || !strings.Contains(diag, `"inspect"`) {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	if code, _, diag := run([]string{"completely-different"}, ""); code != ExitUsage || strings.Contains(diag, "did you mean") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
}

func TestCheckExplainsMissingInputOnTerminals(t *testing.T) {
	var out, diag strings.Builder
	cli := CLI{Stdout: &out, Stderr: &diag, Stdin: strings.NewReader(""), InputTerminal: true}
	if code := cli.Run([]string{"check", "--target", "http://127.0.0.1:9/"}); code != ExitUsage || !strings.Contains(diag.String(), "no proxies given") {
		t.Fatalf("code=%d diag=%q", code, diag.String())
	}
	diag.Reset()
	if code := cli.Run([]string{"check", "--target", "http://127.0.0.1:9/", "-"}); code == ExitUsage {
		t.Fatalf("explicit stdin refused: %q", diag.String())
	}
}

func TestRunsPruneOlderThan(t *testing.T) {
	proxy, target := connectProxy(t), echoTarget(t)
	dir := t.TempDir()
	if code, _, diag := run(checkArgs(target, "--save", "--data-dir", dir), proxy+"\n"); code != ExitOK {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	code, _, diag := run([]string{"runs", "prune", "--data-dir", dir, "--keep", "0", "--older-than", "30d", "--execute"}, "")
	if code != ExitOK || !strings.Contains(diag, "removed=0") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	if code, _, diag := run([]string{"runs", "prune", "--data-dir", dir, "--keep", "0", "--older-than", "soon"}, ""); code != ExitUsage || !strings.Contains(diag, "older-than") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	for value, want := range map[string]time.Duration{"30d": 720 * time.Hour, "12h": 12 * time.Hour} {
		if age, err := parseAge(value); err != nil || age != want {
			t.Fatalf("%s: %v %v", value, age, err)
		}
	}
	for _, value := range []string{"0d", "-1h", "d", ""} {
		if _, err := parseAge(value); err == nil {
			t.Fatalf("%q accepted", value)
		}
	}
}

func TestParseAgeBounds(t *testing.T) {
	for value, want := range map[string]time.Duration{"30d": 720 * time.Hour, "12h": 12 * time.Hour} {
		if age, err := parseAge(value); err != nil || age != want {
			t.Fatalf("%s: %v %v", value, age, err)
		}
	}
	for _, value := range []string{"0d", "-1h", "d", "", "999999999999999999d"} {
		if _, err := parseAge(value); err == nil {
			t.Fatalf("%q accepted", value)
		}
	}
}

func TestCompletionsCoverEveryCommand(t *testing.T) {
	code, bash, _ := run([]string{"completion", "bash"}, "")
	if code != ExitOK || !strings.Contains(bash, "--help 2>&1") || !strings.Contains(bash, "diff") {
		t.Fatalf("code=%d bash=%q", code, bash)
	}
	if _, err := exec.LookPath("bash"); err == nil {
		check := exec.Command("bash", "-n")
		check.Stdin = strings.NewReader(bash)
		if output, err := check.CombinedOutput(); err != nil {
			t.Fatalf("generated bash does not parse: %v %s", err, output)
		}
	}
	code, fish, _ := run([]string{"completion", "fish"}, "")
	if code != ExitOK || !strings.Contains(fish, "__fish_seen_subcommand_from results") {
		t.Fatalf("code=%d fish=%q", code, fish)
	}
}
