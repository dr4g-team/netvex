package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drag-team/netvex/internal/model"
)

func TestAtomicRunAndRead(t *testing.T) {
	d := t.TempDir()
	w, err := NewRunWriter(d)
	if err != nil {
		t.Fatal(err)
	}
	r := model.Result{ID: "x", Proxy: "http://u:***@host:80", Status: model.StatusOK}
	if err := w.Write(r); err != nil {
		t.Fatal(err)
	}
	s := model.RunSummary{RunID: w.ID, StartedAt: time.Now(), Processed: 1, Successful: 1}
	if err := w.Commit(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(w.Path()); err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := ReadResults(w.Path(), func(g model.Result) error {
		n++
		if strings.Contains(g.Proxy, "secret") {
			t.Fatal("secret leaked")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("n=%d", n)
	}
	latest, err := ResolveRun(d, "latest")
	if err != nil || latest != w.Path() {
		t.Fatalf("latest=%s err=%v", latest, err)
	}
}

func TestListRunsNewestFirst(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		w, err := NewRunWriter(dir)
		if err != nil {
			t.Fatal(err)
		}
		s := model.RunSummary{SchemaVersion: model.SchemaVersion, RunID: w.ID, StartedAt: time.Now(), Processed: i + 1}
		if err := w.Commit(s); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := ListRuns(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].RunID <= runs[1].RunID {
		t.Fatalf("unexpected order: %+v", runs)
	}
	empty, err := ListRuns(filepath.Join(dir, "missing"), 10)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list: %+v %v", empty, err)
	}
	plan, err := PruneRuns(dir, 1, time.Time{}, false)
	if err != nil || len(plan) != 1 {
		t.Fatalf("prune plan=%v err=%v", plan, err)
	}
	if runs, _ := ListRuns(dir, 10); len(runs) != 2 {
		t.Fatal("dry-run removed data")
	}
	removed, err := PruneRuns(dir, 1, time.Time{}, true)
	if err != nil || len(removed) != 1 {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	if runs, _ := ListRuns(dir, 10); len(runs) != 1 {
		t.Fatalf("unexpected retained runs: %+v", runs)
	}
}

func benchmarkResult() model.Result {
	return model.Result{SchemaVersion: model.SchemaVersion, ID: "0123456789abcdef01234567", Proxy: "http://203.0.113.9:8080", Endpoint: "203.0.113.9:8080", Protocol: model.ProtocolHTTP, Status: model.StatusTimeout, Attempts: 1, RequiredSuccesses: 1,
		Observations: []model.Observation{{Attempt: 1, Protocol: model.ProtocolHTTP, Target: "https://example.com/", Status: model.StatusTimeout, Stage: model.StageConnect, Code: "deadline_exceeded", Message: "operation timed out", Anonymity: "unavailable", Timings: model.Timings{TotalMS: 1000.5}}},
		Rotation:     model.RotationProfile{Classification: "unavailable"}, Score: model.Score{Confidence: "insufficient", Reason: "at least two measurements are required for a numeric score"}}
}

func BenchmarkRunWriter(b *testing.B) {
	writer, err := NewRunWriter(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer writer.Abort()
	result := benchmarkResult()
	b.ReportAllocs()
	for b.Loop() {
		if err := writer.Write(result); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCompressedRunsBehaveLikePlainRuns(t *testing.T) {
	dir := t.TempDir()
	plain, err := NewRunWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Write(benchmarkResult()); err != nil {
		t.Fatal(err)
	}
	if err := plain.Commit(model.RunSummary{RunID: plain.ID, Processed: 1}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	compressed, err := NewCompressedRunWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := compressed.Write(benchmarkResult()); err != nil {
			t.Fatal(err)
		}
	}
	if err := compressed.Commit(model.RunSummary{RunID: compressed.ID, Processed: 3}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(compressed.Path(), ".jsonl.gz") {
		t.Fatalf("path=%s", compressed.Path())
	}
	raw, err := os.ReadFile(compressed.Path())
	if err != nil || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatalf("not gzip: err=%v", err)
	}
	for _, reference := range []string{"latest", compressed.ID, compressed.ID + ".jsonl", compressed.ID + ".jsonl.gz", compressed.Path()} {
		path, err := ResolveRun(dir, reference)
		if err != nil || path != compressed.Path() {
			t.Fatalf("%s resolved to %s err=%v", reference, path, err)
		}
	}
	count := 0
	if err := ReadResults(compressed.Path(), func(model.Result) error { count++; return nil }); err != nil || count != 3 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	summary, err := ReadSummary(compressed.Path())
	if err != nil || summary.Processed != 3 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	if runs, err := ListRuns(dir, 10); err != nil || len(runs) != 2 {
		t.Fatalf("runs=%d err=%v", len(runs), err)
	}
	if _, err := PruneRuns(dir, 0, time.Time{}, true); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "runs")); err != nil || len(entries) != 0 {
		t.Fatalf("prune left %v err=%v", entries, err)
	}
}

func TestCorruptCompressedRunIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl.gz")
	if err := os.WriteFile(path, []byte{0x1f, 0x8b, 0, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ReadResults(path, func(model.Result) error { return nil }); err == nil {
		t.Fatal("corrupt run accepted")
	}
	if _, err := ResolveRun(t.TempDir(), "/tmp/run.txt"); err == nil {
		t.Fatal("non-run path accepted")
	}
}

func TestOversizedResultIsRefusedWithoutStoppingTheWriter(t *testing.T) {
	writer, err := NewRunWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Abort()
	var encoder resultEncoder
	if _, err := encoder.encode(strings.Repeat("x", MaxResultBytes+1)); err == nil {
		t.Fatal("oversized record accepted")
	}
	if err := writer.Write(benchmarkResult()); err != nil {
		t.Fatal(err)
	}
}

func TestReadResultsRejectsTerminalControlEvidence(t *testing.T) {
	result := benchmarkResult()
	result.Observations[0].Message = "remote\x1b[2Jdiagnostic"
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hostile.jsonl")
	if err := os.WriteFile(path, append(payload, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ReadResults(path, func(model.Result) error { return nil }); err == nil || !strings.Contains(err.Error(), "structural limits") {
		t.Fatalf("terminal control evidence accepted: %v", err)
	}
}

func TestReadSummaryRejectsUnsafeIdentityAndFilenameMismatch(t *testing.T) {
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	if err := os.MkdirAll(runs, 0700); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(runs, "safe.jsonl")
	if err := os.WriteFile(resultPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	writeSummary := func(summary model.RunSummary) {
		t.Helper()
		payload, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runs, "safe.summary.json"), payload, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeSummary(model.RunSummary{RunID: "bad\x1b[2J"})
	if _, err := ReadSummary(resultPath); err == nil {
		t.Fatal("unsafe run ID accepted")
	}
	writeSummary(model.RunSummary{RunID: "different"})
	if _, err := ListRuns(dir, 10); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched run ID accepted: %v", err)
	}
}

func TestPruneRequiresBothCountAndAge(t *testing.T) {
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	if err := os.MkdirAll(runs, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-48*time.Hour).Format("20060102T150405.000000000Z") + "-aaaa"
	recent := now.Add(-time.Hour).Format("20060102T150405.000000000Z") + "-bbbb"
	newest := now.Format("20060102T150405.000000000Z") + "-cccc"
	for _, id := range []string{old, recent, newest, "manual-name"} {
		if err := os.WriteFile(filepath.Join(runs, id+".summary.json"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := PruneRuns(dir, 1, now.Add(-24*time.Hour), false)
	if err != nil || len(plan) != 1 || plan[0] != old {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	if plan, err := PruneRuns(dir, 5, now, false); err != nil || len(plan) != 0 {
		t.Fatalf("keep ignored: %v err=%v", plan, err)
	}
}
