package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drag-team/netvex/internal/model"
)

func TestEvaluateAndJUnit(t *testing.T) {
	maximum := 0.2
	summary := model.RunSummary{Processed: 10, Successful: 7, Failed: 3, LatencyP95MS: 200}
	report := Evaluate(Policy{SchemaVersion: 1, MinSuccessRate: .8, MaxFailureRate: &maximum}, summary)
	if report.Passed || len(report.Checks) != 2 {
		t.Fatalf("report=%+v", report)
	}
	summary.Quality = &report
	payload, err := JUnit(summary)
	if err != nil || !strings.Contains(string(payload), `failures="1"`) || !strings.Contains(string(payload), "min_success_rate") {
		t.Fatalf("payload=%s err=%v", payload, err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestEvaluateCoversEveryGate(t *testing.T) {
	limit := 0.1
	policy := Policy{SchemaVersion: 1, MinProcessed: 10, MinSuccessful: 5, MinSuccessRate: .5, MaxFailureRate: &limit, MaxInconclusiveRate: &limit, MaxTimeoutRate: &limit, MaxP95MS: 100, MinRatePerSec: 2, RequirePreflight: true, Targets: map[string]float64{"a": .5, "missing": .1}}
	passing := model.RunSummary{Processed: 10, Successful: 9, Failed: 1, Attempts: 10, LatencyP95MS: 90, RatePerSec: 3, TargetHealth: map[string]model.TargetHealth{"a": {Status: "ok"}}, Targets: map[string]model.TargetSummary{"a": {SuccessRate: .9}, "missing": {SuccessRate: .9}}}
	if report := Evaluate(policy, passing); !report.Passed || len(report.Checks) != 11 {
		t.Fatalf("report=%+v", report)
	}
	failing := map[string]model.RunSummary{
		"min_processed":         {Processed: 9},
		"min_successful":        {Processed: 10, Successful: 4},
		"max_failure_rate":      {Processed: 10, Failed: 2, Unreliable: 1},
		"max_inconclusive_rate": {Processed: 10, Inconclusive: 2},
		"max_timeout_rate":      {Processed: 10, Attempts: 10, Timeouts: 2},
		"max_p95_ms":            {Processed: 10, Successful: 9, LatencyP95MS: 101},
		"min_rate_per_sec":      {Processed: 10, RatePerSec: 1},
		"require_preflight":     {TargetHealth: map[string]model.TargetHealth{"a": {Status: "failed"}}},
		"target:missing":        {},
	}
	for name, summary := range failing {
		found := false
		for _, check := range Evaluate(policy, summary).Checks {
			if check.Name == name {
				found = true
				if check.Passed {
					t.Fatalf("%s passed: %+v", name, check)
				}
			}
		}
		if !found {
			t.Fatalf("%s did not run", name)
		}
	}
}

func TestValidateRejectsUnsafePolicies(t *testing.T) {
	negative, excessive := -0.1, 1.5
	for name, policy := range map[string]Policy{
		"schema":    {SchemaVersion: 2},
		"processed": {SchemaVersion: 1, MinProcessed: -1},
		"rate":      {SchemaVersion: 1, MinSuccessRate: 2},
		"failure":   {SchemaVersion: 1, MaxFailureRate: &negative},
		"timeout":   {SchemaVersion: 1, MaxTimeoutRate: &excessive},
		"target":    {SchemaVersion: 1, Targets: map[string]float64{"a": 2}},
	} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := (Policy{SchemaVersion: 1}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestJUnitReportsPassingRunsAndEscapesOutput(t *testing.T) {
	limit := 1.0
	report := Evaluate(Policy{SchemaVersion: 1, MaxFailureRate: &limit, Targets: map[string]float64{`<a&b>`: .1}}, model.RunSummary{Processed: 1, Targets: map[string]model.TargetSummary{`<a&b>`: {SuccessRate: .5}}})
	summary := model.RunSummary{Quality: &report}
	payload, err := JUnit(summary)
	if err != nil || !strings.Contains(string(payload), `failures="0"`) || strings.Contains(string(payload), "<failure") {
		t.Fatalf("payload=%s err=%v", payload, err)
	}
	failing := model.RunSummary{Quality: &model.QualityReport{Checks: []model.QualityCheck{{Name: `<x&y>`, Operator: ">=", Expected: 1}}}}
	payload, err = JUnit(failing)
	if err != nil || strings.Contains(string(payload), "<x&y>") {
		t.Fatalf("unescaped: %s err=%v", payload, err)
	}
}

func TestLoadAcceptsValidPolicyAndRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"min_successful":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	if policy, err := Load(path); err != nil || policy.MinSuccessful != 2 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1}{"schema_version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, err := Load(filepath.Join(filepath.Dir(path), "missing.json")); err == nil {
		t.Fatal("missing policy accepted")
	}
}
