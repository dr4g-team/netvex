package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/drag-team/netvex/internal/model"
)

func TestPrometheusSummaryIsAggregateAndDeterministic(t *testing.T) {
	summary := model.RunSummary{
		Input:     model.InputStats{Read: 9, Accepted: 7, Duplicates: 1, Rejected: 1, Resumed: 2},
		Processed: 7, Attempts: 12, Successful: 4, Failed: 1, Inconclusive: 1, Unreliable: 1, Timeouts: 2,
		DurationMS: 1500, RatePerSec: 3.5, LatencyP50MS: 10, LatencyP95MS: 20, LatencyP99MS: 30,
		Quality: &model.QualityReport{Passed: true},
		Targets: map[string]model.TargetSummary{"secret-target.example": {}},
	}
	var first, second bytes.Buffer
	if err := WritePrometheusSummary(&first, summary); err != nil {
		t.Fatal(err)
	}
	if err := WritePrometheusSummary(&second, summary); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() || !strings.Contains(first.String(), `netvex_run_results{status="ok"} 4`) || !strings.Contains(first.String(), "netvex_run_quality_passed 1") {
		t.Fatalf("metrics=%q", first.String())
	}
	if strings.Contains(first.String(), "secret-target") {
		t.Fatal("target identity leaked into aggregate metrics")
	}
}
