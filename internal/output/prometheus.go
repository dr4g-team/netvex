package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/drag-team/netvex/internal/model"
)

// WritePrometheusSummary writes one bounded, aggregate-only snapshot suitable
// for a Prometheus textfile collector. It deliberately excludes proxy and
// target labels to avoid credentials, endpoint disclosure, and high cardinality.
func WritePrometheusSummary(destination io.Writer, summary model.RunSummary) error {
	var output strings.Builder
	output.Grow(2048)
	output.WriteString("# HELP netvex_run_results Results in the completed validation run.\n")
	output.WriteString("# TYPE netvex_run_results gauge\n")
	fmt.Fprintf(&output, "netvex_run_results{status=\"ok\"} %d\n", summary.Successful)
	fmt.Fprintf(&output, "netvex_run_results{status=\"unreliable\"} %d\n", summary.Unreliable)
	fmt.Fprintf(&output, "netvex_run_results{status=\"inconclusive\"} %d\n", summary.Inconclusive)
	fmt.Fprintf(&output, "netvex_run_results{status=\"failed\"} %d\n", summary.Failed)
	output.WriteString("# HELP netvex_run_input_records Input records observed by the parser.\n")
	output.WriteString("# TYPE netvex_run_input_records gauge\n")
	fmt.Fprintf(&output, "netvex_run_input_records{outcome=\"read\"} %d\n", summary.Input.Read)
	fmt.Fprintf(&output, "netvex_run_input_records{outcome=\"accepted\"} %d\n", summary.Input.Accepted)
	fmt.Fprintf(&output, "netvex_run_input_records{outcome=\"duplicate\"} %d\n", summary.Input.Duplicates)
	fmt.Fprintf(&output, "netvex_run_input_records{outcome=\"rejected\"} %d\n", summary.Input.Rejected)
	fmt.Fprintf(&output, "netvex_run_input_records{outcome=\"resumed\"} %d\n", summary.Input.Resumed)
	output.WriteString("# HELP netvex_run_attempts Validation attempts in the completed run.\n")
	output.WriteString("# TYPE netvex_run_attempts gauge\n")
	fmt.Fprintf(&output, "netvex_run_attempts %d\n", summary.Attempts)
	output.WriteString("# HELP netvex_run_timeouts Timed-out validation attempts.\n")
	output.WriteString("# TYPE netvex_run_timeouts gauge\n")
	fmt.Fprintf(&output, "netvex_run_timeouts %d\n", summary.Timeouts)
	output.WriteString("# HELP netvex_run_duration_seconds Completed run duration in seconds.\n")
	output.WriteString("# TYPE netvex_run_duration_seconds gauge\n")
	fmt.Fprintf(&output, "netvex_run_duration_seconds %.6f\n", summary.DurationMS/1000)
	output.WriteString("# HELP netvex_run_rate_per_second Newly processed proxies per second.\n")
	output.WriteString("# TYPE netvex_run_rate_per_second gauge\n")
	fmt.Fprintf(&output, "netvex_run_rate_per_second %.6f\n", summary.RatePerSec)
	output.WriteString("# HELP netvex_run_latency_milliseconds Successful-request latency quantiles.\n")
	output.WriteString("# TYPE netvex_run_latency_milliseconds gauge\n")
	fmt.Fprintf(&output, "netvex_run_latency_milliseconds{quantile=\"0.50\"} %.6f\n", summary.LatencyP50MS)
	fmt.Fprintf(&output, "netvex_run_latency_milliseconds{quantile=\"0.95\"} %.6f\n", summary.LatencyP95MS)
	fmt.Fprintf(&output, "netvex_run_latency_milliseconds{quantile=\"0.99\"} %.6f\n", summary.LatencyP99MS)
	if summary.Quality != nil {
		passed := 0
		if summary.Quality.Passed {
			passed = 1
		}
		output.WriteString("# HELP netvex_run_quality_passed Whether every configured quality gate passed.\n")
		output.WriteString("# TYPE netvex_run_quality_passed gauge\n")
		fmt.Fprintf(&output, "netvex_run_quality_passed %d\n", passed)
	}
	_, err := io.WriteString(destination, output.String())
	return err
}
