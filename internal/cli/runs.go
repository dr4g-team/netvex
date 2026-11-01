package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/drag-team/netvex/internal/config"
	historypkg "github.com/drag-team/netvex/internal/history"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/output"
	"github.com/drag-team/netvex/internal/store"
)

func (c CLI) runs(args []string) int {
	action := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	fs, buf := c.newFlagSet("runs")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	limit := fs.Int("limit", 50, "maximum runs to list")
	jsonOut := fs.Bool("json", false, "emit a JSON array")
	keep := fs.Int("keep", 20, "newest runs to retain when pruning")
	execute := fs.Bool("execute", false, "apply prune; without this flag only show the plan")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if action == "prune" {
		if *keep < 0 || *keep > 1_000_000 {
			fmt.Fprintln(c.Stderr, "keep must be between 0 and 1000000")
			return ExitUsage
		}
		ids, err := store.PruneRuns(*data, *keep, *execute)
		if err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		verb := "would_remove"
		if *execute {
			verb = "removed"
		}
		for _, id := range ids {
			fmt.Fprintln(c.Stdout, id)
		}
		fmt.Fprintf(c.Stderr, "%s=%d keep=%d\n", verb, len(ids), *keep)
		return ExitOK
	}
	if action != "list" {
		fmt.Fprintln(c.Stderr, "runs action must be list or prune")
		return ExitUsage
	}
	if *limit < 1 || *limit > 10000 {
		fmt.Fprintln(c.Stderr, "limit must be between 1 and 10000")
		return ExitUsage
	}
	runs, err := store.ListRuns(*data, *limit)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	if *jsonOut {
		enc := json.NewEncoder(c.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(runs); err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		return ExitOK
	}
	fmt.Fprintln(c.Stdout, "RUN                                      STARTED               PROCESSED  OK      UNREL   FAILED  INCONCL  RATE/S")
	for _, run := range runs {
		fmt.Fprintf(c.Stdout, "%-40s %-21s %9d  %6d  %6d  %6d  %7d  %6.1f\n", run.RunID, run.StartedAt.UTC().Format("2006-01-02 15:04:05Z"), run.Processed, run.Successful, run.Unreliable, run.Failed, run.Inconclusive, run.RatePerSec)
	}
	return ExitOK
}

func (c CLI) stats(args []string) int {
	fs, buf := c.newFlagSet("stats")
	run := fs.String("run", "latest", "run ID or path")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	jsonOut := fs.Bool("json", false, "JSON output")
	prometheusOut := fs.Bool("prometheus", false, "Prometheus text exposition output")
	compare := fs.String("compare", "", "baseline run ID or path")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *jsonOut && *prometheusOut {
		fmt.Fprintln(c.Stderr, "json and prometheus output are mutually exclusive")
		return ExitUsage
	}
	if *prometheusOut && *compare != "" {
		fmt.Fprintln(c.Stderr, "prometheus output does not support run comparison")
		return ExitUsage
	}
	path, err := store.ResolveRun(*data, *run)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	s, err := store.ReadSummary(path)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	if *compare != "" {
		basePath, e := store.ResolveRun(*data, *compare)
		if e != nil {
			fmt.Fprintln(c.Stderr, e)
			return ExitOperational
		}
		base, e := store.ReadSummary(basePath)
		if e != nil {
			fmt.Fprintln(c.Stderr, e)
			return ExitOperational
		}
		delta := map[string]any{"successful": s.Successful - base.Successful, "unreliable": s.Unreliable - base.Unreliable, "failed": s.Failed - base.Failed, "inconclusive": s.Inconclusive - base.Inconclusive, "rate_per_sec": s.RatePerSec - base.RatePerSec, "latency_p50_ms": s.LatencyP50MS - base.LatencyP50MS, "latency_p95_ms": s.LatencyP95MS - base.LatencyP95MS, "latency_p99_ms": s.LatencyP99MS - base.LatencyP99MS}
		if *jsonOut {
			b, _ := json.MarshalIndent(map[string]any{"current": s, "baseline": base, "delta": delta}, "", "  ")
			fmt.Fprintln(c.Stdout, string(b))
		} else {
			fmt.Fprintf(c.Stdout, "current=%s baseline=%s ok_delta=%d unreliable_delta=%d failed_delta=%d inconclusive_delta=%d rate_delta=%+.1f/s p50_delta=%+.0fms p95_delta=%+.0fms p99_delta=%+.0fms\n", s.RunID, base.RunID, s.Successful-base.Successful, s.Unreliable-base.Unreliable, s.Failed-base.Failed, s.Inconclusive-base.Inconclusive, s.RatePerSec-base.RatePerSec, s.LatencyP50MS-base.LatencyP50MS, s.LatencyP95MS-base.LatencyP95MS, s.LatencyP99MS-base.LatencyP99MS)
		}
		return ExitOK
	}
	if *prometheusOut {
		if err := output.WritePrometheusSummary(c.Stdout, s); err != nil {
			if errors.Is(err, syscall.EPIPE) {
				return ExitOK
			}
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		return ExitOK
	}
	if *jsonOut {
		b, _ := json.MarshalIndent(s, "", "  ")
		fmt.Fprintln(c.Stdout, string(b))
	} else {
		fmt.Fprintf(c.Stdout, "run=%s processed=%d restored=%d attempts=%d ok=%d unreliable=%d failed=%d inconclusive=%d timeouts=%d rate=%.1f/s duration=%.0fms p50=%.0fms p95=%.0fms p99=%.0fms\n", s.RunID, s.Processed, s.Restored, s.Attempts, s.Successful, s.Unreliable, s.Failed, s.Inconclusive, s.Timeouts, s.RatePerSec, s.DurationMS, s.LatencyP50MS, s.LatencyP95MS, s.LatencyP99MS)
		if top := topCounts(s.FailureCodes, 10); top != "" {
			fmt.Fprintln(c.Stdout, "top_failures="+top)
		}
	}
	return ExitOK
}

func (c CLI) history(args []string) int {
	fs, buf := c.newFlagSet("history")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	runLimit := fs.Int("runs", 20, "newest saved runs to analyze")
	resultLimit := fs.Int("max-load", 1_000_000, "maximum results to read")
	limit := fs.Int("limit", 1000, "maximum trend rows")
	search := fs.String("search", "", "endpoint substring")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *runLimit < 1 || *runLimit > 10_000 || *resultLimit < 1 || *resultLimit > 10_000_000 || *limit < 1 || *limit > 1_000_000 {
		fmt.Fprintln(c.Stderr, "runs, max-load, or limit is outside safe bounds")
		return ExitUsage
	}
	runs, err := store.ListRuns(*data, *runLimit)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	if len(runs) == 0 {
		fmt.Fprintln(c.Stderr, "no saved runs")
		return ExitOperational
	}
	analyzer := historypkg.New()
	loaded := 0
	for i := len(runs) - 1; i >= 0; i-- {
		path, resolveErr := store.ResolveRun(*data, runs[i].RunID)
		if resolveErr != nil {
			fmt.Fprintln(c.Stderr, resolveErr)
			return ExitOperational
		}
		if readErr := store.ReadResults(path, func(result model.Result) error {
			loaded++
			if loaded > *resultLimit {
				return errors.New("history result limit exceeded")
			}
			analyzer.Add(result)
			return nil
		}); readErr != nil {
			fmt.Fprintln(c.Stderr, readErr)
			return ExitOperational
		}
	}
	trends := analyzer.Results()
	filtered := trends[:0]
	for _, trend := range trends {
		if *search == "" || strings.Contains(strings.ToLower(trend.Endpoint), strings.ToLower(*search)) {
			filtered = append(filtered, trend)
			if len(filtered) >= *limit {
				break
			}
		}
	}
	if *jsonOut {
		encoder := json.NewEncoder(c.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(filtered); err != nil {
			return ExitOperational
		}
		return ExitOK
	}
	fmt.Fprintln(c.Stdout, "AVAIL   CHECKS  STREAK  CHANGES  EXITS  MEDIAN    ENDPOINT")
	for _, trend := range filtered {
		fmt.Fprintf(c.Stdout, "%6.1f%%  %6d  %6d  %7d  %5d  %7.0fms  %s\n", trend.Availability*100, trend.Checks, trend.ConsecutiveSuccess, trend.StatusChanges, trend.UniqueExitIPs, trend.MedianLatencyMS, trend.Endpoint)
	}
	return ExitOK
}

func (c CLI) pool(args []string) int {
	fs, buf := c.newFlagSet("pool")
	run := fs.String("run", "latest", "run ID or path")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	maxLoad := fs.Int("max-load", 1_000_000, "maximum results to load")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *maxLoad < 1 || *maxLoad > 10_000_000 {
		fmt.Fprintln(c.Stderr, "max-load is outside safe bounds")
		return ExitUsage
	}
	path, err := store.ResolveRun(*data, *run)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	results := make([]model.Result, 0, min(*maxLoad, 4096))
	if err := store.ReadResults(path, func(result model.Result) error {
		if len(results) >= *maxLoad {
			return errors.New("pool result limit exceeded")
		}
		results = append(results, result)
		return nil
	}); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	pools := historypkg.Pools(results)
	if *jsonOut {
		encoder := json.NewEncoder(c.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(pools); err != nil {
			return ExitOperational
		}
		return ExitOK
	}
	fmt.Fprintln(c.Stdout, "LABEL                 PROXIES  OK      EXITS  SUBNETS  ASNS  ASN_SHARE  MEDIAN")
	for _, pool := range pools {
		fmt.Fprintf(c.Stdout, "%-21s %7d  %6.1f%%  %5d  %7d  %4d  %8.1f%%  %.0fms\n", pool.Label, pool.Proxies, pool.SuccessRate*100, pool.UniqueExitIPs, pool.UniqueSubnets, pool.UniqueASNs, pool.ASNConcentration*100, pool.MedianLatencyMS)
	}
	return ExitOK
}
