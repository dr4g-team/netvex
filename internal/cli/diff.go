package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/drag-team/netvex/internal/config"
	historypkg "github.com/drag-team/netvex/internal/history"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/store"
)

func (c CLI) diff(args []string) int {
	fs, buf := c.newFlagSet("diff")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	jsonOut := fs.Bool("json", false, "emit JSON")
	maxLoad := fs.Int("max-load", 1_000_000, "maximum results loaded from each run")
	limit := fs.Int("limit", 1000, "maximum listed changes")
	latencyChange := fs.Float64("latency-change", 50, "median latency change in percent reported as slower or faster")
	only := fs.String("only", "", "comma-separated changes: died, revived, added, removed, slower, faster")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if fs.NArg() > 2 || *maxLoad < 1 || *maxLoad > 10_000_000 || *limit < 1 || *latencyChange <= 0 {
		fmt.Fprintln(c.Stderr, "usage: netvex diff [BASE [CURRENT]]; max-load, limit, and latency-change must be positive")
		return ExitUsage
	}
	filter, err := parseDiffFilter(*only)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	basePath, currentPath, err := diffRuns(*data, fs.Args())
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	base, err := loadSnapshots(basePath, *maxLoad)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	current, err := loadSnapshots(currentPath, *maxLoad)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	report := historypkg.Diff(base, current, *latencyChange)
	entries := make([]historypkg.DiffEntry, 0, len(report.Entries))
	for _, entry := range report.Entries {
		if len(filter) == 0 || filter[entry.Change] {
			entries = append(entries, entry)
		}
	}
	report.Truncated = len(entries) > *limit
	if report.Truncated {
		entries = entries[:*limit]
	}
	report.Entries = entries
	if *jsonOut {
		encoder := json.NewEncoder(c.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return ExitOperational
		}
		return ExitOK
	}
	fmt.Fprintf(c.Stdout, "died=%d revived=%d added=%d removed=%d slower=%d faster=%d unchanged=%d\n", report.Counts[historypkg.ChangeDied], report.Counts[historypkg.ChangeRevived], report.Counts[historypkg.ChangeAdded], report.Counts[historypkg.ChangeRemoved], report.Counts[historypkg.ChangeSlower], report.Counts[historypkg.ChangeFaster], report.Unchanged)
	if len(report.Entries) > 0 {
		fmt.Fprintln(c.Stdout, "CHANGE   BASE          CURRENT       BASE_MS  CURRENT_MS  PROTOCOL  ENDPOINT")
	}
	for _, entry := range report.Entries {
		fmt.Fprintf(c.Stdout, "%-8s %-13s %-13s %7.0f  %10.0f  %-8s  %s\n", entry.Change, dash(string(entry.BaseStatus)), dash(string(entry.CurrentStatus)), entry.BaseMedianMS, entry.CurrentMedianMS, entry.Protocol, entry.Endpoint)
	}
	return ExitOK
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func parseDiffFilter(value string) (map[historypkg.Change]bool, error) {
	filter := map[historypkg.Change]bool{}
	if value == "" {
		return filter, nil
	}
	for _, name := range strings.Split(value, ",") {
		change := historypkg.Change(strings.TrimSpace(name))
		switch change {
		case historypkg.ChangeDied, historypkg.ChangeRevived, historypkg.ChangeAdded, historypkg.ChangeRemoved, historypkg.ChangeSlower, historypkg.ChangeFaster:
			filter[change] = true
		default:
			return nil, fmt.Errorf("unknown change %q", name)
		}
	}
	return filter, nil
}

// diffRuns defaults to comparing the two newest saved runs.
func diffRuns(dataDir string, args []string) (string, string, error) {
	if len(args) == 2 {
		base, err := store.ResolveRun(dataDir, args[0])
		if err != nil {
			return "", "", err
		}
		current, err := store.ResolveRun(dataDir, args[1])
		return base, current, err
	}
	if len(args) == 1 {
		base, err := store.ResolveRun(dataDir, args[0])
		if err != nil {
			return "", "", err
		}
		current, err := store.ResolveRun(dataDir, "latest")
		return base, current, err
	}
	runs, err := store.ListRuns(dataDir, 2)
	if err != nil {
		return "", "", err
	}
	if len(runs) < 2 {
		return "", "", errors.New("diff requires two saved runs")
	}
	base, err := store.ResolveRun(dataDir, runs[1].RunID)
	if err != nil {
		return "", "", err
	}
	current, err := store.ResolveRun(dataDir, runs[0].RunID)
	return base, current, err
}

func loadSnapshots(path string, limit int) (map[string]historypkg.Snapshot, error) {
	snapshots := make(map[string]historypkg.Snapshot)
	err := store.ReadResults(path, func(result model.Result) error {
		if len(snapshots) >= limit {
			return errors.New("diff load limit exceeded; increase --max-load")
		}
		snapshots[result.ID] = historypkg.Snapshot{Endpoint: result.Endpoint, Protocol: result.Protocol, Status: result.Status, MedianMS: result.Score.MedianMS}
		return nil
	})
	return snapshots, err
}
