package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"syscall"

	"github.com/drag-team/netvex-go/internal/config"
	"github.com/drag-team/netvex-go/internal/model"
	"github.com/drag-team/netvex-go/internal/output"
	"github.com/drag-team/netvex-go/internal/store"
)

type resultFilter struct {
	status, protocol, search, exitIP, anonymity string
	country, asn, networkType, label, rotation  string
	minUniqueExits                              int
	maxLatency, minScore, minThroughput         float64
}

// addFilterFlags registers the filters shared by results and export. The returned
// filter is populated once the flag set has parsed.
func addFilterFlags(fs *flag.FlagSet) *resultFilter {
	f := &resultFilter{}
	fs.StringVar(&f.status, "status", "", "status filter")
	fs.StringVar(&f.protocol, "protocol", "", "protocol filter")
	fs.StringVar(&f.search, "search", "", "endpoint substring")
	fs.StringVar(&f.exitIP, "exit-ip", "", "observed exit IP filter")
	fs.StringVar(&f.anonymity, "anonymity", "", "anonymity evidence filter")
	fs.StringVar(&f.country, "country", "", "country code or name filter")
	fs.StringVar(&f.asn, "asn", "", "ASN filter, for example AS15169 or 15169")
	fs.StringVar(&f.networkType, "network-type", "", "metadata network type filter")
	fs.StringVar(&f.label, "label", "", "pool label filter")
	fs.StringVar(&f.rotation, "rotation", "", "rotation classification filter")
	fs.IntVar(&f.minUniqueExits, "min-unique-exits", 0, "minimum observed unique exit IPs")
	fs.Float64Var(&f.maxLatency, "max-latency", 0, "maximum median milliseconds")
	fs.Float64Var(&f.minScore, "min-score", 0, "minimum score from 0 to 100")
	fs.Float64Var(&f.minThroughput, "min-throughput-kbps", 0, "minimum observed response throughput")
	return f
}

func matchResult(r model.Result, f resultFilter) bool {
	if f.status != "" && string(r.Status) != f.status {
		return false
	}
	if f.protocol != "" && string(r.Protocol) != f.protocol {
		return false
	}
	if f.search != "" && !strings.Contains(strings.ToLower(r.Endpoint), strings.ToLower(f.search)) {
		return false
	}
	if f.label != "" && !strings.EqualFold(r.Label, f.label) {
		return false
	}
	if f.rotation != "" && !strings.EqualFold(r.Rotation.Classification, f.rotation) {
		return false
	}
	if f.minUniqueExits > 0 && r.Rotation.UniqueExitIPs < f.minUniqueExits {
		return false
	}
	if f.exitIP != "" || f.anonymity != "" || f.country != "" || f.asn != "" || f.networkType != "" {
		matched := false
		for _, o := range r.Observations {
			metadataMatches := f.country == "" && f.asn == "" && f.networkType == ""
			if o.Metadata != nil {
				metadataMatches = (f.country == "" || strings.EqualFold(o.Metadata.CountryCode, f.country) || strings.EqualFold(o.Metadata.Country, f.country)) &&
					(f.asn == "" || strings.EqualFold(o.Metadata.ASN, normalizeASNFilter(f.asn))) &&
					(f.networkType == "" || strings.EqualFold(o.Metadata.NetworkType, f.networkType))
			}
			if (f.exitIP == "" || o.ExitIP == f.exitIP) && (f.anonymity == "" || o.Anonymity == f.anonymity) && metadataMatches {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if f.maxLatency > 0 && (r.Successes == 0 || r.Score.MedianMS > f.maxLatency) {
		return false
	}
	if f.minScore > 0 && (r.Score.Value == nil || *r.Score.Value < f.minScore) {
		return false
	}
	if f.minThroughput > 0 {
		matched := false
		for _, observation := range r.Observations {
			if observation.Status == model.StatusOK && observation.ThroughputKBPS >= f.minThroughput {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func normalizeASNFilter(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || strings.HasPrefix(value, "AS") {
		return value
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return value
		}
	}
	return "AS" + value
}

func validateResultFilter(f resultFilter) error {
	if f.minUniqueExits < 0 {
		return errors.New("min-unique-exits must be non-negative")
	}
	if math.IsNaN(f.maxLatency) || math.IsInf(f.maxLatency, 0) || f.maxLatency < 0 {
		return errors.New("max-latency must be a finite non-negative number")
	}
	if math.IsNaN(f.minScore) || math.IsInf(f.minScore, 0) || f.minScore < 0 || f.minScore > 100 {
		return errors.New("min-score must be between 0 and 100")
	}
	if math.IsNaN(f.minThroughput) || math.IsInf(f.minThroughput, 0) || f.minThroughput < 0 {
		return errors.New("min-throughput-kbps must be a finite non-negative number")
	}
	return nil
}

func (c CLI) results(args []string) int {
	fs, buf := c.newFlagSet("results")
	run := fs.String("run", "latest", "run ID or .jsonl path")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	format := fs.String("format", "table", "output format")
	filter := addFilterFlags(fs)
	limit := fs.Int("limit", 1000, "maximum rows")
	sortBy := fs.String("sort", "", "sort by endpoint, status, score, or latency")
	desc := fs.Bool("descending", false, "reverse sort order")
	maxLoad := fs.Int("max-load", 1_000_000, "maximum records loaded for sorting")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *limit < 1 || *maxLoad < 1 {
		fmt.Fprintln(c.Stderr, "limit and max-load must be positive")
		return ExitUsage
	}
	if err := validateResultFilter(*filter); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	path, err := store.ResolveRun(*data, *run)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	of, err := output.ParseFormat(*format)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	w := output.New(c.Stdout, of, false)
	n := 0
	if *sortBy == "" {
		err = store.ReadResults(path, func(r model.Result) error {
			if matchResult(r, *filter) && n < *limit {
				n++
				return w.WriteResult(r)
			}
			return nil
		})
	} else {
		if *sortBy != "endpoint" && *sortBy != "status" && *sortBy != "score" && *sortBy != "latency" && *sortBy != "unique-exits" {
			fmt.Fprintln(c.Stderr, "sort must be endpoint, status, score, latency, or unique-exits")
			return ExitUsage
		}
		loaded := make([]model.Result, 0, min(*limit, 4096))
		err = store.ReadResults(path, func(r model.Result) error {
			if !matchResult(r, *filter) {
				return nil
			}
			if len(loaded) >= *maxLoad {
				return errors.New("sorting load limit exceeded; narrow filters or increase --max-load")
			}
			loaded = append(loaded, r)
			return nil
		})
		if err == nil {
			sort.SliceStable(loaded, func(i, j int) bool {
				if *desc {
					return resultLess(loaded[j], loaded[i], *sortBy)
				}
				return resultLess(loaded[i], loaded[j], *sortBy)
			})
			for _, r := range loaded {
				if n >= *limit {
					break
				}
				if err = w.WriteResult(r); err != nil {
					break
				}
				n++
			}
		}
	}
	if err == nil {
		err = w.Flush()
	}
	if err != nil {
		if errors.Is(err, syscall.EPIPE) {
			return ExitOK
		}
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	return ExitOK
}

func resultLess(a, b model.Result, field string) bool {
	switch field {
	case "endpoint":
		return a.Endpoint < b.Endpoint
	case "status":
		return a.Status < b.Status
	case "latency":
		return a.Score.MedianMS < b.Score.MedianMS
	case "score":
		av, bv := -1.0, -1.0
		if a.Score.Value != nil {
			av = *a.Score.Value
		}
		if b.Score.Value != nil {
			bv = *b.Score.Value
		}
		return av < bv
	case "unique-exits":
		av, bv := 0, 0
		av = a.Rotation.UniqueExitIPs
		bv = b.Rotation.UniqueExitIPs
		return av < bv
	}
	return false
}

func (c CLI) export(args []string) int {
	fs, buf := c.newFlagSet("export")
	run := fs.String("run", "latest", "run ID or path")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	format := fs.String("format", "jsonl", "json, jsonl, csv, txt")
	out := fs.String("output", "-", "output file or -")
	filter := addFilterFlags(fs)
	force := fs.Bool("force", false, "replace an existing output file")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	path, err := store.ResolveRun(*data, *run)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	of, err := output.ParseFormat(*format)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	if err := validateResultFilter(*filter); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	var dst io.Writer = c.Stdout
	var fileOutput *secureOutput
	if *out != "-" {
		same, sameErr := samePath(path, *out)
		if sameErr != nil {
			fmt.Fprintln(c.Stderr, sameErr)
			return ExitUsage
		}
		if same {
			fmt.Fprintln(c.Stderr, "export output must not overwrite its source run")
			return ExitUsage
		}
		fileOutput, err = openSecureOutput(*out, *force)
		if err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		defer fileOutput.Abort()
		dst = fileOutput
	}
	w := output.New(dst, of, false)
	err = store.ReadResults(path, func(r model.Result) error {
		if matchResult(r, *filter) {
			return w.WriteResult(r)
		}
		return nil
	})
	if err == nil {
		err = w.Flush()
	}
	if err == nil && fileOutput != nil {
		err = fileOutput.Commit()
	}
	if err != nil {
		if errors.Is(err, syscall.EPIPE) {
			return ExitOK
		}
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	return ExitOK
}
