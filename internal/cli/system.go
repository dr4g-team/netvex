package cli

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/drag-team/netvex/internal/config"
	"github.com/drag-team/netvex/internal/engine"
	metadatapkg "github.com/drag-team/netvex/internal/metadata"
	"github.com/drag-team/netvex/internal/model"
)

func (c CLI) configCmd(args []string) int {
	action := "show"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = args[0]
		args = args[1:]
	}
	fs, buf := c.newFlagSet("config")
	path := fs.String("config", "", "configuration file")
	force := fs.Bool("force", false, "replace an existing file when initializing")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	switch action {
	case "show", "validate":
		cfg, err := config.Load(*path)
		if err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitUsage
		}
		if action == "show" {
			b, _ := cfg.MarshalJSON()
			fmt.Fprintln(c.Stdout, string(b))
		} else {
			fmt.Fprintln(c.Stdout, "configuration valid")
		}
		return ExitOK
	case "init":
		if *path == "" {
			*path = filepath.Join(config.Defaults().DataDir, "config.json")
		}
		output, openErr := openSecureOutput(*path, *force)
		if openErr != nil {
			fmt.Fprintln(c.Stderr, openErr)
			return ExitOperational
		}
		defer output.Abort()
		b, _ := config.Defaults().MarshalJSON()
		if err := output.WriteBytes(append(b, '\n')); err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		if err := output.Commit(); err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		fmt.Fprintln(c.Stdout, *path)
		return ExitOK
	default:
		fmt.Fprintln(c.Stderr, "config action must be show, validate, or init")
		return ExitUsage
	}
}

func (c CLI) doctor(args []string) int {
	fs, buf := c.newFlagSet("doctor")
	network := fs.Bool("network", false, "resolve configured targets")
	configPath := fs.String("config", "", "configuration file")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	cfg, err := config.Load(*configPath)
	ok := true
	fmt.Fprintf(c.Stdout, "runtime        OK  %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if soft, hard, available := fileDescriptorLimit(); available {
		fmt.Fprintf(c.Stdout, "resources      OK  cpus=%d nofile_soft=%d nofile_hard=%d\n", runtime.NumCPU(), soft, hard)
		if err == nil && soft < uint64(cfg.Concurrency+64) {
			fmt.Fprintf(c.Stdout, "concurrency    WARN nofile_soft=%d may constrain concurrency=%d\n", soft, cfg.Concurrency)
		}
	} else {
		fmt.Fprintf(c.Stdout, "resources      OK  cpus=%d nofile=unavailable\n", runtime.NumCPU())
	}
	var checker *engine.Checker
	if err != nil {
		fmt.Fprintln(c.Stdout, "configuration FAIL", err)
		ok = false
	} else {
		fmt.Fprintln(c.Stdout, "configuration OK")
		checker = engine.NewChecker(cfg)
		if tlsErr := checker.ConfigureCABundles(cfg.CABundle, cfg.ProxyCABundle); tlsErr != nil {
			fmt.Fprintln(c.Stdout, "TLS bundles    FAIL", tlsErr)
			ok = false
		} else {
			fmt.Fprintln(c.Stdout, "TLS bundles    OK")
		}
		if cfg.MetadataFile != "" {
			provider, metadataErr := metadatapkg.LoadCSV(cfg.MetadataFile)
			if metadataErr != nil {
				fmt.Fprintln(c.Stdout, "metadata       FAIL", metadataErr)
				ok = false
			} else {
				fmt.Fprintf(c.Stdout, "metadata       OK  records=%d\n", provider.Records())
			}
		}
		fmt.Fprintf(c.Stdout, "auto workers   OK  recommended=%d\n", recommendedConcurrency())
		if cfg.ProxyDNSCacheTTL > 0 {
			fmt.Fprintf(c.Stdout, "proxy DNS      OK  cache_ttl=%s bounded_entries=%d\n", cfg.ProxyDNSCacheTTL, min(cfg.MaxInputEntries, 4096))
		} else {
			fmt.Fprintln(c.Stdout, "proxy DNS      OK  cache=disabled")
		}
		captureLimit := cfg.ResponseCaptureLimit()
		upperBound := captureLimit * int64(cfg.Concurrency)
		fmt.Fprintf(c.Stdout, "body capture   OK  per_worker=%d upper_bound=%d budget=%d\n", captureLimit, upperBound, config.MaxConcurrentCaptureBytes)
	}
	if d, err := os.MkdirTemp("", "netvex-doctor-"); err == nil {
		_ = os.Remove(d)
		fmt.Fprintln(c.Stdout, "temporary I/O  OK")
	} else {
		fmt.Fprintln(c.Stdout, "temporary I/O  FAIL", err)
		ok = false
	}
	if *network && err == nil {
		for _, t := range cfg.Targets {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
			_, e := checker.Policy.Resolve(ctx, t)
			cancel()
			if e != nil {
				fmt.Fprintf(c.Stdout, "resolve %-30s FAIL %v\n", sanitizedTarget(t), e)
				ok = false
			} else {
				fmt.Fprintf(c.Stdout, "resolve %-30s OK\n", sanitizedTarget(t))
			}
		}
	}
	if !ok {
		return ExitOperational
	}
	return ExitOK
}

func sanitizedTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "invalid-target"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + "/"
}

type benchProcessor struct{ delay time.Duration }

func (c CLI) completion(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(c.Stderr, "usage: netvex completion bash|zsh|fish")
		return ExitUsage
	}
	commands := "check inspect import results runs export stats history pool shard merge diff explore config doctor bench capabilities schema completion version help"
	fs, _ := c.newFlagSet("completion-check")
	var options checkOptions
	c.addCheckFlags(fs, &options)
	flagNames := []string{"--help"}
	fs.VisitAll(func(option *flag.Flag) { flagNames = append(flagNames, "--"+option.Name) })
	sort.Strings(flagNames)
	checkFlags := strings.Join(flagNames, " ")
	switch args[0] {
	case "bash":
		fmt.Fprintf(c.Stdout, `_netvex() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W %q -- "$cur") )
  elif [[ ${COMP_WORDS[1]} == check ]]; then
    COMPREPLY=( $(compgen -W %q -- "$cur") )
  fi
}
complete -F _netvex netvex
`, commands, checkFlags)
	case "zsh":
		fmt.Fprintf(c.Stdout, `#compdef netvex
_netvex() {
  local -a commands
  commands=(%s)
  if (( CURRENT == 2 )); then
    _describe 'command' commands
  else
    _arguments '*:option:(%s)'
  fi
}
_netvex
`, strings.Join(strings.Fields(commands), " "), strings.Join(strings.Fields(checkFlags), " "))
	case "fish":
		for _, command := range strings.Fields(commands) {
			fmt.Fprintf(c.Stdout, "complete -c netvex -f -n '__fish_use_subcommand' -a %s\n", command)
		}
		for _, option := range strings.Fields(checkFlags) {
			if strings.HasPrefix(option, "--") {
				fmt.Fprintf(c.Stdout, "complete -c netvex -f -n '__fish_seen_subcommand_from check' -l %s\n", strings.TrimPrefix(option, "--"))
			}
		}
	default:
		fmt.Fprintln(c.Stderr, "shell must be bash, zsh, or fish")
		return ExitUsage
	}
	return ExitOK
}

func (b benchProcessor) Check(ctx context.Context, p model.Proxy) model.Result {
	if b.delay > 0 {
		timer := time.NewTimer(b.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
	}
	v := 100.0
	return model.Result{ID: p.Key(), Proxy: p.SafeURI(), Endpoint: p.Address(), Protocol: p.Protocol, Status: model.StatusOK, Attempts: 1, Successes: 1, Score: model.Score{Value: &v, Confidence: "synthetic"}}
}

func (c CLI) bench(args []string) int {
	fs, buf := c.newFlagSet("bench")
	count := fs.Int("count", 10000, "synthetic proxy count")
	workers := fs.Int("concurrency", 128, "workers")
	delay := fs.Duration("delay", 0, "controlled per-item delay")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *count < 1 || *count > 10_000_000 || *workers < 1 || *workers > 4096 {
		fmt.Fprintln(c.Stderr, "count or concurrency outside safe limits")
		return ExitUsage
	}
	if *delay < 0 {
		fmt.Fprintln(c.Stderr, "delay must not be negative")
		return ExitUsage
	}
	ctx := context.Background()
	jobs := make(chan model.Proxy, *workers*2)
	run := engine.Engine{Workers: *workers, QueueSize: *workers * 2, Processor: benchProcessor{*delay}}
	start := time.Now()
	go func() {
		defer close(jobs)
		for i := 0; i < *count; i++ {
			jobs <- model.Proxy{Protocol: model.ProtocolHTTP, Host: "benchmark.invalid", Port: uint16(1000 + i%64000)}
		}
	}()
	n := 0
	for range run.Run(ctx, jobs) {
		n++
	}
	elapsed := time.Since(start)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	fmt.Fprintf(c.Stdout, "mode=controlled-scheduler count=%d concurrency=%d delay=%s elapsed=%s rate=%.1f/s heap=%d_bytes\n", n, *workers, *delay, elapsed, float64(n)/elapsed.Seconds(), mem.HeapAlloc)
	return ExitOK
}
