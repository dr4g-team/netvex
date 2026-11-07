package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/drag-team/netvex-go/internal/config"
	"github.com/drag-team/netvex-go/internal/engine"
	inputpkg "github.com/drag-team/netvex-go/internal/input"
	metadatapkg "github.com/drag-team/netvex-go/internal/metadata"
	"github.com/drag-team/netvex-go/internal/metrics"
	"github.com/drag-team/netvex-go/internal/model"
	"github.com/drag-team/netvex-go/internal/output"
	qualitypkg "github.com/drag-team/netvex-go/internal/quality"
	"github.com/drag-team/netvex-go/internal/store"
)

// checkSession holds one validation run. check() reads as the sequence of steps;
// each step is a method here, which keeps the many outputs and their cleanup in
// one place instead of threading them through a single long function.
type checkSession struct {
	cli      CLI
	options  checkOptions
	detailed bool

	config          config.Config
	protocol        model.Protocol
	outputFormat    output.Format
	color           bool
	inputFormat     inputpkg.Format
	files           []string
	qualityPolicy   *qualitypkg.Policy
	workingTemplate string
	saveStatuses    map[model.Status]bool
	outputStatuses  map[model.Status]bool
	metadata        *metadatapkg.Provider

	checker      *engine.Checker
	adaptive     *engine.AdaptiveController
	identityKey  func() []byte
	targetHealth map[string]model.TargetHealth

	checkpointPath    string
	resumeCheckpoint  bool
	checkpointExisted bool
	checkpoint        *store.Checkpoint
	completed         map[string]store.CheckpointEntry

	working       *workingSink
	summaryOutput *secureOutput
	metricsOutput *secureOutput
	junitOutput   *secureOutput
	history       *store.RunWriter
	writer        *output.Writer

	summary   model.RunSummary
	partial   bool
	latencies *metrics.Histogram
	start     time.Time

	scheduled, resumed atomic.Int64
	parserFinished     atomic.Bool
	parseErr           chan error
	inputStats         chan model.InputStats
	jobs               chan model.Proxy
}

func (c CLI) check(args []string, forceDetailed bool) (code int) {
	s, initialCode := c.newCheckSession(args, forceDetailed)
	if s == nil {
		return initialCode
	}
	ctx, stop := signal.NotifyContext(context.Background(), interruptSignals()...)
	defer stop()
	// Restoring default signal handling lets a second Ctrl-C end a stuck shutdown.
	context.AfterFunc(ctx, stop)
	defer s.release()
	// Validate every path before profiling or network activity can create or
	// truncate anything supplied by the operator.
	if code := s.validatePaths(ctx); code != ExitOK {
		return code
	}
	stopProfiles, err := startProfiles(s.options.cpuProfile, s.options.memProfile, s.options.forceWorking)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	defer func() {
		if err := stopProfiles(); err != nil {
			fmt.Fprintln(c.Stderr, err)
			if code != ExitInterrupted {
				code = ExitOperational
			}
		}
	}()
	for _, step := range []func(context.Context) int{s.prepareChecker, s.runPreflight, s.openCheckpoint, s.openOutputs, s.openHistory} {
		if code := step(ctx); code != ExitOK {
			return code
		}
	}
	if code := s.restoreCheckpoint(); code != ExitOK {
		return code
	}
	go s.readInput(ctx)
	if code, finished := s.consume(ctx, s.startPipeline(ctx)); !finished {
		return code
	}
	return s.finish(ctx)
}

func (c CLI) newCheckSession(args []string, detailed bool) (*checkSession, int) {
	fs, buf := c.newFlagSet("check")
	var o checkOptions
	c.addCheckFlags(fs, &o)
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return nil, code
	}
	if buf.Len() > 0 {
		fmt.Fprint(c.Stdout, buf.String())
		return nil, ExitOK
	}
	s := &checkSession{cli: c, options: o, detailed: detailed, files: fs.Args(), completed: map[string]store.CheckpointEntry{}, parseErr: make(chan error, 1), inputStats: make(chan model.InputStats, 1)}
	invalidZero := ""
	s.options.explicit = make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		s.options.explicit[f.Name] = true
		switch f.Name {
		case "concurrency", "queue-size", "per-target", "repeat", "min-success-rate":
			if f.Value.String() == "0" {
				invalidZero = f.Name
			}
		}
	})
	if invalidZero != "" {
		fmt.Fprintf(c.Stderr, "%s must be greater than zero\n", invalidZero)
		return nil, ExitUsage
	}
	if err := s.validateOptions(); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return nil, ExitUsage
	}
	if len(s.files) == 0 && c.InputTerminal {
		fmt.Fprintln(c.Stderr, "no proxies given: pass a file, or pipe a list with `netvex check -`")
		return nil, ExitUsage
	}
	if s.options.qualityPolicy != "" {
		loaded, err := qualitypkg.Load(s.options.qualityPolicy)
		if err != nil {
			fmt.Fprintln(c.Stderr, "quality policy error:", err)
			return nil, ExitUsage
		}
		s.qualityPolicy = &loaded
	}
	var err error
	s.config, s.protocol, s.outputFormat, s.color, err = c.loadCheck(s.options)
	if err != nil {
		fmt.Fprintln(c.Stderr, "configuration error:", err)
		return nil, ExitUsage
	}
	// Checked after loading because saving may come from the file or environment.
	if s.options.saveStatus != "" && !s.config.Save {
		fmt.Fprintln(c.Stderr, "save-status requires save")
		return nil, ExitUsage
	}
	if s.options.saveGzip && !s.config.Save {
		fmt.Fprintln(c.Stderr, "save-gzip requires save")
		return nil, ExitUsage
	}
	if s.options.label == "" && s.config.ScenarioName != "" {
		s.options.label = s.config.ScenarioName
	}
	if s.inputFormat, err = inputpkg.ParseFormat(s.options.inputFormat); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return nil, ExitUsage
	}
	if s.config.MetadataFile != "" {
		if s.metadata, err = metadatapkg.LoadCSV(s.config.MetadataFile); err != nil {
			fmt.Fprintln(c.Stderr, "metadata error:", err)
			return nil, ExitUsage
		}
		if s.options.verbose {
			fmt.Fprintf(c.Stderr, "loaded %d metadata prefixes\n", s.metadata.Records())
		}
	}
	s.jobs = make(chan model.Proxy, s.config.QueueSize)
	return s, ExitOK
}

// validateOptions rejects flag combinations that need no configuration to judge.
func (s *checkSession) validateOptions() error {
	o := &s.options
	if o.requireCount < 0 || o.requireCount > 1_000_000_000 {
		return errors.New("require-count must be between 0 and 1000000000")
	}
	if o.requireSuccess && o.requireCount < 1 {
		o.requireCount = 1
	}
	if o.checkpointOutput != "" && o.resumeCheckpoint != "" {
		return errors.New("checkpoint and resume are mutually exclusive")
	}
	if o.workingOutput != "" && o.workingDir != "" {
		return errors.New("working-output and working-dir are mutually exclusive")
	}
	if o.keepPartial && !o.exportsWorking() && !o.save && o.summaryOutput == "" {
		return errors.New("keep-partial requires working-output, working-dir, save, or summary-output")
	}
	if o.workingTemplate != "" && !o.exportsWorking() {
		return errors.New("working-template requires working-output or working-dir")
	}
	var err error
	if s.workingTemplate, err = parseWorkingTemplate(o.workingTemplate); err != nil {
		return err
	}
	if s.saveStatuses, err = parseStatusList(o.saveStatus); err != nil {
		return err
	}
	if o.outputStatus != "all" {
		// An empty result means every status, matching the --save-status default.
		if s.outputStatuses, err = parseStatusList(o.outputStatus); err != nil {
			return errors.New("output-status is invalid")
		}
	}
	if o.metricsOutput == "-" {
		return errors.New("metrics-output requires a file path; use stats --prometheus for stdout")
	}
	if o.checkpointSync < 1 || o.checkpointSync > 100_000 {
		return errors.New("checkpoint-sync must be between 1 and 100000")
	}
	stdinSources := 0
	for _, name := range s.files {
		if name == "-" {
			stdinSources++
		}
	}
	if stdinSources > 1 {
		return errors.New("standard input may be specified only once")
	}
	s.checkpointPath = o.checkpointOutput
	if o.resumeCheckpoint != "" {
		s.checkpointPath = o.resumeCheckpoint
		s.resumeCheckpoint = true
	}
	return nil
}

func (o checkOptions) exportsWorking() bool { return o.workingOutput != "" || o.workingDir != "" }

func (s *checkSession) prepareChecker(context.Context) int {
	s.identityKey = s.cli.identityKey(s.config.DataDir)
	s.checker = engine.NewChecker(s.config)
	if s.metadata != nil {
		s.checker.Metadata = s.metadata
	}
	s.checker.IdentityKey = s.identityKey
	s.checker.Label = s.options.label
	s.checker.IncludeInputProxy = s.options.exportsWorking()
	if err := s.checker.ConfigureCABundles(s.config.CABundle, s.config.ProxyCABundle); err != nil {
		fmt.Fprintln(s.cli.Stderr, "TLS configuration error:", err)
		return ExitUsage
	}
	return ExitOK
}

func (s *checkSession) runPreflight(ctx context.Context) int {
	if s.config.Preflight == "off" {
		return ExitOK
	}
	s.targetHealth = s.checker.Preflight(ctx)
	failed := false
	targets := make([]string, 0, len(s.targetHealth))
	for target := range s.targetHealth {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		health := s.targetHealth[target]
		if s.options.verbose || health.Status != "ok" {
			fmt.Fprintf(s.cli.Stderr, "preflight target=%s status=%s http=%d latency=%.1fms code=%s\n", target, health.Status, health.HTTPStatus, health.LatencyMS, health.Code)
		}
		failed = failed || health.Status != "ok"
	}
	if failed && s.config.Preflight == "strict" {
		fmt.Fprintln(s.cli.Stderr, "strict preflight failed; no proxy validation was started")
		return ExitOperational
	}
	return ExitOK
}

// validatePaths refuses overlapping outputs before anything is created, so a
// mistaken flag can never truncate an input or another report.
func (s *checkSession) validatePaths(context.Context) int {
	o := s.options
	outputs := []struct{ label, path string }{
		{"checkpoint", s.checkpointPath}, {"working output", o.workingOutput}, {"summary output", o.summaryOutput},
		{"metrics output", o.metricsOutput}, {"JUnit output", o.junitOutput}, {"CPU profile", o.cpuProfile}, {"memory profile", o.memProfile},
	}
	if s.checkpointPath != "" {
		outputs = append(outputs, struct{ label, path string }{"checkpoint fingerprint", s.checkpointPath + checkpointConfigSuffix})
	}
	if o.workingDir != "" {
		for _, path := range workingDirPaths(o.workingDir) {
			outputs = append(outputs, struct{ label, path string }{"working output", path})
		}
	}
	for index, left := range outputs {
		if left.path == "" {
			continue
		}
		for _, name := range s.files {
			if name == "-" {
				continue
			}
			same, err := samePath(name, left.path)
			if err != nil {
				fmt.Fprintln(s.cli.Stderr, left.label, "error:", err)
				return ExitUsage
			}
			if same {
				fmt.Fprintln(s.cli.Stderr, left.label, "must not overwrite an input file")
				return ExitUsage
			}
		}
		for _, right := range outputs[index+1:] {
			if right.path == "" {
				continue
			}
			same, err := samePath(left.path, right.path)
			if err != nil {
				fmt.Fprintln(s.cli.Stderr, "output path error:", err)
				return ExitUsage
			}
			if same {
				fmt.Fprintln(s.cli.Stderr, "checkpoint and report outputs must use different files")
				return ExitUsage
			}
		}
	}
	return ExitOK
}

func (s *checkSession) openCheckpoint(context.Context) int {
	if s.checkpointPath == "" {
		return ExitOK
	}
	if _, err := os.Lstat(s.checkpointPath); err == nil {
		s.checkpointExisted = true
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(s.cli.Stderr, "checkpoint error:", err)
		return ExitUsage
	}
	fingerprint := checkpointFingerprint(s.config, s.protocol)
	if s.resumeCheckpoint && !s.options.resumeAnyConfig {
		if err := verifyCheckpointFingerprint(s.checkpointPath, fingerprint, s.cli.Stderr); err != nil {
			fmt.Fprintln(s.cli.Stderr, "checkpoint error:", err)
			return ExitUsage
		}
	}
	var err error
	s.checkpoint, s.completed, err = store.OpenCheckpoint(s.checkpointPath, s.resumeCheckpoint, s.options.forceWorking, s.options.checkpointSync, s.config.MaxInputEntries)
	if err != nil {
		fmt.Fprintln(s.cli.Stderr, "checkpoint error:", err)
		return ExitOperational
	}
	if !s.resumeCheckpoint {
		if err := writeCheckpointFingerprint(s.checkpointPath, fingerprint); err != nil {
			_ = s.checkpoint.Close()
			s.checkpoint = nil
			if !s.checkpointExisted {
				_ = os.Remove(s.checkpointPath)
				_ = os.Remove(s.checkpointPath + checkpointConfigSuffix)
			}
			fmt.Fprintln(s.cli.Stderr, "checkpoint error:", err)
			return ExitOperational
		}
	}
	return ExitOK
}

func (s *checkSession) openOutputs(context.Context) int {
	o := s.options
	var err error
	switch {
	case o.workingOutput != "":
		s.working, err = openWorkingFile(o.workingOutput, s.workingTemplate, o.forceWorking)
	case o.workingDir != "":
		s.working, err = openWorkingDir(o.workingDir, s.workingTemplate, o.forceWorking)
	}
	if err != nil {
		fmt.Fprintln(s.cli.Stderr, "working output error:", err)
		return ExitOperational
	}
	for _, report := range []struct {
		label, path string
		target      **secureOutput
	}{{"summary output", o.summaryOutput, &s.summaryOutput}, {"metrics output", o.metricsOutput, &s.metricsOutput}, {"JUnit output", o.junitOutput, &s.junitOutput}} {
		if report.path == "" {
			continue
		}
		if *report.target, err = openSecureOutput(report.path, o.forceWorking); err != nil {
			fmt.Fprintln(s.cli.Stderr, report.label, "error:", err)
			return ExitOperational
		}
	}
	return ExitOK
}

func (s *checkSession) openHistory(context.Context) int {
	if !s.options.quiet {
		s.writer = output.New(s.cli.Stdout, s.outputFormat, s.color)
	}
	if s.config.Save {
		var err error
		newWriter := store.NewRunWriter
		if s.config.SaveGzip {
			newWriter = store.NewCompressedRunWriter
		}
		if s.history, err = newWriter(s.config.DataDir); err != nil {
			fmt.Fprintln(s.cli.Stderr, "history error:", err)
			return ExitOperational
		}
	}
	s.start = time.Now()
	s.summary = model.RunSummary{SchemaVersion: model.SchemaVersion, Configuration: runConfiguration(s.config, s.protocol, s.options), StartedAt: s.start.UTC(), StatusCount: map[model.Status]int{}, FailureCodes: map[string]int{}, FailureStages: map[model.Stage]int{}, Targets: map[string]model.TargetSummary{}, TargetHealth: s.targetHealth}
	s.latencies = metrics.NewHistogram(1, 300000)
	return ExitOK
}

// release discards everything that was not committed. Commit marks each output
// closed, so this is safe on every exit path.
func (s *checkSession) release() {
	if s.history != nil {
		s.history.Abort()
	}
	if s.junitOutput != nil {
		s.junitOutput.Abort()
	}
	if s.metricsOutput != nil {
		s.metricsOutput.Abort()
	}
	if s.summaryOutput != nil {
		s.summaryOutput.Abort()
	}
	if s.working != nil {
		s.working.Abort()
	}
	if s.checkpoint != nil {
		_ = s.checkpoint.Close()
	}
}

func (s *checkSession) restoreCheckpoint() int {
	if !s.resumeCheckpoint {
		return ExitOK
	}
	if err := s.checkpoint.Replay(func(result model.Result) error { return s.record(result, false) }); err != nil {
		fmt.Fprintln(s.cli.Stderr, "resume checkpoint error:", err)
		return ExitOperational
	}
	s.summary.Restored = s.summary.Processed
	return ExitOK
}

// readInput streams proxies into the job queue until the input ends. It runs on
// its own goroutine and may block forever on an open stdin, so nothing waits for
// it after an interrupt.
func (s *checkSession) readInput(ctx context.Context) {
	defer close(s.jobs)
	defer s.parserFinished.Store(true)
	o := s.options
	parser := inputpkg.New(inputpkg.Options{Format: s.inputFormat, DefaultProtocol: s.protocol, Source: "input", MaxBytes: s.config.MaxInputBytes, MaxEntries: s.config.MaxInputEntries, Deduplicate: !o.noDeduplicate})
	warnedCredentialFiles := map[string]struct{}{}
	emit := func(p model.Proxy) error {
		if entry, done := s.completed[p.ResultID(s.identityKey)]; done {
			s.resumed.Add(1)
			if s.working != nil && entry.Status == model.StatusOK {
				// Checkpoints are redacted, so credentials for an already validated
				// proxy can only come from this re-read of the input.
				restored := p
				restored.Protocol = entry.Protocol
				return s.working.Write(restored)
			}
			return nil
		}
		if p.Credentials != nil && p.Source != "stdin" {
			if _, warned := warnedCredentialFiles[p.Source]; !warned {
				warnedCredentialFiles[p.Source] = struct{}{}
				if info, err := os.Stat(p.Source); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0077 != 0 {
					fmt.Fprintf(s.cli.Stderr, "security warning: credential input %q has mode %04o; use chmod 600\n", p.Source, info.Mode().Perm())
				}
			}
		}
		s.scheduled.Add(1)
		select {
		case s.jobs <- p:
			return nil
		case <-ctx.Done():
			s.scheduled.Add(-1)
			return ctx.Err()
		}
	}
	reject := func(r inputpkg.Rejection) {
		if o.verbose {
			fmt.Fprintf(s.cli.Stderr, "rejected %q:%d: %q (%s)\n", r.Source, r.Line, r.Value, r.Reason)
		}
	}
	err := s.cli.emitFiles(parser, s.files, s.inputFormat, emit, reject)
	s.inputStats <- parser.Stats
	s.parseErr <- err
}

func (s *checkSession) startPipeline(ctx context.Context) <-chan model.Result {
	cfg := s.config
	runner := engine.Engine{Workers: cfg.Concurrency, QueueSize: cfg.QueueSize, Processor: s.checker}
	prescreenWorkers := 0
	if cfg.Prescreen {
		prescreenWorkers = boundedPrescreenWorkers(cfg.PrescreenWorkers, cfg.Concurrency)
	}
	if cfg.AdaptiveConcurrency {
		runner.Adaptive = engine.NewAdaptiveController(cfg.AdaptiveMinimum, max(cfg.Concurrency, prescreenWorkers), cfg.AdaptiveWindow)
		s.adaptive = runner.Adaptive
	}
	var unreachable <-chan model.Result
	var results <-chan model.Result
	if cfg.Prescreen {
		workers := prescreenWorkers
		if workers < cfg.PrescreenWorkers {
			fmt.Fprintf(s.cli.Stderr, "prescreen concurrency reduced to %d by the file descriptor limit\n", workers)
		}
		validationInput, rejected := s.checker.PrescreenPreparedControlled(ctx, s.jobs, workers, cfg.QueueSize, cfg.PrescreenReuse, runner.Adaptive)
		unreachable = rejected
		results = runner.RunPrepared(ctx, validationInput)
	} else {
		results = runner.Run(ctx, s.jobs)
	}
	if cfg.CanaryInterval > 0 {
		go s.checker.RunCanary(ctx)
	}
	if unreachable != nil {
		results = engine.Merge(results, unreachable, cfg.QueueSize)
	}
	return results
}

// consume drains results. It reports finished=false with an exit code when the
// run must stop early, such as a closed stdout pipe.
func (s *checkSession) consume(ctx context.Context, results <-chan model.Result) (int, bool) {
	var progressC <-chan time.Time
	live := !s.options.verbose && !s.options.noProgress && s.cli.ErrorTerminal
	if s.options.verbose || live {
		ticker := time.NewTicker(s.config.ProgressInterval)
		progressC = ticker.C
		defer ticker.Stop()
	}
	for results != nil {
		select {
		case <-progressC:
			s.reportProgress(live)
		case r, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			if err := s.record(r, true); err != nil {
				if errors.Is(err, syscall.EPIPE) {
					return ExitOK, false
				}
				fmt.Fprintln(s.cli.Stderr, err)
				return ExitOperational, false
			}
		}
	}
	if live {
		fmt.Fprint(s.cli.Stderr, clearLine)
	}
	if s.writer != nil {
		if err := s.writer.Flush(); err != nil {
			fmt.Fprintln(s.cli.Stderr, "output error:", err)
			return ExitOperational, false
		}
	}
	return ExitOK, true
}

func (s *checkSession) reportProgress(live bool) {
	summary := &s.summary
	processed := summary.Processed - summary.Restored
	elapsed := time.Since(s.start)
	if live {
		fmt.Fprint(s.cli.Stderr, clearLine, progressLine(progressState{processed: int64(processed), scheduled: s.scheduled.Load(), ingestDone: s.parserFinished.Load(), ok: summary.Successful, failed: summary.Failed, elapsed: elapsed, concurrency: s.currentConcurrency()}))
		return
	}
	pending := max(s.scheduled.Load()-int64(processed), 0)
	ingest := "streaming"
	if s.parserFinished.Load() {
		ingest = "done"
	}
	fmt.Fprintf(s.cli.Stderr, "processed_new=%d restored=%d scheduled=%d pending=%d ingest=%s ok=%d unreliable=%d failed=%d inconclusive=%d timeouts=%d concurrency=%d rate=%.1f/s elapsed=%s\n", processed, summary.Restored, s.scheduled.Load(), pending, ingest, summary.Successful, summary.Unreliable, summary.Failed, summary.Inconclusive, summary.Timeouts, s.currentConcurrency(), float64(processed)/elapsed.Seconds(), elapsed.Round(100*time.Millisecond))
}

func (s *checkSession) currentConcurrency() int {
	if s.adaptive != nil {
		return s.adaptive.Limit()
	}
	return s.config.Concurrency
}

// record sends one result to every sink and accumulates it into the summary.
// Replayed results skip the checkpoint they came from.
func (s *checkSession) record(r model.Result, fresh bool) error {
	o := s.options
	if fresh && s.checkpoint != nil && r.Status != model.StatusInterrupted {
		if err := s.checkpoint.Write(r); err != nil {
			return fmt.Errorf("checkpoint: %w", err)
		}
	}
	if !o.quiet && (len(s.outputStatuses) == 0 || s.outputStatuses[r.Status]) {
		if s.detailed {
			if err := output.WriteDetailed(s.cli.Stdout, r); err != nil {
				return fmt.Errorf("output: %w", err)
			}
		} else if err := s.writer.WriteResult(r); err != nil {
			return fmt.Errorf("output: %w", err)
		}
	}
	if s.history != nil && (len(s.saveStatuses) == 0 || s.saveStatuses[r.Status]) {
		if err := s.history.Write(r); err != nil {
			return fmt.Errorf("history: %w", err)
		}
	}
	summary := &s.summary
	summary.Processed++
	summary.StatusCount[r.Status]++
	switch r.Status {
	case model.StatusOK:
		summary.Successful++
		if s.working != nil && r.Validated != nil {
			if err := s.working.Write(*r.Validated); err != nil {
				return fmt.Errorf("working output: %w", err)
			}
		}
	case model.StatusInconclusive:
		summary.Inconclusive++
	case model.StatusUnreliable:
		summary.Unreliable++
	default:
		summary.Failed++
	}
	for _, observation := range r.Observations {
		s.recordObservation(observation)
	}
	return nil
}

func (s *checkSession) recordObservation(observation model.Observation) {
	summary := &s.summary
	summary.Attempts++
	target := summary.Targets[observation.Target]
	target.Attempts++
	target.TotalMS += observation.Timings.TotalMS
	switch observation.Status {
	case model.StatusOK:
		target.Successful++
		s.latencies.Observe(observation.Timings.TotalMS)
	case model.StatusInconclusive:
		target.Inconclusive++
	default:
		target.Failed++
	}
	if observation.Status == model.StatusTimeout {
		summary.Timeouts++
		target.Timeouts++
	}
	if observation.Status != model.StatusOK {
		if observation.Code != "" {
			summary.FailureCodes[observation.Code]++
		}
		if observation.Stage != "" {
			summary.FailureStages[observation.Stage]++
		}
	}
	summary.Targets[observation.Target] = target
}

func (s *checkSession) finish(ctx context.Context) int {
	stderr := s.cli.Stderr
	summary := &s.summary
	if ctx.Err() == nil {
		summary.Input = <-s.inputStats
		if err := <-s.parseErr; err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "input error:", err)
			return ExitOperational
		}
	}
	// After an interrupt the parser may be blocked reading an open stdin, which
	// cannot be cancelled, so the run must not wait for it.
	summary.Input.Resumed = int(s.resumed.Load())
	if s.checkpoint != nil {
		if err := s.checkpoint.Close(); err != nil {
			fmt.Fprintln(stderr, "checkpoint error:", err)
			return ExitOperational
		}
	}
	if ctx.Err() != nil {
		return s.finishInterrupted()
	}
	if summary.Input.Accepted == 0 {
		return s.discardEmptyRun()
	}
	qualityPassed := s.concludeSummary()
	if code := s.publish(); code != ExitOK {
		return code
	}
	s.reportOutcome()
	if summary.Successful < s.options.requireCount || !qualityPassed {
		return ExitNoSuccess
	}
	return ExitOK
}

// finishInterrupted publishes completed work when --keep-partial asks for it.
// Input statistics are taken only if the parser already finished, because it may
// be blocked on an open stdin. Quality gates still run but cannot change the exit.
func (s *checkSession) finishInterrupted() int {
	if !s.options.keepPartial {
		return ExitInterrupted
	}
	select {
	case s.summary.Input = <-s.inputStats:
		s.summary.Input.Resumed = int(s.resumed.Load())
	default:
	}
	s.summary.Interrupted = true
	s.partial = true
	s.concludeSummary()
	if code := s.publish(); code != ExitOK {
		return code
	}
	return ExitInterrupted
}

func (s *checkSession) discardEmptyRun() int {
	if s.checkpointPath != "" && !s.resumeCheckpoint && !s.checkpointExisted {
		_ = os.Remove(s.checkpointPath + checkpointConfigSuffix)
		if err := os.Remove(s.checkpointPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(s.cli.Stderr, "checkpoint cleanup error:", err)
			return ExitOperational
		}
	}
	return ExitNoValidInput
}

func (s *checkSession) workingPath() string { return s.options.workingOutput + s.options.workingDir }

// concludeSummary computes derived figures and evaluates quality gates.
func (s *checkSession) concludeSummary() bool {
	summary := &s.summary
	summary.FinishedAt = time.Now().UTC()
	summary.Canary = s.checker.CanaryReport()
	summary.LatencyP50MS = s.latencies.Percentile(.50)
	summary.LatencyP95MS = s.latencies.Percentile(.95)
	summary.LatencyP99MS = s.latencies.Percentile(.99)
	summary.DurationMS = float64(time.Since(s.start).Microseconds()) / 1000
	if summary.DurationMS > 0 {
		summary.RatePerSec = float64(summary.Processed-summary.Restored) / (summary.DurationMS / 1000)
	}
	for name, target := range summary.Targets {
		if target.Attempts > 0 {
			target.SuccessRate = float64(target.Successful) / float64(target.Attempts)
			target.AverageTotalMS = target.TotalMS / float64(target.Attempts)
		}
		summary.Targets[name] = target
	}
	if s.qualityPolicy != nil {
		report := qualitypkg.Evaluate(*s.qualityPolicy, *summary)
		summary.Quality = &report
		for _, check := range report.Checks {
			if !check.Passed {
				fmt.Fprintf(s.cli.Stderr, "quality gate failed: %s actual=%g expected %s %g\n", check.Name, check.Actual, check.Operator, check.Expected)
			}
		}
	}
	if s.options.requireCount > 0 {
		if summary.Quality == nil {
			summary.Quality = &model.QualityReport{Passed: true}
		}
		passed := summary.Successful >= s.options.requireCount
		summary.Quality.Checks = append(summary.Quality.Checks, model.QualityCheck{Name: "require_count", Passed: passed, Actual: float64(summary.Successful), Operator: ">=", Expected: float64(s.options.requireCount)})
		summary.Quality.Passed = summary.Quality.Passed && passed
	}
	return summary.Quality == nil || summary.Quality.Passed
}

// publish commits every output. History goes first because it assigns the run ID
// that the other reports include.
func (s *checkSession) publish() int {
	stderr := s.cli.Stderr
	summary := &s.summary
	if s.history != nil {
		summary.RunID = s.history.ID
		if err := s.history.Commit(*summary); err != nil {
			fmt.Fprintln(stderr, "history commit error:", err)
			return ExitOperational
		}
		fmt.Fprintf(stderr, "saved run %s\n", s.history.ID)
	}
	if s.summaryOutput != nil {
		err := s.summaryOutput.WriteJSON(*summary)
		if err == nil {
			err = s.summaryOutput.Commit()
		}
		if err != nil {
			fmt.Fprintln(stderr, "summary output error:", err)
			return ExitOperational
		}
		fmt.Fprintf(stderr, "saved run summary to %q\n", s.options.summaryOutput)
	}
	if s.metricsOutput != nil {
		err := output.WritePrometheusSummary(s.metricsOutput, *summary)
		if err == nil {
			err = s.metricsOutput.Commit()
		}
		if err != nil {
			fmt.Fprintln(stderr, "metrics output error:", err)
			return ExitOperational
		}
		fmt.Fprintf(stderr, "saved aggregate metrics to %q\n", s.options.metricsOutput)
	}
	if s.partial {
		if err := commitPartialWorking(s.working, s.workingPath(), stderr); err != nil {
			fmt.Fprintln(stderr, "partial working output error:", err)
			return ExitOperational
		}
	} else if s.working != nil {
		if err := s.working.Commit(); err != nil {
			fmt.Fprintln(stderr, "working output error:", err)
			return ExitOperational
		}
		fmt.Fprintf(stderr, "saved %d validated proxies to %q\n", s.working.Count(), s.workingPath())
		if missing := summary.Successful - s.working.Count(); missing > 0 {
			fmt.Fprintf(stderr, "warning: %d validated proxies in the checkpoint were not in this input, so their credentials could not be exported\n", missing)
		}
	}
	if s.junitOutput != nil {
		payload, err := qualitypkg.JUnit(*summary)
		if err == nil {
			err = s.junitOutput.WriteBytes(payload)
		}
		if err == nil {
			err = s.junitOutput.Commit()
		}
		if err != nil {
			fmt.Fprintln(stderr, "JUnit output error:", err)
			return ExitOperational
		}
	}
	return ExitOK
}

func (s *checkSession) reportOutcome() {
	stderr := s.cli.Stderr
	summary := &s.summary
	if count := summary.FailureCodes["local_resource_exhausted"]; count > 0 {
		fmt.Fprintf(stderr, "warning: %d attempts failed because this host ran out of sockets or file descriptors; their proxies are inconclusive, not dead\n", count)
	}
	if s.options.verbose || s.cli.IsTerminal {
		fmt.Fprintf(stderr, "read=%d accepted=%d duplicates=%d resumed=%d rejected=%d processed=%d ok=%d unreliable=%d failed=%d inconclusive=%d elapsed=%s rate=%.1f/s p50=%.0fms p95=%.0fms p99=%.0fms\n", summary.Input.Read, summary.Input.Accepted, summary.Input.Duplicates, s.resumed.Load(), summary.Input.Rejected, summary.Processed, summary.Successful, summary.Unreliable, summary.Failed, summary.Inconclusive, time.Since(s.start).Round(time.Millisecond), summary.RatePerSec, summary.LatencyP50MS, summary.LatencyP95MS, summary.LatencyP99MS)
		if top := topCounts(summary.FailureCodes, 5); top != "" {
			fmt.Fprintln(stderr, "top_failures="+top)
		}
	}
}
