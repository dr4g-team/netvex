package store

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/drag-team/netvex/internal/fsx"
	"github.com/drag-team/netvex/internal/model"
)

type RunWriter struct {
	ID      string
	dir     string
	part    string
	final   string
	f       *os.File
	gz      *gzip.Writer
	w       *bufio.Writer
	encoder resultEncoder
	closed  bool
}

const (
	MaxResultBytes = 16 << 20
	runSuffix      = ".jsonl"
	gzipRunSuffix  = ".jsonl.gz"
	summarySuffix  = ".summary.json"
)

// resultEncoder reuses one buffer across results. Saving is the largest source of
// allocation in a big run, and json.Marshal copies every record it returns.
type resultEncoder struct {
	buffer  bytes.Buffer
	encoder *json.Encoder
}

// encode returns one newline-terminated record, valid until the next call.
func (e *resultEncoder) encode(value any) ([]byte, error) {
	if e.encoder == nil {
		e.encoder = json.NewEncoder(&e.buffer)
	}
	e.buffer.Reset()
	if err := e.encoder.Encode(value); err != nil {
		return nil, err
	}
	if e.buffer.Len() > MaxResultBytes {
		return nil, fmt.Errorf("serialized result exceeds %d bytes", MaxResultBytes)
	}
	return e.buffer.Bytes(), nil
}

func NewRunWriter(dataDir string) (*RunWriter, error) { return newRunWriter(dataDir, false) }

// NewCompressedRunWriter stores results as gzip. Readers detect the format, so
// every command handles both kinds of run.
func NewCompressedRunWriter(dataDir string) (*RunWriter, error) { return newRunWriter(dataDir, true) }

func newRunWriter(dataDir string, compress bool) (*RunWriter, error) {
	dir := filepath.Join(dataDir, "runs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create history directory: %w", err)
	}
	id := newID()
	suffix := runSuffix
	if compress {
		suffix = gzipRunSuffix
	}
	part := filepath.Join(dir, id+suffix+".part")
	final := filepath.Join(dir, id+suffix)
	f, err := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("create run: %w", err)
	}
	writer := &RunWriter{ID: id, dir: dir, part: part, final: final, f: f}
	var sink io.Writer = f
	if compress {
		// BestSpeed: this runs on the result loop, and run files are highly
		// repetitive, so higher levels cost far more time than they save.
		writer.gz, err = gzip.NewWriterLevel(f, gzip.BestSpeed)
		if err != nil {
			_ = f.Close()
			_ = os.Remove(part)
			return nil, err
		}
		sink = writer.gz
	}
	writer.w = bufio.NewWriterSize(sink, 128<<10)
	return writer, nil
}

func newID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(b[:])
}

func (r *RunWriter) Write(result model.Result) error {
	if r.closed {
		return errors.New("run writer is closed")
	}
	if err := validateResult(result); err != nil {
		return err
	}
	record, err := r.encoder.encode(result)
	if err != nil {
		return err
	}
	_, err = r.w.Write(record)
	return err
}

func (r *RunWriter) Commit(summary model.RunSummary) error {
	if r.closed {
		return errors.New("run writer is closed")
	}
	r.closed = true
	metaPart := filepath.Join(r.dir, r.ID+summarySuffix+".part")
	metaFinal := filepath.Join(r.dir, r.ID+summarySuffix)
	committed := false
	resultPublished := false
	metaPublished := false
	defer func() {
		if !committed {
			_ = r.f.Close()
			_ = os.Remove(r.part)
			_ = os.Remove(metaPart)
			if resultPublished {
				_ = os.Remove(r.final)
			}
			if metaPublished {
				_ = os.Remove(metaFinal)
			}
		}
	}()
	if err := r.w.Flush(); err != nil {
		_ = r.f.Close()
		return err
	}
	if r.gz != nil {
		if err := r.gz.Close(); err != nil {
			_ = r.f.Close()
			return err
		}
	}
	if err := r.f.Sync(); err != nil {
		_ = r.f.Close()
		return err
	}
	if err := r.f.Close(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	metaFile, err := os.OpenFile(metaPart, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := metaFile.Write(append(b, '\n')); err != nil {
		_ = metaFile.Close()
		_ = os.Remove(metaPart)
		return err
	}
	if err := metaFile.Sync(); err != nil {
		_ = metaFile.Close()
		_ = os.Remove(metaPart)
		return err
	}
	if err := metaFile.Close(); err != nil {
		_ = os.Remove(metaPart)
		return err
	}
	if err := os.Rename(r.part, r.final); err != nil {
		_ = os.Remove(metaPart)
		return fmt.Errorf("commit run: %w", err)
	}
	resultPublished = true
	if err := os.Rename(metaPart, metaFinal); err != nil {
		_ = os.Remove(r.final)
		return err
	}
	metaPublished = true
	if err := fsx.SyncDir(r.dir); err != nil {
		return err
	}
	committed = true
	return nil
}

func (r *RunWriter) Abort() {
	if r.closed {
		return
	}
	r.closed = true
	_ = r.f.Close()
	_ = os.Remove(r.part)
}
func (r *RunWriter) Path() string { return r.final }

func ResolveRun(dataDir, id string) (string, error) {
	dir := filepath.Join(dataDir, "runs")
	if id == "" || id == "latest" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", fmt.Errorf("list runs: %w", err)
		}
		names := []string{}
		for _, e := range entries {
			if !e.IsDir() && isRunFile(e.Name()) {
				names = append(names, e.Name())
			}
		}
		if len(names) == 0 {
			return "", errors.New("no saved runs")
		}
		sort.Strings(names)
		return filepath.Join(dir, names[len(names)-1]), nil
	}
	if strings.ContainsAny(id, "/\\") {
		if isRunFile(id) {
			return id, nil
		}
		return "", errors.New("run path must name a .jsonl or .jsonl.gz file")
	}
	base := filepath.Join(dir, strings.TrimSuffix(strings.TrimSuffix(id, ".gz"), runSuffix))
	if _, err := os.Stat(base + runSuffix); err != nil {
		if _, gzipErr := os.Stat(base + gzipRunSuffix); gzipErr == nil {
			return base + gzipRunSuffix, nil
		}
	}
	return base + runSuffix, nil
}

func isRunFile(name string) bool {
	return strings.HasSuffix(name, runSuffix) || strings.HasSuffix(name, gzipRunSuffix)
}

func ReadResults(path string, emit func(model.Result) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open run: %w", err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	if magic, _ := reader.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		decompressed, err := gzip.NewReader(reader)
		if err != nil {
			return fmt.Errorf("open compressed run: %w", err)
		}
		defer decompressed.Close()
		return decodeResults(decompressed, emit)
	}
	return decodeResults(reader, emit)
}

func decodeResults(reader io.Reader, emit func(model.Result) error) error {
	s := bufio.NewScanner(reader)
	s.Buffer(make([]byte, 64<<10), MaxResultBytes)
	line := 0
	for s.Scan() {
		line++
		var r model.Result
		if err := json.Unmarshal(s.Bytes(), &r); err != nil {
			return fmt.Errorf("decode run line %d: %w", line, err)
		}
		if err := validateResult(r); err != nil {
			return fmt.Errorf("validate run line %d: %w", line, err)
		}
		if err := emit(r); err != nil {
			return err
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read run: %w", err)
	}
	return nil
}

func validateResult(result model.Result) error {
	if len(result.ID) < 1 || len(result.ID) > 128 || strings.IndexFunc(result.ID, unicode.IsControl) >= 0 {
		return errors.New("result ID is invalid")
	}
	if len(result.Endpoint) > 512 || len(result.Proxy) > 1024 || len(result.Label) > 64 || hasControl(result.Endpoint) || hasControl(result.Proxy) || hasControl(result.Label) {
		return errors.New("result identity fields are invalid")
	}
	if len(result.Observations) > 2048 || len(result.TargetResults) > 64 {
		return errors.New("result contains too many observations or target summaries")
	}
	for _, observation := range result.Observations {
		if len(observation.Target) > 512 || len(observation.Code) > 128 || len(observation.Message) > 2048 || len(observation.ResponseHeaders) > 32 {
			return errors.New("result observation exceeds structural limits")
		}
	}
	return nil
}

func hasControl(value string) bool { return strings.IndexFunc(value, unicode.IsControl) >= 0 }

func ReadSummary(path string) (model.RunSummary, error) {
	var s model.RunSummary
	f, err := os.Open(strings.TrimSuffix(strings.TrimSuffix(path, ".gz"), runSuffix) + summarySuffix)
	if err != nil {
		return s, err
	}
	defer f.Close()
	limited := &io.LimitedReader{R: f, N: (1 << 20) + 1}
	dec := json.NewDecoder(limited)
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return s, errors.New("summary contains trailing JSON data")
	}
	if limited.N <= 0 {
		return s, errors.New("summary exceeds 1 MiB")
	}
	return s, nil
}

func ListRuns(dataDir string, limit int) ([]model.RunSummary, error) {
	dir := filepath.Join(dataDir, "runs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []model.RunSummary{}, nil
		}
		return nil, fmt.Errorf("list runs: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".summary.json") {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > limit {
		names = names[:limit]
	}
	runs := make([]model.RunSummary, 0, len(names))
	for _, name := range names {
		resultPath := filepath.Join(dir, strings.TrimSuffix(name, ".summary.json")+".jsonl")
		summary, err := ReadSummary(resultPath)
		if err != nil {
			return nil, fmt.Errorf("read summary %s: %w", name, err)
		}
		runs = append(runs, summary)
	}
	return runs, nil
}

func PruneRuns(dataDir string, keep int, execute bool) ([]string, error) {
	if keep < 0 {
		return nil, errors.New("keep must not be negative")
	}
	dir := filepath.Join(dataDir, "runs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("list runs: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".summary.json") {
			names = append(names, strings.TrimSuffix(entry.Name(), ".summary.json"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if keep >= len(names) {
		return []string{}, nil
	}
	candidates := append([]string(nil), names[keep:]...)
	if !execute {
		return candidates, nil
	}
	for _, id := range candidates {
		for _, suffix := range []string{runSuffix, gzipRunSuffix, summarySuffix} {
			if err := os.Remove(filepath.Join(dir, id+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove run %s: %w", id, err)
			}
		}
	}
	if err := fsx.SyncDir(dir); err != nil {
		return nil, err
	}
	return candidates, nil
}

func StreamCopy(dst io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(dst, f)
	return err
}
