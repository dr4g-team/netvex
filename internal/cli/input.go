package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/drag-team/netvex/internal/config"
	inputpkg "github.com/drag-team/netvex/internal/input"
	"github.com/drag-team/netvex/internal/model"
)

// inspect feeds the proxy through standard input rather than a temporary file,
// so credentials never reach the disk. "-" reads it from standard input, which
// also keeps them out of the process list.
func (c CLI) inspect(args []string) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(c.Stderr, inspectUsage)
		return ExitOK
	}
	fs, _ := c.newFlagSet("inspect")
	var ignored checkOptions
	c.addCheckFlags(fs, &ignored)
	if err := parseArguments(fs, args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(c.Stderr, inspectUsage)
		return ExitUsage
	}
	proxy := fs.Arg(0)
	flags := make([]string, 0, len(args)+3)
	removed := false
	for _, arg := range args {
		if !removed && arg == proxy {
			removed = true
			continue
		}
		flags = append(flags, arg)
	}
	if proxy == "-" {
		line, err := bufio.NewReader(c.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		proxy = strings.TrimSpace(line)
	}
	c.Stdin = strings.NewReader(proxy + "\n")
	return c.check(append([]string{"--format", "jsonl", "--repeat", "3"}, flags...), true)
}

const inspectUsage = "usage: netvex inspect PROXY|- [check options]"

func (c CLI) importCmd(args []string) int {
	fs, buf := c.newFlagSet("import")
	inFmt := fs.String("input-format", "auto", "input: auto, text, csv, json, jsonl")
	protoText := fs.String("protocol", "http", "default protocol")
	outFmt := fs.String("format", "txt", "output: txt, jsonl")
	maxBytes := fs.Int64("max-bytes", 256<<20, "maximum input bytes")
	maxEntries := fs.Int("max-entries", 1_000_000, "maximum input records")
	noDeduplicate := fs.Bool("no-deduplicate", false, "disable exact deduplication for bounded parser memory")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *maxBytes < 1 || *maxEntries < 1 || *maxEntries > 50_000_000 {
		fmt.Fprintln(c.Stderr, "max-bytes and max-entries must be within safe positive bounds")
		return ExitUsage
	}
	if *outFmt != "txt" && *outFmt != "jsonl" {
		fmt.Fprintln(c.Stderr, "format must be txt or jsonl")
		return ExitUsage
	}
	p, err := model.ParseProtocol(*protoText)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	parsedInputFormat, err := inputpkg.ParseFormat(*inFmt)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	stdinSources := 0
	for _, name := range fs.Args() {
		if name == "-" {
			stdinSources++
		}
	}
	if stdinSources > 1 {
		fmt.Fprintln(c.Stderr, "standard input may be specified only once")
		return ExitUsage
	}
	parser := inputpkg.New(inputpkg.Options{Format: parsedInputFormat, DefaultProtocol: p, Source: "input", MaxBytes: *maxBytes, MaxEntries: *maxEntries, Deduplicate: !*noDeduplicate})
	identityKey := c.identityKey(config.Defaults().DataDir)
	emit := func(x model.Proxy) error {
		if *outFmt == "jsonl" {
			b, _ := json.Marshal(map[string]any{"id": x.ResultID(identityKey), "proxy": x.SafeURI(), "endpoint": x.Address(), "protocol": x.Protocol})
			_, err := fmt.Fprintln(c.Stdout, string(b))
			return err
		} else {
			_, err := fmt.Fprintln(c.Stdout, x.SafeURI())
			return err
		}
	}
	var e error
	if len(fs.Args()) == 0 {
		e = emitInputSource(parser, c.Stdin, parsedInputFormat, "stdin", emit, nil)
	} else {
		for _, n := range fs.Args() {
			if n == "-" {
				e = emitInputSource(parser, c.Stdin, parsedInputFormat, "stdin", emit, nil)
				if e != nil {
					break
				}
				continue
			}
			f, er := os.Open(n)
			if er != nil {
				e = er
				break
			}
			e = emitInputSource(parser, f, parsedInputFormat, n, emit, nil)
			_ = f.Close()
			if e != nil {
				break
			}
		}
	}
	if e != nil {
		if errors.Is(e, syscall.EPIPE) {
			return ExitOK
		}
		fmt.Fprintln(c.Stderr, e)
		return ExitOperational
	}
	fmt.Fprintf(c.Stderr, "read=%d accepted=%d duplicates=%d rejected=%d\n", parser.Stats.Read, parser.Stats.Accepted, parser.Stats.Duplicates, parser.Stats.Rejected)
	if parser.Stats.Accepted == 0 {
		return ExitNoValidInput
	}
	return ExitOK
}

func emitInputSource(parser *inputpkg.Parser, reader io.Reader, format inputpkg.Format, source string, emit func(model.Proxy) error, reject func(inputpkg.Rejection)) error {
	reader, compressed, err := inputpkg.MaybeDecompress(reader)
	if err != nil {
		return err
	}
	if compressed != nil {
		defer compressed.Close()
	}
	return parser.EmitSource(reader, format, source, emit, reject)
}
