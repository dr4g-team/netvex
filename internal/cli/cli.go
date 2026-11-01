package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"
	"syscall"

	"github.com/drag-team/netvex/internal/buildinfo"
	schemapkg "github.com/drag-team/netvex/internal/schema"
)

const (
	ExitOK           = 0
	ExitUsage        = 2
	ExitOperational  = 3
	ExitNoValidInput = 4
	ExitNoSuccess    = 5
	ExitInterrupted  = 130
)

type CLI struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	IsTerminal     bool
	// ErrorTerminal enables the live progress line, which writes to stderr so that
	// redirecting stdout to a file still shows progress.
	ErrorTerminal bool
	// InputTerminal reports that stdin is a person, not a pipe. Reading proxies from
	// it would look like a hang, so commands ask for a file instead.
	InputTerminal bool
}

func (c CLI) Run(args []string) int {
	if len(args) == 0 {
		return c.help()
	}
	switch args[0] {
	case "help", "--help", "-h":
		return c.help()
	case "version", "--version":
		fmt.Fprintf(c.Stdout, "netvex %s commit=%s built=%s go=%s\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date, runtime.Version())
		return ExitOK
	case "check":
		return c.check(args[1:], false)
	case "inspect":
		return c.inspect(args[1:])
	case "import":
		return c.importCmd(args[1:])
	case "results":
		return c.results(args[1:])
	case "runs":
		return c.runs(args[1:])
	case "export":
		return c.export(args[1:])
	case "stats":
		return c.stats(args[1:])
	case "history":
		return c.history(args[1:])
	case "pool":
		return c.pool(args[1:])
	case "shard":
		return c.shard(args[1:])
	case "merge":
		return c.merge(args[1:])
	case "diff":
		return c.diff(args[1:])
	case "explore":
		return c.explore(args[1:])
	case "config":
		return c.configCmd(args[1:])
	case "doctor":
		return c.doctor(args[1:])
	case "bench":
		return c.bench(args[1:])
	case "completion":
		return c.completion(args[1:])
	case "capabilities":
		return c.capabilities(args[1:])
	case "schema":
		return c.schemaCmd(args[1:])
	default:
		if suggestion := closestCommand(args[0]); suggestion != "" {
			fmt.Fprintf(c.Stderr, "netvex: unknown command %q; did you mean %q?\n", args[0], suggestion)
		} else {
			fmt.Fprintf(c.Stderr, "netvex: unknown command %q; run 'netvex help'\n", args[0])
		}
		return ExitUsage
	}
}

const commandNames = "check inspect import results runs export stats history pool shard merge diff explore config doctor bench capabilities schema completion version help"

// closestCommand suggests a command within two edits, so typos get an answer
// instead of a pointer to the help text.
func closestCommand(input string) string {
	best, bestDistance := "", 3
	for _, name := range strings.Fields(commandNames) {
		if distance := editDistance(strings.ToLower(input), name); distance < bestDistance {
			best, bestDistance = name, distance
		}
	}
	return best
}

func editDistance(left, right string) int {
	previous := make([]int, len(right)+1)
	for index := range previous {
		previous[index] = index
	}
	for row := 1; row <= len(left); row++ {
		current := make([]int, len(right)+1)
		current[0] = row
		for column := 1; column <= len(right); column++ {
			cost := 1
			if left[row-1] == right[column-1] {
				cost = 0
			}
			current[column] = min(previous[column]+1, current[column-1]+1, previous[column-1]+cost)
		}
		previous = current
	}
	return previous[len(right)]
}

func (c CLI) schemaCmd(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(c.Stderr, "usage: netvex schema result|summary")
		return ExitUsage
	}
	document, err := schemapkg.Generate(args[0])
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	fmt.Fprintln(c.Stdout, string(document))
	return ExitOK
}

func (c CLI) help() int {
	fmt.Fprint(c.Stdout, `NetVex — proxy validation and intelligence

Usage: netvex <command> [options]

Commands:
  check      validate proxy datasets with bounded concurrency
  inspect    deeply inspect one proxy
  import     normalize and validate input without network access
  results    filter a saved run
  runs       list saved validation runs
  export     export a saved run as JSON, JSONL, CSV, or TXT
  stats      summarize a saved run
  history    analyze stability across saved runs
  pool       analyze exit, subnet, ASN, and country diversity
  shard      split normalized proxy datasets reproducibly
  merge      merge and deduplicate result runs
  diff       show what changed between two saved runs
  explore    interactively browse a saved run
  config     show, validate, or initialize configuration
  doctor     diagnose the local runtime and optional network resolution
  bench      run a controlled scheduler benchmark
  capabilities show machine-readable protocols, formats, and safeguards
  schema     print the JSON Schema for results or summaries
  completion generate shell completion for bash, zsh, or fish
  version    show build information

Run 'netvex <command> --help' for command options.
Exit codes: 0 completed, 2 usage/config, 3 operational, 4 no valid input,
5 validation threshold or quality policy not met, 130 interrupted.
`)
	return ExitOK
}

type capabilityDocument struct {
	SchemaVersion    int      `json:"schema_version"`
	Product          string   `json:"product"`
	Version          string   `json:"version"`
	Protocols        []string `json:"protocols"`
	ProxyAuth        []string `json:"proxy_authentication"`
	InputFormats     []string `json:"input_formats"`
	InputCompression []string `json:"input_compression"`
	OutputFormats    []string `json:"output_formats"`
	Reports          []string `json:"reports"`
	Safeguards       []string `json:"safeguards"`
	Platforms        []string `json:"build_platforms"`
}

func currentCapabilities() capabilityDocument {
	return capabilityDocument{
		SchemaVersion:    1,
		Product:          "netvex",
		Version:          buildinfo.Version,
		Protocols:        []string{"http", "https", "socks4", "socks4a", "socks5", "auto"},
		ProxyAuth:        []string{"http_basic", "http_digest", "socks4_userid", "socks5_username_password"},
		InputFormats:     []string{"text", "csv", "json", "jsonl", "auto"},
		InputCompression: []string{"gzip", "bzip2"},
		OutputFormats:    []string{"table", "json", "jsonl", "csv", "txt"},
		Reports:          []string{"summary_json", "prometheus_textfile", "junit_xml"},
		Safeguards:       []string{"bounded_concurrency", "bounded_input", "bounded_response", "credential_redaction", "destination_allowlist", "dns_pinning", "private_gateway_block", "safe_redirects", "tls_verification"},
		Platforms:        []string{"linux", "darwin", "windows", "freebsd", "openbsd", "netbsd", "dragonfly", "illumos", "solaris", "aix"},
	}
}

func (c CLI) capabilities(args []string) int {
	fs, buf := c.newFlagSet("capabilities")
	jsonOutput := fs.Bool("json", false, "emit a JSON capability document")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	document := currentCapabilities()
	if *jsonOutput {
		encoder := json.NewEncoder(c.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(document); err != nil {
			if errors.Is(err, syscall.EPIPE) {
				return ExitOK
			}
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		return ExitOK
	}
	fmt.Fprintf(c.Stdout, "protocols=%s\n", strings.Join(document.Protocols, ","))
	fmt.Fprintf(c.Stdout, "proxy_authentication=%s\n", strings.Join(document.ProxyAuth, ","))
	fmt.Fprintf(c.Stdout, "input_formats=%s compression=%s\n", strings.Join(document.InputFormats, ","), strings.Join(document.InputCompression, ","))
	fmt.Fprintf(c.Stdout, "output_formats=%s reports=%s\n", strings.Join(document.OutputFormats, ","), strings.Join(document.Reports, ","))
	fmt.Fprintf(c.Stdout, "safeguards=%s\n", strings.Join(document.Safeguards, ","))
	fmt.Fprintf(c.Stdout, "build_platforms=%s\n", strings.Join(document.Platforms, ","))
	return ExitOK
}

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }

func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func (c CLI) newFlagSet(name string) (*flag.FlagSet, *bytesBuffer) {
	b := &bytesBuffer{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(b)
	return fs, b
}

type bytesBuffer struct{ strings.Builder }

// parseArguments accepts flags before and after positional arguments, because
// the standard parser treats everything after the first file name as a file.
func parseArguments(fs *flag.FlagSet, args []string) error {
	positional := make([]string, 0, 4)
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		rest := fs.Args()
		consumed := args[:len(args)-len(rest)]
		if len(rest) == 0 || (len(consumed) > 0 && consumed[len(consumed)-1] == "--") {
			positional = append(positional, rest...)
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return fs.Parse(append([]string{"--"}, positional...))
}

func (c CLI) parseFlags(fs *flag.FlagSet, buf *bytesBuffer, args []string) (bool, int) {
	err := parseArguments(fs, args)
	if err == nil {
		return true, ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(c.Stdout, buf.String())
		return false, ExitOK
	}
	fmt.Fprint(c.Stderr, buf.String())
	return false, ExitUsage
}
