package main

import (
	"os"

	"github.com/drag-team/netvex/internal/cli"
)

func main() {
	ignoreBrokenPipe()
	st, err := os.Stdout.Stat()
	isTTY := err == nil && (st.Mode()&os.ModeCharDevice) != 0
	errorInfo, err := os.Stderr.Stat()
	isErrorTTY := err == nil && (errorInfo.Mode()&os.ModeCharDevice) != 0
	inputInfo, err := os.Stdin.Stat()
	isInputTTY := err == nil && (inputInfo.Mode()&os.ModeCharDevice) != 0
	c := cli.CLI{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, IsTerminal: isTTY, ErrorTerminal: isErrorTTY, InputTerminal: isInputTTY}
	os.Exit(c.Run(os.Args[1:]))
}
