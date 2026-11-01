package cli

import (
	"fmt"
	"strings"
	"time"
)

// clearLine returns the cursor to the start of an erased terminal line.
const clearLine = "\r\x1b[2K"

type progressState struct {
	processed, scheduled int64
	ingestDone           bool
	ok, failed           int
	elapsed              time.Duration
}

// progressLine renders one terminal status line. The total is only known once
// the input is fully read, so percentage and ETA appear from that point on.
func progressLine(state progressState) string {
	rate := 0.0
	if state.elapsed > 0 {
		rate = float64(state.processed) / state.elapsed.Seconds()
	}
	var line strings.Builder
	if state.ingestDone && state.scheduled > 0 {
		fmt.Fprintf(&line, "%d/%d %.1f%%", state.processed, state.scheduled, float64(state.processed)*100/float64(state.scheduled))
	} else {
		fmt.Fprintf(&line, "%d/%d+", state.processed, state.scheduled)
	}
	fmt.Fprintf(&line, "  ok=%d failed=%d  %.0f/s", state.ok, state.failed, rate)
	if state.ingestDone && rate > 0 {
		remaining := time.Duration(float64(state.scheduled-state.processed) / rate * float64(time.Second))
		fmt.Fprintf(&line, "  ETA %s", remaining.Round(time.Second))
	}
	return line.String()
}
