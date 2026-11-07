package engine

import (
	"sync"
	"time"
)

// durationEstimator uses an EWMA and absolute deviation. It remains inactive
// until enough successful samples exist, then supplies a conservative bound.
type durationEstimator struct {
	mu              sync.Mutex
	samples         int
	mean, deviation float64
}

func (e *durationEstimator) Observe(value time.Duration) {
	if value <= 0 {
		return
	}
	e.mu.Lock()
	x := float64(value)
	if e.samples == 0 {
		e.mean = x
	} else {
		delta := x - e.mean
		e.mean += delta / 8
		if delta < 0 {
			delta = -delta
		}
		e.deviation += (delta - e.deviation) / 8
	}
	e.samples++
	e.mu.Unlock()
}

func (e *durationEstimator) Timeout(floor, ceiling time.Duration) time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.samples < 16 {
		return ceiling
	}
	value := time.Duration(e.mean + 4*e.deviation)
	return max(floor, min(value, ceiling))
}

func (e *durationEstimator) Reset() {
	e.mu.Lock()
	e.samples, e.mean, e.deviation = 0, 0, 0
	e.mu.Unlock()
}
