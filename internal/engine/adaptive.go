package engine

import (
	"context"
	"sync"

	"github.com/drag-team/netvex-go/internal/model"
)

// AdaptiveController is an opt-in AIMD admission controller. It reacts only to
// local socket exhaustion, never to slow or dead remote proxies, so it cannot
// accidentally serialize a timeout-heavy list.
type AdaptiveController struct {
	mu                              sync.Mutex
	changed                         chan struct{}
	active, limit, minimum, maximum int
	window, completed, exhausted    int
}

func NewAdaptiveController(minimum, maximum, window int) *AdaptiveController {
	minimum = max(1, min(minimum, maximum))
	return &AdaptiveController{changed: make(chan struct{}), limit: minimum, minimum: minimum, maximum: maximum, window: max(8, window)}
}

func (a *AdaptiveController) Acquire(ctx context.Context) bool {
	for {
		a.mu.Lock()
		if a.active < a.limit {
			a.active++
			a.mu.Unlock()
			return true
		}
		changed := a.changed
		a.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return false
		}
	}
}

func (a *AdaptiveController) Release(result model.Result) {
	a.mu.Lock()
	a.active--
	a.completed++
	for _, observation := range result.Observations {
		if observation.Code == "local_resource_exhausted" {
			a.exhausted++
			break
		}
	}
	if a.completed >= a.window {
		if a.exhausted > 0 {
			a.limit = max(a.minimum, a.limit/2)
		} else if a.limit < a.maximum {
			a.limit = min(a.maximum, a.limit+max(1, a.limit/8))
		}
		a.completed, a.exhausted = 0, 0
	}
	close(a.changed)
	a.changed = make(chan struct{})
	a.mu.Unlock()
}

func (a *AdaptiveController) Limit() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.limit
}

func (a *AdaptiveController) SetMaximum(maximum int) {
	a.mu.Lock()
	a.maximum = max(1, maximum)
	a.limit = min(a.limit, a.maximum)
	a.minimum = min(a.minimum, a.maximum)
	close(a.changed)
	a.changed = make(chan struct{})
	a.mu.Unlock()
}
