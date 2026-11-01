package engine

import (
	"context"
	"sync"
	"time"

	"github.com/drag-team/netvex/internal/model"
)

const (
	canaryRecheckDelay = time.Second
	canaryPollInterval = 200 * time.Millisecond
	canaryMaxPause     = 2 * time.Minute
)

// RunCanary checks targets directly until ctx ends. Without it, a target outage
// mid-run looks exactly like every proxy failing at once. It only reduces that
// window: failures before the next probe keep their original classification.
func (c *Checker) RunCanary(ctx context.Context) {
	ticker := time.NewTicker(c.Config.CanaryInterval)
	defer ticker.Stop()
	for {
		c.probeTargets(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Checker) probeTargets(ctx context.Context) {
	down := make(map[string]struct{})
	var mu sync.Mutex
	var group sync.WaitGroup
	for _, target := range c.Config.Targets {
		group.Add(1)
		go func() {
			defer group.Done()
			if c.targetHealthy(ctx, target) || ctx.Err() != nil {
				return
			}
			mu.Lock()
			down[target] = struct{}{}
			mu.Unlock()
		}()
	}
	group.Wait()
	if ctx.Err() != nil {
		return
	}
	previous := c.canaryDown.Swap(&down)
	if previous == nil || len(*previous) == 0 {
		if len(down) > 0 {
			c.canaryOutages.Add(1)
		}
	}
}

// targetHealthy confirms a failure once, so one lost packet cannot pause a run.
func (c *Checker) targetHealthy(ctx context.Context, target string) bool {
	probe := c.canaryProbe
	if probe == nil {
		probe = c.preflightTarget
	}
	c.canaryChecks.Add(1)
	if probe(ctx, target).Status == "ok" {
		return true
	}
	timer := time.NewTimer(min(canaryRecheckDelay, c.Config.CanaryInterval))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return false
	}
	c.canaryChecks.Add(1)
	if probe(ctx, target).Status == "ok" {
		return true
	}
	c.canaryFailures.Add(1)
	return false
}

func (c *Checker) targetDown(target string) bool {
	down := c.canaryDown.Load()
	if down == nil {
		return false
	}
	_, unhealthy := (*down)[target]
	return unhealthy
}

// waitTargetHealthy holds a worker during an outage. The pause is bounded so an
// outage cannot hang unattended runs; after it, results become inconclusive.
func (c *Checker) waitTargetHealthy(ctx context.Context, target string) bool {
	if !c.targetDown(target) {
		return true
	}
	deadline := time.NewTimer(min(canaryMaxPause, 5*c.Config.CanaryInterval))
	defer deadline.Stop()
	poll := time.NewTicker(canaryPollInterval)
	defer poll.Stop()
	for c.targetDown(target) {
		select {
		case <-poll.C:
		case <-deadline.C:
			return true
		case <-ctx.Done():
			return false
		}
	}
	return true
}

// reclassifyDuringOutage withholds judgment on proxies that failed while the
// target itself was down. Authentication and policy results stay, because they
// are decided before the destination is involved.
func (c *Checker) reclassifyDuringOutage(obs *model.Observation, target string) {
	if obs.Status != model.StatusFailed && obs.Status != model.StatusTimeout {
		return
	}
	if c.targetDown(target) {
		obs.Status = model.StatusInconclusive
		obs.Code = "target_unhealthy"
		obs.Message = "the target failed a direct health check during this measurement"
		c.canaryReclassified.Add(1)
	}
}

// CanaryReport summarizes canary activity for the run summary.
func (c *Checker) CanaryReport() *model.CanaryReport {
	if c.Config.CanaryInterval <= 0 {
		return nil
	}
	return &model.CanaryReport{Checks: c.canaryChecks.Load(), Failures: c.canaryFailures.Load(), Outages: c.canaryOutages.Load(), Reclassified: c.canaryReclassified.Load()}
}
