package engine

import (
	"context"
	"time"

	"github.com/drag-team/netvex/internal/model"
)

func (c *Checker) waitInterval(ctx context.Context) bool {
	if c.Config.RotationInterval <= 0 {
		return true
	}
	timer := time.NewTimer(c.Config.RotationInterval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Checker) waitBackoff(ctx context.Context, p model.Proxy, retry int) bool {
	base := c.Config.RetryBackoff
	if base <= 0 {
		return true
	}
	delay := base
	for n := 0; n < retry && delay < 5*time.Second; n++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}
	id := p.Identity()
	factor := 0.75 + float64(id[0])/255*0.5
	delay = time.Duration(float64(delay) * factor)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// localBackoff is how long new attempts wait after this host runs out of sockets
// or descriptors. Without it, every worker would fail at once and turn one
// momentary shortage into a large batch of inconclusive results.
const localBackoff = 250 * time.Millisecond

func (c *Checker) noteLocalExhaustion(obs model.Observation) {
	if obs.Code == "local_resource_exhausted" {
		c.localPauseUntil.Store(time.Now().Add(localBackoff).UnixNano())
		c.localPauses.Add(1)
	}
}

// waitTurn holds an attempt until this host has capacity and the rate allows it.
func (c *Checker) waitTurn(ctx context.Context) bool {
	if wait := time.Until(time.Unix(0, c.localPauseUntil.Load())); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return false
		}
	}
	return c.waitRate(ctx)
}

func (c *Checker) waitRate(ctx context.Context) bool {
	if c.Config.RateLimit <= 0 {
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	spacing := time.Duration(float64(time.Second) / c.Config.RateLimit)
	// Slots are reserved on a virtual schedule and slept on outside the lock.
	// Timer overshoot therefore cannot accumulate, which previously capped the
	// real rate near 900/s whatever was configured.
	now := time.Now()
	c.rateMu.Lock()
	slot := c.nextStart
	if slot.Before(now.Add(-rateCatchUp)) {
		// Idle time earns no credit; only a schedule in progress may catch up.
		slot = now
	}
	c.nextStart = slot.Add(spacing)
	c.rateMu.Unlock()
	wait := slot.Sub(now)
	if wait <= 0 {
		return true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		c.rateMu.Lock()
		if c.nextStart.Equal(slot.Add(spacing)) {
			c.nextStart = slot
		}
		c.rateMu.Unlock()
		return false
	}
}

func (c *Checker) acquireTarget(ctx context.Context, host string) func() {
	c.mu.Lock()
	sem := c.targetSem[host]
	if sem == nil {
		limit := c.Config.PerTarget
		if limit > c.Config.Concurrency {
			limit = c.Config.Concurrency
		}
		sem = make(chan struct{}, limit)
		c.targetSem[host] = sem
	}
	c.mu.Unlock()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }
	case <-ctx.Done():
		return nil
	}
}

// rateCatchUp is how far the schedule may lag before unused capacity is
// forfeited. It absorbs timer overshoot without allowing a meaningful burst.
const rateCatchUp = 5 * time.Millisecond
