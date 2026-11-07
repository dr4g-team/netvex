package engine

import (
	"context"
	"sync"
	"time"

	"github.com/drag-team/netvex-go/internal/model"
	"github.com/drag-team/netvex-go/internal/protocol"
)

// PreparedProxy owns a live gateway socket produced by the prescreen stage.
// Exactly one validation consumes it; Close is safe after consumption.
type PreparedProxy struct {
	Proxy  model.Proxy
	Dialed protocol.Dialed
}

func (p *PreparedProxy) Close() { p.Dialed.Close() }

// Prescreen separates reachable gateways from dead ones with a TCP handshake.
// Pending connects cost little, so this stage runs far wider than validation.
// Reachable proxies continue on the first channel; the rest become final results
// on the second, which is drained by the caller alongside validation results.
func (c *Checker) Prescreen(ctx context.Context, input <-chan model.Proxy, workers, buffer int) (<-chan model.Proxy, <-chan model.Result) {
	prepared, rejected := c.PrescreenPrepared(ctx, input, workers, buffer, false)
	reachable := make(chan model.Proxy, max(1, buffer))
	go func() {
		defer close(reachable)
		for candidate := range prepared {
			candidate.Close()
			select {
			case reachable <- candidate.Proxy:
			case <-ctx.Done():
				return
			}
		}
	}()
	return reachable, rejected
}

// PrescreenPrepared optionally transfers each healthy TCP connection to the
// validator. This removes one DNS lookup and one TCP handshake from the hot path.
func (c *Checker) PrescreenPrepared(ctx context.Context, input <-chan model.Proxy, workers, buffer int, reuse bool) (<-chan PreparedProxy, <-chan model.Result) {
	return c.PrescreenPreparedControlled(ctx, input, workers, buffer, reuse, nil)
}

// PrescreenPreparedControlled shares an optional admission controller with the
// validation stage, keeping the total socket pressure adaptive end to end.
func (c *Checker) PrescreenPreparedControlled(ctx context.Context, input <-chan model.Proxy, workers, buffer int, reuse bool, adaptive *AdaptiveController) (<-chan PreparedProxy, <-chan model.Result) {
	reachable := make(chan PreparedProxy, max(1, buffer))
	rejected := make(chan model.Result, max(1, buffer))
	connector := c.Connector
	if c.Config.PrescreenTimeout > 0 {
		connector.ConnectTimeout = c.Config.PrescreenTimeout
	}
	var group sync.WaitGroup
	group.Add(max(1, workers))
	for range max(1, workers) {
		go func() {
			defer group.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case proxy, ok := <-input:
					if !ok {
						return
					}
					if adaptive != nil && !adaptive.Acquire(ctx) {
						return
					}
					result, dialed, alive := c.screen(ctx, connector, proxy)
					if adaptive != nil {
						observed := result
						if alive {
							observed = model.Result{Status: model.StatusOK}
						}
						adaptive.Release(observed)
					}
					if alive {
						if !reuse {
							dialed.Close()
						}
						candidate := PreparedProxy{Proxy: proxy, Dialed: dialed}
						select {
						case reachable <- candidate:
						case <-ctx.Done():
							candidate.Close()
							return
						}
						continue
					}
					select {
					case rejected <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		group.Wait()
		if adaptive != nil {
			adaptive.SetMaximum(c.Config.Concurrency)
		}
		close(reachable)
		close(rejected)
	}()
	return reachable, rejected
}

func (c *Checker) screen(ctx context.Context, connector protocol.Connector, proxy model.Proxy) (model.Result, protocol.Dialed, bool) {
	plan := c.plan()
	result := c.newResult(proxy, plan)
	target := c.Config.Targets[0]
	var last model.Observation
	ceiling := connector.ConnectTimeout
	for attempt := 0; attempt <= c.Config.PrescreenRetries; attempt++ {
		if attempt > 0 && !c.waitBackoff(ctx, proxy, attempt-1) {
			break
		}
		if !c.waitTurn(ctx) {
			break
		}
		start := time.Now()
		if c.Config.AdaptiveTimeouts {
			connector.ConnectTimeout = c.connectEstimator.Timeout(c.Config.AdaptiveTimeoutFloor, ceiling)
		}
		dialed, err := connector.Dial(ctx, proxy)
		if err == nil {
			c.observeConnect(dialed)
			return model.Result{}, dialed, true
		}
		c.observeConnectFailure(err)
		last = finishError(model.Observation{Attempt: 1, StartedAt: start.UTC(), Protocol: proxy.Protocol, Target: c.targetName(target), Status: model.StatusFailed, Stage: model.StageConnect, Anonymity: "unavailable"}, start, err)
		c.noteLocalExhaustion(last)
		if last.Code == "proxy_gateway_blocked" {
			break
		}
		if c.Config.AdaptivePrescreen && !prescreenRetryable(last) {
			break
		}
	}
	if last.Code != "" {
		result.Observations = []model.Observation{last}
		result.Attempts = 1
	}
	c.conclude(ctx, &result, proxy, plan)
	return result, protocol.Dialed{}, false
}

func prescreenRetryable(observation model.Observation) bool {
	if observation.Status == model.StatusTimeout || observation.Status == model.StatusInconclusive {
		return observation.Code != "local_resource_exhausted"
	}
	switch observation.Code {
	case "connection_reset", "connection_closed", "unexpected_eof":
		return true
	default:
		return false
	}
}

// Merge forwards two result streams into one until both are closed.
func Merge(first, second <-chan model.Result, buffer int) <-chan model.Result {
	out := make(chan model.Result, max(1, buffer))
	var group sync.WaitGroup
	forward := func(source <-chan model.Result) {
		defer group.Done()
		for result := range source {
			out <- result
		}
	}
	group.Add(2)
	go forward(first)
	go forward(second)
	go func() {
		group.Wait()
		close(out)
	}()
	return out
}
