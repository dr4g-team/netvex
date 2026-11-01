package engine

import (
	"context"
	"sync"
	"time"

	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/protocol"
)

// Prescreen separates reachable gateways from dead ones with a TCP handshake.
// Pending connects cost little, so this stage runs far wider than validation.
// Reachable proxies continue on the first channel; the rest become final results
// on the second, which is drained by the caller alongside validation results.
func (c *Checker) Prescreen(ctx context.Context, input <-chan model.Proxy, workers, buffer int) (<-chan model.Proxy, <-chan model.Result) {
	reachable := make(chan model.Proxy, max(1, buffer))
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
					result, alive := c.screen(ctx, connector, proxy)
					if alive {
						select {
						case reachable <- proxy:
						case <-ctx.Done():
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
		close(reachable)
		close(rejected)
	}()
	return reachable, rejected
}

func (c *Checker) screen(ctx context.Context, connector protocol.Connector, proxy model.Proxy) (model.Result, bool) {
	plan := c.plan()
	result := c.newResult(proxy, plan)
	target := c.Config.Targets[0]
	var last model.Observation
	for attempt := 0; attempt <= c.Config.PrescreenRetries; attempt++ {
		if attempt > 0 && !c.waitBackoff(ctx, proxy, attempt-1) {
			break
		}
		if !c.waitRate(ctx) {
			break
		}
		start := time.Now()
		dialed, err := connector.Dial(ctx, proxy)
		if err == nil {
			dialed.Close()
			return model.Result{}, true
		}
		last = finishError(model.Observation{Attempt: 1, StartedAt: start.UTC(), Protocol: proxy.Protocol, Target: c.targetName(target), Status: model.StatusFailed, Stage: model.StageConnect, Anonymity: "unavailable"}, start, err)
		if last.Code == "proxy_gateway_blocked" {
			break
		}
	}
	if last.Code != "" {
		result.Observations = []model.Observation{last}
		result.Attempts = 1
	}
	c.conclude(ctx, &result, proxy, plan)
	return result, false
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
