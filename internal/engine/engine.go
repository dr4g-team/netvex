package engine

import (
	"context"
	"sync"

	"github.com/drag-team/netvex-go/internal/model"
)

type Processor interface {
	Check(context.Context, model.Proxy) model.Result
}

type Engine struct {
	Workers   int
	QueueSize int
	Processor Processor
	Adaptive  *AdaptiveController
}

type PreparedProcessor interface {
	CheckPrepared(context.Context, PreparedProxy) model.Result
}

func (e Engine) Run(ctx context.Context, input <-chan model.Proxy) <-chan model.Result {
	return runJobs(ctx, e, input, func(proxy model.Proxy) model.Result {
		return e.Processor.Check(ctx, proxy)
	}, func(model.Proxy) {})
}

func (e Engine) RunPrepared(ctx context.Context, input <-chan PreparedProxy) <-chan model.Result {
	processor, acceptsPrepared := e.Processor.(PreparedProcessor)
	return runJobs(ctx, e, input, func(candidate PreparedProxy) model.Result {
		if acceptsPrepared {
			return processor.CheckPrepared(ctx, candidate)
		}
		candidate.Close()
		return e.Processor.Check(ctx, candidate.Proxy)
	}, func(candidate PreparedProxy) { candidate.Close() })
}

func runJobs[T any](ctx context.Context, e Engine, input <-chan T, process func(T) model.Result, cleanup func(T)) <-chan model.Result {
	out := make(chan model.Result, max(1, e.QueueSize))
	workers := e.Workers
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-input:
					if !ok {
						return
					}
					if e.Adaptive != nil && !e.Adaptive.Acquire(ctx) {
						cleanup(job)
						return
					}
					r := process(job)
					if e.Adaptive != nil {
						e.Adaptive.Release(r)
					}
					select {
					case out <- r:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		// Cancellation can leave prepared sockets buffered after every worker
		// exits. Let cleanup continue independently so result shutdown never
		// depends on an arbitrary caller closing its input channel.
		if ctx.Err() != nil {
			go func() {
				for job := range input {
					cleanup(job)
				}
			}()
			close(out)
			return
		}
		for job := range input {
			cleanup(job)
		}
		close(out)
	}()
	return out
}
