package dashboard

import (
	"context"
	"sync"
)

// scanJob is a queued scan request processed by the worker pool.
type scanJob struct {
	tenant    string
	clusterID string
	subject   string
	scanID    string
}

// workerPool runs scans off the request path (P4) so the API stays responsive on
// large clusters: POST /v1/scans enqueues and returns immediately while a worker
// executes the (potentially slow) scan and streams progress over SSE.
type workerPool struct {
	jobs chan scanJob
	wg   sync.WaitGroup
}

func (a *API) startWorkers(n, queueSize int) {
	if queueSize <= 0 {
		queueSize = 256
	}
	a.pool = &workerPool{jobs: make(chan scanJob, queueSize)}
	for i := 0; i < n; i++ {
		a.pool.wg.Add(1)
		go func() {
			defer a.pool.wg.Done()
			for j := range a.pool.jobs {
				a.runScanJob(context.Background(), j)
			}
		}()
	}
}

// enqueue submits a job without blocking. Returns false if the queue is full
// (the handler then responds 503 so a flood can't grow memory unbounded).
func (a *API) enqueue(j scanJob) bool {
	select {
	case a.pool.jobs <- j:
		return true
	default:
		return false
	}
}

// Close drains and stops the worker pool (called on graceful shutdown).
func (a *API) Close() {
	if a.pool != nil {
		close(a.pool.jobs)
		a.pool.wg.Wait()
		a.pool = nil
	}
}
