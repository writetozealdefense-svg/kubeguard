package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubeguard/kubeguard/internal/analyzer"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/pkg/api"
)

func TestAsyncWorkerProcessesScan(t *testing.T) {
	store := NewMemStore()
	store.RegisterCluster("acme", Cluster{ID: "prod-eu", Name: "prod-eu"})
	auth := NewStaticAuth(map[string]Principal{"admin-tok": {Subject: "ad", Tenant: "acme", Role: RoleAdmin}})
	a := New(Config{Store: store, Auth: auth, Broker: NewBroker(), Clock: fixedClock, AsyncWorkers: 2,
		Scanner: func(_ context.Context, _ string) (api.Report, error) { return sampleReport(), nil }})
	defer a.Close()

	// POST returns immediately with a queued scan.
	w := do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "queued") {
		t.Fatalf("async trigger: want 202 queued, got %d %s", w.Code, w.Body.String())
	}
	// The worker completes the scan shortly after.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, total := store.ListScans("acme", "prod-eu", 10, 0); total == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("worker did not persist the scan")
}

// TestAPILatencyP95 measures read-path p95 under concurrent load against the
// in-memory handler. The target mirrors the API p95 NFR (<120ms).
func TestAPILatencyP95(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)
	h := a.Handler()

	const total = 2000
	const concurrency = 32
	lat := make([]time.Duration, total)
	var wg sync.WaitGroup
	ch := make(chan int, total)
	for i := 0; i < total; i++ {
		ch <- i
	}
	close(ch)
	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				req := httptest.NewRequest("GET", "/v1/findings?cluster=prod-eu", nil)
				req.Header.Set("Authorization", "Bearer viewer-tok")
				rec := httptest.NewRecorder()
				start := time.Now()
				h.ServeHTTP(rec, req)
				lat[i] = time.Since(start)
				if rec.Code != http.StatusOK {
					t.Errorf("status %d", rec.Code)
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p95 := lat[int(float64(total)*0.95)]
	t.Logf("API read p95 over %d reqs (%d concurrent): %v", total, concurrency, p95)
	if p95 > 120*time.Millisecond {
		t.Fatalf("p95 %v exceeds 120ms target", p95)
	}
}

// TestScan5kPodsWithinBudget builds a synthetic 5,000-workload cluster fixture,
// runs it through the real loader + engine, and asserts it completes within a
// documented budget. The measured time is logged.
func TestScan5kPodsWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 5k-pod perf test in -short mode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.yaml")
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&b, `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-%d
  namespace: ns-%d
spec:
  template:
    spec:
      containers:
      - name: c
        image: nginx:latest
---
`, i, i%50)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	resources, err := offline.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := analyzer.Analyze(resources, "zeal-default", false)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	t.Logf("5k-pod scan: loaded %d resources, %d findings, in %v", len(resources), len(rep.Findings), elapsed)
	const budget = 30 * time.Second
	if elapsed > budget {
		t.Fatalf("5k-pod scan took %v, over budget %v", elapsed, budget)
	}
}
