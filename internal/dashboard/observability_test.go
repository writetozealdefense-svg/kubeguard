package dashboard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func apiWithScanner(t *testing.T, scan Scanner) (*API, *MemStore) {
	t.Helper()
	store := NewMemStore()
	store.RegisterCluster("acme", Cluster{ID: "prod-eu", Name: "prod-eu"})
	auth := NewStaticAuth(map[string]Principal{"admin-tok": {Subject: "ad", Tenant: "acme", Role: RoleAdmin}})
	a := New(Config{Store: store, Auth: auth, Broker: NewBroker(), Clock: fixedClock, Scanner: scan})
	return a, store
}

func TestMetricsExposedAfterScan(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)

	w := do(t, a.Handler(), "GET", "/metrics", "", "")
	body := w.Body.String()
	for _, want := range []string{
		"kubeguard_dashboard_findings",
		"kubeguard_dashboard_compliance_pass_rate",
		"kubeguard_dashboard_scans_total",
		"kubeguard_dashboard_scan_duration_seconds",
		"kubeguard_dashboard_http_request_duration_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	// The findings gauge for prod-eu/critical should reflect the scan (1).
	if !strings.Contains(body, `kubeguard_dashboard_findings{cluster="prod-eu",severity="critical"} 1`) {
		t.Error("findings gauge not set from the scan")
	}
}

func TestScanEmitsTraceSpan(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(otel.GetTracerProvider()) })

	a, _ := testAPI(t)
	a.RunScan(context.Background(), "acme", "prod-eu", "tester")

	var found bool
	for _, s := range sr.Ended() {
		if s.Name() == "dashboard.RunScan" {
			found = true
		}
	}
	if !found {
		t.Fatal("no dashboard.RunScan span recorded")
	}
}

// TestFailedScanLeavesNoPartialState is the chaos/reliability guard: a scan that
// fails (a crash mid-scan) must not persist any scan or history row — the store
// is never left half-written.
func TestFailedScanLeavesNoPartialState(t *testing.T) {
	calls := 0
	a, store := apiWithScanner(t, func(_ context.Context, _ string) (api.Report, error) {
		calls++
		return api.Report{}, errors.New("boom")
	})
	scan := a.RunScan(context.Background(), "acme", "prod-eu", "tester")

	if scan.Status != ScanFailed {
		t.Fatalf("want failed status, got %s", scan.Status)
	}
	if _, total := store.ListScans("acme", "prod-eu", 10, 0); total != 0 {
		t.Fatalf("failed scan must not persist a scan row, got %d", total)
	}
	if len(store.History("acme", "prod-eu")) != 0 {
		t.Fatal("failed scan must not write a history snapshot")
	}
	if _, ok := store.Report("acme", "prod-eu"); ok {
		t.Fatal("failed scan must not leave a report")
	}
	// Reliability: the scanner was retried before giving up.
	if calls != 3 {
		t.Fatalf("expected 3 retry attempts, got %d", calls)
	}
}

func TestScannerRetryRecovers(t *testing.T) {
	calls := 0
	a, store := apiWithScanner(t, func(_ context.Context, _ string) (api.Report, error) {
		calls++
		if calls < 2 {
			return api.Report{}, errors.New("transient")
		}
		return sampleReport(), nil
	})
	scan := a.RunScan(context.Background(), "acme", "prod-eu", "tester")
	if scan.Status != ScanSucceeded {
		t.Fatalf("retry should recover, got %s", scan.Status)
	}
	if _, total := store.ListScans("acme", "prod-eu", 10, 0); total != 1 {
		t.Fatalf("want 1 persisted scan after retry, got %d", total)
	}
}
