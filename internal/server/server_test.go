package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubeguard/kubeguard/internal/history"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
)

func fixtureLoader(t *testing.T, file string) Loader {
	t.Helper()
	return func(context.Context) ([]model.Resource, string, error) {
		rs, err := offline.Load("../../test/fixtures/" + file)
		return rs, file, err
	}
}

func newTestServer(t *testing.T, file string) *Server {
	t.Helper()
	s, err := New(Config{Loader: fixtureLoader(t, file)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestServeScanAndPosture(t *testing.T) {
	s := newTestServer(t, "vulnerable.yaml")

	// Before any scan, readiness is not ok.
	if rec := get(t, s, "/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz before scan = %d, want 503", rec.Code)
	}

	// Trigger a scan.
	if rec := get(t, s, "/v1/scan"); rec.Code != http.StatusOK {
		t.Fatalf("/v1/scan = %d", rec.Code)
	}

	if rec := get(t, s, "/readyz"); rec.Code != http.StatusOK {
		t.Errorf("readyz after scan = %d, want 200", rec.Code)
	}
	if rec := get(t, s, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("healthz = %d", rec.Code)
	}

	// Posture endpoint.
	rec := get(t, s, "/v1/posture")
	if rec.Code != http.StatusOK {
		t.Fatalf("/v1/posture = %d", rec.Code)
	}
	var body struct {
		Posture    api.PostureSummary    `json:"posture"`
		Compliance []api.FrameworkResult `json:"compliance"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode posture: %v", err)
	}
	if body.Posture.ControlsAssessed == 0 || body.Posture.ControlsBreached == 0 {
		t.Errorf("vulnerable posture should have assessed + breached controls: %+v", body.Posture)
	}
	if len(body.Compliance) != 11 {
		t.Errorf("expected 11 frameworks, got %d", len(body.Compliance))
	}

	// Findings endpoint.
	frec := get(t, s, "/v1/findings")
	var findings []api.Finding
	if err := json.Unmarshal(frec.Body.Bytes(), &findings); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings")
	}
}

func TestServeMetrics(t *testing.T) {
	s := newTestServer(t, "vulnerable.yaml")
	if _, err := s.ScanOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := get(t, s, "/metrics").Body.String()
	for _, want := range []string{
		"kubeguard_compliance_pass_rate",
		"kubeguard_findings_total",
		"kubeguard_attack_paths_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing gauge %q", want)
		}
	}
	// The pass-rate gauge must carry a framework label and a value.
	if !strings.Contains(body, `kubeguard_compliance_pass_rate{framework=`) {
		t.Error("pass-rate gauge missing framework label")
	}
}

func TestServeDashboard(t *testing.T) {
	s := newTestServer(t, "vulnerable.yaml")
	if _, err := s.ScanOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := get(t, s, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "KubeGuard Report") {
		t.Errorf("dashboard not rendered: code=%d", rec.Code)
	}
}

func TestServeRequiresLoader(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New should require a Loader")
	}
}

func TestEndpointsBeforeScan(t *testing.T) {
	s := newTestServer(t, "hardened.yaml")
	for _, p := range []string{"/v1/findings", "/v1/posture", "/v1/report", "/"} {
		if rec := get(t, s, p); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s before scan = %d, want 503", p, rec.Code)
		}
	}
}

func TestScanLoaderError(t *testing.T) {
	s, err := New(Config{Loader: func(context.Context) ([]model.Resource, string, error) {
		return nil, "", fmt.Errorf("cluster unreachable")
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScanOnce(context.Background()); err == nil {
		t.Error("expected scan error")
	}
	if rec := get(t, s, "/v1/scan"); rec.Code != http.StatusInternalServerError {
		t.Errorf("/v1/scan with bad loader = %d, want 500", rec.Code)
	}
}

func TestServeWithHistoryAndReport(t *testing.T) {
	store, _ := history.OpenFile(filepath.Join(t.TempDir(), "h.jsonl"))
	s, err := New(Config{Loader: fixtureLoader(t, "vulnerable.yaml"), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScanOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := get(t, s, "/v1/report")
	var rep api.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Error("report should carry findings")
	}
	// History persisted; dashboard renders with a trend.
	if recs, _ := store.All(); len(recs) != 1 {
		t.Errorf("history records = %d, want 1", len(recs))
	}
	if !strings.Contains(get(t, s, "/").Body.String(), "KubeGuard Report") {
		t.Error("dashboard should render with history")
	}
}

func TestStartRunsAndShutsDown(t *testing.T) {
	s := newTestServer(t, "hardened.yaml")
	s.cfg.Schedule = "@every 1h" // exercise the scheduler branch
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx, "127.0.0.1:0") }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Start did not shut down within 3s")
	}
}
