package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// fixedClock makes timestamps deterministic in tests (NFR-11).
func fixedClock() time.Time { return time.Date(2026, 6, 7, 8, 0, 0, 0, time.UTC) }

func sampleReport() api.Report {
	return api.Report{
		Profile: "zeal-default",
		Findings: []api.Finding{
			{ID: "KG-001", Title: "Privileged container", Severity: api.SeverityCritical, Category: "workload",
				Resource: api.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "checkout"},
				Refs:     []api.ControlRef{{Framework: "CIS Kubernetes Benchmark", ID: "5.2.1"}}},
			{ID: "KG-013", Title: "RBAC reads secrets", Severity: api.SeverityHigh, Category: "rbac",
				Resource: api.ResourceRef{Kind: "ClusterRole", Name: "checkout-power"},
				Refs:     []api.ControlRef{{Framework: "NSA", ID: "RBAC"}}},
			{ID: "KG-017", Title: "No default-deny NetworkPolicy", Severity: api.SeverityMedium, Category: "network",
				Resource: api.ResourceRef{Kind: "Namespace", Name: "payments"}},
			{ID: "KG-019", Title: "Mutable image tag", Severity: api.SeverityLow, Category: "supply-chain",
				Resource: api.ResourceRef{Kind: "Deployment", Namespace: "web", Name: "frontend"}},
		},
		Paths: []api.AttackPath{{ID: "AP-001", Title: "Cluster-admin takeover", Severity: api.SeverityCritical,
			Entry: api.ResourceRef{Kind: "Service", Name: "checkout-lb"}, Hops: []api.PathHop{{Order: 1, From: "InternetIngress", To: "NetworkReachable", EnabledBy: "KG-018", Technique: []string{"T1190"}}}}},
		Posture: api.PostureSummary{
			TotalFindings: 4, BySeverity: map[api.Severity]int{api.SeverityCritical: 1, api.SeverityHigh: 1, api.SeverityMedium: 1, api.SeverityLow: 1},
			CriticalPaths: 1, ControlsAssessed: 9, ControlsBreached: 8, OverallPassRate: 0.11,
		},
		Compliance: []api.FrameworkResult{
			{Framework: "CIS Kubernetes Benchmark", Assessed: 9, Breached: 8, Passed: 1, PassRate: 0.11, Disclaimer: "indicative mapping only"},
		},
	}
}

// testAPI wires an API with a static authenticator (viewer/analyst/admin in
// tenant "acme", and one principal in tenant "other"), a deterministic clock/id,
// and a scanner that returns sampleReport.
func testAPI(t *testing.T) (*API, *MemStore) {
	t.Helper()
	store := NewMemStore()
	store.RegisterCluster("acme", Cluster{ID: "prod-eu", Name: "prod-eu", Environment: "production"})
	store.RegisterCluster("acme", Cluster{ID: "staging", Name: "staging"})
	store.RegisterCluster("other", Cluster{ID: "secret-cluster", Name: "secret-cluster"})

	auth := NewStaticAuth(map[string]Principal{
		"viewer-tok":  {Subject: "v", Tenant: "acme", Role: RoleViewer},
		"analyst-tok": {Subject: "a", Tenant: "acme", Role: RoleAnalyst},
		"admin-tok":   {Subject: "ad", Tenant: "acme", Role: RoleAdmin},
		"other-tok":   {Subject: "o", Tenant: "other", Role: RoleAdmin},
	})
	a := New(Config{
		Store: store, Auth: auth, Broker: NewBroker(), Clock: fixedClock,
		Scanner: func(_ context.Context, _ string) (api.Report, error) { return sampleReport(), nil },
	})
	return a, store
}

func do(t *testing.T, h http.Handler, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthFailClosed(t *testing.T) {
	a, _ := testAPI(t)
	if w := do(t, a.Handler(), "GET", "/v1/clusters", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", w.Code)
	}
	if w := do(t, a.Handler(), "GET", "/v1/clusters", "bogus", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401, got %d", w.Code)
	}
}

func TestViewerCannotTriggerScan(t *testing.T) {
	a, _ := testAPI(t)
	w := do(t, a.Handler(), "POST", "/v1/scans", "viewer-tok", `{"clusterId":"prod-eu"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer trigger: want 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestAnalystCanTriggerScanAndItPersists(t *testing.T) {
	a, _ := testAPI(t)
	w := do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("analyst trigger: want 202, got %d (%s)", w.Code, w.Body.String())
	}
	// The scan now shows up and findings render off the persisted report.
	fw := do(t, a.Handler(), "GET", "/v1/findings?cluster=prod-eu", "viewer-tok", "")
	var page struct {
		Total int `json:"total"`
	}
	mustJSON(t, fw, &page)
	if page.Total != 4 {
		t.Fatalf("findings total after scan: want 4, got %d", page.Total)
	}
}

func TestTenantIsolation(t *testing.T) {
	a, _ := testAPI(t)
	// acme analyst scans prod-eu.
	do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`)

	// "other" tenant must never see acme clusters or findings.
	cw := do(t, a.Handler(), "GET", "/v1/clusters", "other-tok", "")
	var cl struct {
		Clusters []Cluster `json:"clusters"`
	}
	mustJSON(t, cw, &cl)
	for _, c := range cl.Clusters {
		if c.ID == "prod-eu" {
			t.Fatal("cross-tenant cluster leaked into other tenant")
		}
	}
	fw := do(t, a.Handler(), "GET", "/v1/findings", "other-tok", "")
	var page struct {
		Total int `json:"total"`
	}
	mustJSON(t, fw, &page)
	if page.Total != 0 {
		t.Fatalf("cross-tenant findings leaked: want 0, got %d", page.Total)
	}
}

func TestFindingsFilterSeverityAndFramework(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)

	// severity filter
	w := do(t, a.Handler(), "GET", "/v1/findings?cluster=prod-eu&severity=critical,high", "viewer-tok", "")
	var page struct {
		Total    int           `json:"total"`
		Findings []api.Finding `json:"findings"`
	}
	mustJSON(t, w, &page)
	if page.Total != 2 {
		t.Fatalf("severity filter: want 2, got %d", page.Total)
	}
	// framework filter (CIS only tags KG-001)
	w = do(t, a.Handler(), "GET", "/v1/findings?cluster=prod-eu&framework=cis", "viewer-tok", "")
	mustJSON(t, w, &page)
	if page.Total != 1 || page.Findings[0].ID != "KG-001" {
		t.Fatalf("framework filter: want [KG-001], got total=%d", page.Total)
	}
	// search filter
	w = do(t, a.Handler(), "GET", "/v1/findings?cluster=prod-eu&search=networkpolicy", "viewer-tok", "")
	mustJSON(t, w, &page)
	if page.Total != 1 || page.Findings[0].ID != "KG-017" {
		t.Fatalf("search filter: want [KG-017], got total=%d", page.Total)
	}
}

func TestFindingsSortAndPaginate(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)

	// default sort = severity desc → first page of 2 is the two most severe.
	w := do(t, a.Handler(), "GET", "/v1/findings?cluster=prod-eu&limit=2&offset=0", "viewer-tok", "")
	var page struct {
		Total    int           `json:"total"`
		Limit    int           `json:"limit"`
		Offset   int           `json:"offset"`
		Findings []api.Finding `json:"findings"`
	}
	mustJSON(t, w, &page)
	if page.Total != 4 || len(page.Findings) != 2 || page.Findings[0].Severity != api.SeverityCritical {
		t.Fatalf("page1: total=%d len=%d first=%s", page.Total, len(page.Findings), page.Findings[0].Severity)
	}
	// second page
	w = do(t, a.Handler(), "GET", "/v1/findings?cluster=prod-eu&limit=2&offset=2", "viewer-tok", "")
	mustJSON(t, w, &page)
	if len(page.Findings) != 2 || page.Findings[1].Severity != api.SeverityLow {
		t.Fatalf("page2 last want low, got len=%d", len(page.Findings))
	}
	// sort by id asc
	w = do(t, a.Handler(), "GET", "/v1/findings?cluster=prod-eu&sort=id&order=asc", "viewer-tok", "")
	mustJSON(t, w, &page)
	if page.Findings[0].ID != "KG-001" {
		t.Fatalf("id asc first: want KG-001, got %s", page.Findings[0].ID)
	}
}

func TestPostureCarriesHonestDenominators(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)
	w := do(t, a.Handler(), "GET", "/v1/posture?cluster=prod-eu", "viewer-tok", "")
	var resp struct {
		Posture    api.PostureSummary    `json:"posture"`
		Compliance []api.FrameworkResult `json:"compliance"`
	}
	mustJSON(t, w, &resp)
	if resp.Posture.ControlsAssessed != 9 || resp.Posture.ControlsBreached != 8 {
		t.Fatalf("posture denominators: assessed=%d breached=%d", resp.Posture.ControlsAssessed, resp.Posture.ControlsBreached)
	}
	if len(resp.Compliance) != 1 || resp.Compliance[0].Disclaimer == "" {
		t.Fatal("compliance must carry a disclaimer")
	}
}

func TestHistoryAccumulates(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)
	w := do(t, a.Handler(), "GET", "/v1/history?cluster=prod-eu", "viewer-tok", "")
	var resp struct {
		Snapshots []HistorySnapshot `json:"snapshots"`
	}
	mustJSON(t, w, &resp)
	if len(resp.Snapshots) != 2 {
		t.Fatalf("history snapshots: want 2, got %d", len(resp.Snapshots))
	}
}

// TestSSEEmitsOnScanCompletion connects to /v1/stream, triggers a scan, and
// asserts a scan_completed event is delivered to the subscriber.
func TestSSEEmitsOnScanCompletion(t *testing.T) {
	a, _ := testAPI(t)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/v1/stream", nil)
	req.Header.Set("Authorization", "Bearer viewer-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status: %d", resp.StatusCode)
	}

	// Wait for the subscription to register before triggering.
	deadline := time.Now().Add(2 * time.Second)
	for a.Broker().subscriberCount("acme") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	go do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`)

	if d, ok := resp.Body.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	sc := bufio.NewScanner(resp.Body)
	var sawCompleted bool
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "scan_completed") {
			sawCompleted = true
			break
		}
	}
	if !sawCompleted {
		t.Fatal("did not receive scan_completed SSE event")
	}
}

func mustJSON(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
}
