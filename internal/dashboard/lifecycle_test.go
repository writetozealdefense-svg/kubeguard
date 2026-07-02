package dashboard

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// lifecycleTestAPI wires an API with a mutable clock so waiver-expiry can be
// exercised deterministically, a MemStore, and viewer/analyst/admin principals.
func lifecycleTestAPI(t *testing.T) (*API, *MemStore, *time.Time) {
	t.Helper()
	store := NewMemStore()
	store.RegisterCluster("acme", Cluster{ID: "prod-eu", Name: "prod-eu"})
	auth := NewStaticAuth(map[string]Principal{
		"viewer-tok":  {Subject: "v", Tenant: "acme", Role: RoleViewer},
		"analyst-tok": {Subject: "a", Tenant: "acme", Role: RoleAnalyst},
		"admin-tok":   {Subject: "ad", Tenant: "acme", Role: RoleAdmin},
	})
	clk := time.Date(2026, 6, 7, 8, 0, 0, 0, time.UTC)
	a := New(Config{
		Store: store, Auth: auth, Broker: NewBroker(),
		Clock:   func() time.Time { return clk },
		Scanner: func(_ context.Context, _ string) (api.Report, error) { return sampleReport(), nil },
	})
	return a, store, &clk
}

// firstKey scans once and returns the lifecycle key of the KG-001 finding.
func seedAndKey(t *testing.T, a *API) string {
	t.Helper()
	if w := do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`); w.Code != http.StatusAccepted {
		t.Fatalf("seed scan: %d", w.Code)
	}
	w := do(t, a.Handler(), "GET", "/v1/lifecycle?cluster=prod-eu", "viewer-tok", "")
	var v lifecycleView
	mustJSON(t, w, &v)
	for _, it := range v.Items {
		if it.FindingID == "KG-001" {
			return it.Key
		}
	}
	t.Fatal("KG-001 not in lifecycle view")
	return ""
}

func TestLifecycleSeedsOpenWithFirstSeen(t *testing.T) {
	a, _, _ := lifecycleTestAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`)
	w := do(t, a.Handler(), "GET", "/v1/lifecycle?cluster=prod-eu", "viewer-tok", "")
	var v lifecycleView
	mustJSON(t, w, &v)
	if len(v.Items) != 4 { // sampleReport has 4 findings
		t.Fatalf("want 4 lifecycle items, got %d", len(v.Items))
	}
	for _, it := range v.Items {
		if it.State != StateOpen || it.FirstSeen == "" {
			t.Fatalf("seeded finding should be open with firstSeen: %+v", it)
		}
	}
	if v.MTTR.Open != 4 {
		t.Fatalf("MTTR.Open want 4, got %d", v.MTTR.Open)
	}
}

func TestLifecycleTriageAndMTTR(t *testing.T) {
	a, _, clk := lifecycleTestAPI(t)
	key := seedAndKey(t, a)

	// Analyst moves it in-progress.
	if w := do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/state", "analyst-tok", `{"state":"in-progress","assignee":"alice"}`); w.Code != http.StatusOK {
		t.Fatalf("set in-progress: %d (%s)", w.Code, w.Body.String())
	}
	// Advance 10 hours, resolve it.
	*clk = clk.Add(10 * time.Hour)
	if w := do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/state", "analyst-tok", `{"state":"resolved"}`); w.Code != http.StatusOK {
		t.Fatalf("resolve: %d", w.Code)
	}
	w := do(t, a.Handler(), "GET", "/v1/lifecycle?cluster=prod-eu", "viewer-tok", "")
	var v lifecycleView
	mustJSON(t, w, &v)
	if v.MTTR.Resolved != 1 {
		t.Fatalf("want 1 resolved, got %d", v.MTTR.Resolved)
	}
	if v.MTTR.MeanTimeToResolveHours != 10 {
		t.Fatalf("MTTR want 10h, got %v", v.MTTR.MeanTimeToResolveHours)
	}
	// The resolved finding carries assignee + resolvedAt.
	for _, it := range v.Items {
		if it.Key == key {
			if it.State != StateResolved || it.Assignee != "alice" || it.ResolvedAt == "" {
				t.Fatalf("resolved row wrong: %+v", it)
			}
		}
	}
}

func TestLifecycleAnalystCannotWaiveAdminCan(t *testing.T) {
	a, _, clk := lifecycleTestAPI(t)
	key := seedAndKey(t, a)
	exp := clk.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	body := `{"justification":"compensating control X","expiresAt":"` + exp + `"}`

	// Analyst proposes → forbidden (admin approves).
	if w := do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "analyst-tok", body); w.Code != http.StatusForbidden {
		t.Fatalf("analyst waiver: want 403, got %d", w.Code)
	}
	// Admin approves.
	if w := do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "admin-tok", body); w.Code != http.StatusOK {
		t.Fatalf("admin waiver: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	// It shows as risk-accepted and is actively waived.
	w := do(t, a.Handler(), "GET", "/v1/lifecycle?cluster=prod-eu", "viewer-tok", "")
	var v lifecycleView
	mustJSON(t, w, &v)
	waived := a.WaivedKeys("acme", "prod-eu", *clk)
	if !waived[key] {
		t.Fatal("finding should be actively waived")
	}
	for _, it := range v.Items {
		if it.Key == key && it.State != StateRiskAccepted {
			t.Fatalf("want risk-accepted, got %s", it.State)
		}
	}
}

func TestLifecycleWaiverExpiryReSurfaces(t *testing.T) {
	a, _, clk := lifecycleTestAPI(t)
	key := seedAndKey(t, a)
	exp := clk.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "admin-tok",
		`{"justification":"temporary","expiresAt":"`+exp+`"}`)

	// Before expiry: waived, not blocking.
	if !a.WaivedKeys("acme", "prod-eu", *clk)[key] {
		t.Fatal("should be waived before expiry")
	}
	// Advance past expiry: waiver lapses, finding re-surfaces as open + blocking.
	*clk = clk.Add(48 * time.Hour)
	if a.WaivedKeys("acme", "prod-eu", *clk)[key] {
		t.Fatal("waiver should have lapsed after expiry")
	}
	w := do(t, a.Handler(), "GET", "/v1/lifecycle?cluster=prod-eu", "viewer-tok", "")
	var v lifecycleView
	mustJSON(t, w, &v)
	for _, it := range v.Items {
		if it.Key == key && it.EffectiveState(*clk) != StateOpen {
			t.Fatalf("expired waiver should re-surface as open, got %s", it.State)
		}
	}
}

func TestLifecycleWaiverValidation(t *testing.T) {
	a, _, clk := lifecycleTestAPI(t)
	key := seedAndKey(t, a)

	// Missing justification.
	exp := clk.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if w := do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "admin-tok", `{"expiresAt":"`+exp+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing justification: want 400, got %d", w.Code)
	}
	// Beyond the 90-day cap.
	tooLong := clk.Add(200 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if w := do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "admin-tok", `{"justification":"x","expiresAt":"`+tooLong+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("over-cap waiver: want 400, got %d", w.Code)
	}
	// Past expiry.
	past := clk.Add(-time.Hour).UTC().Format(time.RFC3339)
	if w := do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "admin-tok", `{"justification":"x","expiresAt":"`+past+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("past waiver: want 400, got %d", w.Code)
	}
}

func TestLifecycleWaiverRevoke(t *testing.T) {
	a, _, clk := lifecycleTestAPI(t)
	key := seedAndKey(t, a)
	exp := clk.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "admin-tok", `{"justification":"x","expiresAt":"`+exp+`"}`)
	if w := do(t, a.Handler(), "DELETE", "/v1/lifecycle/"+key+"/waiver", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d", w.Code)
	}
	if a.WaivedKeys("acme", "prod-eu", *clk)[key] {
		t.Fatal("waiver should be gone after revoke")
	}
}

func TestLifecycleAuditTrailComplete(t *testing.T) {
	a, _, clk := lifecycleTestAPI(t)
	key := seedAndKey(t, a)
	exp := clk.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/state", "analyst-tok", `{"state":"acknowledged"}`)
	do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "admin-tok", `{"justification":"x","expiresAt":"`+exp+`"}`)
	do(t, a.Handler(), "DELETE", "/v1/lifecycle/"+key+"/waiver", "admin-tok", "")
	do(t, a.Handler(), "POST", "/v1/lifecycle/"+key+"/waiver", "analyst-tok", `{"justification":"x","expiresAt":"`+exp+`"}`) // denied

	var triage, waiver, revoke, denied bool
	for _, e := range a.audit.List("acme") {
		switch {
		case e.Action == "finding.triage" && e.Result == "allowed":
			triage = true
		case e.Action == "finding.waiver" && e.Result == "allowed":
			waiver = true
		case e.Action == "finding.waiver.revoke" && e.Result == "allowed":
			revoke = true
		case e.Action == "finding.waiver" && e.Result == "denied":
			denied = true
		}
	}
	if !triage || !waiver || !revoke || !denied {
		t.Fatalf("audit incomplete: triage=%v waiver=%v revoke=%v denied=%v", triage, waiver, revoke, denied)
	}
}

func TestBlockingFindingsPartition(t *testing.T) {
	findings := []api.Finding{
		{ID: "KG-001", Resource: api.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "checkout"}},
		{ID: "KG-013", Resource: api.ResourceRef{Kind: "ClusterRole", Name: "power"}},
	}
	waived := map[string]bool{LifecycleKey("prod-eu", findings[0]): true}
	blocking, waivedOut := BlockingFindings("prod-eu", findings, waived)
	if len(blocking) != 1 || blocking[0].ID != "KG-013" {
		t.Fatalf("blocking wrong: %+v", blocking)
	}
	if len(waivedOut) != 1 || waivedOut[0].ID != "KG-001" {
		t.Fatalf("waived wrong: %+v", waivedOut)
	}
}
