package pg

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kubeguard/kubeguard/internal/dashboard"
	"github.com/kubeguard/kubeguard/pkg/api"
)

// These tests run against an ephemeral Postgres. Set KUBEGUARD_TEST_POSTGRES to
// a DSN (e.g. postgres://kubeguard:kubeguard@localhost:5432/kubeguard?sslmode=disable);
// they skip cleanly when it is unset so `go test ./...` is green without Docker.
func dsn(t *testing.T) string {
	d := os.Getenv("KUBEGUARD_TEST_POSTGRES")
	if d == "" {
		t.Skip("set KUBEGUARD_TEST_POSTGRES to run Postgres integration tests")
	}
	return d
}

func sample() api.Report {
	return api.Report{
		Source: "prod-eu",
		Findings: []api.Finding{
			{ID: "KG-001", Title: "Privileged container", Severity: api.SeverityCritical, Category: "workload", Resource: api.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "checkout"}},
			{ID: "KG-013", Title: "RBAC reads secrets", Severity: api.SeverityHigh, Category: "rbac", Resource: api.ResourceRef{Kind: "ClusterRole", Name: "power"}},
		},
		Paths: []api.AttackPath{{ID: "AP-001", Title: "takeover", Severity: api.SeverityCritical}},
		Posture: api.PostureSummary{
			TotalFindings: 2, BySeverity: map[api.Severity]int{api.SeverityCritical: 1, api.SeverityHigh: 1},
			CriticalPaths: 1, ControlsAssessed: 9, ControlsBreached: 8, OverallPassRate: 0.11,
		},
		Compliance: []api.FrameworkResult{{Framework: "CIS", Assessed: 9, Breached: 8, Passed: 1, PassRate: 0.11, Disclaimer: "indicative"}},
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	d := dsn(t)
	if err := Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := Open(context.Background(), d)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Clean slate.
	if _, err := st.pool.Exec(context.Background(),
		`TRUNCATE finding_lifecycle, audit, history, scans, clusters, users, tenants CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func TestMigrateUpDownClean(t *testing.T) {
	d := dsn(t)
	if err := Migrate(d); err != nil {
		t.Fatalf("up: %v", err)
	}
	if err := MigrateDown(d); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := Migrate(d); err != nil {
		t.Fatalf("up again: %v", err)
	}
}

func TestPgStoreRoundTrip(t *testing.T) {
	st := newTestStore(t)
	st.RegisterCluster("acme", dashboard.Cluster{ID: "prod-eu", Name: "prod-eu", Environment: "production"})
	st.RegisterCluster("acme", dashboard.Cluster{ID: "staging", Name: "staging"})
	st.RegisterCluster("other", dashboard.Cluster{ID: "secret", Name: "secret"})

	at := time.Date(2026, 6, 7, 8, 0, 0, 0, time.UTC).Format(time.RFC3339)
	scan := st.RecordScan("acme", "prod-eu", "scan-1", sample(), at)
	if scan.TotalFindings != 2 {
		t.Fatalf("scan total: %d", scan.TotalFindings)
	}

	// Clusters list is tenant-scoped and ordered.
	cl := st.ListClusters("acme")
	if len(cl) != 2 || cl[0].ID != "prod-eu" {
		t.Fatalf("clusters: %+v", cl)
	}
	if c, ok := st.GetCluster("acme", "prod-eu"); !ok || c.TotalFindings != 2 {
		t.Fatalf("get cluster: %+v ok=%v", c, ok)
	}

	// Report reconstructs from jsonb.
	rep, ok := st.Report("acme", "prod-eu")
	if !ok || len(rep.Findings) != 2 || rep.Posture.ControlsAssessed != 9 {
		t.Fatalf("report: ok=%v findings=%d", ok, len(rep.Findings))
	}

	// History snapshot written.
	hist := st.History("acme", "prod-eu")
	if len(hist) != 1 || hist[0].ControlsBreached != 8 || hist[0].BySeverity["critical"] != 1 {
		t.Fatalf("history: %+v", hist)
	}

	// Scans listed.
	scans, total := st.ListScans("acme", "prod-eu", 10, 0)
	if total != 1 || len(scans) != 1 || scans[0].ID != "scan-1" {
		t.Fatalf("scans: total=%d %+v", total, scans)
	}

	// Tenant isolation: "other" sees none of acme's data.
	if len(st.ListClusters("other")) != 1 {
		t.Fatal("other tenant should see only its own cluster")
	}
	if _, ok := st.Report("other", "prod-eu"); ok {
		t.Fatal("cross-tenant report leaked")
	}

	// Audit append-only + tenant-scoped.
	st.Write(dashboard.AuditEntry{At: at, Subject: "u", Tenant: "acme", Action: "scan.trigger", Resource: "prod-eu", Result: "allowed"})
	if got := st.List("acme"); len(got) != 1 || got[0].Action != "scan.trigger" {
		t.Fatalf("audit: %+v", got)
	}
	if len(st.List("other")) != 0 {
		t.Fatal("cross-tenant audit leaked")
	}
}

func TestLatestReportReplacesPrevious(t *testing.T) {
	st := newTestStore(t)
	st.RegisterCluster("acme", dashboard.Cluster{ID: "prod-eu", Name: "prod-eu"})
	st.RecordScan("acme", "prod-eu", "scan-1", sample(), "2026-06-06T08:00:00Z")
	r2 := sample()
	r2.Findings = r2.Findings[:1] // improved: 1 finding
	st.RecordScan("acme", "prod-eu", "scan-2", r2, "2026-06-07T08:00:00Z")

	rep, _ := st.Report("acme", "prod-eu")
	if len(rep.Findings) != 1 {
		t.Fatalf("latest report should have 1 finding, got %d", len(rep.Findings))
	}
	if _, total := st.ListScans("acme", "prod-eu", 10, 0); total != 2 {
		t.Fatalf("both scans retained: total=%d", total)
	}
	if len(st.History("acme", "prod-eu")) != 2 {
		t.Fatal("two history snapshots expected")
	}
}

func TestRetentionPrunesOldKeepsLatest(t *testing.T) {
	st := newTestStore(t)
	st.RegisterCluster("acme", dashboard.Cluster{ID: "prod-eu", Name: "prod-eu"})
	st.RecordScan("acme", "prod-eu", "old", sample(), "2026-01-01T00:00:00Z")
	st.RecordScan("acme", "prod-eu", "new", sample(), "2026-06-07T00:00:00Z")

	removed, err := st.Retention(context.Background(), "2026-03-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 {
		t.Fatal("expected rows pruned")
	}
	// The latest scan survives; the old non-latest is gone.
	_, total := st.ListScans("acme", "prod-eu", 10, 0)
	if total != 1 {
		t.Fatalf("after retention want 1 scan, got %d", total)
	}
	if rep, ok := st.Report("acme", "prod-eu"); !ok || len(rep.Findings) != 2 {
		t.Fatal("latest report must survive retention")
	}
}

func TestPgFindingLifecycle(t *testing.T) {
	st := newTestStore(t)
	st.RegisterCluster("acme", dashboard.Cluster{ID: "prod-eu", Name: "prod-eu"})
	rep := sample()
	now := "2026-06-07T08:00:00Z"

	// Seed is idempotent: two seeds create rows once, all open with first_seen.
	st.SeedFindings("acme", "prod-eu", rep.Findings, now)
	st.SeedFindings("acme", "prod-eu", rep.Findings, now)
	rows := st.ListLifecycle("acme", "prod-eu")
	if len(rows) != 2 {
		t.Fatalf("want 2 seeded rows, got %d", len(rows))
	}
	for _, lc := range rows {
		if lc.State != dashboard.StateOpen || lc.FirstSeen != now {
			t.Fatalf("seeded row wrong: %+v", lc)
		}
	}

	// Upsert a resolved state + a waiver round-trips through jsonb.
	key := dashboard.LifecycleKey("prod-eu", rep.Findings[0])
	lc, ok := st.GetLifecycle("acme", key)
	if !ok {
		t.Fatal("get seeded row")
	}
	lc.State = dashboard.StateResolved
	lc.Assignee = "alice"
	lc.ResolvedAt = "2026-06-07T18:00:00Z"
	lc.LastUpdated = "2026-06-07T18:00:00Z"
	st.UpsertLifecycle("acme", lc)

	got, _ := st.GetLifecycle("acme", key)
	if got.State != dashboard.StateResolved || got.Assignee != "alice" || got.ResolvedAt == "" {
		t.Fatalf("resolved round-trip wrong: %+v", got)
	}

	// Waiver round-trips.
	key2 := dashboard.LifecycleKey("prod-eu", rep.Findings[1])
	lc2, _ := st.GetLifecycle("acme", key2)
	lc2.State = dashboard.StateRiskAccepted
	lc2.Waiver = &dashboard.Waiver{Justification: "compensating control", ApprovedBy: "ad", CreatedAt: now, ExpiresAt: "2026-07-01T00:00:00Z"}
	st.UpsertLifecycle("acme", lc2)
	got2, _ := st.GetLifecycle("acme", key2)
	if got2.Waiver == nil || got2.Waiver.Justification != "compensating control" || got2.Waiver.ExpiresAt != "2026-07-01T00:00:00Z" {
		t.Fatalf("waiver round-trip wrong: %+v", got2.Waiver)
	}

	// Tenant isolation.
	if len(st.ListLifecycle("other", "")) != 0 {
		t.Fatal("cross-tenant lifecycle leaked")
	}

	// DeleteCluster purges lifecycle rows.
	st.DeleteCluster("acme", "prod-eu")
	if len(st.ListLifecycle("acme", "prod-eu")) != 0 {
		t.Fatal("DeleteCluster left lifecycle rows")
	}
}

func TestProvisionTenantIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.ProvisionTenant(ctx, "newco", "New Co"); err != nil {
		t.Fatal(err)
	}
	// Idempotent: re-provisioning updates the display name, no error.
	if err := st.ProvisionTenant(ctx, "newco", "New Co Renamed"); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := st.pool.QueryRow(ctx, `SELECT COALESCE(display_name,'') FROM tenants WHERE id=$1`, "newco").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "New Co Renamed" {
		t.Fatalf("display name = %q, want New Co Renamed", name)
	}
}

func TestDeleteTenantDPDP(t *testing.T) {
	st := newTestStore(t)
	st.RegisterCluster("acme", dashboard.Cluster{ID: "prod-eu", Name: "prod-eu"})
	st.RecordScan("acme", "prod-eu", "s1", sample(), "2026-06-07T00:00:00Z")
	st.SeedFindings("acme", "prod-eu", sample().Findings, "2026-06-07T00:00:00Z")
	st.Write(dashboard.AuditEntry{At: "2026-06-07T00:00:00Z", Subject: "u", Tenant: "acme", Action: "x", Result: "allowed"})

	if err := st.DeleteTenant(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if len(st.ListClusters("acme")) != 0 || len(st.History("acme", "")) != 0 || len(st.List("acme")) != 0 {
		t.Fatal("DPDP hard-delete left residual data")
	}
	if len(st.ListLifecycle("acme", "")) != 0 {
		t.Fatal("DPDP hard-delete left residual lifecycle rows")
	}
}
