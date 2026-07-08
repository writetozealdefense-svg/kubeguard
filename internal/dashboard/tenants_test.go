package dashboard

import (
	"context"
	"net/http"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
)

func tenantsTestAPI(t *testing.T) (*API, *MemStore) {
	t.Helper()
	store := NewMemStore()
	store.RegisterCluster("acme", Cluster{ID: "prod-eu", Name: "prod-eu"})
	store.RegisterCluster("globex", Cluster{ID: "gc", Name: "gc"})
	auth := NewStaticAuth(map[string]Principal{
		"admin-tok": {Subject: "ad", Tenant: "acme", Role: RoleAdmin},
		"super-tok": {Subject: "root", Tenant: "ops", Role: RoleAdmin, SuperAdmin: true},
	})
	a := New(Config{
		Store: store, Auth: auth, Broker: NewBroker(), Clock: fixedClock,
		Scanner: func(_ context.Context, _ string) (api.Report, error) { return sampleReport(), nil },
	})
	return a, store
}

func TestProvisionTenantSuperAdminOnly(t *testing.T) {
	a, store := tenantsTestAPI(t)
	// A tenant-scoped admin cannot provision.
	if w := do(t, a.Handler(), "POST", "/v1/tenants", "admin-tok", `{"tenant":"newco","displayName":"New Co"}`); w.Code != http.StatusForbidden {
		t.Fatalf("admin provision: want 403, got %d", w.Code)
	}
	// Super-admin can, idempotently.
	if w := do(t, a.Handler(), "POST", "/v1/tenants", "super-tok", `{"tenant":"newco","displayName":"New Co"}`); w.Code != http.StatusCreated {
		t.Fatalf("super provision: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	if w := do(t, a.Handler(), "POST", "/v1/tenants", "super-tok", `{"tenant":"newco","displayName":"New Co 2"}`); w.Code != http.StatusCreated {
		t.Fatalf("idempotent re-provision: want 201, got %d", w.Code)
	}
	// The tenant now exists (registering a cluster into it lists it).
	store.RegisterCluster("newco", Cluster{ID: "c1", Name: "c1"})
	if len(store.ListClusters("newco")) != 1 {
		t.Fatal("provisioned tenant should accept clusters")
	}
	// Invalid tenant id rejected.
	if w := do(t, a.Handler(), "POST", "/v1/tenants", "super-tok", `{"tenant":"bad id!"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid tenant id: want 400, got %d", w.Code)
	}
}

func TestDeleteTenantOwnVsCrossTenant(t *testing.T) {
	a, store := tenantsTestAPI(t)
	// Seed acme with a scan (creates lifecycle rows + a report) and an audit entry.
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)
	if len(store.ListLifecycle("acme", "")) == 0 {
		t.Fatal("precondition: acme should have lifecycle rows")
	}

	// Admin cannot erase another tenant.
	if w := do(t, a.Handler(), "DELETE", "/v1/tenants/globex", "admin-tok", ""); w.Code != http.StatusForbidden {
		t.Fatalf("admin cross-tenant delete: want 403, got %d", w.Code)
	}
	if len(store.ListClusters("globex")) != 1 {
		t.Fatal("globex must be untouched by the denied delete")
	}

	// Admin erases their own tenant → 204, all data gone.
	if w := do(t, a.Handler(), "DELETE", "/v1/tenants/acme", "admin-tok", ""); w.Code != http.StatusNoContent {
		t.Fatalf("admin self-erase: want 204, got %d (%s)", w.Code, w.Body.String())
	}
	if len(store.ListClusters("acme")) != 0 || len(store.ListLifecycle("acme", "")) != 0 {
		t.Fatal("DPDP erasure left residual acme data")
	}
	if len(a.audit.List("acme")) != 0 {
		t.Fatal("DPDP erasure left residual acme audit entries")
	}

	// Super-admin erases a different tenant → 204, and the proof survives in the
	// operator (ops) tenant.
	if w := do(t, a.Handler(), "DELETE", "/v1/tenants/globex", "super-tok", ""); w.Code != http.StatusNoContent {
		t.Fatalf("super cross-tenant erase: want 204, got %d", w.Code)
	}
	if len(store.ListClusters("globex")) != 0 {
		t.Fatal("globex data should be erased")
	}
	var sawProof bool
	for _, e := range a.audit.List("ops") {
		if e.Action == "tenant.delete" && e.Resource == "globex" && e.Result == "allowed" {
			sawProof = true
		}
	}
	if !sawProof {
		t.Fatal("cross-tenant erasure proof should survive in the operator tenant")
	}
}
