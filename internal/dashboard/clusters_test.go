package dashboard

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// fakeRegistrar is a test ClusterRegistrar: an in-memory source map that rejects
// a source literally equal to "bad" so the reject path can be exercised.
type fakeRegistrar struct {
	mu  sync.Mutex
	src map[string]string
}

func newFakeRegistrar() *fakeRegistrar { return &fakeRegistrar{src: map[string]string{}} }

func (f *fakeRegistrar) AddSource(clusterID, source string) error {
	if source == "bad" {
		return errors.New("unusable source")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.src[clusterID] = source
	return nil
}

func (f *fakeRegistrar) RemoveSource(clusterID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.src, clusterID)
}

func (f *fakeRegistrar) has(clusterID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.src[clusterID]
	return ok
}

// registrarAPI builds an API with a fake registrar and a scanner that only
// succeeds for clusters the registrar currently knows — modelling the real
// wiring where the scanner reads the live source map.
func registrarAPI(t *testing.T) (*API, *fakeRegistrar) {
	t.Helper()
	reg := newFakeRegistrar()
	store := NewMemStore()
	auth := NewStaticAuth(map[string]Principal{
		"analyst-tok": {Subject: "a", Tenant: "acme", Role: RoleAnalyst},
		"admin-tok":   {Subject: "ad", Tenant: "acme", Role: RoleAdmin},
	})
	a := New(Config{
		Store: store, Auth: auth, Broker: NewBroker(), Clock: fixedClock, Registrar: reg,
		Scanner: func(_ context.Context, clusterID string) (api.Report, error) {
			if !reg.has(clusterID) {
				return api.Report{}, errors.New("unknown cluster")
			}
			return sampleReport(), nil
		},
	})
	return a, reg
}

func TestClusterRegisterLifecycle(t *testing.T) {
	a, reg := registrarAPI(t)

	// Register a cluster as admin → 201.
	w := do(t, a.Handler(), "POST", "/v1/clusters", "admin-tok", `{"id":"prod-eu","name":"Prod EU","source":"/tmp/x.yaml"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	if !reg.has("prod-eu") {
		t.Fatal("source not registered with the registrar")
	}

	// It appears in GET /v1/clusters.
	cw := do(t, a.Handler(), "GET", "/v1/clusters", "admin-tok", "")
	var cl struct {
		Clusters []Cluster `json:"clusters"`
	}
	mustJSON(t, cw, &cl)
	if len(cl.Clusters) != 1 || cl.Clusters[0].ID != "prod-eu" || cl.Clusters[0].Name != "Prod EU" {
		t.Fatalf("cluster list after register: %+v", cl.Clusters)
	}

	// It is scannable.
	if w := do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`); w.Code != http.StatusAccepted {
		t.Fatalf("scan after register: want 202, got %d (%s)", w.Code, w.Body.String())
	}

	// Delete it as admin → 204.
	if w := do(t, a.Handler(), "DELETE", "/v1/clusters/prod-eu", "admin-tok", ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d (%s)", w.Code, w.Body.String())
	}
	if reg.has("prod-eu") {
		t.Fatal("source still registered after delete")
	}

	// After removal the cluster is gone → scan 404.
	if w := do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`); w.Code != http.StatusNotFound {
		t.Fatalf("scan after delete: want 404, got %d (%s)", w.Code, w.Body.String())
	}

	// Deleting again → 404 (idempotent-ish, no crash).
	if w := do(t, a.Handler(), "DELETE", "/v1/clusters/prod-eu", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("delete missing: want 404, got %d", w.Code)
	}
}

func TestClusterWriteRequiresAdmin(t *testing.T) {
	a, _ := registrarAPI(t)
	// Analyst can trigger scans but must not register/delete clusters.
	if w := do(t, a.Handler(), "POST", "/v1/clusters", "analyst-tok", `{"id":"x","source":"/tmp/x.yaml"}`); w.Code != http.StatusForbidden {
		t.Fatalf("analyst register: want 403, got %d", w.Code)
	}
	if w := do(t, a.Handler(), "DELETE", "/v1/clusters/x", "analyst-tok", ""); w.Code != http.StatusForbidden {
		t.Fatalf("analyst delete: want 403, got %d", w.Code)
	}
}

func TestClusterRegisterRejectsBadInput(t *testing.T) {
	a, _ := registrarAPI(t)
	// Missing source.
	if w := do(t, a.Handler(), "POST", "/v1/clusters", "admin-tok", `{"id":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing source: want 400, got %d", w.Code)
	}
	// Registrar rejects the source → 400, and nothing is left in the store.
	if w := do(t, a.Handler(), "POST", "/v1/clusters", "admin-tok", `{"id":"x","source":"bad"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad source: want 400, got %d", w.Code)
	}
	cw := do(t, a.Handler(), "GET", "/v1/clusters", "admin-tok", "")
	var cl struct {
		Clusters []Cluster `json:"clusters"`
	}
	mustJSON(t, cw, &cl)
	if len(cl.Clusters) != 0 {
		t.Fatalf("rejected source left a dangling cluster: %+v", cl.Clusters)
	}
}

// TestClusterWriteDisabledWithoutRegistrar asserts the routes fail safe (501)
// when no registrar is wired, rather than half-registering in the store.
func TestClusterWriteDisabledWithoutRegistrar(t *testing.T) {
	a, _ := testAPI(t) // testAPI wires no Registrar
	if w := do(t, a.Handler(), "POST", "/v1/clusters", "admin-tok", `{"id":"x","source":"/tmp/x.yaml"}`); w.Code != http.StatusNotImplemented {
		t.Fatalf("register without registrar: want 501, got %d", w.Code)
	}
	if w := do(t, a.Handler(), "DELETE", "/v1/clusters/prod-eu", "admin-tok", ""); w.Code != http.StatusNotImplemented {
		t.Fatalf("delete without registrar: want 501, got %d", w.Code)
	}
}

func TestClusterWriteAudited(t *testing.T) {
	a, _ := registrarAPI(t)
	do(t, a.Handler(), "POST", "/v1/clusters", "admin-tok", `{"id":"prod-eu","source":"/tmp/x.yaml"}`)
	do(t, a.Handler(), "DELETE", "/v1/clusters/prod-eu", "admin-tok", "")
	// Analyst denied write is also audited.
	do(t, a.Handler(), "POST", "/v1/clusters", "analyst-tok", `{"id":"y","source":"/tmp/y.yaml"}`)

	entries := a.audit.List("acme")
	var wrote, deleted, denied bool
	for _, e := range entries {
		switch {
		case e.Action == "cluster.write" && e.Result == "allowed":
			wrote = true
		case e.Action == "cluster.delete" && e.Result == "allowed":
			deleted = true
		case e.Action == "cluster.write" && e.Result == "denied":
			denied = true
		}
	}
	if !wrote || !deleted || !denied {
		t.Fatalf("audit incomplete: wrote=%v deleted=%v denied=%v (%d entries)", wrote, deleted, denied, len(entries))
	}
}
