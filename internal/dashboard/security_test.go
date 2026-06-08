package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
)

func secAPI(t *testing.T, sec SecurityConfig) *API {
	t.Helper()
	store := NewMemStore()
	store.RegisterCluster("acme", Cluster{ID: "prod-eu", Name: "prod-eu"})
	store.RegisterCluster("beta", Cluster{ID: "b1", Name: "b1"})
	auth := NewStaticAuth(map[string]Principal{
		"admin-tok": {Subject: "ad", Tenant: "acme", Role: RoleAdmin},
		"beta-tok":  {Subject: "b", Tenant: "beta", Role: RoleAdmin},
	})
	return New(Config{
		Store: store, Auth: auth, Broker: NewBroker(), Clock: fixedClock, Security: sec,
		Scanner: func(_ context.Context, _ string) (api.Report, error) { return sampleReport(), nil },
	})
}

func TestSecurityHeadersAlwaysSet(t *testing.T) {
	a := secAPI(t, SecurityConfig{})
	w := do(t, a.Handler(), "GET", "/healthz", "", "")
	h := w.Header()
	for k, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	} {
		if !strings.Contains(h.Get(k), want) {
			t.Errorf("header %s = %q, want contains %q", k, h.Get(k), want)
		}
	}
	if h.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS should be off unless TLS is configured")
	}
}

func TestHSTSWhenEnabled(t *testing.T) {
	a := secAPI(t, SecurityConfig{HSTS: true})
	w := do(t, a.Handler(), "GET", "/healthz", "", "")
	if !strings.Contains(w.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Error("HSTS header missing when enabled")
	}
}

func TestCSRFOriginAllowlist(t *testing.T) {
	a := secAPI(t, SecurityConfig{AllowedOrigins: []string{"https://app.example.com"}})
	// Disallowed browser origin on an unsafe method → 403.
	r := httptest.NewRequest("POST", "/v1/scans", strings.NewReader(`{"clusterId":"prod-eu"}`))
	r.Header.Set("Authorization", "Bearer admin-tok")
	r.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("evil origin: want 403, got %d", w.Code)
	}
	// Allowed origin passes.
	r = httptest.NewRequest("POST", "/v1/scans", strings.NewReader(`{"clusterId":"prod-eu"}`))
	r.Header.Set("Authorization", "Bearer admin-tok")
	r.Header.Set("Origin", "https://app.example.com")
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("allowed origin: want 202, got %d", w.Code)
	}
	// No Origin (non-browser client) passes — bearer auth is CSRF-resistant.
	if got := do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`); got.Code != http.StatusAccepted {
		t.Fatalf("no origin: want 202, got %d", got.Code)
	}
}

func TestPerTenantRateLimit(t *testing.T) {
	a := secAPI(t, SecurityConfig{RatePerSecond: 1, Burst: 1})
	// First request for tenant acme passes, second is limited.
	if w := do(t, a.Handler(), "GET", "/v1/clusters", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("first acme: want 200, got %d", w.Code)
	}
	if w := do(t, a.Handler(), "GET", "/v1/clusters", "admin-tok", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second acme: want 429, got %d", w.Code)
	}
	// A different tenant has its own bucket — not affected.
	if w := do(t, a.Handler(), "GET", "/v1/clusters", "beta-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("beta first: want 200, got %d", w.Code)
	}
}

func TestBodyTooLargeRejected(t *testing.T) {
	a := secAPI(t, SecurityConfig{MaxBodyBytes: 64})
	big := `{"clusterId":"` + strings.Repeat("a", 200) + `"}`
	w := do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", big)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: want 413, got %d", w.Code)
	}
}
