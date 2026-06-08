package dashboard

import (
	"net/http"
	"testing"
)

func TestAuditLogsAllowedScanTrigger(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`)

	w := do(t, a.Handler(), "GET", "/v1/audit", "admin-tok", "")
	var resp struct {
		Entries []AuditEntry `json:"entries"`
	}
	mustJSON(t, w, &resp)
	if len(resp.Entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(resp.Entries))
	}
	e := resp.Entries[0]
	if e.Action != "scan.trigger" || e.Result != "allowed" || e.Subject != "a" || e.Resource != "prod-eu" {
		t.Fatalf("unexpected audit entry: %+v", e)
	}
}

func TestAuditLogsDeniedScanTrigger(t *testing.T) {
	a, _ := testAPI(t)
	// Viewer is denied — that denial must be audited.
	if w := do(t, a.Handler(), "POST", "/v1/scans", "viewer-tok", `{"clusterId":"prod-eu"}`); w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	w := do(t, a.Handler(), "GET", "/v1/audit", "admin-tok", "")
	var resp struct {
		Entries []AuditEntry `json:"entries"`
	}
	mustJSON(t, w, &resp)
	if len(resp.Entries) != 1 || resp.Entries[0].Result != "denied" {
		t.Fatalf("denied action not audited: %+v", resp.Entries)
	}
}

func TestAuditIsAdminOnlyAndTenantScoped(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "analyst-tok", `{"clusterId":"prod-eu"}`)

	// Analyst (non-admin) cannot read the audit log.
	if w := do(t, a.Handler(), "GET", "/v1/audit", "analyst-tok", ""); w.Code != http.StatusForbidden {
		t.Fatalf("analyst audit read: want 403, got %d", w.Code)
	}
	// Another tenant's admin sees none of acme's audit entries.
	w := do(t, a.Handler(), "GET", "/v1/audit", "other-tok", "")
	var resp struct {
		Entries []AuditEntry `json:"entries"`
	}
	mustJSON(t, w, &resp)
	if len(resp.Entries) != 0 {
		t.Fatalf("cross-tenant audit leak: %d entries", len(resp.Entries))
	}
}
