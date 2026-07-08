package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// registerTenantRoutes wires the operator-lifecycle routes (K8) under /v1.
// Provisioning is super-admin only; erasure is admin for the caller's own tenant
// and super-admin for any other tenant (checked in the handler).
func (a *API) registerTenantRoutes(r chi.Router) {
	r.With(a.requireSuperAdmin("tenant.provision")).Post("/tenants", a.handleProvisionTenant)
	r.With(a.requireRole(RoleAdmin, "tenant.delete")).Delete("/tenants/{tenant}", a.handleDeleteTenant)
}

// handleProvisionTenant onboards a tenant (super-admin, idempotent). JIT
// provisioning on first valid JWT is the default; this is the managed path.
func (a *API) handleProvisionTenant(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var body struct {
		Tenant      string `json:"tenant"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Tenant == "" || !validClusterID(body.Tenant) { // same DNS-subdomain charset as cluster ids
		writeError(w, http.StatusBadRequest, "valid tenant id is required")
		return
	}
	if err := a.store.ProvisionTenant(r.Context(), body.Tenant, body.DisplayName); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.audit.Write(AuditEntry{At: a.now(), Subject: p.Subject, Tenant: p.Tenant,
		Action: "tenant.provision", Resource: body.Tenant, Result: "allowed"})
	writeJSON(w, http.StatusCreated, map[string]string{"tenant": body.Tenant, "displayName": body.DisplayName})
}

// handleDeleteTenant erases a tenant (DPDP right-to-erasure). An admin may erase
// only their own tenant; erasing any other tenant requires super-admin. The
// erasure is recorded in the *acting* principal's tenant so a cross-tenant
// operation leaves durable proof-of-erasure that survives the purge.
func (a *API) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	target := chi.URLParam(r, "tenant")
	if target == "" || !validClusterID(target) {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	if target != p.Tenant && !p.SuperAdmin {
		a.audit.Write(AuditEntry{At: a.now(), Subject: p.Subject, Tenant: p.Tenant,
			Action: "tenant.delete", Resource: target, Result: "denied"})
		writeError(w, http.StatusForbidden, "cross-tenant erasure requires super-admin")
		return
	}
	// Record the erasure first, under the caller's tenant, so a super-admin's
	// proof survives the purge of the target tenant.
	a.audit.Write(AuditEntry{At: a.now(), Subject: p.Subject, Tenant: p.Tenant,
		Action: "tenant.delete", Resource: target, Result: "allowed"})
	if err := a.store.DeleteTenant(r.Context(), target); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Erase the target's audit entries too (personal data). The pg audit log
	// clears them inside DeleteTenant; an in-memory audit log implements
	// tenantPurger and is purged here.
	if purger, ok := a.audit.(tenantPurger); ok {
		purger.PurgeTenant(target)
	}
	w.WriteHeader(http.StatusNoContent)
}
