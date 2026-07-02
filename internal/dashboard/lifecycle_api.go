package dashboard

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kubeguard/kubeguard/pkg/api"
)

// LifecycleConfig tunes the findings-lifecycle product semantics (K6). The
// zero value is the conservative default: an admin must approve a risk-accept
// (waiver), and a waiver may not exceed 90 days.
type LifecycleConfig struct {
	// WaiverApproverRole is the minimum role that may create/extend a waiver
	// (risk-accept). Default RoleAdmin.
	WaiverApproverRole Role
	// MaxWaiverDuration caps how far in the future a waiver may expire. Default
	// 90 days. A request beyond the cap is rejected (400).
	MaxWaiverDuration time.Duration
}

func (c LifecycleConfig) withDefaults() LifecycleConfig {
	if c.WaiverApproverRole == "" {
		c.WaiverApproverRole = RoleAdmin
	}
	if c.MaxWaiverDuration <= 0 {
		c.MaxWaiverDuration = 90 * 24 * time.Hour
	}
	return c
}

// registerLifecycleRoutes wires the K6 routes under /v1 (called from routes()).
// State/assign are analyst+ (propose/triage); waiver create/delete require the
// configured approver role (admin by default) — "analyst proposes, admin
// approves".
func (a *API) registerLifecycleRoutes(r chi.Router) {
	r.Get("/lifecycle", a.handleListLifecycle)
	r.With(a.requireRole(RoleAnalyst, "finding.triage")).Post("/lifecycle/{key}/state", a.handleSetState)
	r.With(a.requireRole(a.life.WaiverApproverRole, "finding.waiver")).Post("/lifecycle/{key}/waiver", a.handleCreateWaiver)
	r.With(a.requireRole(a.life.WaiverApproverRole, "finding.waiver")).Delete("/lifecycle/{key}/waiver", a.handleDeleteWaiver)
}

// lifecycleView is the merged triage lane: every current finding overlaid with
// its stored lifecycle state (or a default "open"), plus the MTTR summary.
type lifecycleView struct {
	Items []FindingLifecycle `json:"items"`
	MTTR  MTTRSummary        `json:"mttr"`
}

// handleListLifecycle merges the latest report's findings with stored lifecycle
// rows so the triage lane shows untouched findings as "open" and applies waiver
// expiry (effective state). Waiver-lapsed findings re-surface as open.
func (a *API) handleListLifecycle(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	cluster := r.URL.Query().Get("cluster")
	now := a.clock()

	// Stored rows, indexed by key.
	stored := map[string]FindingLifecycle{}
	for _, lc := range a.store.ListLifecycle(p.Tenant, cluster) {
		stored[lc.Key] = lc
	}

	// Which clusters' current findings to overlay: one cluster, or all when the
	// fleet view is requested. Lifecycle identity is per-cluster, so keys are
	// always computed with a concrete cluster id.
	var clusterIDs []string
	if cluster != "" {
		clusterIDs = []string{cluster}
	} else {
		for _, c := range a.store.ListClusters(p.Tenant) {
			clusterIDs = append(clusterIDs, c.ID)
		}
	}

	items := []FindingLifecycle{}
	seen := map[string]bool{}
	for _, cid := range clusterIDs {
		rep, ok := a.store.Report(p.Tenant, cid)
		if !ok {
			continue
		}
		for _, f := range rep.Findings {
			key := LifecycleKey(cid, f)
			if seen[key] {
				continue
			}
			lc, ok := stored[key]
			if !ok {
				lc = FindingLifecycle{Key: key, ClusterID: cid, FindingID: f.ID, Resource: f.Resource, State: StateOpen}
			}
			lc.State = lc.EffectiveState(now) // reflect waiver expiry
			items = append(items, lc)
			seen[key] = true
		}
	}
	// Include stored rows no longer present in a current report (e.g. resolved
	// findings that dropped out) so MTTR stays honest.
	for key, lc := range stored {
		if seen[key] {
			continue
		}
		lc.State = lc.EffectiveState(now)
		items = append(items, lc)
	}
	sortLifecycle(items)

	writeJSON(w, http.StatusOK, lifecycleView{Items: items, MTTR: ComputeMTTR(items, now)})
}

// loadOrInitLifecycle fetches the stored row for a key, or synthesizes an open
// default from the current report so a first transition on an untouched finding
// works and carries the finding's identity/first-seen.
func (a *API) loadOrInitLifecycle(tenant, key string) (FindingLifecycle, bool) {
	if lc, ok := a.store.GetLifecycle(tenant, key); ok {
		return lc, true
	}
	// Not yet tracked: find it in any of the tenant's current reports.
	for _, c := range a.store.ListClusters(tenant) {
		rep, ok := a.store.Report(tenant, c.ID)
		if !ok {
			continue
		}
		for _, f := range rep.Findings {
			if LifecycleKey(c.ID, f) == key {
				return FindingLifecycle{
					Key: key, ClusterID: c.ID, FindingID: f.ID, Resource: f.Resource,
					State: StateOpen, FirstSeen: a.now(),
				}, true
			}
		}
	}
	return FindingLifecycle{}, false
}

func (a *API) handleSetState(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	key := chi.URLParam(r, "key")
	var body struct {
		State    string `json:"state"`
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	state := FindingState(body.State)
	if !triageStates[state] {
		writeError(w, http.StatusBadRequest, "state must be one of open, acknowledged, in-progress, resolved (risk-accepted is set via a waiver)")
		return
	}
	lc, ok := a.loadOrInitLifecycle(p.Tenant, key)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown finding")
		return
	}
	now := a.now()
	prev := lc.State
	lc.State = state
	if body.Assignee != "" {
		lc.Assignee = body.Assignee
	}
	// Setting a non-risk-accepted state clears any waiver (finding re-opened for
	// work / resolved for real).
	lc.Waiver = nil
	if state == StateResolved {
		lc.ResolvedAt = now
	} else {
		lc.ResolvedAt = ""
	}
	lc.LastUpdated = now
	a.store.UpsertLifecycle(p.Tenant, lc)
	a.audit.Write(AuditEntry{At: now, Subject: p.Subject, Tenant: p.Tenant,
		Action: "finding.triage", Resource: lc.FindingID + " " + string(prev) + "→" + string(state), Result: "allowed"})
	writeJSON(w, http.StatusOK, lc)
}

func (a *API) handleCreateWaiver(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	key := chi.URLParam(r, "key")
	var body struct {
		Justification string `json:"justification"`
		ExpiresAt     string `json:"expiresAt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Justification == "" {
		writeError(w, http.StatusBadRequest, "justification is required to accept risk")
		return
	}
	exp, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "expiresAt must be an RFC3339 timestamp")
		return
	}
	now := a.clock()
	if !exp.After(now) {
		writeError(w, http.StatusBadRequest, "expiresAt must be in the future")
		return
	}
	if exp.After(now.Add(a.life.MaxWaiverDuration)) {
		writeError(w, http.StatusBadRequest, "waiver exceeds the maximum allowed duration")
		return
	}
	lc, ok := a.loadOrInitLifecycle(p.Tenant, key)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown finding")
		return
	}
	nowStr := a.now()
	lc.State = StateRiskAccepted
	lc.ResolvedAt = ""
	lc.Waiver = &Waiver{
		Justification: body.Justification,
		ApprovedBy:    p.Subject,
		CreatedAt:     nowStr,
		ExpiresAt:     exp.UTC().Format(time.RFC3339),
	}
	lc.LastUpdated = nowStr
	a.store.UpsertLifecycle(p.Tenant, lc)
	a.audit.Write(AuditEntry{At: nowStr, Subject: p.Subject, Tenant: p.Tenant,
		Action: "finding.waiver", Resource: lc.FindingID + " until " + lc.Waiver.ExpiresAt, Result: "allowed"})
	writeJSON(w, http.StatusOK, lc)
}

func (a *API) handleDeleteWaiver(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	key := chi.URLParam(r, "key")
	lc, ok := a.store.GetLifecycle(p.Tenant, key)
	if !ok || lc.Waiver == nil {
		writeError(w, http.StatusNotFound, "no active waiver for this finding")
		return
	}
	now := a.now()
	lc.State = StateOpen
	lc.Waiver = nil
	lc.LastUpdated = now
	a.store.UpsertLifecycle(p.Tenant, lc)
	a.audit.Write(AuditEntry{At: now, Subject: p.Subject, Tenant: p.Tenant,
		Action: "finding.waiver.revoke", Resource: lc.FindingID, Result: "allowed"})
	writeJSON(w, http.StatusOK, lc)
}

// WaivedKeys returns the set of finding keys under a valid, unexpired waiver for
// a tenant/cluster at now — the input waiver-aware enforcement (K7, --fail-on)
// uses to suppress-but-log blocked findings.
func (a *API) WaivedKeys(tenant, clusterID string, now time.Time) map[string]bool {
	out := map[string]bool{}
	for _, lc := range a.store.ListLifecycle(tenant, clusterID) {
		if lc.IsActivelyWaived(now) {
			out[lc.Key] = true
		}
	}
	return out
}

// BlockingFindings partitions a report's findings into those that should block
// (open/unwaived) and those suppressed by an active waiver, given a waived-key
// set. Deterministic; used by waiver-aware guardrails.
func BlockingFindings(clusterID string, findings []api.Finding, waived map[string]bool) (blocking, waivedOut []api.Finding) {
	for _, f := range findings {
		if waived[LifecycleKey(clusterID, f)] {
			waivedOut = append(waivedOut, f)
			continue
		}
		blocking = append(blocking, f)
	}
	return blocking, waivedOut
}
