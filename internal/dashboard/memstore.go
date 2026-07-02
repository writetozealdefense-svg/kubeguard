package dashboard

import (
	"sort"
	"sync"

	"github.com/kubeguard/kubeguard/internal/risk"
	"github.com/kubeguard/kubeguard/pkg/api"
)

type clusterState struct {
	meta    Cluster
	latest  api.Report
	hasScan bool
	scans   []Scan            // newest first
	history []HistorySnapshot // oldest first
}

type tenantState struct {
	clusters map[string]*clusterState
	order    []string // cluster registration order, for stable listing
}

// MemStore is an in-memory, tenant-partitioned Store. Safe for concurrent use.
type MemStore struct {
	mu      sync.RWMutex
	tenants map[string]*tenantState
	// lifecycle[tenant][key] holds finding triage state, keyed by the stable
	// LifecycleKey so it survives scans coming and going.
	lifecycle map[string]map[string]FindingLifecycle
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		tenants:   map[string]*tenantState{},
		lifecycle: map[string]map[string]FindingLifecycle{},
	}
}

func (m *MemStore) tenant(t string) *tenantState {
	ts := m.tenants[t]
	if ts == nil {
		ts = &tenantState{clusters: map[string]*clusterState{}}
		m.tenants[t] = ts
	}
	return ts
}

// RegisterCluster adds a cluster to a tenant (no-op if it already exists).
func (m *MemStore) RegisterCluster(tenant string, c Cluster) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ts := m.tenant(tenant)
	if _, ok := ts.clusters[c.ID]; ok {
		return
	}
	ts.clusters[c.ID] = &clusterState{meta: c}
	ts.order = append(ts.order, c.ID)
}

// DeleteCluster removes a cluster (and its scans/history) from a tenant.
// Returns false if it was not registered.
func (m *MemStore) DeleteCluster(tenant, clusterID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ts := m.tenants[tenant]
	if ts == nil {
		return false
	}
	if _, ok := ts.clusters[clusterID]; !ok {
		return false
	}
	delete(ts.clusters, clusterID)
	for i, id := range ts.order {
		if id == clusterID {
			ts.order = append(ts.order[:i], ts.order[i+1:]...)
			break
		}
	}
	// Drop the cluster's lifecycle rows too.
	for key, lc := range m.lifecycle[tenant] {
		if lc.ClusterID == clusterID {
			delete(m.lifecycle[tenant], key)
		}
	}
	return true
}

// ListClusters returns the tenant's clusters in registration order.
func (m *MemStore) ListClusters(tenant string) []Cluster {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ts := m.tenants[tenant]
	if ts == nil {
		return []Cluster{}
	}
	out := make([]Cluster, 0, len(ts.order))
	for _, id := range ts.order {
		out = append(out, ts.clusters[id].meta)
	}
	return out
}

// GetCluster returns a cluster's metadata if it exists in the tenant.
func (m *MemStore) GetCluster(tenant, clusterID string) (Cluster, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ts := m.tenants[tenant]
	if ts == nil {
		return Cluster{}, false
	}
	cs, ok := ts.clusters[clusterID]
	if !ok {
		return Cluster{}, false
	}
	return cs.meta, true
}

// ListScans returns a tenant's scans (newest first), optionally filtered to one
// cluster, paginated; the second return is the unpaginated total.
func (m *MemStore) ListScans(tenant, clusterID string, limit, offset int) ([]Scan, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ts := m.tenants[tenant]
	if ts == nil {
		return []Scan{}, 0
	}
	var all []Scan
	for _, id := range ts.order {
		if clusterID != "" && id != clusterID {
			continue
		}
		all = append(all, ts.clusters[id].scans...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].StartedAt > all[j].StartedAt })
	total := len(all)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if limit <= 0 || end > total {
		end = total
	}
	return append([]Scan{}, all[offset:end]...), total
}

// RecordScan persists a finished scan's report, appends a history snapshot, and
// refreshes the cluster's summary metadata.
func (m *MemStore) RecordScan(tenant, clusterID, scanID string, rep api.Report, at string) Scan {
	m.mu.Lock()
	defer m.mu.Unlock()
	ts := m.tenant(tenant)
	cs := ts.clusters[clusterID]
	if cs == nil {
		cs = &clusterState{meta: Cluster{ID: clusterID, Name: clusterID}}
		ts.clusters[clusterID] = cs
		ts.order = append(ts.order, clusterID)
	}
	cs.latest = rep
	cs.hasScan = true

	assessed, breached := postureControls(rep)
	scan := Scan{
		ID:            scanID,
		ClusterID:     clusterID,
		Status:        ScanSucceeded,
		StartedAt:     at,
		FinishedAt:    at,
		TotalFindings: len(rep.Findings),
	}
	cs.scans = append([]Scan{scan}, cs.scans...)
	cs.history = append(cs.history, HistorySnapshot{
		ScanID:           scanID,
		At:               at,
		TotalFindings:    len(rep.Findings),
		ControlsAssessed: assessed,
		ControlsBreached: breached,
		OverallPassRate:  rep.Posture.OverallPassRate,
		BySeverity:       severityMap(rep),
	})
	cs.meta.LastScanAt = at
	cs.meta.TotalFindings = len(rep.Findings)
	cs.meta.OverallPassRate = rep.Posture.OverallPassRate
	return scan
}

// Report returns the latest report for a cluster, or a tenant-wide merged
// report when clusterID is "" (the fleet view).
func (m *MemStore) Report(tenant, clusterID string) (api.Report, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ts := m.tenants[tenant]
	if ts == nil {
		return api.Report{}, false
	}
	if clusterID != "" {
		cs, ok := ts.clusters[clusterID]
		if !ok || !cs.hasScan {
			return api.Report{}, false
		}
		return cs.latest, true
	}
	// Merge across all clusters in the tenant (fleet view).
	reps := make([]api.Report, 0, len(ts.order))
	for _, id := range ts.order {
		if cs := ts.clusters[id]; cs.hasScan {
			reps = append(reps, cs.latest)
		}
	}
	return MergeReports(reps), true
}

// History returns a tenant's posture snapshots (oldest first), optionally
// filtered to one cluster.
func (m *MemStore) History(tenant, clusterID string) []HistorySnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ts := m.tenants[tenant]
	if ts == nil {
		return []HistorySnapshot{}
	}
	var out []HistorySnapshot
	for _, id := range ts.order {
		if clusterID != "" && id != clusterID {
			continue
		}
		out = append(out, ts.clusters[id].history...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At < out[j].At })
	if out == nil {
		out = []HistorySnapshot{}
	}
	return out
}

// --- findings lifecycle (K6) ---

// SeedFindings creates an open lifecycle row (FirstSeen=now) for any current
// finding not yet tracked. Idempotent — existing rows are untouched.
func (m *MemStore) SeedFindings(tenant, clusterID string, findings []api.Finding, now string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byKey := m.lifecycle[tenant]
	if byKey == nil {
		byKey = map[string]FindingLifecycle{}
		m.lifecycle[tenant] = byKey
	}
	for _, f := range findings {
		key := LifecycleKey(clusterID, f)
		if _, ok := byKey[key]; ok {
			continue
		}
		byKey[key] = FindingLifecycle{
			Key: key, ClusterID: clusterID, FindingID: f.ID, Resource: f.Resource,
			State: StateOpen, FirstSeen: now, LastUpdated: now,
		}
	}
}

// GetLifecycle returns a lifecycle row by key.
func (m *MemStore) GetLifecycle(tenant, key string) (FindingLifecycle, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	lc, ok := m.lifecycle[tenant][key]
	return lc, ok
}

// ListLifecycle returns a tenant's lifecycle rows, optionally filtered to one
// cluster, in a stable order.
func (m *MemStore) ListLifecycle(tenant, clusterID string) []FindingLifecycle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []FindingLifecycle{}
	for _, lc := range m.lifecycle[tenant] {
		if clusterID != "" && lc.ClusterID != clusterID {
			continue
		}
		out = append(out, lc)
	}
	sortLifecycle(out)
	return out
}

// UpsertLifecycle persists a lifecycle row (create or replace).
func (m *MemStore) UpsertLifecycle(tenant string, lc FindingLifecycle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byKey := m.lifecycle[tenant]
	if byKey == nil {
		byKey = map[string]FindingLifecycle{}
		m.lifecycle[tenant] = byKey
	}
	byKey[lc.Key] = lc
}

// MergeReports combines per-cluster reports into one tenant-wide fleet report:
// concatenated findings/paths, summed posture + per-severity, and per-framework
// compliance aggregated with honest recomputed pass rates.
func MergeReports(reps []api.Report) api.Report {
	merged := api.Report{Posture: api.PostureSummary{BySeverity: map[api.Severity]int{}}}
	seenFw := map[string]int{} // framework -> index in merged.Compliance
	for _, r := range reps {
		merged.Findings = append(merged.Findings, r.Findings...)
		merged.Paths = append(merged.Paths, r.Paths...)
		for sev, n := range r.Posture.BySeverity {
			merged.Posture.BySeverity[sev] += n
		}
		merged.Posture.TotalFindings += r.Posture.TotalFindings
		merged.Posture.CriticalPaths += r.Posture.CriticalPaths
		merged.Posture.ControlsAssessed += r.Posture.ControlsAssessed
		merged.Posture.ControlsBreached += r.Posture.ControlsBreached
		for _, fw := range r.Compliance {
			if idx, ok := seenFw[fw.Framework]; ok {
				merged.Compliance[idx].Assessed += fw.Assessed
				merged.Compliance[idx].Breached += fw.Breached
				merged.Compliance[idx].Passed += fw.Passed
				merged.Compliance[idx].Breaches = append(merged.Compliance[idx].Breaches, fw.Breaches...)
			} else {
				seenFw[fw.Framework] = len(merged.Compliance)
				merged.Compliance = append(merged.Compliance, fw)
			}
		}
	}
	for i := range merged.Compliance {
		fw := &merged.Compliance[i]
		if fw.Assessed > 0 {
			fw.PassRate = float64(fw.Passed) / float64(fw.Assessed)
		}
	}
	if merged.Posture.ControlsAssessed > 0 {
		merged.Posture.OverallPassRate =
			float64(merged.Posture.ControlsAssessed-merged.Posture.ControlsBreached) /
				float64(merged.Posture.ControlsAssessed)
	}
	// Recompute top risks over the merged fleet so the tenant-wide posture view
	// prioritizes across all clusters, not per-cluster.
	if len(merged.Findings) > 0 {
		merged.TopRisks = risk.Score(merged)
	}
	return merged
}

func postureControls(rep api.Report) (assessed, breached int) {
	if rep.Posture.ControlsAssessed > 0 {
		return rep.Posture.ControlsAssessed, rep.Posture.ControlsBreached
	}
	for _, fw := range rep.Compliance {
		assessed += fw.Assessed
		breached += fw.Breached
	}
	return assessed, breached
}

func severityMap(rep api.Report) map[string]int {
	out := map[string]int{}
	for sev, n := range rep.Posture.BySeverity {
		out[string(sev)] = n
	}
	return out
}
