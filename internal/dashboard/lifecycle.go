package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// FindingState is the triage state of a finding across scans. A finding's
// identity is stable (cluster + check id + resource), so its state persists even
// as scans come and go.
type FindingState string

// Finding lifecycle states.
const (
	StateOpen         FindingState = "open"
	StateAcknowledged FindingState = "acknowledged"
	StateInProgress   FindingState = "in-progress"
	StateResolved     FindingState = "resolved"
	StateRiskAccepted FindingState = "risk-accepted"
)

// triageStates are the states an analyst may set directly. risk-accepted is
// reached only by an admin creating a waiver (approve), not by a direct set.
var triageStates = map[FindingState]bool{
	StateOpen: true, StateAcknowledged: true, StateInProgress: true, StateResolved: true,
}

// Waiver is an approved, time-boxed risk acceptance for a finding. Justification
// is mandatory; on expiry the waiver auto-lapses and the finding re-surfaces
// (EffectiveState reverts to open). ApprovedBy records the approving admin.
type Waiver struct {
	Justification string `json:"justification"`
	ApprovedBy    string `json:"approvedBy"`
	CreatedAt     string `json:"createdAt"`
	ExpiresAt     string `json:"expiresAt"`
}

// Active reports whether the waiver is present and not yet expired at now.
func (w *Waiver) Active(now time.Time) bool {
	if w == nil || w.ExpiresAt == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, w.ExpiresAt)
	if err != nil {
		return false
	}
	return now.Before(exp)
}

// FindingLifecycle is the persisted triage state for one finding identity.
type FindingLifecycle struct {
	Key         string          `json:"key"`
	ClusterID   string          `json:"clusterId"`
	FindingID   string          `json:"findingId"` // check id, e.g. KG-001
	Resource    api.ResourceRef `json:"resource"`
	State       FindingState    `json:"state"`
	Assignee    string          `json:"assignee,omitempty"`
	Waiver      *Waiver         `json:"waiver,omitempty"`
	FirstSeen   string          `json:"firstSeen,omitempty"`
	LastUpdated string          `json:"lastUpdated,omitempty"`
	ResolvedAt  string          `json:"resolvedAt,omitempty"`
}

// EffectiveState is the state after applying waiver expiry: a risk-accepted
// finding whose waiver has lapsed is effectively open again (it re-surfaces).
func (lc FindingLifecycle) EffectiveState(now time.Time) FindingState {
	if lc.State == StateRiskAccepted && !lc.Waiver.Active(now) {
		return StateOpen
	}
	return lc.State
}

// IsActivelyWaived reports whether the finding is suppressed by a valid,
// unexpired waiver at now — the predicate waiver-aware enforcement uses.
func (lc FindingLifecycle) IsActivelyWaived(now time.Time) bool {
	return lc.State == StateRiskAccepted && lc.Waiver.Active(now)
}

// LifecycleKey is the stable, URL-safe identity of a finding across scans:
// a hash over cluster + check id + resource. Deterministic, so the same finding
// maps to the same key every scan.
func LifecycleKey(clusterID string, f api.Finding) string {
	h := sha256.New()
	// NUL-separated so distinct field boundaries can't collide.
	for _, s := range []string{clusterID, f.ID, f.Resource.Kind, f.Resource.Namespace, f.Resource.Name} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// MTTRSummary reports the triage distribution and mean time-to-resolve.
type MTTRSummary struct {
	Open                   int     `json:"open"`
	Acknowledged           int     `json:"acknowledged"`
	InProgress             int     `json:"inProgress"`
	Resolved               int     `json:"resolved"`
	RiskAccepted           int     `json:"riskAccepted"`
	MeanTimeToResolveHours float64 `json:"meanTimeToResolveHours"`
}

// ComputeMTTR summarizes a set of lifecycle rows at now: counts by effective
// state and the mean time-to-resolve (resolvedAt − firstSeen) over resolved
// findings that carry both timestamps. Honest: findings missing a timestamp are
// excluded from the mean rather than counted as zero.
func ComputeMTTR(rows []FindingLifecycle, now time.Time) MTTRSummary {
	var s MTTRSummary
	var totalHours float64
	var measured int
	for _, lc := range rows {
		switch lc.EffectiveState(now) {
		case StateOpen:
			s.Open++
		case StateAcknowledged:
			s.Acknowledged++
		case StateInProgress:
			s.InProgress++
		case StateResolved:
			s.Resolved++
		case StateRiskAccepted:
			s.RiskAccepted++
		}
		if lc.State == StateResolved && lc.FirstSeen != "" && lc.ResolvedAt != "" {
			seen, e1 := time.Parse(time.RFC3339, lc.FirstSeen)
			done, e2 := time.Parse(time.RFC3339, lc.ResolvedAt)
			if e1 == nil && e2 == nil && !done.Before(seen) {
				totalHours += done.Sub(seen).Hours()
				measured++
			}
		}
	}
	if measured > 0 {
		s.MeanTimeToResolveHours = totalHours / float64(measured)
	}
	return s
}

// sortLifecycle orders rows deterministically for stable API output: by finding
// id then key.
func sortLifecycle(rows []FindingLifecycle) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].FindingID != rows[j].FindingID {
			return rows[i].FindingID < rows[j].FindingID
		}
		return rows[i].Key < rows[j].Key
	})
}
