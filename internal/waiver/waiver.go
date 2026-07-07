// Package waiver is the offline, file-based waiver mechanism for the shift-left
// guardrails (CLI --fail-on and the admission webhook). It is the offline peer
// of the dashboard's store-backed lifecycle waivers (K6): the dashboard tracks
// waivers online per finding identity; here an operator supplies a waiver file
// so guardrails that run with no store (a CI runner, an admission controller in
// an air-gapped cluster) can still honor a valid, unexpired risk acceptance —
// and log that it was applied — without any network access.
//
// Constitution: offline-first (the file is operator-supplied, no fetch),
// deterministic (matching is a pure function of the finding + now), and honest
// (a waived finding is never silently dropped from the report — only the *gate*
// ignores it, and every application is logged by the caller).
package waiver

import (
	"fmt"
	"os"
	"time"

	"github.com/kubeguard/kubeguard/pkg/api"
	"sigs.k8s.io/yaml"
)

// Selector narrows a waiver to a specific resource. Any empty field is a
// wildcard, so `{kind: Deployment}` waives the check on every Deployment and an
// omitted selector waives it everywhere.
type Selector struct {
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// Entry is one offline waiver: which check (and optionally which resource) is
// risk-accepted, why, and until when. Justification and expires are mandatory —
// an undated or unjustified waiver is rejected at load time.
type Entry struct {
	ID            string    `json:"id"`
	Resource      *Selector `json:"resource,omitempty"`
	Justification string    `json:"justification"`
	Expires       string    `json:"expires"`

	expiresAt time.Time // parsed at load
}

// file is the on-disk shape.
type file struct {
	Waivers []Entry `json:"waivers"`
}

// Set is a loaded, validated collection of waivers.
type Set struct {
	entries []Entry
}

// WaivedFinding pairs a finding with the entry that waived it, for logging.
type WaivedFinding struct {
	Finding api.Finding
	Entry   Entry
}

// Empty reports whether the set has no waivers (nil-safe).
func (s *Set) Empty() bool { return s == nil || len(s.entries) == 0 }

// Load reads and validates a waiver file (YAML or JSON). Unknown keys are
// rejected (strict), and every entry must carry a check id, a justification, and
// a parseable RFC3339 expiry.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-specified waiver file
	if err != nil {
		return nil, fmt.Errorf("read waiver file: %w", err)
	}
	return Parse(data)
}

// Parse validates waiver bytes (exposed for tests and non-file sources).
func Parse(data []byte) (*Set, error) {
	var f file
	if err := yaml.UnmarshalStrict(data, &f); err != nil {
		return nil, fmt.Errorf("parse waiver file: %w", err)
	}
	set := &Set{}
	for i := range f.Waivers {
		e := f.Waivers[i]
		if e.ID == "" {
			return nil, fmt.Errorf("waiver[%d]: id is required", i)
		}
		if e.Justification == "" {
			return nil, fmt.Errorf("waiver[%d] (%s): justification is required", i, e.ID)
		}
		if e.Expires == "" {
			return nil, fmt.Errorf("waiver[%d] (%s): expires is required", i, e.ID)
		}
		t, err := time.Parse(time.RFC3339, e.Expires)
		if err != nil {
			return nil, fmt.Errorf("waiver[%d] (%s): expires must be RFC3339: %w", i, e.ID, err)
		}
		e.expiresAt = t
		set.entries = append(set.entries, e)
	}
	return set, nil
}

// Match returns the first active (unexpired) waiver covering a finding at now,
// or ok=false. Deterministic: entries are matched in file order.
func (s *Set) Match(f api.Finding, now time.Time) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	for _, e := range s.entries {
		if e.ID != f.ID {
			continue
		}
		if !now.Before(e.expiresAt) {
			continue // expired → does not apply (finding re-blocks)
		}
		if e.matchesResource(f.Resource) {
			return e, true
		}
	}
	return Entry{}, false
}

func (e Entry) matchesResource(r api.ResourceRef) bool {
	if e.Resource == nil {
		return true // no selector → applies to every resource for this check
	}
	if e.Resource.Kind != "" && e.Resource.Kind != r.Kind {
		return false
	}
	if e.Resource.Namespace != "" && e.Resource.Namespace != r.Namespace {
		return false
	}
	if e.Resource.Name != "" && e.Resource.Name != r.Name {
		return false
	}
	return true
}

// Partition splits findings into those that still block (unwaived) and those
// suppressed by an active waiver at now. The report itself is never mutated —
// callers keep showing every finding and use `blocking` only for the gate,
// logging `waived` so a suppression is always visible.
func (s *Set) Partition(findings []api.Finding, now time.Time) (blocking []api.Finding, waived []WaivedFinding) {
	for _, f := range findings {
		if e, ok := s.Match(f, now); ok {
			waived = append(waived, WaivedFinding{Finding: f, Entry: e})
			continue
		}
		blocking = append(blocking, f)
	}
	return blocking, waived
}
