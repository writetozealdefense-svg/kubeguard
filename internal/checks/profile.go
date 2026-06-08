package checks

import (
	"fmt"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// Profile selects and overrides the active check set (ARCHITECTURE.md §7.2).
// A profile is data, not code: Include (empty = all), Exclude, and per-id
// severity overrides.
type Profile struct {
	Name             string
	Include          []string
	Exclude          []string
	SeverityOverride map[string]api.Severity
}

// RunnableIDs returns the set of check ids this profile will execute, used by
// the compliance engine to compute honest denominators.
func (p Profile) RunnableIDs() map[string]bool {
	out := map[string]bool{}
	for _, c := range Registry() {
		if id := c.Meta().ID; p.includes(id) {
			out[id] = true
		}
	}
	return out
}

func (p Profile) includes(id string) bool {
	for _, e := range p.Exclude {
		if e == id {
			return false
		}
	}
	if len(p.Include) == 0 {
		return true
	}
	for _, i := range p.Include {
		if i == id {
			return true
		}
	}
	return false
}

// zealDefault is KubeGuard's opinionated default: all 20 checks with
// attack-path-aware severities (KG-018 escalates by context inside the check).
func zealDefault() Profile {
	return Profile{Name: "zeal-default"}
}

// cisProfile aligns severities to the CIS Kubernetes Benchmark: exposure is a
// flat medium (CIS does not escalate a LoadBalancer by what it fronts).
func cisProfile() Profile {
	return Profile{
		Name: "cis",
		SeverityOverride: map[string]api.Severity{
			"KG-018": api.SeverityMedium,
		},
	}
}

// ProfileByName returns a named profile, defaulting to zeal-default.
func ProfileByName(name string) (Profile, error) {
	switch name {
	case "", "zeal-default":
		return zealDefault(), nil
	case "cis":
		return cisProfile(), nil
	default:
		return Profile{}, fmt.Errorf("unknown profile %q (want cis|zeal-default)", name)
	}
}
