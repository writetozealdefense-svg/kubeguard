package checks

import (
	"fmt"
	"sort"

	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
)

// Categories (ARCHITECTURE.md §7.1).
const (
	catWorkload    = "workload-hardening"
	catHostAccess  = "host-access"
	catRBAC        = "rbac"
	catNetwork     = "network"
	catExposure    = "exposure"
	catSupplyChain = "supply-chain"
)

// Meta is the static description of a check. Severity here is the default
// (zeal-default profile); checks may override per-finding for computed cases,
// and profiles may override by id.
type Meta struct {
	ID          string
	Title       string
	Severity    api.Severity
	Category    string
	Grants      []api.Capability
	Refs        []api.ControlRef
	Remediation string
}

// Check is a single detection rule. Run is pure over the graph.
type Check interface {
	Meta() Meta
	Run(g *graph.Graph) []api.Finding
}

// finding builds a Finding from this check's metadata, attaching the per-check
// fix snippet (ARCHITECTURE.md §11).
func (m Meta) finding(ref api.ResourceRef, evidence ...api.Evidence) api.Finding {
	return api.Finding{
		ID:          m.ID,
		Title:       m.Title,
		Severity:    m.Severity,
		Category:    m.Category,
		Resource:    ref,
		Evidence:    evidence,
		Remediation: api.Remediation{Summary: m.Remediation, Snippet: remediationSnippets[m.ID]},
		Grants:      m.Grants,
		Refs:        m.Refs,
	}
}

// remediationSnippets are the per-finding fix snippets surfaced in JSON/HTML.
var remediationSnippets = map[string]string{
	"KG-001": "securityContext:\n  privileged: false",
	"KG-002": "# remove the hostPath volume; use a CSI or projected volume instead",
	"KG-003": "spec:\n  hostNetwork: false",
	"KG-004": "spec:\n  hostPID: false",
	"KG-005": "spec:\n  hostIPC: false",
	"KG-006": "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
	"KG-007": "securityContext:\n  allowPrivilegeEscalation: false",
	"KG-008": "securityContext:\n  capabilities:\n    drop: [\"ALL\"]",
	"KG-009": "securityContext:\n  readOnlyRootFilesystem: true",
	"KG-010": "resources:\n  limits:\n    cpu: \"500m\"\n    memory: \"256Mi\"",
	"KG-011": "# bind a least-privilege Role, not cluster-admin or a wildcard ClusterRole",
	"KG-012": "# replace wildcard rules with explicit apiGroups/resources/verbs",
	"KG-013": "# remove get/list/watch on secrets; scope via resourceNames if required",
	"KG-014": "# remove create on pods and access to pods/exec and pods/attach",
	"KG-015": "spec:\n  automountServiceAccountToken: false",
	"KG-016": "spec:\n  serviceAccountName: <dedicated-service-account>",
	"KG-017": "# apply a default-deny NetworkPolicy (see `kubeguard harden`)",
	"KG-018": "spec:\n  type: ClusterIP   # front with an ingress + WAF instead",
	"KG-019": "image: <repo>@sha256:<digest>   # pin by digest",
	"KG-020": "securityContext:\n  seccompProfile:\n    type: RuntimeDefault",
}

func ref(r model.Resource) api.ResourceRef {
	return api.ResourceRef{Kind: r.Kind, Namespace: r.Namespace, Name: r.Name}
}

func nsRef(namespace string) api.ResourceRef {
	return api.ResourceRef{Kind: "Namespace", Name: namespace}
}

func ev(path, value string) api.Evidence { return api.Evidence{Path: path, Value: value} }

func cpath(c model.ContainerView, field string) string {
	return fmt.Sprintf("spec.containers[%s].%s", c.Name, field)
}

func cis(id string) api.ControlRef { return api.ControlRef{Framework: "CIS", ID: id} }
func nsa(title string) api.ControlRef {
	return api.ControlRef{Framework: "NSA", ID: "k8s-hardening", Title: title}
}
func attack(id string) api.ControlRef { return api.ControlRef{Framework: "ATT&CK", ID: id} }

// Registry returns all built-in checks in id order.
func Registry() []Check {
	return []Check{
		privilegedCheck{}, hostPathCheck{}, hostNetworkCheck{}, hostPIDCheck{}, hostIPCCheck{},
		runAsRootCheck{}, allowPrivEscCheck{}, dangerousCapsCheck{}, readOnlyRootFSCheck{}, resourceLimitsCheck{},
		clusterAdminBindingCheck{}, wildcardRBACCheck{}, secretsAccessCheck{}, podCreateCheck{}, automountTokenCheck{},
		defaultSACheck{}, networkPolicyCheck{}, exposureCheck{}, mutableImageCheck{}, seccompCheck{},
		capDropAllCheck{}, untrustedRegistryCheck{},
	}
}

// Scan runs the profile's selected checks over the graph and returns findings
// in deterministic order: severity desc, category asc, id asc, then resource.
func Scan(g *graph.Graph, p Profile) []api.Finding {
	var findings []api.Finding
	for _, c := range Registry() {
		id := c.Meta().ID
		if !p.includes(id) {
			continue
		}
		for _, f := range c.Run(g) {
			if ov, ok := p.SeverityOverride[id]; ok {
				f.Severity = ov
			}
			findings = append(findings, f)
		}
	}
	SortFindings(findings)
	return findings
}

// SortFindings applies the canonical stable ordering (ARCHITECTURE.md §3.4).
func SortFindings(fs []api.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return resourceKey(a.Resource) < resourceKey(b.Resource)
	})
}

func resourceKey(r api.ResourceRef) string {
	return r.Namespace + "/" + r.Kind + "/" + r.Name
}
