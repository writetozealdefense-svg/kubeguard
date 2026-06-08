package attack

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
)

// Check ids referenced as the enabler of each hop (ARCHITECTURE.md §8.2).
const (
	kgPrivileged   = "KG-001"
	kgHostPath     = "KG-002"
	kgDangerousCap = "KG-008"
	kgClusterAdmin = "KG-011"
	kgSecrets      = "KG-013"
	kgPodCreate    = "KG-014"
	kgAutomount    = "KG-015"
	kgNoNetPol     = "KG-017"
	kgExposure     = "KG-018"
)

// Host paths and capabilities that enable a container escape to the node.
var escapeHostPaths = map[string]bool{
	"/": true, "/var/run": true, "/var/run/docker.sock": true,
	"/run/docker.sock": true, "/run/containerd/containerd.sock": true,
	"/var/run/crio/crio.sock": true, "/proc": true,
	"/var/lib/kubelet": true, "/var/lib/docker": true,
}

var escapeCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "SYS_MODULE": true,
	"SYS_RAWIO": true, "SYS_PTRACE": true, "DAC_READ_SEARCH": true, "BPF": true,
}

// BuildPaths chains the resource graph into ordered, ATT&CK-tagged attack paths
// (ARCHITECTURE.md §8). With assumeBreach, every workload is treated as
// reachable from an in-cluster foothold (§8.3). Output is deterministic.
func BuildPaths(g *graph.Graph, assumeBreach bool) []api.AttackPath {
	var paths []api.AttackPath
	for _, w := range g.Workloads {
		if p, ok := buildForWorkload(g, w, assumeBreach); ok {
			paths = append(paths, p)
		}
	}
	sortPaths(paths)
	for i := range paths {
		paths[i].ID = fmt.Sprintf("AP-%03d", i+1)
	}
	return paths
}

func buildForWorkload(g *graph.Graph, w model.Workload, assumeBreach bool) (api.AttackPath, bool) {
	var hops []api.PathHop
	cur := api.Capability("")
	add := func(to api.Capability, by string, tech []string, narr string) {
		hops = append(hops, api.PathHop{
			Order: len(hops) + 1, From: cur, To: to,
			EnabledBy: by, Technique: tech, Narrative: narr,
		})
		cur = to
	}

	// --- entry ---
	exposed, svcName := exposingService(g, w)
	hasEscape := workloadEscape(w)
	switch {
	case exposed:
		cur = api.CapInternetIngress
		add(api.CapNetworkReachable, kgExposure, []string{"T1190"},
			fmt.Sprintf("Internet-facing Service %q exposes workload %q.", svcName, w.Name))
	case hasEscape || assumeBreach:
		cur = api.CapNetworkReachable // in-cluster foothold; no explicit hop
	default:
		return api.AttackPath{}, false
	}

	// --- container escape -> node ---
	if hasEscape {
		by, narr := escapeEnabler(w)
		add(api.CapContainerEscape, by, []string{"T1611"}, narr)
		nodeBy := kgPrivileged
		if hostPathName(w) != "" {
			nodeBy = kgHostPath
		}
		add(api.CapNodeAccess, nodeBy, []string{"T1611"},
			fmt.Sprintf("Breakout yields code execution on the node hosting %q.", w.Name))
	}

	// --- ServiceAccount token -> RBAC escalation ---
	saAdmin := g.SAIsClusterAdmin(w.Namespace, w.ServiceAccountName)
	saSecrets := g.SACanReadSecrets(w.Namespace, w.ServiceAccountName)
	saPods := g.SACanCreatePods(w.Namespace, w.ServiceAccountName)
	footholdInCluster := cur == api.CapNodeAccess || cur == api.CapContainerEscape || cur == api.CapNetworkReachable
	if automountOn(g, w) && footholdInCluster && (saAdmin || saSecrets || saPods) {
		add(api.CapServiceAccountToken, kgAutomount, []string{"T1552.001"},
			fmt.Sprintf("ServiceAccount %q token is auto-mounted and harvestable.", w.ServiceAccountName))
		switch {
		case saAdmin:
			add(api.CapClusterAdmin, kgClusterAdmin, []string{"T1078"},
				fmt.Sprintf("%q is bound to cluster-admin — full cluster control.", w.ServiceAccountName))
		default:
			if saSecrets {
				add(api.CapSecretRead, kgSecrets, []string{"T1552"},
					fmt.Sprintf("%q can read Secrets across the cluster.", w.ServiceAccountName))
			}
			if saPods {
				add(api.CapPodCreate, kgPodCreate, []string{"T1610"},
					fmt.Sprintf("%q can create or exec into pods to pivot.", w.ServiceAccountName))
			}
		}
	}

	// --- lateral movement ---
	if !g.HasDefaultDeny(w.Namespace) && hasFoothold(cur) {
		add(api.CapLateralMovement, kgNoNetPol, []string{"T1021"},
			fmt.Sprintf("No default-deny NetworkPolicy in %q enables lateral movement.", w.Namespace))
	}

	sev := pathSeverity(hops, cur)
	if sev.Rank() < api.SeverityHigh.Rank() {
		return api.AttackPath{}, false
	}
	return api.AttackPath{
		Title:    pathTitle(w, hops),
		Severity: sev,
		Entry:    api.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
		Hops:     hops,
		Summary:  pathSummary(w, hops),
	}, true
}

// --- predicates -----------------------------------------------------------

func workloadEscape(w model.Workload) bool {
	for _, c := range w.PodSpec.Containers {
		if c.Privileged {
			return true
		}
		for _, capName := range c.CapsAdd {
			if escapeCaps[strings.ToUpper(capName)] {
				return true
			}
		}
	}
	return hostPathName(w) != ""
}

func hostPathName(w model.Workload) string {
	for _, v := range w.PodSpec.Volumes {
		if v.HostPath != "" && escapeHostPaths[v.HostPath] {
			return v.HostPath
		}
	}
	return ""
}

func escapeEnabler(w model.Workload) (string, string) {
	for _, c := range w.PodSpec.Containers {
		if c.Privileged {
			return kgPrivileged, "Privileged container allows breakout from the pod."
		}
	}
	for _, c := range w.PodSpec.Containers {
		for _, capName := range c.CapsAdd {
			if escapeCaps[strings.ToUpper(capName)] {
				return kgDangerousCap, "Dangerous capability (" + capName + ") allows breakout."
			}
		}
	}
	if hp := hostPathName(w); hp != "" {
		return kgHostPath, "Sensitive hostPath (" + hp + ") allows breakout."
	}
	return kgPrivileged, "Container escape."
}

func exposingService(g *graph.Graph, w model.Workload) (bool, string) {
	for _, svc := range g.Services {
		if svc.Type != "LoadBalancer" && svc.Type != "NodePort" {
			continue
		}
		for _, m := range g.WorkloadsForService(svc) {
			if m.Namespace == w.Namespace && m.Name == w.Name && m.Kind == w.Kind {
				return true, svc.Name
			}
		}
	}
	return false, ""
}

func automountOn(g *graph.Graph, w model.Workload) bool {
	if w.PodSpec.AutomountSAToken != nil {
		return *w.PodSpec.AutomountSAToken
	}
	if sa, ok := g.ServiceAccountByName(w.Namespace, w.ServiceAccountName); ok && sa.AutomountToken != nil {
		return *sa.AutomountToken
	}
	return true
}

func hasFoothold(c api.Capability) bool {
	switch c {
	case api.CapContainerEscape, api.CapNodeAccess, api.CapServiceAccountToken,
		api.CapSecretRead, api.CapPodCreate, api.CapClusterAdmin:
		return true
	default:
		return false
	}
}

// --- severity / presentation ---------------------------------------------

func capSeverity(c api.Capability) api.Severity {
	switch c {
	case api.CapClusterAdmin, api.CapNodeAccess:
		return api.SeverityCritical
	case api.CapContainerEscape, api.CapHostNetworkAccess, api.CapHostProcessAccess,
		api.CapSecretRead, api.CapPodCreate, api.CapBroadAPIAccess:
		return api.SeverityHigh
	case api.CapServiceAccountToken, api.CapLateralMovement:
		return api.SeverityMedium
	default:
		return api.SeverityLow
	}
}

func pathSeverity(hops []api.PathHop, cur api.Capability) api.Severity {
	best := api.SeverityInfo
	consider := func(c api.Capability) {
		if capSeverity(c).Rank() > best.Rank() {
			best = capSeverity(c)
		}
	}
	for _, h := range hops {
		consider(h.From)
		consider(h.To)
	}
	consider(cur)
	return best
}

// capPrecedence ranks outcomes for titling: cluster-admin is the headline even
// though node access shares its critical severity.
func capPrecedence(c api.Capability) int {
	switch c {
	case api.CapClusterAdmin:
		return 100
	case api.CapNodeAccess:
		return 90
	case api.CapSecretRead:
		return 80
	case api.CapPodCreate:
		return 75
	case api.CapContainerEscape:
		return 70
	case api.CapBroadAPIAccess:
		return 65
	case api.CapLateralMovement:
		return 30
	case api.CapServiceAccountToken:
		return 20
	default:
		return 10
	}
}

func apexCap(hops []api.PathHop) api.Capability {
	best := api.Capability("")
	bestRank := -1
	for _, h := range hops {
		if r := capPrecedence(h.To); r > bestRank {
			bestRank, best = r, h.To
		}
	}
	return best
}

func pathTitle(w model.Workload, hops []api.PathHop) string {
	switch apexCap(hops) {
	case api.CapClusterAdmin:
		return "Cluster-admin takeover via " + w.Name
	case api.CapNodeAccess:
		return "Node breakout via " + w.Name
	case api.CapSecretRead:
		return "Secret exfiltration via " + w.Name
	case api.CapPodCreate:
		return "Pod-create pivot via " + w.Name
	default:
		return "Privilege escalation via " + w.Name
	}
}

func pathSummary(w model.Workload, hops []api.PathHop) string {
	return fmt.Sprintf("Entry %s/%s. Chain: %s. Techniques: %s.",
		w.Kind, w.Name,
		strings.Join(capChain(hops), " -> "),
		strings.Join(uniqueTechniques(hops), ", "))
}

func capChain(hops []api.PathHop) []string {
	if len(hops) == 0 {
		return nil
	}
	out := []string{string(hops[0].From)}
	for _, h := range hops {
		out = append(out, string(h.To))
	}
	return out
}

func uniqueTechniques(hops []api.PathHop) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hops {
		for _, t := range h.Technique {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

func sortPaths(paths []api.AttackPath) {
	sort.SliceStable(paths, func(i, j int) bool {
		a, b := paths[i], paths[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if len(a.Hops) != len(b.Hops) {
			return len(a.Hops) < len(b.Hops)
		}
		return entryKey(a.Entry) < entryKey(b.Entry)
	})
}

func entryKey(r api.ResourceRef) string { return r.Namespace + "/" + r.Kind + "/" + r.Name }
