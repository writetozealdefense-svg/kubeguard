package checks

import (
	"strings"

	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
)

// --- shared helpers -------------------------------------------------------

func effectiveSeccomp(c model.ContainerView, pod model.PodSpecView) string {
	if c.SeccompProfile != "" {
		return c.SeccompProfile
	}
	return pod.SecurityContext.SeccompProfile
}

// runsAsRoot reports whether a container is not provably non-root.
func runsAsRoot(c model.ContainerView, pod model.PodSpecView) bool {
	nonRoot := c.RunAsNonRoot
	if nonRoot == nil {
		nonRoot = pod.SecurityContext.RunAsNonRoot
	}
	user := c.RunAsUser
	if user == nil {
		user = pod.SecurityContext.RunAsUser
	}
	if user != nil && *user == 0 {
		return true
	}
	if nonRoot != nil && *nonRoot {
		return false
	}
	if user != nil && *user > 0 {
		return false
	}
	return true
}

// sensitiveHostPaths break container isolation (node/runtime sockets, host root).
var sensitiveHostPaths = map[string]bool{
	"/":                               true,
	"/var/run":                        true,
	"/var/run/docker.sock":            true,
	"/run/docker.sock":                true,
	"/run/containerd/containerd.sock": true,
	"/var/run/crio/crio.sock":         true,
	"/proc":                           true,
	"/var/lib/kubelet":                true,
	"/etc/kubernetes":                 true,
	"/var/lib/docker":                 true,
}

var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true,
	"SYS_MODULE": true, "SYS_BOOT": true, "SYS_RAWIO": true,
	"DAC_READ_SEARCH": true, "BPF": true, "NET_RAW": true,
}

func isMutableImage(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	name := image
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndex(name, ":"); i >= 0 {
		return name[i+1:] == "latest"
	}
	return true // no tag implies :latest
}

// --- container-level checks ----------------------------------------------

type privilegedCheck struct{}

func (privilegedCheck) Meta() Meta {
	return Meta{
		ID: "KG-001", Title: "Privileged container", Severity: api.SeverityCritical,
		Category: catHostAccess,
		Grants:   []api.Capability{api.CapContainerEscape, api.CapNodeAccess},
		Refs:     []api.ControlRef{cis("5.2.1"), nsa("Pod security"), attack("T1611")},
		Remediation: "Remove securityContext.privileged or set it to false; grant only the " +
			"specific capabilities the workload needs.",
	}
}

func (m privilegedCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, c := range w.PodSpec.Containers {
			if c.Privileged {
				out = append(out, m.Meta().finding(ref(w.Resource), ev(cpath(c, "securityContext.privileged"), "true")))
			}
		}
	}
	return out
}

type hostPathCheck struct{}

func (hostPathCheck) Meta() Meta {
	return Meta{
		ID: "KG-002", Title: "Sensitive hostPath mount", Severity: api.SeverityCritical,
		Category: catHostAccess,
		Grants:   []api.Capability{api.CapHostFilesystemAccess, api.CapContainerEscape},
		Refs:     []api.ControlRef{cis("5.2.10"), nsa("Pod security"), attack("T1611")},
		Remediation: "Remove the hostPath volume; use a projected/ephemeral volume or a CSI " +
			"driver instead of mounting host paths or runtime sockets.",
	}
}

func (m hostPathCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, v := range w.PodSpec.Volumes {
			if v.HostPath == "" {
				continue
			}
			f := m.Meta().finding(ref(w.Resource), ev("spec.volumes["+v.Name+"].hostPath.path", v.HostPath))
			if !sensitiveHostPaths[v.HostPath] {
				f.Severity = api.SeverityHigh
			}
			out = append(out, f)
		}
	}
	return out
}

type runAsRootCheck struct{}

func (runAsRootCheck) Meta() Meta {
	return Meta{
		ID: "KG-006", Title: "Container may run as root", Severity: api.SeverityMedium,
		Category: catWorkload, Grants: []api.Capability{api.CapRootInContainer},
		Refs:        []api.ControlRef{cis("5.2.6"), nsa("Pod security")},
		Remediation: "Set runAsNonRoot: true and a non-zero runAsUser in the security context.",
	}
}

func (m runAsRootCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, c := range w.PodSpec.Containers {
			if runsAsRoot(c, w.PodSpec) {
				out = append(out, m.Meta().finding(ref(w.Resource), ev(cpath(c, "securityContext.runAsNonRoot"), "not enforced")))
			}
		}
	}
	return out
}

type allowPrivEscCheck struct{}

func (allowPrivEscCheck) Meta() Meta {
	return Meta{
		ID: "KG-007", Title: "Privilege escalation not disabled", Severity: api.SeverityMedium,
		Category: catWorkload, Grants: []api.Capability{api.CapPrivEsc},
		Refs:        []api.ControlRef{cis("5.2.5"), nsa("Pod security")},
		Remediation: "Set allowPrivilegeEscalation: false in the container security context.",
	}
}

func (m allowPrivEscCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, c := range w.PodSpec.Containers {
			if c.AllowPrivEsc == nil || *c.AllowPrivEsc {
				out = append(out, m.Meta().finding(ref(w.Resource), ev(cpath(c, "securityContext.allowPrivilegeEscalation"), "not set (defaults true)")))
			}
		}
	}
	return out
}

type dangerousCapsCheck struct{}

func (dangerousCapsCheck) Meta() Meta {
	return Meta{
		ID: "KG-008", Title: "Dangerous Linux capability added", Severity: api.SeverityHigh,
		Category: catWorkload, Grants: []api.Capability{api.CapContainerEscape},
		Refs:        []api.ControlRef{cis("5.2.8"), nsa("Pod security"), attack("T1611")},
		Remediation: "Drop ALL capabilities and add back only those strictly required.",
	}
}

func (m dangerousCapsCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, c := range w.PodSpec.Containers {
			for _, capName := range c.CapsAdd {
				if dangerousCaps[strings.ToUpper(capName)] {
					out = append(out, m.Meta().finding(ref(w.Resource), ev(cpath(c, "securityContext.capabilities.add"), capName)))
				}
			}
		}
	}
	return out
}

type readOnlyRootFSCheck struct{}

func (readOnlyRootFSCheck) Meta() Meta {
	return Meta{
		ID: "KG-009", Title: "Root filesystem is writable", Severity: api.SeverityLow,
		Category:    catWorkload,
		Refs:        []api.ControlRef{cis("5.2.12"), nsa("Pod security")},
		Remediation: "Set readOnlyRootFilesystem: true and mount writable paths as volumes.",
	}
}

func (m readOnlyRootFSCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, c := range w.PodSpec.Containers {
			if c.ReadOnlyRootFS == nil || !*c.ReadOnlyRootFS {
				out = append(out, m.Meta().finding(ref(w.Resource), ev(cpath(c, "securityContext.readOnlyRootFilesystem"), "not true")))
			}
		}
	}
	return out
}

type resourceLimitsCheck struct{}

func (resourceLimitsCheck) Meta() Meta {
	return Meta{
		ID: "KG-010", Title: "Missing CPU/memory limits", Severity: api.SeverityLow,
		Category: catWorkload, Grants: []api.Capability{api.CapResourceExhaustion},
		Refs:        []api.ControlRef{cis("5.7.3"), nsa("Resource limits")},
		Remediation: "Set resources.limits.cpu and resources.limits.memory.",
	}
}

func (m resourceLimitsCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, c := range w.PodSpec.Containers {
			if !c.Limits.HasLimits() {
				out = append(out, m.Meta().finding(ref(w.Resource), ev(cpath(c, "resources.limits"), "missing cpu/memory")))
			}
		}
	}
	return out
}

type mutableImageCheck struct{}

func (mutableImageCheck) Meta() Meta {
	return Meta{
		ID: "KG-019", Title: "Image uses a mutable tag", Severity: api.SeverityLow,
		Category:    catSupplyChain,
		Refs:        []api.ControlRef{cis("5.5.1"), nsa("Supply chain")},
		Remediation: "Pin images by digest (image@sha256:...) or an immutable, versioned tag.",
	}
}

func (m mutableImageCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, c := range w.PodSpec.Containers {
			if isMutableImage(c.Image) {
				out = append(out, m.Meta().finding(ref(w.Resource), ev(cpath(c, "image"), c.Image)))
			}
		}
	}
	return out
}

type seccompCheck struct{}

func (seccompCheck) Meta() Meta {
	return Meta{
		ID: "KG-020", Title: "Seccomp profile is not RuntimeDefault", Severity: api.SeverityLow,
		Category:    catWorkload,
		Refs:        []api.ControlRef{cis("5.7.2"), nsa("Pod security")},
		Remediation: "Set seccompProfile.type: RuntimeDefault on the pod or container.",
	}
}

func (m seccompCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		for _, c := range w.PodSpec.Containers {
			if effectiveSeccomp(c, w.PodSpec) != "RuntimeDefault" {
				out = append(out, m.Meta().finding(ref(w.Resource), ev(cpath(c, "securityContext.seccompProfile.type"), "not RuntimeDefault")))
			}
		}
	}
	return out
}

// --- pod / workload-level checks -----------------------------------------

type hostNetworkCheck struct{}

func (hostNetworkCheck) Meta() Meta {
	return Meta{
		ID: "KG-003", Title: "hostNetwork enabled", Severity: api.SeverityHigh,
		Category: catHostAccess, Grants: []api.Capability{api.CapHostNetworkAccess},
		Refs:        []api.ControlRef{cis("5.2.4"), nsa("Pod security")},
		Remediation: "Set hostNetwork: false; expose the workload via a Service instead.",
	}
}

func (m hostNetworkCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		if w.PodSpec.HostNetwork {
			out = append(out, m.Meta().finding(ref(w.Resource), ev("spec.hostNetwork", "true")))
		}
	}
	return out
}

type hostPIDCheck struct{}

func (hostPIDCheck) Meta() Meta {
	return Meta{
		ID: "KG-004", Title: "hostPID enabled", Severity: api.SeverityHigh,
		Category: catHostAccess, Grants: []api.Capability{api.CapHostProcessAccess},
		Refs:        []api.ControlRef{cis("5.2.3"), nsa("Pod security")},
		Remediation: "Set hostPID: false.",
	}
}

func (m hostPIDCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		if w.PodSpec.HostPID {
			out = append(out, m.Meta().finding(ref(w.Resource), ev("spec.hostPID", "true")))
		}
	}
	return out
}

type hostIPCCheck struct{}

func (hostIPCCheck) Meta() Meta {
	return Meta{
		ID: "KG-005", Title: "hostIPC enabled", Severity: api.SeverityMedium,
		Category: catHostAccess, Grants: []api.Capability{api.CapHostIPCAccess},
		Refs:        []api.ControlRef{cis("5.2.3"), nsa("Pod security")},
		Remediation: "Set hostIPC: false.",
	}
}

func (m hostIPCCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		if w.PodSpec.HostIPC {
			out = append(out, m.Meta().finding(ref(w.Resource), ev("spec.hostIPC", "true")))
		}
	}
	return out
}

type automountTokenCheck struct{}

func (automountTokenCheck) Meta() Meta {
	return Meta{
		ID: "KG-015", Title: "ServiceAccount token auto-mounted", Severity: api.SeverityMedium,
		Category: catRBAC, Grants: []api.Capability{api.CapServiceAccountToken},
		Refs:        []api.ControlRef{cis("5.1.6"), nsa("RBAC")},
		Remediation: "Set automountServiceAccountToken: false on the pod or ServiceAccount when the token is not needed.",
	}
}

func (m automountTokenCheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		if automountEffective(g, w) {
			out = append(out, m.Meta().finding(ref(w.Resource), ev("spec.automountServiceAccountToken", "not disabled")))
		}
	}
	return out
}

// automountEffective resolves pod-level then SA-level automount, defaulting to
// true (cluster default).
func automountEffective(g *graph.Graph, w model.Workload) bool {
	if w.PodSpec.AutomountSAToken != nil {
		return *w.PodSpec.AutomountSAToken
	}
	if sa, ok := g.ServiceAccountByName(w.Namespace, w.ServiceAccountName); ok && sa.AutomountToken != nil {
		return *sa.AutomountToken
	}
	return true
}

type defaultSACheck struct{}

func (defaultSACheck) Meta() Meta {
	return Meta{
		ID: "KG-016", Title: "Workload uses the default ServiceAccount", Severity: api.SeverityLow,
		Category:    catRBAC,
		Refs:        []api.ControlRef{cis("5.1.5"), nsa("RBAC")},
		Remediation: "Assign a dedicated, least-privilege ServiceAccount instead of default.",
	}
}

func (m defaultSACheck) Run(g *graph.Graph) []api.Finding {
	var out []api.Finding
	for _, w := range g.Workloads {
		if w.ServiceAccountName == "default" {
			out = append(out, m.Meta().finding(ref(w.Resource), ev("spec.serviceAccountName", "default")))
		}
	}
	return out
}
