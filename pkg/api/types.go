package api

// Severity is the ordered severity of a finding or attack path.
type Severity string

// Severity levels, highest to lowest.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank returns a sortable rank (higher = more severe). Unknown values rank
// below info so they never sort above a real severity.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Capability is an attacker primitive a finding grants and the attack-path
// engine chains over (ARCHITECTURE.md §8.1).
type Capability string

// Capability primitives.
const (
	CapInternetIngress      Capability = "InternetIngress"
	CapNetworkReachable     Capability = "NetworkReachable"
	CapContainerEscape      Capability = "ContainerEscape"
	CapNodeAccess           Capability = "NodeAccess"
	CapHostFilesystemAccess Capability = "HostFilesystemAccess"
	CapHostNetworkAccess    Capability = "HostNetworkAccess"
	CapHostProcessAccess    Capability = "HostProcessAccess"
	CapHostIPCAccess        Capability = "HostIPCAccess"
	CapServiceAccountToken  Capability = "ServiceAccountToken"
	CapSecretRead           Capability = "SecretRead"
	CapPodCreate            Capability = "PodCreate"
	CapBroadAPIAccess       Capability = "BroadAPIAccess"
	CapClusterAdmin         Capability = "ClusterAdmin"
	CapLateralMovement      Capability = "LateralMovement"
	CapResourceExhaustion   Capability = "ResourceExhaustion"
	CapRootInContainer      Capability = "RootInContainer"
	CapPrivEsc              Capability = "PrivEscWithinContainer"
)

// ResourceRef identifies the Kubernetes object a finding is about.
type ResourceRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Evidence is a single field-path observation backing a finding. Values are
// redacted where sensitive (secret env vars become the key name only).
type Evidence struct {
	Path  string `json:"path"`
	Value string `json:"value,omitempty"`
}

// Remediation is human guidance plus an optional fix snippet (filled in by the
// hardening squad).
type Remediation struct {
	Summary string `json:"summary"`
	Snippet string `json:"snippet,omitempty"`
}

// ControlRef is an indicative mapping to an external control or technique
// (e.g. CIS 5.2.1, NSA, ATT&CK T1611).
type ControlRef struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
}

// Finding is a single detected issue (ARCHITECTURE.md §4.2).
type Finding struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Severity    Severity     `json:"severity"`
	Category    string       `json:"category"`
	Resource    ResourceRef  `json:"resource"`
	Evidence    []Evidence   `json:"evidence,omitempty"`
	Remediation Remediation  `json:"remediation"`
	Grants      []Capability `json:"grants,omitempty"`
	Refs        []ControlRef `json:"refs,omitempty"`
}

// PathHop is one ordered step in an attack path: the attacker moves from one
// capability to another, enabled by a specific finding and tagged with ATT&CK
// techniques. Narrative is descriptive only — never a runnable exploit
// (ARCHITECTURE.md §3, §8).
type PathHop struct {
	Order     int        `json:"order"`
	From      Capability `json:"from"`
	To        Capability `json:"to"`
	EnabledBy string     `json:"enabledBy"` // finding/check id that enables this hop
	Technique []string   `json:"technique"` // MITRE ATT&CK technique ids
	Narrative string     `json:"narrative"`
}

// AttackPath is an ordered, ATT&CK-tagged chain of capability transitions from
// an entry point to a high-value outcome (ARCHITECTURE.md §8).
type AttackPath struct {
	ID       string      `json:"id"`
	Title    string      `json:"title"`
	Severity Severity    `json:"severity"`
	Entry    ResourceRef `json:"entry"`
	Hops     []PathHop   `json:"hops"`
	Summary  string      `json:"summary"`
}

// ControlBreach records a compliance control that was breached and the finding
// ids that breached it.
type ControlBreach struct {
	ControlID string   `json:"controlId"`
	Title     string   `json:"title,omitempty"`
	Findings  []string `json:"findings"`
}

// FrameworkResult is the posture for one compliance framework, always carrying
// its assessed denominator and the indicative-mapping disclaimer (honest
// metrics, ARCHITECTURE.md §9.3). Never a bare compliant/non-compliant verdict.
type FrameworkResult struct {
	Framework  string          `json:"framework"`
	Version    string          `json:"version,omitempty"`
	Assessed   int             `json:"assessed"`
	Breached   int             `json:"breached"`
	Passed     int             `json:"passed"`
	PassRate   float64         `json:"passRate"`
	Breaches   []ControlBreach `json:"breaches,omitempty"`
	Disclaimer string          `json:"disclaimer"`
}

// PostureSummary aggregates findings, attack paths, and compliance into a
// headline posture (ARCHITECTURE.md §9).
type PostureSummary struct {
	TotalFindings    int              `json:"totalFindings"`
	BySeverity       map[Severity]int `json:"bySeverity"`
	CriticalPaths    int              `json:"criticalPaths"`
	ControlsAssessed int              `json:"controlsAssessed"`
	ControlsBreached int              `json:"controlsBreached"`
	OverallPassRate  float64          `json:"overallPassRate"`
}

// Report is the top-level document KubeGuard emits (ARCHITECTURE.md §4.2,
// §12.4). Fields are populated additively across squads.
type Report struct {
	GeneratedAt string            `json:"generatedAt"`
	Source      string            `json:"source"`
	Profile     string            `json:"profile"`
	Findings    []Finding         `json:"findings"`
	Paths       []AttackPath      `json:"paths,omitempty"`
	Posture     PostureSummary    `json:"posture"`
	Compliance  []FrameworkResult `json:"compliance,omitempty"`
}
