// Package policy is KubeGuard's custom policy-as-code engine (K3): operators
// define org-specific checks as *data* — a YAML pack of CEL expressions loaded
// at runtime — without forking or recompiling the tool. It extends the existing
// data-driven pattern (profiles, framework packs) and produces standard
// api.Finding values, so custom findings flow through the same report, gate,
// SARIF, and lifecycle surfaces as the built-in checks.
//
// Engine choice (⟐ DECISION): CEL (google/cel-go) — pure-Go and fully offline,
// so it honours the offline-first / no-telemetry constitution, and it is the
// same expression language Kubernetes uses for ValidatingAdmissionPolicy, so the
// syntax is already familiar to platform engineers. (Rego/OPA would pull a
// heavier runtime and a second policy language for no benefit here.)
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
	"sigs.k8s.io/yaml"
)

// apiVersion is the only accepted pack apiVersion.
const apiVersion = "kubeguard.io/policy/v1"

// Target selects what a policy's CEL expression is evaluated against.
type Target string

// Policy evaluation targets.
const (
	TargetWorkload  Target = "workload"  // once per workload, with `workload` in scope
	TargetContainer Target = "container" // once per container, with `container` + `workload` in scope
)

// Ref is an indicative control reference on a custom policy (mirrors ControlRef).
type Ref struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
}

// Policy is one custom check defined as data.
type Policy struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Target      Target `json:"target,omitempty"`
	Match       string `json:"match"`
	Remediation string `json:"remediation,omitempty"`
	Refs        []Ref  `json:"refs,omitempty"`

	program cel.Program // compiled `match`
}

// pack is the on-disk shape.
type pack struct {
	APIVersion string   `json:"apiVersion"`
	Policies   []Policy `json:"policies"`
}

// Set is a loaded, compiled collection of custom policies.
type Set struct {
	policies []Policy
}

// Empty reports whether the set has no policies (nil-safe).
func (s *Set) Empty() bool { return s == nil || len(s.policies) == 0 }

// Len returns the number of loaded policies.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.policies)
}

var validSeverity = map[string]api.Severity{
	"critical": api.SeverityCritical, "high": api.SeverityHigh,
	"medium": api.SeverityMedium, "low": api.SeverityLow, "info": api.SeverityInfo,
}

// Load reads and compiles a policy pack from a file, or every *.yaml/*.yml under
// a directory (deterministic order). All packs merge into one Set.
func Load(path string) (*Set, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("policy path: %w", err)
	}
	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("read policy dir: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if ext := strings.ToLower(filepath.Ext(e.Name())); ext == ".yaml" || ext == ".yml" {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	set := &Set{}
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // operator-specified policy path
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		ps, err := parse(data, filepath.Base(f))
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if seen[p.ID] {
				return nil, fmt.Errorf("duplicate policy id %q (in %s)", p.ID, filepath.Base(f))
			}
			seen[p.ID] = true
			set.policies = append(set.policies, p)
		}
	}
	return set, nil
}

// Parse validates+compiles a single pack's bytes (exposed for tests).
func Parse(data []byte) (*Set, error) {
	ps, err := parse(data, "<bytes>")
	if err != nil {
		return nil, err
	}
	return &Set{policies: ps}, nil
}

func parse(data []byte, src string) ([]Policy, error) {
	var pk pack
	// Strict: unknown keys are rejected so a typo'd field fails loudly rather
	// than silently disabling a policy.
	if err := yaml.UnmarshalStrict(data, &pk); err != nil {
		return nil, fmt.Errorf("parse policy pack %s: %w", src, err)
	}
	if pk.APIVersion != apiVersion {
		return nil, fmt.Errorf("policy pack %s: apiVersion must be %q, got %q", src, apiVersion, pk.APIVersion)
	}
	if len(pk.Policies) == 0 {
		return nil, fmt.Errorf("policy pack %s: no policies", src)
	}
	for i := range pk.Policies {
		p := &pk.Policies[i]
		if err := compilePolicy(p); err != nil {
			return nil, fmt.Errorf("policy pack %s: %w", src, err)
		}
	}
	return pk.Policies, nil
}

func compilePolicy(p *Policy) error {
	if p.ID == "" {
		return fmt.Errorf("policy is missing an id")
	}
	if p.Title == "" {
		return fmt.Errorf("policy %q: title is required", p.ID)
	}
	if _, ok := validSeverity[p.Severity]; !ok {
		return fmt.Errorf("policy %q: severity must be critical|high|medium|low|info, got %q", p.ID, p.Severity)
	}
	if p.Category == "" {
		return fmt.Errorf("policy %q: category is required", p.ID)
	}
	if p.Match == "" {
		return fmt.Errorf("policy %q: match expression is required", p.ID)
	}
	if p.Target == "" {
		p.Target = TargetWorkload
	}
	env, err := envFor(p.Target)
	if err != nil {
		return fmt.Errorf("policy %q: %w", p.ID, err)
	}
	ast, iss := env.Compile(p.Match)
	if iss != nil && iss.Err() != nil {
		return fmt.Errorf("policy %q: match does not compile: %w", p.ID, iss.Err())
	}
	// The variables are dynamically typed, so bare field access (workload.hostNetwork)
	// statically types as `dyn` even though it is a bool at runtime — accept bool or
	// dyn. A statically-typed non-bool (e.g. an int like "1 + 1") is rejected here;
	// a dyn that resolves to a non-bool at runtime simply never matches.
	if ot := ast.OutputType(); ot != cel.BoolType && ot != cel.DynType {
		return fmt.Errorf("policy %q: match must evaluate to bool, got %s", p.ID, ot)
	}
	prg, err := env.Program(ast)
	if err != nil {
		return fmt.Errorf("policy %q: program: %w", p.ID, err)
	}
	p.program = prg
	return nil
}

// envFor builds the CEL environment for a target. workload-scoped policies see
// `workload`; container-scoped policies additionally see `container`.
func envFor(t Target) (*cel.Env, error) {
	vars := []cel.EnvOption{cel.Variable("workload", cel.DynType)}
	switch t {
	case TargetWorkload:
	case TargetContainer:
		vars = append(vars, cel.Variable("container", cel.DynType))
	default:
		return nil, fmt.Errorf("target must be workload or container, got %q", t)
	}
	return cel.NewEnv(vars...)
}

// Evaluate runs every policy over the graph's workloads and returns standard
// findings (deterministically sorted by the caller). A per-resource evaluation
// error is skipped rather than aborting the whole scan.
func (s *Set) Evaluate(g *graph.Graph) []api.Finding {
	if s.Empty() {
		return nil
	}
	var out []api.Finding
	for _, p := range s.policies {
		for _, w := range g.Workloads {
			wmap := workloadMap(w)
			switch p.Target {
			case TargetContainer:
				for _, c := range w.PodSpec.Containers {
					if p.matches(map[string]any{"workload": wmap, "container": containerMap(c)}) {
						out = append(out, p.finding(w, "container "+c.Name))
					}
				}
			default: // workload
				if p.matches(map[string]any{"workload": wmap}) {
					out = append(out, p.finding(w, ""))
				}
			}
		}
	}
	return out
}

func (p Policy) matches(vars map[string]any) bool {
	val, _, err := p.program.Eval(vars)
	if err != nil {
		return false // eval error (e.g. missing field on this resource) → no match
	}
	b, ok := val.Value().(bool)
	return ok && b
}

func (p Policy) finding(w model.Workload, detail string) api.Finding {
	evVal := "custom policy matched"
	if detail != "" {
		evVal = detail
	}
	refs := make([]api.ControlRef, 0, len(p.Refs))
	for _, r := range p.Refs {
		refs = append(refs, api.ControlRef{Framework: r.Framework, ID: r.ID, Title: r.Title})
	}
	return api.Finding{
		ID:       p.ID,
		Title:    p.Title,
		Severity: validSeverity[p.Severity],
		Category: p.Category,
		Resource: api.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
		Evidence: []api.Evidence{{Path: "custom-policy/" + p.ID, Value: evVal}},
		Remediation: api.Remediation{Summary: orDefault(p.Remediation,
			"Review this custom policy violation and remediate per your org's guidance.")},
		Refs: refs,
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// --- CEL variable projections ---------------------------------------------

func workloadMap(w model.Workload) map[string]any {
	cs := make([]any, 0, len(w.PodSpec.Containers))
	for _, c := range w.PodSpec.Containers {
		cs = append(cs, containerMap(c))
	}
	return map[string]any{
		"kind":                         w.Kind,
		"name":                         w.Name,
		"namespace":                    w.Namespace,
		"serviceAccountName":           w.ServiceAccountName,
		"hostNetwork":                  w.PodSpec.HostNetwork,
		"hostPID":                      w.PodSpec.HostPID,
		"hostIPC":                      w.PodSpec.HostIPC,
		"automountServiceAccountToken": derefBool(w.PodSpec.AutomountSAToken, true),
		"labels":                       toAnyMap(w.PodLabels),
		"containers":                   cs,
	}
}

func containerMap(c model.ContainerView) map[string]any {
	return map[string]any{
		"name":                     c.Name,
		"image":                    c.Image,
		"role":                     c.Role,
		"privileged":               c.Privileged,
		"runAsUser":                derefInt(c.RunAsUser, -1),
		"runAsNonRoot":             derefBool(c.RunAsNonRoot, false),
		"readOnlyRootFilesystem":   derefBool(c.ReadOnlyRootFS, false),
		"allowPrivilegeEscalation": derefBool(c.AllowPrivEsc, true), // k8s default is true
		"capsAdd":                  toAnySlice(c.CapsAdd),
		"capsDrop":                 toAnySlice(c.CapsDrop),
		"seccompProfile":           c.SeccompProfile,
		"envSecretKeys":            toAnySlice(c.EnvSecretKeys),
		"hasLimits":                c.Limits.HasLimits(),
	}
}

func derefBool(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

func derefInt(i *int64, def int64) int64 {
	if i == nil {
		return def
	}
	return *i
}

func toAnySlice(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
