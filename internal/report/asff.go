package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// AWS Security Hub Finding Format (ASFF) reporter.
//
// This writes findings as an ASFF v2018-10-08 document — the shape AWS Security
// Hub ingests via BatchImportFindings. It is the offline, deterministic *format*
// half of the Security Hub integration; the network publisher that actually
// calls BatchImportFindings lives behind an explicit opt-in (it is not part of
// the offline-first core, per ARCHITECTURE.md §3). Writing ASFF to a file or
// stdout performs no network I/O.
//
// Determinism: findings are already sorted by the engine; the only timestamp is
// rep.GeneratedAt, reused for ASFF's required CreatedAt/UpdatedAt so output is
// byte-stable given a fixed report (ARCHITECTURE.md §3.4).
const asffSchemaVersion = "2018-10-08"

// ASFF field length caps (AWS Security Hub limits). We truncate rather than let
// BatchImportFindings reject the batch.
const (
	asffTitleMax        = 256
	asffDescriptionMax  = 1024
	asffMaxRequirements = 32
)

// ASFFOptions is the AWS identity Security Hub requires on every finding. These
// are configuration, not detection data: defaults are placeholders meant to be
// overridden by env (for offline file output) or by the publisher.
type ASFFOptions struct {
	Region     string
	AccountID  string
	ProductArn string
}

// asffOptionsFromEnv resolves ASFF identity from the standard AWS env vars,
// falling back to clearly-fake placeholders so offline output is still valid
// ASFF. The publisher overrides these with the live account/region/product ARN.
func asffOptionsFromEnv() ASFFOptions {
	region := asffFirstNonEmpty(
		os.Getenv("KUBEGUARD_AWS_REGION"),
		os.Getenv("AWS_REGION"),
		os.Getenv("AWS_DEFAULT_REGION"),
		"us-east-1",
	)
	account := asffFirstNonEmpty(
		os.Getenv("KUBEGUARD_AWS_ACCOUNT_ID"),
		os.Getenv("AWS_ACCOUNT_ID"),
		"000000000000",
	)
	product := os.Getenv("KUBEGUARD_SECURITYHUB_PRODUCT_ARN")
	if product == "" {
		// The account's built-in "default" product ARN, used by
		// BatchImportFindings for self-managed (non-Marketplace) integrations.
		product = fmt.Sprintf("arn:aws:securityhub:%s:%s:product/%s/default", region, account, account)
	}
	return ASFFOptions{Region: region, AccountID: account, ProductArn: product}
}

// --- ASFF wire types (hand-rolled to keep the core SDK-free) -----------------

type asffDocument struct {
	Findings []asffFinding `json:"Findings"`
}

type asffFinding struct {
	SchemaVersion string            `json:"SchemaVersion"`
	ID            string            `json:"Id"`
	ProductArn    string            `json:"ProductArn"`
	GeneratorID   string            `json:"GeneratorId"`
	AwsAccountID  string            `json:"AwsAccountId"`
	Region        string            `json:"Region,omitempty"`
	Types         []string          `json:"Types"`
	CreatedAt     string            `json:"CreatedAt"`
	UpdatedAt     string            `json:"UpdatedAt"`
	Severity      asffSeverity      `json:"Severity"`
	Title         string            `json:"Title"`
	Description   string            `json:"Description"`
	Remediation   asffRemediation   `json:"Remediation"`
	ProductFields map[string]string `json:"ProductFields,omitempty"`
	Resources     []asffResource    `json:"Resources"`
	Compliance    *asffCompliance   `json:"Compliance,omitempty"`
	RecordState   string            `json:"RecordState"`
	Workflow      asffWorkflow      `json:"Workflow"`
}

type asffSeverity struct {
	Label      string `json:"Label"`
	Normalized int    `json:"Normalized"`
}

type asffRemediation struct {
	Recommendation asffRecommendation `json:"Recommendation"`
}

type asffRecommendation struct {
	Text string `json:"Text"`
}

type asffResource struct {
	Type    string           `json:"Type"`
	ID      string           `json:"Id"`
	Region  string           `json:"Region,omitempty"`
	Details *asffResourceDet `json:"Details,omitempty"`
}

type asffResourceDet struct {
	Other map[string]string `json:"Other"`
}

type asffCompliance struct {
	Status              string   `json:"Status"`
	RelatedRequirements []string `json:"RelatedRequirements,omitempty"`
}

type asffWorkflow struct {
	Status string `json:"Status"`
}

// --- public entry points -----------------------------------------------------

// ASFF writes the report as an ASFF document, resolving AWS identity from env.
func ASFF(w io.Writer, r api.Report) error {
	return ASFFWithOptions(w, r, asffOptionsFromEnv())
}

// ASFFWithOptions writes ASFF with explicit AWS identity. The publisher calls
// this with the live account/region/product ARN; tests call it with fixed
// options for byte-stable golden output.
func ASFFWithOptions(w io.Writer, r api.Report, opts ASFFOptions) error {
	doc := buildASFF(r, opts)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode asff: %w", err)
	}
	return nil
}

// BuildASFF exposes the pure report→ASFF mapping so the Security Hub publisher
// can reuse it without re-serializing JSON.
func BuildASFF(r api.Report, opts ASFFOptions) []asffFinding {
	return buildASFF(r, opts).Findings
}

func buildASFF(r api.Report, opts ASFFOptions) asffDocument {
	ts := r.GeneratedAt // the single document timestamp; reused for Created/Updated
	out := asffDocument{Findings: make([]asffFinding, 0, len(r.Findings))}

	for i, f := range r.Findings {
		fqn := resourceFQN(f.Resource)
		af := asffFinding{
			SchemaVersion: asffSchemaVersion,
			// Deterministic, unique id: profile + resource + check + index. The
			// index guards against the same check firing twice on one resource.
			ID:           fmt.Sprintf("kubeguard/%s/%s/%s/%d", asffSlug(r.Profile), fqn, f.ID, i),
			ProductArn:   opts.ProductArn,
			GeneratorID:  "kubeguard/" + f.ID,
			AwsAccountID: opts.AccountID,
			Region:       opts.Region,
			Types:        asffTypes(f),
			CreatedAt:    ts,
			UpdatedAt:    ts,
			Severity:     asffSeverityFor(f.Severity),
			Title:        asffTruncate(fmt.Sprintf("%s: %s", f.ID, f.Title), asffTitleMax),
			Description:  asffTruncate(asffDescription(f, fqn), asffDescriptionMax),
			Remediation: asffRemediation{
				Recommendation: asffRecommendation{Text: asffRemediationText(f)},
			},
			ProductFields: asffProductFields(f, r.Profile),
			Resources: []asffResource{{
				Type:    "Other",
				ID:      fqn,
				Region:  opts.Region,
				Details: &asffResourceDet{Other: asffResourceDetails(f)},
			}},
			Compliance:  asffComplianceFor(f),
			RecordState: "ACTIVE",
			Workflow:    asffWorkflow{Status: "NEW"},
		}
		out.Findings = append(out.Findings, af)
	}
	return out
}

// --- mapping helpers ----------------------------------------------------------

func asffSeverityFor(s api.Severity) asffSeverity {
	switch s {
	case api.SeverityCritical:
		return asffSeverity{Label: "CRITICAL", Normalized: 90}
	case api.SeverityHigh:
		return asffSeverity{Label: "HIGH", Normalized: 70}
	case api.SeverityMedium:
		return asffSeverity{Label: "MEDIUM", Normalized: 40}
	case api.SeverityLow:
		return asffSeverity{Label: "LOW", Normalized: 10}
	default:
		return asffSeverity{Label: "INFORMATIONAL", Normalized: 0}
	}
}

// asffTypes maps a finding to the ASFF Types taxonomy: a configuration-check
// namespace plus any MITRE ATT&CK techniques as TTP types.
func asffTypes(f api.Finding) []string {
	types := []string{"Software and Configuration Checks/AWS Security Best Practices"}
	for _, t := range asffTechniques(f) {
		types = append(types, "TTPs/"+t)
	}
	return types
}

// asffTechniques pulls ATT&CK technique ids from the finding's refs (framework
// containing "ATT&CK" or ids shaped like T1234[.001]).
func asffTechniques(f api.Finding) []string {
	var out []string
	seen := map[string]bool{}
	for _, ref := range f.Refs {
		isAttack := strings.Contains(strings.ToUpper(ref.Framework), "ATT&CK") ||
			strings.Contains(strings.ToUpper(ref.Framework), "ATTACK")
		looksLikeTID := len(ref.ID) >= 4 && (ref.ID[0] == 'T' || ref.ID[0] == 't')
		if (isAttack || looksLikeTID) && !seen[ref.ID] {
			seen[ref.ID] = true
			out = append(out, ref.ID)
		}
	}
	return out
}

func asffDescription(f api.Finding, fqn string) string {
	var b strings.Builder
	if f.Remediation.Summary != "" {
		b.WriteString(f.Remediation.Summary)
	} else {
		b.WriteString(f.Title)
	}
	b.WriteString(" Resource: ")
	b.WriteString(fqn)
	b.WriteString(".")
	if len(f.Evidence) > 0 {
		b.WriteString(" Evidence: ")
		parts := make([]string, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			if e.Value != "" {
				parts = append(parts, e.Path+"="+e.Value)
			} else {
				parts = append(parts, e.Path)
			}
		}
		b.WriteString(strings.Join(parts, "; "))
		b.WriteString(".")
	}
	return b.String()
}

func asffRemediationText(f api.Finding) string {
	if f.Remediation.Summary != "" {
		return asffTruncate(f.Remediation.Summary, asffDescriptionMax)
	}
	return "Review and remediate per the KubeGuard finding details."
}

func asffProductFields(f api.Finding, profile string) map[string]string {
	pf := map[string]string{
		"kubeguard/checkId":  f.ID,
		"kubeguard/category": f.Category,
		"kubeguard/profile":  profile,
		"kubeguard/severity": string(f.Severity),
	}
	if len(f.Grants) > 0 {
		grants := make([]string, len(f.Grants))
		for i, g := range f.Grants {
			grants[i] = string(g)
		}
		pf["kubeguard/grants"] = strings.Join(grants, ",")
	}
	if reqs := asffRequirements(f); len(reqs) > 0 {
		pf["kubeguard/refs"] = strings.Join(reqs, "; ")
	}
	return pf
}

func asffResourceDetails(f api.Finding) map[string]string {
	d := map[string]string{
		"Kind": f.Resource.Kind,
		"Name": f.Resource.Name,
	}
	if f.Resource.Namespace != "" {
		d["Namespace"] = f.Resource.Namespace
	}
	if f.Category != "" {
		d["Category"] = f.Category
	}
	return d
}

func asffComplianceFor(f api.Finding) *asffCompliance {
	// Every emitted finding represents a control gap, so Compliance.Status is
	// FAILED — this is what surfaces KubeGuard findings in Security Hub's
	// compliance/standards views.
	c := &asffCompliance{Status: "FAILED"}
	if reqs := asffRequirements(f); len(reqs) > 0 {
		c.RelatedRequirements = reqs
	}
	return c
}

// asffRequirements renders the finding's control refs as "Framework ID Title"
// strings, deduped and capped at the ASFF limit.
func asffRequirements(f api.Finding) []string {
	var out []string
	seen := map[string]bool{}
	for _, ref := range f.Refs {
		s := strings.TrimSpace(ref.Framework + " " + ref.ID)
		if ref.Title != "" {
			s += " " + ref.Title
		}
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= asffMaxRequirements {
			break
		}
	}
	sort.Strings(out)
	return out
}

// --- small utilities ----------------------------------------------------------

func asffFirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func asffTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// asffSlug makes a token safe for an ASFF Id segment (no spaces/slashes).
func asffSlug(s string) string {
	if s == "" {
		return "default"
	}
	r := strings.NewReplacer(" ", "-", "/", "-")
	return r.Replace(s)
}
