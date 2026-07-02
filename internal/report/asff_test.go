package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/pkg/api"
)

func sampleASFFReport() api.Report {
	return api.Report{
		GeneratedAt: "2026-06-08T00:00:00Z",
		Source:      "test/fixtures/vulnerable.yaml",
		Profile:     "zeal-default",
		Findings: []api.Finding{
			{
				ID:       "KG-001",
				Title:    "Privileged container",
				Severity: api.SeverityCritical,
				Category: "host-access",
				Resource: api.ResourceRef{Kind: "Deployment", Namespace: "shop", Name: "checkout"},
				Evidence: []api.Evidence{
					{Path: "spec.containers[0].securityContext.privileged", Value: "true"},
					{Path: "env.AWS_SECRET_ACCESS_KEY", Value: "[redacted]"},
				},
				Remediation: api.Remediation{Summary: "Remove privileged:true from the container securityContext."},
				Grants:      []api.Capability{api.CapContainerEscape, api.CapNodeAccess},
				Refs: []api.ControlRef{
					{Framework: "CIS Kubernetes Benchmark", ID: "5.2.1", Title: "Minimize privileged containers"},
					{Framework: "MITRE ATT&CK", ID: "T1611", Title: "Escape to Host"},
				},
			},
		},
	}
}

func fixedOpts() ASFFOptions {
	return ASFFOptions{
		Region:     "ap-south-1",
		AccountID:  "123456789012",
		ProductArn: "arn:aws:securityhub:ap-south-1:123456789012:product/123456789012/default",
	}
}

func TestASFF_ShapeAndMapping(t *testing.T) {
	var buf bytes.Buffer
	if err := ASFFWithOptions(&buf, sampleASFFReport(), fixedOpts()); err != nil {
		t.Fatalf("ASFFWithOptions: %v", err)
	}

	var doc struct {
		Findings []map[string]any `json:"Findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(doc.Findings))
	}
	f := doc.Findings[0]

	if f["SchemaVersion"] != asffSchemaVersion {
		t.Errorf("SchemaVersion = %v, want %s", f["SchemaVersion"], asffSchemaVersion)
	}
	if f["ProductArn"] != fixedOpts().ProductArn {
		t.Errorf("ProductArn = %v", f["ProductArn"])
	}
	if f["AwsAccountId"] != "123456789012" {
		t.Errorf("AwsAccountId = %v", f["AwsAccountId"])
	}
	// ASFF requires the single document timestamp on both Created/Updated.
	if f["CreatedAt"] != "2026-06-08T00:00:00Z" || f["UpdatedAt"] != "2026-06-08T00:00:00Z" {
		t.Errorf("timestamps not pinned to GeneratedAt: created=%v updated=%v", f["CreatedAt"], f["UpdatedAt"])
	}

	sev, _ := f["Severity"].(map[string]any)
	if sev["Label"] != "CRITICAL" {
		t.Errorf("Severity.Label = %v, want CRITICAL", sev["Label"])
	}

	comp, _ := f["Compliance"].(map[string]any)
	if comp["Status"] != "FAILED" {
		t.Errorf("Compliance.Status = %v, want FAILED", comp["Status"])
	}

	// ATT&CK technique must surface as a TTP type.
	types, _ := f["Types"].([]any)
	var hasTTP bool
	for _, ty := range types {
		if s, _ := ty.(string); strings.Contains(s, "TTPs/T1611") {
			hasTTP = true
		}
	}
	if !hasTTP {
		t.Errorf("expected a TTPs/T1611 type, got %v", types)
	}

	// Id must be deterministic and embed the check id + resource.
	id, _ := f["Id"].(string)
	if !strings.Contains(id, "KG-001") || !strings.Contains(id, "checkout") {
		t.Errorf("Id missing expected segments: %s", id)
	}
}

func TestASFF_Deterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := ASFFWithOptions(&a, sampleASFFReport(), fixedOpts()); err != nil {
		t.Fatal(err)
	}
	if err := ASFFWithOptions(&b, sampleASFFReport(), fixedOpts()); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("ASFF output is not byte-stable across runs")
	}
}

func TestASFF_SeverityLabels(t *testing.T) {
	cases := map[api.Severity]string{
		api.SeverityCritical: "CRITICAL",
		api.SeverityHigh:     "HIGH",
		api.SeverityMedium:   "MEDIUM",
		api.SeverityLow:      "LOW",
		api.SeverityInfo:     "INFORMATIONAL",
	}
	for sev, want := range cases {
		if got := asffSeverityFor(sev).Label; got != want {
			t.Errorf("severity %s -> %s, want %s", sev, got, want)
		}
	}
}

func TestASFF_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	r := api.Report{GeneratedAt: "2026-06-08T00:00:00Z", Profile: "zeal-default"}
	if err := ASFFWithOptions(&buf, r, fixedOpts()); err != nil {
		t.Fatalf("empty report: %v", err)
	}
	var doc struct {
		Findings []json.RawMessage `json:"Findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Findings) != 0 {
		t.Errorf("want 0 findings, got %d", len(doc.Findings))
	}
}
