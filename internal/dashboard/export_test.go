package dashboard

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"strings"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

func TestExportCSV(t *testing.T) {
	body, err := ExportCSV(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("CSV not parseable: %v", err)
	}
	// header + 4 findings
	if len(rows) != 5 {
		t.Fatalf("want 5 rows (header+4), got %d", len(rows))
	}
	if rows[0][0] != "id" || rows[1][0] != "KG-001" {
		t.Fatalf("unexpected CSV content: %v / %v", rows[0], rows[1])
	}
}

func TestExportSARIFValidates(t *testing.T) {
	body, err := ExportSARIF(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	// Parse it back through the SARIF types — structural validation.
	rep, err := sarif.FromBytes(body)
	if err != nil {
		t.Fatalf("SARIF does not parse: %v", err)
	}
	if rep.Version != "2.1.0" {
		t.Fatalf("want SARIF 2.1.0, got %q", rep.Version)
	}
}

func TestExportPDFIsValidAndCarriesHonestMetrics(t *testing.T) {
	body, err := ExportPDF(sampleReport(), Brand{Title: "ZealDefense", Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte("%PDF")) {
		t.Fatal("output is not a PDF")
	}
	s := string(body)
	// Co-branding + honest metrics + chain present (compression disabled so the
	// text is legible in the stream).
	for _, want := range []string{
		"ZealDefense", "acme", "breached of", "assessed", "Attack paths",
		"Cluster-admin takeover", "Indicative control mapping only",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("PDF missing %q", want)
		}
	}
}

func TestReportEndpointFormatsAuthAndTenant(t *testing.T) {
	a, _ := testAPI(t)
	do(t, a.Handler(), "POST", "/v1/scans", "admin-tok", `{"clusterId":"prod-eu"}`)

	cases := map[string]string{
		"sarif": "application/sarif+json",
		"csv":   "text/csv",
		"pdf":   "application/pdf",
	}
	for format, ct := range cases {
		w := do(t, a.Handler(), "GET", "/v1/report?cluster=prod-eu&format="+format, "viewer-tok", "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", format, w.Code)
		}
		if got := w.Header().Get("Content-Type"); got != ct {
			t.Errorf("%s: content-type %q, want %q", format, got, ct)
		}
		if !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
			t.Errorf("%s: missing attachment disposition", format)
		}
		if w.Body.Len() == 0 {
			t.Errorf("%s: empty body", format)
		}
	}

	// Auth required.
	if w := do(t, a.Handler(), "GET", "/v1/report?cluster=prod-eu&format=csv", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("report without token: want 401, got %d", w.Code)
	}
	// Cross-tenant: other tenant has no prod-eu scan → 404.
	if w := do(t, a.Handler(), "GET", "/v1/report?cluster=prod-eu&format=csv", "other-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant report: want 404, got %d", w.Code)
	}
	// Unknown format → 400.
	if w := do(t, a.Handler(), "GET", "/v1/report?cluster=prod-eu&format=xml", "viewer-tok", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("bad format: want 400, got %d", w.Code)
	}
}
