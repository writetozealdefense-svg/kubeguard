//go:build sarif_schema

// Package report SARIF schema conformance test (K8 / A3). Gated behind the
// `sarif_schema` build tag so the 112 KB official schema is only compiled in CI
// (`go test -tags sarif_schema ./internal/report/`), keeping the default
// `go test ./...` fast. It validates the emitted SARIF for the vulnerable and
// hardened fixtures against the official SARIF 2.1.0 JSON Schema.
package report

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/kubeguard/kubeguard/internal/analyzer"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed testdata/sarif-2.1.0.schema.json
var sarifSchema []byte

func TestSARIFConformsToOfficialSchema(t *testing.T) {
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(sarifSchema))
	if err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("sarif-2.1.0.json", schemaDoc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := c.Compile("sarif-2.1.0.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	for _, fx := range []string{"vulnerable.yaml", "hardened.yaml"} {
		t.Run(fx, func(t *testing.T) {
			resources, err := offline.Load("../../test/fixtures/" + fx)
			if err != nil {
				t.Fatalf("load %s: %v", fx, err)
			}
			rep, err := analyzer.Analyze(resources, "zeal-default", false)
			if err != nil {
				t.Fatalf("analyze %s: %v", fx, err)
			}
			rep.GeneratedAt = "2026-01-01T00:00:00Z"

			var buf bytes.Buffer
			if err := SARIF(&buf, rep); err != nil {
				t.Fatalf("emit sarif: %v", err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("parse emitted sarif: %v", err)
			}
			if err := schema.Validate(inst); err != nil {
				t.Fatalf("SARIF for %s does not conform to 2.1.0 schema:\n%v", fx, err)
			}
		})
	}
}
