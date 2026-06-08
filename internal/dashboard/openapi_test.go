package dashboard

import (
	"path/filepath"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestOpenAPISpecValidates loads docs/openapi.yaml (the BFF contract that the
// frontend codegens its client from) and validates it. A malformed spec — or
// drift that breaks the document — fails the build here.
func TestOpenAPISpecValidates(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load openapi.yaml: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("openapi spec invalid: %v", err)
	}

	// Spot-check that the routes the BFF serves are described.
	for _, p := range []string{"/v1/clusters", "/v1/scans", "/v1/findings", "/v1/posture", "/v1/attack-paths", "/v1/history", "/v1/stream"} {
		if doc.Paths.Find(p) == nil {
			t.Errorf("openapi.yaml missing path %s", p)
		}
	}
}
