package harden

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/internal/checks"
	"github.com/kubeguard/kubeguard/internal/graph"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"sigs.k8s.io/yaml"
)

func TestBundleYieldsZeroFindings(t *testing.T) {
	dir := t.TempDir()
	if _, err := Write(dir, Options{}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	resources, err := offline.Load(dir)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	g := graph.Build(resources)
	prof, _ := checks.ProfileByName("zeal-default")
	findings := checks.Scan(g, prof)
	if len(findings) != 0 {
		ids := make([]string, len(findings))
		for i, f := range findings {
			ids[i] = f.ID + "@" + f.Resource.Name
		}
		t.Fatalf("hardened bundle should yield 0 findings, got %d: %v", len(findings), ids)
	}
}

func TestBundleFilesAreValidYAML(t *testing.T) {
	files, err := Generate(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 10 {
		t.Fatalf("got %d files, want 10", len(files))
	}
	sawChecklist := false
	for _, f := range files {
		if strings.HasSuffix(f.Name, ".md") {
			sawChecklist = true
			continue
		}
		// Each YAML document in the file must decode.
		for i, doc := range strings.Split(f.Content, "\n---\n") {
			var m map[string]any
			if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
				t.Errorf("%s[doc %d]: invalid YAML: %v", f.Name, i, err)
				continue
			}
			if m["apiVersion"] == nil || m["kind"] == nil {
				t.Errorf("%s[doc %d]: missing apiVersion/kind", f.Name, i)
			}
		}
	}
	if !sawChecklist {
		t.Error("bundle missing CHECKLIST.md")
	}
}

func TestWriteCreatesFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "bundle")
	written, err := Write(dir, Options{Namespace: "payments", App: "checkout"})
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 10 {
		t.Fatalf("wrote %d files, want 10", len(written))
	}
	data, err := os.ReadFile(filepath.Join(dir, "30-deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "namespace: payments") || !strings.Contains(string(data), "name: checkout") {
		t.Error("options not applied to deployment")
	}
}

func TestPerFindingSnippetInJSON(t *testing.T) {
	rs, err := offline.Load("../../test/fixtures/vulnerable.yaml")
	if err != nil {
		t.Fatal(err)
	}
	prof, _ := checks.ProfileByName("zeal-default")
	findings := checks.Scan(graph.Build(rs), prof)

	withSnippet := 0
	for _, f := range findings {
		if f.Remediation.Snippet != "" {
			withSnippet++
		}
	}
	if withSnippet == 0 {
		t.Fatal("no findings carry a remediation snippet")
	}

	b, _ := json.Marshal(findings)
	if !strings.Contains(string(b), `"snippet"`) {
		t.Error("JSON output missing remediation snippet field")
	}
	if !strings.Contains(string(b), "privileged: false") {
		t.Error("expected KG-001 fix snippet in JSON")
	}
}
