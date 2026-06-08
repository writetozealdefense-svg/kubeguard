package offline

import (
	"os"
	"path/filepath"
	"testing"
)

const fixturesDir = "../../../test/fixtures"

func TestLoadFixtures(t *testing.T) {
	cases := []struct {
		file  string
		count int
	}{
		{"vulnerable.yaml", 7},
		{"partially-hardened.yaml", 6},
		{"hardened.yaml", 8},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			rs, err := Load(filepath.Join(fixturesDir, tc.file))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(rs) != tc.count {
				t.Fatalf("resource count = %d, want %d", len(rs), tc.count)
			}
			for _, r := range rs {
				if r.Kind == "" || r.Name == "" {
					t.Errorf("resource missing kind/name: %+v", r)
				}
				if r.UID == "" {
					t.Errorf("resource %s missing synthesized UID", r.Ref())
				}
			}
		})
	}
}

func TestLoadDirAggregates(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.yaml"), "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: a\n")
	writeFile(t, filepath.Join(dir, "b.yml"), "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: b\n")
	writeFile(t, filepath.Join(dir, "ignore.txt"), "not a manifest")

	rs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load dir: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("count = %d, want 2", len(rs))
	}
}

func TestLoadKindList(t *testing.T) {
	doc := `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ServiceAccount
    metadata: {name: one, namespace: x}
  - apiVersion: v1
    kind: ServiceAccount
    metadata: {name: two, namespace: x}
`
	rs := loadString(t, "list.yaml", doc)
	if len(rs) != 2 {
		t.Fatalf("count = %d, want 2", len(rs))
	}
	if rs[0].Kind != "ServiceAccount" || rs[1].Name != "two" {
		t.Errorf("unexpected items: %+v", rs)
	}
}

func TestLoadSnapshotArray(t *testing.T) {
	doc := `[
	  {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"a"}},
	  {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"b"}}
	]`
	rs := loadString(t, "snap.json", doc)
	if len(rs) != 2 {
		t.Fatalf("count = %d, want 2", len(rs))
	}
}

func TestLoadSnapshotItemsObject(t *testing.T) {
	doc := `{"items":[
	  {"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"x"}}
	]}`
	rs := loadString(t, "items.json", doc)
	if len(rs) != 1 || rs[0].Kind != "Pod" {
		t.Fatalf("unexpected: %+v", rs)
	}
}

func TestLoadMultiDocSkipsEmpty(t *testing.T) {
	doc := "apiVersion: v1\nkind: Namespace\nmetadata: {name: a}\n---\n---\napiVersion: v1\nkind: Namespace\nmetadata: {name: b}\n"
	rs := loadString(t, "multi.yaml", doc)
	if len(rs) != 2 {
		t.Fatalf("count = %d, want 2 (empty doc skipped)", len(rs))
	}
}

func TestLoadMissingPath(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadString(t *testing.T, name, content string) []resourceAlias {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	writeFile(t, path, content)
	rs, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out := make([]resourceAlias, len(rs))
	for i, r := range rs {
		out[i] = resourceAlias{Kind: r.Kind, Name: r.Name}
	}
	return out
}

type resourceAlias struct {
	Kind string
	Name string
}
