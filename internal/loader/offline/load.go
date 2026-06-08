package offline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubeguard/kubeguard/internal/model"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

// Load ingests Kubernetes resources from a path. The path may be a directory
// (walked recursively for *.yaml/*.yml/*.json), a multi-document YAML file, a
// kind:List object, or a snapshot JSON (array or {"items":[...]}).
func Load(path string) ([]model.Resource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if info.IsDir() {
		return loadDir(path)
	}
	return loadFile(path)
}

func loadDir(dir string) ([]model.Resource, error) {
	var out []model.Resource
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !hasManifestExt(p) {
			return nil
		}
		rs, ferr := loadFile(p)
		if ferr != nil {
			return ferr
		}
		out = append(out, rs...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %q: %w", dir, err)
	}
	return out, nil
}

func hasManifestExt(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

func loadFile(path string) ([]model.Resource, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-provided input
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	rs, err := decodeDocuments(data, path)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// decodeDocuments parses one file's bytes into resources, handling multi-doc
// YAML, kind:List, snapshot {"items":[...]}, and a top-level JSON array.
func decodeDocuments(data []byte, src string) ([]model.Resource, error) {
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '[' {
		var items []map[string]any
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("%s: snapshot array: %w", src, err)
		}
		return resourcesFromMaps(items), nil
	}

	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []model.Resource
	for idx := 0; ; idx++ {
		var raw map[string]any
		err := dec.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("%s [doc %d]: decode: %w", src, idx, err)
		}
		if len(raw) == 0 {
			continue
		}
		out = append(out, expand(raw)...)
	}
	return out, nil
}

// expand turns a decoded document into one or more resources, unwrapping
// kind:List and bare {"items":[...]} snapshots.
func expand(raw map[string]any) []model.Resource {
	if isList(raw) {
		return resourcesFromMaps(toMaps(raw["items"]))
	}
	if r, ok := toResource(raw); ok {
		return []model.Resource{r}
	}
	return nil
}

func isList(raw map[string]any) bool {
	if k, _ := raw["kind"].(string); k == "List" {
		return true
	}
	// A bare {"items":[...]} object with no own kind is a snapshot list.
	if _, hasItems := raw["items"]; hasItems {
		if _, hasKind := raw["kind"]; !hasKind {
			return true
		}
	}
	return false
}

func resourcesFromMaps(items []map[string]any) []model.Resource {
	out := make([]model.Resource, 0, len(items))
	for _, m := range items {
		if r, ok := toResource(m); ok {
			out = append(out, r)
		}
	}
	return out
}

// toResource extracts the common envelope from a decoded document. Documents
// without a kind (e.g. nil docs) are skipped.
func toResource(raw map[string]any) (model.Resource, bool) {
	kind, _ := raw["kind"].(string)
	if kind == "" {
		return model.Resource{}, false
	}
	meta, _ := raw["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	ns, _ := meta["namespace"].(string)
	uid, _ := meta["uid"].(string)

	r := model.Resource{
		APIVersion:  stringOf(raw["apiVersion"]),
		Kind:        kind,
		Namespace:   ns,
		Name:        name,
		Labels:      toStringMap(meta["labels"]),
		Annotations: toStringMap(meta["annotations"]),
		Raw:         raw,
	}
	if uid != "" {
		r.UID = uid
	} else {
		r.UID = r.Ref()
	}
	return r, true
}

func toMaps(v any) []map[string]any {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func toStringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		out[k] = stringOf(val)
	}
	return out
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}
