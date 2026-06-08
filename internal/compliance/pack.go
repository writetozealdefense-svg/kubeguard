package compliance

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/kubeguard/kubeguard/frameworks"
	"sigs.k8s.io/yaml"
)

// Control is one framework control mapped to KubeGuard checks (ARCHITECTURE.md §9.1).
type Control struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	MapsTo     []string `json:"mapsTo"`
	Assessable bool     `json:"assessable"`
}

// Pack is a data-driven compliance framework. Adding a pack is a YAML drop-in;
// no code change is required.
type Pack struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Version    string    `json:"version"`
	Disclaimer string    `json:"disclaimer"`
	Controls   []Control `json:"controls"`
}

// ParsePack decodes and validates a single pack. Decoding is strict: unknown
// keys are rejected.
func ParsePack(data []byte) (Pack, error) {
	var p Pack
	if err := yaml.UnmarshalStrict(data, &p); err != nil {
		return Pack{}, fmt.Errorf("decode pack: %w", err)
	}
	if err := p.validate(); err != nil {
		return Pack{}, err
	}
	return p, nil
}

func (p Pack) validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("pack: missing id")
	}
	if strings.TrimSpace(p.Title) == "" {
		return fmt.Errorf("pack %q: missing title", p.ID)
	}
	if strings.TrimSpace(p.Disclaimer) == "" {
		return fmt.Errorf("pack %q: missing disclaimer (honest-metrics policy)", p.ID)
	}
	if len(p.Controls) == 0 {
		return fmt.Errorf("pack %q: no controls", p.ID)
	}
	for i, c := range p.Controls {
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("pack %q: control[%d] missing id", p.ID, i)
		}
		if c.Assessable && len(c.MapsTo) == 0 {
			return fmt.Errorf("pack %q: control %q is assessable but maps to no checks", p.ID, c.ID)
		}
	}
	return nil
}

// LoadFS loads and validates every *.yaml pack in a filesystem, sorted by name.
func LoadFS(fsys fs.FS) ([]Pack, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, fmt.Errorf("glob packs: %w", err)
	}
	sort.Strings(names)
	packs := make([]Pack, 0, len(names))
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		p, err := ParsePack(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		packs = append(packs, p)
	}
	return packs, nil
}

// LoadEmbedded loads the built-in packs shipped in the binary.
func LoadEmbedded() ([]Pack, error) {
	return LoadFS(frameworks.Packs)
}
