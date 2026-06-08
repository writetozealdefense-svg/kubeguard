package harden

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// Options parameterizes the hardened baseline bundle.
type Options struct {
	Namespace      string
	App            string
	Image          string
	ServiceAccount string
}

// Default returns sensible, fully-hardened defaults. The default Image is
// digest-pinned so the emitted Deployment passes every check.
func Default() Options {
	return Options{
		Namespace:      "secure-app",
		App:            "app",
		Image:          "registry.example.com/app:1.0.0@sha256:" + strings.Repeat("a", 64),
		ServiceAccount: "app-sa",
	}
}

func (o Options) withDefaults() Options {
	d := Default()
	if o.Namespace == "" {
		o.Namespace = d.Namespace
	}
	if o.App == "" {
		o.App = d.App
	}
	if o.Image == "" {
		o.Image = d.Image
	}
	if o.ServiceAccount == "" {
		o.ServiceAccount = d.ServiceAccount
	}
	return o
}

// File is one emitted artifact.
type File struct {
	Name    string
	Content string
}

// Generate renders the baseline bundle (ARCHITECTURE.md §11) in a deterministic
// order.
func Generate(o Options) ([]File, error) {
	o = o.withDefaults()
	files := make([]File, 0, len(bundleTemplates))
	for _, bt := range bundleTemplates {
		tmpl, err := template.New(bt.name).Parse(bt.body)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", bt.name, err)
		}
		var sb strings.Builder
		if err := tmpl.Execute(&sb, o); err != nil {
			return nil, fmt.Errorf("render %s: %w", bt.name, err)
		}
		files = append(files, File{Name: bt.name, Content: sb.String()})
	}
	return files, nil
}

// Write generates and writes the bundle into dir (created if needed).
func Write(dir string, o Options) ([]string, error) {
	files, err := Generate(o)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create %q: %w", dir, err)
	}
	written := make([]string, 0, len(files))
	for _, f := range files {
		path := filepath.Join(dir, f.Name)
		if err := os.WriteFile(path, []byte(f.Content), 0o600); err != nil {
			return nil, fmt.Errorf("write %q: %w", path, err)
		}
		written = append(written, path)
	}
	return written, nil
}

type bundleTemplate struct {
	name string
	body string
}

var bundleTemplates = []bundleTemplate{
	{"00-namespace.yaml", nsTemplate},
	{"10-networkpolicy-default-deny.yaml", denyTemplate},
	{"11-networkpolicy-allow-dns.yaml", dnsTemplate},
	{"20-serviceaccount.yaml", saTemplate},
	{"21-rbac.yaml", rbacTemplate},
	{"30-deployment.yaml", deployTemplate},
	{"40-service.yaml", svcTemplate},
	{"50-kyverno-policies.yaml", kyvernoTemplate},
	{"51-gatekeeper.yaml", gatekeeperTemplate},
	{"CHECKLIST.md", checklistTemplate},
}
