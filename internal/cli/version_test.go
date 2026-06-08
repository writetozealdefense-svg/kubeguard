package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	got := stdout.String()
	for _, want := range []string{"kubeguard", "commit:", "built:", "go:"} {
		if !strings.Contains(got, want) {
			t.Errorf("version output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestInvalidLogLevel(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--log-level", "bogus", "version"})

	if err := root.Execute(); err == nil {
		t.Fatal("expected error for invalid --log-level, got nil")
	}
}
