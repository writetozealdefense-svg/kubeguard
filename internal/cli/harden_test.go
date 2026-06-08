package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHardenCommandWritesBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	out, err := runCLI(t, "harden", "-o", dir, "--namespace", "payments", "--app", "checkout")
	if err != nil {
		t.Fatalf("harden: %v", err)
	}
	if !strings.Contains(out, "Wrote 10 files") {
		t.Errorf("unexpected output: %s", out)
	}
	for _, name := range []string{"30-deployment.yaml", "10-networkpolicy-default-deny.yaml", "CHECKLIST.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}
