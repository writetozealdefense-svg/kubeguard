package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLIErr runs the CLI and returns stdout, stderr, and the error, so the
// waived-finding log (written to stderr) can be asserted.
func runCLIErr(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := NewRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errb.String(), err
}

func writeWaivers(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "waivers.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFailOnIsWaiverAware(t *testing.T) {
	// Waive every critical finding in the vulnerable fixture (KG-001/002/011);
	// --fail-on critical then passes, and each waived finding is logged.
	wf := writeWaivers(t, `
waivers:
  - id: KG-001
    justification: legacy workload
    expires: "2099-01-01T00:00:00Z"
  - id: KG-002
    justification: legacy hostPath
    expires: "2099-01-01T00:00:00Z"
  - id: KG-011
    justification: break-glass admin
    expires: "2099-01-01T00:00:00Z"
`)
	_, errOut, err := runCLIErr(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "-f", "json",
		"--fail-on", "critical", "--waivers", wf)
	if err != nil {
		t.Fatalf("waived criticals should pass --fail-on critical, got %v", err)
	}
	if !strings.Contains(errOut, "waived: KG-001") || !strings.Contains(errOut, "waived: KG-011") {
		t.Fatalf("expected waived findings logged to stderr, got:\n%s", errOut)
	}
}

func TestExpiredWaiverStillTripsGate(t *testing.T) {
	wf := writeWaivers(t, `
waivers:
  - id: KG-001
    justification: expired
    expires: "2000-01-01T00:00:00Z"
  - id: KG-002
    justification: expired
    expires: "2000-01-01T00:00:00Z"
  - id: KG-011
    justification: expired
    expires: "2000-01-01T00:00:00Z"
`)
	_, _, err := runCLIErr(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "-f", "json",
		"--fail-on", "critical", "--waivers", wf)
	var ce *codedError
	if !isCodedError(err, &ce) {
		t.Fatalf("expired waivers must not suppress the gate, got %v", err)
	}
}

func TestWaiverFileValidation(t *testing.T) {
	wf := writeWaivers(t, "waivers:\n  - id: KG-001\n") // missing justification + expires
	if _, _, err := runCLIErr(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "--waivers", wf); err == nil {
		t.Fatal("a malformed waiver file should be rejected")
	}
}

func TestGitOpsAnnotationsFormat(t *testing.T) {
	out, err := runCLI(t, "scan", "-i", fixturesDir+"/vulnerable.yaml", "-f", "gitops")
	if err != nil {
		t.Fatalf("gitops format: %v", err)
	}
	if !strings.Contains(out, "::error title=KG-001") {
		t.Errorf("expected a GitHub Actions error annotation for KG-001, got:\n%s", out)
	}
	if !strings.Contains(out, "::notice title=KubeGuard::") {
		t.Errorf("expected the summary notice annotation, got:\n%s", out)
	}
}
