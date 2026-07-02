package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubeguard/kubeguard/internal/checks"
	"github.com/kubeguard/kubeguard/internal/compliance"
	"github.com/kubeguard/kubeguard/pkg/api"
)

func buildEvidence(t *testing.T, file string) []api.EvidencePack {
	t.Helper()
	rep := buildReport(t, file)
	packs, err := compliance.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	prof, _ := checks.ProfileByName("zeal-default")
	return compliance.BuildEvidence(rep, packs, prof.RunnableIDs())
}

func TestEvidenceGolden(t *testing.T) {
	for _, fx := range []string{"vulnerable", "hardened"} {
		t.Run(fx, func(t *testing.T) {
			evs := buildEvidence(t, fx+".yaml")
			b, _ := json.MarshalIndent(evs, "", "  ")
			b = append(b, '\n')
			goldenPath := filepath.Join(fixturesDir, "golden", fx+".evidence.json")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				_ = os.WriteFile(goldenPath, b, 0o600)
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden (UPDATE_GOLDEN=1 to create): %v", err)
			}
			if !bytes.Equal(lfr(b), lfr(want)) {
				t.Errorf("evidence differs from golden\n--- got ---\n%s", b)
			}
		})
	}
}

func TestEvidenceHonestDenominators(t *testing.T) {
	evs := buildEvidence(t, "vulnerable.yaml")
	var ce api.EvidencePack
	for _, ev := range evs {
		if ev.Passed+ev.Breached != ev.Assessed {
			t.Errorf("%s: passed+breached (%d+%d) != assessed (%d)", ev.Framework, ev.Passed, ev.Breached, ev.Assessed)
		}
		if len(ev.Controls) != ev.Assessed {
			t.Errorf("%s: %d controls listed but assessed=%d", ev.Framework, len(ev.Controls), ev.Assessed)
		}
		if ev.Disclaimer == "" {
			t.Errorf("%s: missing disclaimer", ev.Framework)
		}
		if ev.ID == "cyber-essentials" {
			ce = ev
		}
	}
	if ce.ID == "" {
		t.Fatal("cyber-essentials evidence missing")
	}
	// 2 of 5 controls are assessable:false and must be excluded from the denominator.
	if ce.Assessed != 3 {
		t.Errorf("cyber-essentials assessed = %d, want 3 (assessable:false excluded)", ce.Assessed)
	}
}

func TestEvidenceHardenedFullPass(t *testing.T) {
	evs := buildEvidence(t, "hardened.yaml")
	for _, ev := range evs {
		if ev.Breached != 0 || ev.Passed != ev.Assessed {
			t.Errorf("%s: hardened should pass all assessed, got breached=%d passed=%d assessed=%d",
				ev.Framework, ev.Breached, ev.Passed, ev.Assessed)
		}
		for _, c := range ev.Controls {
			if c.Breached || len(c.Findings) != 0 {
				t.Errorf("%s/%s: hardened control should carry no findings", ev.Framework, c.ControlID)
			}
		}
	}
}

func TestEvidenceHTMLDeterministicAndOffline(t *testing.T) {
	evs := buildEvidence(t, "vulnerable.yaml")
	var ev api.EvidencePack
	for _, e := range evs {
		if e.ID == "uk-gdpr-dpa-2018" {
			ev = e
		}
	}
	if ev.ID == "" {
		t.Fatal("uk-gdpr evidence missing")
	}
	var a, b bytes.Buffer
	if err := EvidenceHTML(&a, ev); err != nil {
		t.Fatal(err)
	}
	if err := EvidenceHTML(&b, ev); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("evidence HTML is not deterministic")
	}
	out := a.String()
	for _, want := range []string{
		"UK GDPR", "Art.5(1)(f)", "T1078", // framework, control, ATT&CK technique
		"breached of", "Indicative control mapping", "Evidence shows redacted", // honest-metrics
	} {
		if !strings.Contains(out, want) {
			t.Errorf("evidence HTML missing %q", want)
		}
	}
	if strings.Contains(out, "http://") || strings.Contains(out, "https://") {
		t.Error("evidence HTML must not reference external resources")
	}
}

func TestEvidenceJSONDeterministic(t *testing.T) {
	evs := buildEvidence(t, "vulnerable.yaml")
	var a, b bytes.Buffer
	_ = EvidenceJSON(&a, evs[0])
	_ = EvidenceJSON(&b, evs[0])
	if a.String() != b.String() {
		t.Error("evidence JSON is not deterministic")
	}
}

func lfr(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
