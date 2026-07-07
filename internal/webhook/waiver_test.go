package webhook

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubeguard/kubeguard/internal/waiver"
)

func hostPathVolume() corev1.Volume {
	return corev1.Volume{
		Name:         "sock",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}},
	}
}

func waiverValidator(t *testing.T, y string) *Validator {
	t.Helper()
	set, err := waiver.Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse waivers: %v", err)
	}
	return NewValidator(admission.NewDecoder(scheme.Scheme), Config{
		Waivers: set,
		Now:     func() time.Time { return time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC) },
	})
}

func TestWaivedPrivilegedPodAdmittedWithWarning(t *testing.T) {
	// A valid waiver for KG-001 admits the otherwise-denied privileged pod, but
	// surfaces the suppression as a warning (never silent).
	v := waiverValidator(t, `
waivers:
  - id: KG-001
    justification: legacy workload, migration tracked in JIRA-42
    expires: "2026-12-31T00:00:00Z"
`)
	resp := v.Handle(context.Background(), request(t, privilegedPod()))
	if !resp.Allowed {
		t.Fatalf("waived privileged pod should be admitted, got denied: %s", resp.Result.Message)
	}
	if len(resp.Warnings) == 0 || !strings.Contains(strings.Join(resp.Warnings, " "), "KG-001") {
		t.Fatalf("expected a warning citing the waived KG-001, got %v", resp.Warnings)
	}
}

func TestExpiredWaiverStillDenies(t *testing.T) {
	v := waiverValidator(t, `
waivers:
  - id: KG-001
    justification: temporary
    expires: "2026-06-01T00:00:00Z"
`)
	resp := v.Handle(context.Background(), request(t, privilegedPod()))
	if resp.Allowed {
		t.Fatal("an expired waiver must not suppress the denial")
	}
	if !strings.Contains(resp.Result.Message, "KG-001") {
		t.Fatalf("denial should still cite KG-001, got %q", resp.Result.Message)
	}
}

func TestPartialWaiverStillDeniesUnwaived(t *testing.T) {
	// Pod violates KG-001 (privileged) and KG-002 (hostPath). A waiver for only
	// KG-001 must still deny on KG-002.
	p := privilegedPod()
	p.Spec.Volumes = append(p.Spec.Volumes, hostPathVolume())
	v := waiverValidator(t, `
waivers:
  - id: KG-001
    justification: waived
    expires: "2026-12-31T00:00:00Z"
`)
	resp := v.Handle(context.Background(), request(t, p))
	if resp.Allowed {
		t.Fatal("pod with an unwaived KG-002 violation should still be denied")
	}
	if !strings.Contains(resp.Result.Message, "KG-002") || strings.Contains(resp.Result.Message, "KG-001") {
		t.Fatalf("denial should cite only the unwaived KG-002, got %q", resp.Result.Message)
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("the waived KG-001 should still be reported as a warning")
	}
}
