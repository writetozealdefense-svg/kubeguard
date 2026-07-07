package webhook

import (
	"context"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/kubeguard/kubeguard/internal/waiver"
)

// Config configures the validating webhook.
type Config struct {
	// FailOpen admits pods when KubeGuard cannot evaluate them (decode/engine
	// error). Default (false) is fail-closed.
	FailOpen bool
	// Waivers, when set, makes admission waiver-aware (K7): a violation under a
	// valid, unexpired waiver does not deny the pod, but the waiver is reported in
	// the admission warnings so the suppression is never silent. Offline —
	// operator-supplied file, no network.
	Waivers *waiver.Set
	// Now is injectable for deterministic tests; defaults to time.Now.
	Now func() time.Time
}

// Validator is a controller-runtime validating admission handler that denies
// pods violating the active profile (ARCHITECTURE.md §14). It is read-only: it
// only admits or denies and never mutates the object.
type Validator struct {
	decoder admission.Decoder
	cfg     Config
}

// NewValidator builds a Validator.
func NewValidator(decoder admission.Decoder, cfg Config) *Validator {
	return &Validator{decoder: decoder, cfg: cfg}
}

// Handle decodes the pod and admits or denies it.
func (v *Validator) Handle(_ context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := v.decoder.Decode(req, pod); err != nil {
		if v.cfg.FailOpen {
			return admission.Allowed("kubeguard: could not decode pod (fail-open)")
		}
		return admission.Denied("kubeguard: could not decode pod (fail-closed): " + err.Error())
	}

	violations, err := Violations(pod)
	if err != nil {
		if v.cfg.FailOpen {
			return admission.Allowed("kubeguard: evaluation error (fail-open)")
		}
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if len(violations) == 0 {
		return admission.Allowed("kubeguard: no restricted-profile violations")
	}

	// Waiver-aware (K7): a violation under a valid, unexpired waiver does not
	// block admission, but it is surfaced as a warning so the suppression is
	// visible. Only unwaived violations deny.
	blocking, waived := violations, []waiver.WaivedFinding(nil)
	if !v.cfg.Waivers.Empty() {
		now := time.Now
		if v.cfg.Now != nil {
			now = v.cfg.Now
		}
		blocking, waived = v.cfg.Waivers.Partition(violations, now().UTC())
	}

	var warnings []string
	for _, wf := range waived {
		warnings = append(warnings, "kubeguard: waived "+wf.Finding.ID+" ("+wf.Entry.Justification+", until "+wf.Entry.Expires+")")
	}

	if len(blocking) == 0 {
		resp := admission.Allowed("kubeguard: all violations covered by active waivers")
		resp.Warnings = warnings
		return resp
	}

	reasons := make([]string, len(blocking))
	for i, f := range blocking {
		reasons[i] = f.ID + " " + f.Title
	}
	resp := admission.Denied("kubeguard denied pod: " + strings.Join(reasons, "; "))
	resp.Warnings = warnings
	return resp
}
