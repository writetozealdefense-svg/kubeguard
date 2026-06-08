package webhook

import (
	"context"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Config configures the validating webhook.
type Config struct {
	// FailOpen admits pods when KubeGuard cannot evaluate them (decode/engine
	// error). Default (false) is fail-closed.
	FailOpen bool
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

	reasons := make([]string, len(violations))
	for i, f := range violations {
		reasons[i] = f.ID + " " + f.Title
	}
	return admission.Denied("kubeguard denied pod: " + strings.Join(reasons, "; "))
}
