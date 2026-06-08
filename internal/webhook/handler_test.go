package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func bp(b bool) *bool    { return &b }
func i64(i int64) *int64 { return &i }

func podTypeMeta() metav1.TypeMeta { return metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"} }

func hardenedPod() *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   podTypeMeta(),
		ObjectMeta: metav1.ObjectMeta{Name: "good", Namespace: "prod"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "c",
				Image: "app@sha256:" + strings.Repeat("a", 64),
				SecurityContext: &corev1.SecurityContext{
					Privileged:               bp(false),
					RunAsNonRoot:             bp(true),
					RunAsUser:                i64(1000),
					AllowPrivilegeEscalation: bp(false),
					ReadOnlyRootFilesystem:   bp(true),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
			}},
		},
	}
}

func privilegedPod() *corev1.Pod {
	p := hardenedPod()
	p.Name = "bad"
	p.Spec.Containers[0].SecurityContext.Privileged = bp(true)
	return p
}

func request(t *testing.T, pod *corev1.Pod) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Object: runtime.RawExtension{Raw: raw},
	}}
}

func newValidator(t *testing.T, failOpen bool) *Validator {
	t.Helper()
	return NewValidator(admission.NewDecoder(scheme.Scheme), Config{FailOpen: failOpen})
}

func TestAdmitsHardenedPod(t *testing.T) {
	resp := newValidator(t, false).Handle(context.Background(), request(t, hardenedPod()))
	if !resp.Allowed {
		t.Errorf("hardened pod should be admitted: %s", resp.Result.Message)
	}
}

func TestDeniesPrivilegedPod(t *testing.T) {
	resp := newValidator(t, false).Handle(context.Background(), request(t, privilegedPod()))
	if resp.Allowed {
		t.Fatal("privileged pod should be denied")
	}
	if !strings.Contains(resp.Result.Message, "KG-001") {
		t.Errorf("denial reason should cite KG-001, got %q", resp.Result.Message)
	}
}

func TestDeniesHostPathPod(t *testing.T) {
	p := hardenedPod()
	p.Spec.Volumes = []corev1.Volume{{
		Name:         "sock",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}},
	}}
	resp := newValidator(t, false).Handle(context.Background(), request(t, p))
	if resp.Allowed || !strings.Contains(resp.Result.Message, "KG-002") {
		t.Errorf("hostPath pod should be denied with KG-002, got allowed=%v msg=%q", resp.Allowed, resp.Result.Message)
	}
}

func TestFailClosedOnDecodeError(t *testing.T) {
	bad := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Object: runtime.RawExtension{Raw: []byte("not a pod")},
	}}
	if resp := newValidator(t, false).Handle(context.Background(), bad); resp.Allowed {
		t.Error("fail-closed should deny an undecodable object")
	}
	if resp := newValidator(t, true).Handle(context.Background(), bad); !resp.Allowed {
		t.Error("fail-open should admit an undecodable object")
	}
}
