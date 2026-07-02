package graph

import (
	"testing"

	"github.com/kubeguard/kubeguard/internal/model"
)

func TestCoverageCountsAssessableVsSkipped(t *testing.T) {
	g := Build([]model.Resource{
		{Kind: "Deployment", Name: "app"},         // assessable (workload)
		{Kind: "ServiceAccount", Name: "app-sa"},  // assessable (rbac)
		{Kind: "Service", Name: "app-svc"},        // assessable
		{Kind: "ConfigMap", Name: "app-config"},   // skipped
		{Kind: "ConfigMap", Name: "app-config-2"}, // skipped (same kind)
		{Kind: "Ingress", Name: "app-ing"},        // skipped
	})
	cov := g.Coverage()

	if cov.Discovered != 6 {
		t.Fatalf("discovered: want 6, got %d", cov.Discovered)
	}
	if cov.Assessable != 3 {
		t.Fatalf("assessable: want 3, got %d", cov.Assessable)
	}
	if cov.Skipped != 3 {
		t.Fatalf("skipped: want 3, got %d", cov.Skipped)
	}
	if cov.Rate != 0.5 {
		t.Fatalf("rate: want 0.5, got %v", cov.Rate)
	}
	if cov.SkippedByKind["ConfigMap"] != 2 || cov.SkippedByKind["Ingress"] != 1 {
		t.Fatalf("skippedByKind: %+v", cov.SkippedByKind)
	}
}

func TestCoverageEmptyInventory(t *testing.T) {
	cov := Build(nil).Coverage()
	if cov.Discovered != 0 || cov.Assessable != 0 || cov.Rate != 0 {
		t.Fatalf("empty coverage: %+v", cov)
	}
	if cov.SkippedByKind != nil {
		t.Fatalf("empty coverage should have nil SkippedByKind, got %+v", cov.SkippedByKind)
	}
}
