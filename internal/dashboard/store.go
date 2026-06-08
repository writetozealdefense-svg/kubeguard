// Package dashboard is the backend-for-frontend (BFF) that the KubeGuard web
// dashboard consumes: multi-tenant, multi-cluster posture (findings, attack
// paths, compliance) tracked over time, served over a chi router described by
// docs/openapi.yaml.
//
// Cluster access stays read-only — the BFF never mutates a scanned cluster; it
// only runs the existing scan/attack-path/compliance engines via a Scanner and
// serves the results. Compliance figures always carry their assessed
// denominator (honest metrics). Secret values are never stored or returned —
// evidence carries key names only, as produced by the engine.
package dashboard

import (
	"context"

	"github.com/kubeguard/kubeguard/pkg/api"
)

// Cluster is a scannable cluster registered in a tenant.
type Cluster struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Environment     string  `json:"environment,omitempty"`
	LastScanAt      string  `json:"lastScanAt,omitempty"`
	TotalFindings   int     `json:"totalFindings"`
	OverallPassRate float64 `json:"overallPassRate"`
}

// ScanStatus is the lifecycle of a scan job.
type ScanStatus string

// Scan lifecycle states.
const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanSucceeded ScanStatus = "succeeded"
	ScanFailed    ScanStatus = "failed"
)

// Scan is one scan job/run against a cluster.
type Scan struct {
	ID            string     `json:"id"`
	ClusterID     string     `json:"clusterId"`
	Status        ScanStatus `json:"status"`
	StartedAt     string     `json:"startedAt,omitempty"`
	FinishedAt    string     `json:"finishedAt,omitempty"`
	TotalFindings int        `json:"totalFindings"`
}

// HistorySnapshot is a point-in-time posture summary for drift tracking.
type HistorySnapshot struct {
	ScanID           string         `json:"scanId"`
	At               string         `json:"at"`
	TotalFindings    int            `json:"totalFindings"`
	ControlsAssessed int            `json:"controlsAssessed"`
	ControlsBreached int            `json:"controlsBreached"`
	OverallPassRate  float64        `json:"overallPassRate"`
	BySeverity       map[string]int `json:"bySeverity"`
}

// Scanner runs the engine for one cluster and returns its report. It must be
// read-only against the cluster. The BFF owns lifecycle/persistence; the
// Scanner only produces a report (or an error).
type Scanner func(ctx context.Context, clusterID string) (api.Report, error)

// Store is the BFF persistence boundary. The in-memory implementation backs D2;
// Squad P1 swaps in a Postgres-backed implementation behind this same interface.
// Every method is tenant-scoped — callers pass the authenticated tenant and the
// store never returns another tenant's data.
type Store interface {
	// RegisterCluster adds a cluster to a tenant (idempotent).
	RegisterCluster(tenant string, c Cluster)
	ListClusters(tenant string) []Cluster
	GetCluster(tenant, clusterID string) (Cluster, bool)
	ListScans(tenant, clusterID string, limit, offset int) ([]Scan, int)
	// RecordScan persists a finished scan's report + derived summaries for a
	// cluster and returns the Scan record.
	RecordScan(tenant, clusterID, scanID string, rep api.Report, at string) Scan
	// Report returns the latest report for a cluster, or merged across all
	// clusters in the tenant when clusterID is "".
	Report(tenant, clusterID string) (api.Report, bool)
	History(tenant, clusterID string) []HistorySnapshot
}
