package dashboard

import (
	"context"
	"log/slog"

	"github.com/robfig/cron/v3"
)

// ScheduleSpec schedules recurring scans for one cluster in a tenant.
type ScheduleSpec struct {
	Tenant    string
	ClusterID string
	Cron      string // standard cron expression, e.g. "0 * * * *"
}

// Scheduler runs scans on a cron so the dashboard's compliance/trend/attack-path
// views are continuously populated without user action. Each scheduled run goes
// through API.RunScan, so it writes a history snapshot and streams SSE events
// exactly like an on-demand scan.
type Scheduler struct {
	api   *API
	cron  *cron.Cron
	specs []ScheduleSpec
}

// NewScheduler builds a scheduler over the given specs.
func NewScheduler(a *API, specs []ScheduleSpec) *Scheduler {
	return &Scheduler{api: a, cron: cron.New(), specs: specs}
}

// RunOnce executes a single scan cycle for a spec immediately (used to seed
// initial data and in tests). The actor is recorded as "scheduler".
func (s *Scheduler) RunOnce(ctx context.Context, spec ScheduleSpec) Scan {
	return s.api.RunScan(ctx, spec.Tenant, spec.ClusterID, "scheduler")
}

// Start registers every spec on the cron and begins ticking. Returns an error
// if any cron expression is invalid (fail-closed: nothing starts).
func (s *Scheduler) Start() error {
	for _, spec := range s.specs {
		spec := spec
		if _, err := s.cron.AddFunc(spec.Cron, func() {
			s.api.RunScan(context.Background(), spec.Tenant, spec.ClusterID, "scheduler")
			slog.Info("scheduled scan", "tenant", spec.Tenant, "cluster", spec.ClusterID)
		}); err != nil {
			return err
		}
	}
	s.cron.Start()
	return nil
}

// Stop halts the cron.
func (s *Scheduler) Stop() {
	if s.cron != nil {
		s.cron.Stop()
	}
}
