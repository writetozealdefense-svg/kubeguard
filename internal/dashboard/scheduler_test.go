package dashboard

import (
	"context"
	"testing"
	"time"
)

func TestScheduledScanWritesHistorySnapshotAndStreams(t *testing.T) {
	a, store := testAPI(t)

	// Subscribe to the tenant's event stream before the scheduled run.
	ch, unsubscribe := a.Broker().Subscribe("acme")
	defer unsubscribe()

	sched := NewScheduler(a, []ScheduleSpec{{Tenant: "acme", ClusterID: "prod-eu", Cron: "@every 1h"}})
	sched.RunOnce(context.Background(), ScheduleSpec{Tenant: "acme", ClusterID: "prod-eu"})

	// A history snapshot must have been written for drift tracking.
	hist := store.History("acme", "prod-eu")
	if len(hist) != 1 {
		t.Fatalf("scheduled scan should write 1 history snapshot, got %d", len(hist))
	}

	// And the run must have streamed a scan_completed event.
	if !drain(ch, "scan_completed", time.Second) {
		t.Fatal("scheduled scan did not emit scan_completed")
	}

	// The scheduled run is audited with the "scheduler" subject.
	entries := a.audit.List("acme")
	if len(entries) != 1 || entries[0].Subject != "scheduler" || entries[0].Result != "allowed" {
		t.Fatalf("scheduled scan audit wrong: %+v", entries)
	}
}

func TestSchedulerRejectsBadCron(t *testing.T) {
	a, _ := testAPI(t)
	sched := NewScheduler(a, []ScheduleSpec{{Tenant: "acme", ClusterID: "prod-eu", Cron: "not-a-cron"}})
	if err := sched.Start(); err == nil {
		t.Fatal("expected error for invalid cron expression")
	}
	sched.Stop()
}

func drain(ch <-chan Event, typ string, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ch:
			if ev.Type == typ {
				return true
			}
		case <-deadline:
			return false
		}
	}
}
