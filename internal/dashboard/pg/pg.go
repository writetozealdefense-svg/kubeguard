// Package pg is the Postgres-backed implementation of the dashboard Store and
// AuditLog (Squad P1). It uses pgx + a pgxpool connection pool, runs goose
// migrations from an embedded FS, and partitions every table by tenant (no
// cross-tenant foreign keys, NFR-3). The full scan report is stored as jsonb so
// the API reconstructs findings/paths/compliance without a wide schema.
package pg

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/kubeguard/kubeguard/internal/dashboard"
	"github.com/kubeguard/kubeguard/pkg/api"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store is the Postgres-backed dashboard.Store + dashboard.AuditLog.
type Store struct {
	pool *pgxpool.Pool
}

var (
	_ dashboard.Store    = (*Store)(nil)
	_ dashboard.AuditLog = (*Store)(nil)
)

// Open connects a pgxpool to the DSN, runs migrations, and returns the Store.
func Open(ctx context.Context, dsn string) (*Store, error) {
	if err := Migrate(dsn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pool: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Migrate applies all up migrations against the DSN (idempotent).
func Migrate(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrationFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, "migrations")
}

// MigrateDown rolls back all migrations (used by the up/down clean test).
func MigrateDown(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrationFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.DownTo(db, "migrations", 0)
}

var _ = stdlib.GetDefaultDriver // ensure the pgx stdlib driver is registered

// RegisterCluster inserts a cluster (and its tenant) idempotently.
func (s *Store) RegisterCluster(tenant string, c dashboard.Cluster) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `INSERT INTO tenants (id) VALUES ($1) ON CONFLICT DO NOTHING`, tenant)
	if err != nil {
		slog.Error("pg register tenant", "err", err)
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO clusters (tenant, id, name, environment) VALUES ($1,$2,$3,$4)
		 ON CONFLICT (tenant, id) DO NOTHING`,
		tenant, c.ID, c.Name, nullStr(c.Environment))
	if err != nil {
		slog.Error("pg register cluster", "err", err)
	}
}

// DeleteCluster removes a cluster and all of its scans/history from a tenant.
// Returns false if the cluster did not exist. Tenant-scoped.
func (s *Store) DeleteCluster(tenant, clusterID string) bool {
	ctx := context.Background()
	// Remove dependent rows first (no cross-table FKs, so order is explicit).
	for _, table := range []string{"history", "scans"} {
		if _, err := s.pool.Exec(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE tenant=$1 AND cluster_id=$2", table), tenant, clusterID); err != nil {
			slog.Error("pg delete cluster deps", "table", table, "err", err)
			return false
		}
	}
	ct, err := s.pool.Exec(ctx, `DELETE FROM clusters WHERE tenant=$1 AND id=$2`, tenant, clusterID)
	if err != nil {
		slog.Error("pg delete cluster", "err", err)
		return false
	}
	return ct.RowsAffected() > 0
}

// ListClusters returns a tenant's clusters in registration order.
func (s *Store) ListClusters(tenant string) []dashboard.Cluster {
	rows, err := s.pool.Query(context.Background(),
		`SELECT id, name, COALESCE(environment,''), COALESCE(last_scan_at,''), total_findings, overall_pass_rate
		 FROM clusters WHERE tenant=$1 ORDER BY registered_seq`, tenant)
	if err != nil {
		slog.Error("pg list clusters", "err", err)
		return []dashboard.Cluster{}
	}
	defer rows.Close()
	out := []dashboard.Cluster{}
	for rows.Next() {
		var c dashboard.Cluster
		if err := rows.Scan(&c.ID, &c.Name, &c.Environment, &c.LastScanAt, &c.TotalFindings, &c.OverallPassRate); err != nil {
			slog.Error("pg scan cluster", "err", err)
			continue
		}
		out = append(out, c)
	}
	return out
}

// GetCluster returns one cluster's metadata if present in the tenant.
func (s *Store) GetCluster(tenant, clusterID string) (dashboard.Cluster, bool) {
	var c dashboard.Cluster
	err := s.pool.QueryRow(context.Background(),
		`SELECT id, name, COALESCE(environment,''), COALESCE(last_scan_at,''), total_findings, overall_pass_rate
		 FROM clusters WHERE tenant=$1 AND id=$2`, tenant, clusterID).
		Scan(&c.ID, &c.Name, &c.Environment, &c.LastScanAt, &c.TotalFindings, &c.OverallPassRate)
	if err != nil {
		return dashboard.Cluster{}, false
	}
	return c, true
}

// ListScans returns a tenant's scans (newest first), paginated, plus the total.
func (s *Store) ListScans(tenant, clusterID string, limit, offset int) ([]dashboard.Scan, int) {
	ctx := context.Background()
	args := []any{tenant}
	where := "tenant=$1"
	if clusterID != "" {
		where += " AND cluster_id=$2"
		args = append(args, clusterID)
	}
	var total int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM scans WHERE "+where, args...).Scan(&total); err != nil {
		slog.Error("pg count scans", "err", err)
		return []dashboard.Scan{}, 0
	}
	q := fmt.Sprintf(`SELECT id, cluster_id, status, COALESCE(started_at,''), COALESCE(finished_at,''), total_findings
		FROM scans WHERE %s ORDER BY started_at DESC LIMIT %d OFFSET %d`, where, sanitizeLimit(limit), max0(offset))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		slog.Error("pg list scans", "err", err)
		return []dashboard.Scan{}, total
	}
	defer rows.Close()
	out := []dashboard.Scan{}
	for rows.Next() {
		var sc dashboard.Scan
		var status string
		if err := rows.Scan(&sc.ID, &sc.ClusterID, &status, &sc.StartedAt, &sc.FinishedAt, &sc.TotalFindings); err != nil {
			slog.Error("pg scan row", "err", err)
			continue
		}
		sc.Status = dashboard.ScanStatus(status)
		out = append(out, sc)
	}
	return out, total
}

// RecordScan persists a scan's report (jsonb), flips the latest pointer, and
// appends a history snapshot — all in one transaction.
func (s *Store) RecordScan(tenant, clusterID, scanID string, rep api.Report, at string) dashboard.Scan {
	ctx := context.Background()
	scan := dashboard.Scan{ID: scanID, ClusterID: clusterID, Status: dashboard.ScanSucceeded, StartedAt: at, FinishedAt: at, TotalFindings: len(rep.Findings)}
	reportJSON, err := json.Marshal(rep)
	if err != nil {
		slog.Error("pg marshal report", "err", err)
		return scan
	}
	assessed, breached := postureControls(rep)
	sevJSON, _ := json.Marshal(severityMap(rep))

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		slog.Error("pg begin", "err", err)
		return scan
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (tenant, id, name) VALUES ($1,$2,$2) ON CONFLICT (tenant, id) DO NOTHING`,
		tenant, clusterID); err != nil {
		slog.Error("pg upsert cluster", "err", err)
		return scan
	}
	if _, err := tx.Exec(ctx, `UPDATE scans SET is_latest=false WHERE tenant=$1 AND cluster_id=$2 AND is_latest`, tenant, clusterID); err != nil {
		slog.Error("pg clear latest", "err", err)
		return scan
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO scans (tenant, id, cluster_id, status, started_at, finished_at, total_findings, is_latest, report)
		 VALUES ($1,$2,$3,'succeeded',$4,$4,$5,true,$6)`,
		tenant, scanID, clusterID, at, len(rep.Findings), reportJSON); err != nil {
		slog.Error("pg insert scan", "err", err)
		return scan
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO history (tenant, cluster_id, scan_id, at, total_findings, controls_assessed, controls_breached, overall_pass_rate, by_severity)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		tenant, clusterID, scanID, at, len(rep.Findings), assessed, breached, rep.Posture.OverallPassRate, sevJSON); err != nil {
		slog.Error("pg insert history", "err", err)
		return scan
	}
	if _, err := tx.Exec(ctx,
		`UPDATE clusters SET last_scan_at=$3, total_findings=$4, overall_pass_rate=$5 WHERE tenant=$1 AND id=$2`,
		tenant, clusterID, at, len(rep.Findings), rep.Posture.OverallPassRate); err != nil {
		slog.Error("pg update cluster meta", "err", err)
		return scan
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Error("pg commit", "err", err)
	}
	return scan
}

// Report reconstructs the latest report for a cluster, or the merged fleet
// report across the tenant when clusterID is empty.
func (s *Store) Report(tenant, clusterID string) (api.Report, bool) {
	ctx := context.Background()
	if clusterID != "" {
		var raw []byte
		err := s.pool.QueryRow(ctx, `SELECT report FROM scans WHERE tenant=$1 AND cluster_id=$2 AND is_latest LIMIT 1`, tenant, clusterID).Scan(&raw)
		if err != nil {
			return api.Report{}, false
		}
		var rep api.Report
		if err := json.Unmarshal(raw, &rep); err != nil {
			return api.Report{}, false
		}
		return rep, true
	}
	rows, err := s.pool.Query(ctx, `SELECT report FROM scans WHERE tenant=$1 AND is_latest`, tenant)
	if err != nil {
		return api.Report{}, false
	}
	defer rows.Close()
	var reps []api.Report
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var rep api.Report
		if err := json.Unmarshal(raw, &rep); err == nil {
			reps = append(reps, rep)
		}
	}
	if len(reps) == 0 {
		return api.Report{}, false
	}
	return dashboard.MergeReports(reps), true
}

// History returns a tenant's posture snapshots (oldest first).
func (s *Store) History(tenant, clusterID string) []dashboard.HistorySnapshot {
	ctx := context.Background()
	args := []any{tenant}
	where := "tenant=$1"
	if clusterID != "" {
		where += " AND cluster_id=$2"
		args = append(args, clusterID)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT scan_id, at, total_findings, controls_assessed, controls_breached, overall_pass_rate, by_severity
		 FROM history WHERE `+where+` ORDER BY at`, args...)
	if err != nil {
		slog.Error("pg history", "err", err)
		return []dashboard.HistorySnapshot{}
	}
	defer rows.Close()
	out := []dashboard.HistorySnapshot{}
	for rows.Next() {
		var h dashboard.HistorySnapshot
		var sevRaw []byte
		if err := rows.Scan(&h.ScanID, &h.At, &h.TotalFindings, &h.ControlsAssessed, &h.ControlsBreached, &h.OverallPassRate, &sevRaw); err != nil {
			slog.Error("pg scan history", "err", err)
			continue
		}
		_ = json.Unmarshal(sevRaw, &h.BySeverity)
		out = append(out, h)
	}
	return out
}

// --- AuditLog -------------------------------------------------------------

// Write appends an audit entry (append-only).
func (s *Store) Write(e dashboard.AuditEntry) {
	_, err := s.pool.Exec(context.Background(),
		`INSERT INTO audit (tenant, at, subject, action, resource, result) VALUES ($1,$2,$3,$4,$5,$6)`,
		e.Tenant, e.At, e.Subject, e.Action, nullStr(e.Resource), e.Result)
	if err != nil {
		slog.Error("pg write audit", "err", err)
	}
}

// List returns a tenant's audit entries in write order.
func (s *Store) List(tenant string) []dashboard.AuditEntry {
	rows, err := s.pool.Query(context.Background(),
		`SELECT at, subject, COALESCE(resource,''), action, result FROM audit WHERE tenant=$1 ORDER BY id`, tenant)
	if err != nil {
		slog.Error("pg list audit", "err", err)
		return []dashboard.AuditEntry{}
	}
	defer rows.Close()
	out := []dashboard.AuditEntry{}
	for rows.Next() {
		var e dashboard.AuditEntry
		if err := rows.Scan(&e.At, &e.Subject, &e.Resource, &e.Action, &e.Result); err != nil {
			continue
		}
		e.Tenant = tenant
		out = append(out, e)
	}
	return out
}

// --- retention / DPDP -----------------------------------------------------

// Retention prunes scans (non-latest) and history snapshots older than the
// RFC3339 cutoff. The latest scan per cluster is always kept so the lenses keep
// rendering. Returns the number of scans + history rows removed.
func (s *Store) Retention(ctx context.Context, cutoffRFC3339 string) (int64, error) {
	st, err := s.pool.Exec(ctx, `DELETE FROM scans WHERE is_latest=false AND started_at < $1`, cutoffRFC3339)
	if err != nil {
		return 0, err
	}
	ht, err := s.pool.Exec(ctx, `DELETE FROM history WHERE at < $1`, cutoffRFC3339)
	if err != nil {
		return st.RowsAffected(), err
	}
	return st.RowsAffected() + ht.RowsAffected(), nil
}

// DeleteTenant hard-deletes all of a tenant's data (DPDP right-to-erasure).
func (s *Store) DeleteTenant(ctx context.Context, tenant string) error {
	for _, table := range []string{"audit", "history", "scans", "clusters", "users", "tenants"} {
		col := "tenant"
		if table == "tenants" {
			col = "id"
		}
		if _, err := s.pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s=$1", table, col), tenant); err != nil {
			return fmt.Errorf("delete %s: %w", table, err)
		}
	}
	return nil
}

// --- helpers --------------------------------------------------------------

func postureControls(rep api.Report) (assessed, breached int) {
	if rep.Posture.ControlsAssessed > 0 {
		return rep.Posture.ControlsAssessed, rep.Posture.ControlsBreached
	}
	for _, fw := range rep.Compliance {
		assessed += fw.Assessed
		breached += fw.Breached
	}
	return assessed, breached
}

func severityMap(rep api.Report) map[string]int {
	out := map[string]int{}
	for sev, n := range rep.Posture.BySeverity {
		out[string(sev)] = n
	}
	return out
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func sanitizeLimit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 1000
	}
	return limit
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
