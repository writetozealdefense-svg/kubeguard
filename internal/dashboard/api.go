package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kubeguard/kubeguard/pkg/api"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config configures the dashboard BFF.
type Config struct {
	Store   Store
	Auth    Authenticator
	Scanner Scanner
	Broker  *Broker
	Audit   AuditLog
	// Registrar, when set, enables dynamic cluster registration: POST/DELETE
	// /v1/clusters add/remove a scannable source at runtime. Nil disables those
	// routes (they return 501) — e.g. a pure-API test with a fixed Scanner.
	Registrar ClusterRegistrar
	// BrandTitle co-brands exported engagement reports (e.g. "ZealDefense").
	// Defaults to "KubeGuard".
	BrandTitle string
	// Security hardens the HTTP surface (headers, CSRF, rate limit, body cap).
	Security SecurityConfig
	// AsyncWorkers > 0 runs scans off the request path via a worker pool of this
	// size (P4); 0 = synchronous. QueueSize bounds the pending-scan queue.
	AsyncWorkers int
	QueueSize    int
	// Lifecycle configures findings triage/waivers (K6). Zero value applies the
	// conservative defaults: admin approval, 90-day max waiver.
	Lifecycle LifecycleConfig
	// Clock and NewID are injectable for deterministic tests (NFR-11). Defaults
	// use the wall clock and a monotonic counter.
	Clock func() time.Time
	NewID func() string
}

// API is the dashboard backend-for-frontend HTTP handler.
type API struct {
	store     Store
	auth      Authenticator
	scanner   Scanner
	broker    *Broker
	audit     AuditLog
	registrar ClusterRegistrar
	brand     string
	sec       SecurityConfig
	rl        *tenantRateLimiter
	metrics   *Metrics
	pool      *workerPool
	clock     func() time.Time
	life      LifecycleConfig

	mu     sync.Mutex
	nextID int
	newID  func() string

	handler http.Handler
}

// New builds the dashboard API handler.
func New(cfg Config) *API {
	a := &API{
		store:   cfg.Store,
		auth:    cfg.Auth,
		scanner: cfg.Scanner,
		broker:  cfg.Broker,
		clock:   cfg.Clock,
		newID:   cfg.NewID,
	}
	a.audit = cfg.Audit
	a.registrar = cfg.Registrar
	a.life = cfg.Lifecycle.withDefaults()
	a.brand = cfg.BrandTitle
	a.sec = cfg.Security
	if a.sec.MaxBodyBytes <= 0 {
		a.sec.MaxBodyBytes = defaultMaxBody
	}
	if a.sec.RatePerSecond > 0 {
		burst := a.sec.Burst
		if burst <= 0 {
			burst = 1
		}
		a.rl = newTenantRateLimiter(a.sec.RatePerSecond, burst)
	}
	if a.store == nil {
		a.store = NewMemStore()
	}
	if a.broker == nil {
		a.broker = NewBroker()
	}
	if a.audit == nil {
		a.audit = NewMemAuditLog()
	}
	a.metrics = newMetrics()
	if cfg.AsyncWorkers > 0 {
		a.startWorkers(cfg.AsyncWorkers, cfg.QueueSize)
	}
	if a.clock == nil {
		a.clock = time.Now
	}
	if a.newID == nil {
		a.newID = a.seqID
	}
	a.handler = a.routes()
	return a
}

// Handler exposes the composed HTTP handler.
func (a *API) Handler() http.Handler { return a.handler }

// Broker exposes the event broker (used to wire scheduled scans, Squad D5).
func (a *API) Broker() *Broker { return a.broker }

// seqID returns a process-unique scan id. A monotonic counter keeps ids ordered
// and readable within a run; a short random suffix keeps them globally unique
// across process restarts (so a Postgres-persisted store never collides on the
// scans primary key). Tests inject a deterministic NewID where they need one.
func (a *API) seqID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextID++
	return fmt.Sprintf("scan-%d-%s", a.nextID, randSuffix())
}

func (a *API) now() string { return a.clock().UTC().Format(time.RFC3339) }

func randSuffix() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// validClusterID bounds and sanitizes a cluster identifier (server-side input
// validation; the client validates the same shape for a fast fail).
func validClusterID(id string) bool {
	if len(id) == 0 || len(id) > 253 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

func (a *API) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)
	// Structured request logging + Prometheus latency metrics on every route.
	r.Use(requestLogger)
	r.Use(a.metrics.middleware)
	// Defensive headers on every response; body cap against memory exhaustion.
	r.Use(securityHeaders(a.sec.HSTS))
	r.Use(limitBody(a.sec.MaxBodyBytes))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	r.Get("/readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready")) })
	r.Handle("/metrics", promhttp.HandlerFor(a.metrics.reg, promhttp.HandlerOpts{}))

	r.Route("/v1", func(r chi.Router) {
		r.Use(a.authMiddleware) // fail-closed auth on every /v1 route
		// CSRF origin defense-in-depth + per-tenant rate limiting (after auth so
		// the tenant is known).
		r.Use(csrfOrigin(a.sec.AllowedOrigins))
		if a.rl != nil {
			r.Use(a.rl.middleware)
		}
		r.Get("/clusters", a.handleClusters)
		r.With(a.requireRole(RoleAdmin, "cluster.write")).Post("/clusters", a.handleRegisterCluster)
		r.With(a.requireRole(RoleAdmin, "cluster.write")).Delete("/clusters/{id}", a.handleDeleteCluster)
		r.Get("/scans", a.handleListScans)
		r.With(a.requireRole(RoleAnalyst, "scan.trigger")).Post("/scans", a.handleTriggerScan)
		r.Get("/findings", a.handleFindings)
		r.Get("/posture", a.handlePosture)
		r.Get("/attack-paths", a.handleAttackPaths)
		r.Get("/history", a.handleHistory)
		r.With(a.requireRole(RoleAdmin, "audit.read")).Get("/audit", a.handleAudit)
		r.Get("/report", a.handleReport)
		r.Get("/stream", a.handleStream)
		a.registerLifecycleRoutes(r) // findings lifecycle (K6)
		a.registerTenantRoutes(r)    // operator lifecycle (K8)
	})
	return r
}

// --- handlers -------------------------------------------------------------

func (a *API) handleClusters(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"clusters": a.store.ListClusters(p.Tenant)})
}

// handleRegisterCluster adds a cluster + its scannable source at runtime
// (admin-only). The source string is the same form the CLI accepts for
// --cluster (an offline manifest path or "live[:context]"); the API stays
// agnostic to which — the configured registrar interprets it. Idempotent on the
// store side; a fresh registration is audited and returns 201.
func (a *API) handleRegisterCluster(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	if a.registrar == nil {
		writeError(w, http.StatusNotImplemented, "dynamic cluster registration is not enabled")
		return
	}
	var body struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.ID == "" || body.Source == "" {
		writeError(w, http.StatusBadRequest, "id and source are required")
		return
	}
	if !validClusterID(body.ID) {
		writeError(w, http.StatusBadRequest, "invalid cluster id")
		return
	}
	// Register the source first so a rejected/malformed source never leaves a
	// dangling, unscannable cluster row in the store.
	if err := a.registrar.AddSource(body.ID, body.Source); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid source: %v", err))
		return
	}
	name := body.Name
	if name == "" {
		name = body.ID
	}
	a.store.RegisterCluster(p.Tenant, Cluster{ID: body.ID, Name: name})
	a.audit.Write(AuditEntry{At: a.now(), Subject: p.Subject, Tenant: p.Tenant, Action: "cluster.write", Resource: body.ID, Result: "allowed"})
	c, _ := a.store.GetCluster(p.Tenant, body.ID)
	writeJSON(w, http.StatusCreated, c)
}

// handleDeleteCluster deregisters a cluster (admin-only): drops its store rows
// and its scannable source so subsequent scans 404. Idempotent-ish: a missing
// cluster returns 404. Audited either way.
func (a *API) handleDeleteCluster(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	if a.registrar == nil {
		writeError(w, http.StatusNotImplemented, "dynamic cluster registration is not enabled")
		return
	}
	id := chi.URLParam(r, "id")
	if !validClusterID(id) {
		writeError(w, http.StatusBadRequest, "invalid cluster id")
		return
	}
	ok := a.store.DeleteCluster(p.Tenant, id)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown cluster")
		return
	}
	a.registrar.RemoveSource(id)
	a.audit.Write(AuditEntry{At: a.now(), Subject: p.Subject, Tenant: p.Tenant, Action: "cluster.delete", Resource: id, Result: "allowed"})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleListScans(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)
	scans, total := a.store.ListScans(p.Tenant, r.URL.Query().Get("cluster"), limit, offset)
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans, "total": total})
}

func (a *API) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var body struct {
		ClusterID string `json:"clusterId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ClusterID == "" {
		writeError(w, http.StatusBadRequest, "clusterId is required")
		return
	}
	if !validClusterID(body.ClusterID) {
		writeError(w, http.StatusBadRequest, "invalid clusterId")
		return
	}
	if _, ok := a.store.GetCluster(p.Tenant, body.ClusterID); !ok {
		writeError(w, http.StatusNotFound, "unknown cluster")
		return
	}
	if a.scanner == nil {
		writeError(w, http.StatusServiceUnavailable, "no scanner configured")
		return
	}
	// Async mode (P4): enqueue and return immediately so the API stays responsive
	// on large clusters. The worker streams progress over SSE. Sync mode (default)
	// runs inline.
	if a.pool != nil {
		scanID := a.newID()
		if !a.enqueue(scanJob{tenant: p.Tenant, clusterID: body.ClusterID, subject: p.Subject, scanID: scanID}) {
			writeError(w, http.StatusServiceUnavailable, "scan queue full, retry shortly")
			return
		}
		writeJSON(w, http.StatusAccepted, Scan{ID: scanID, ClusterID: body.ClusterID, Status: ScanQueued})
		return
	}
	scan := a.RunScan(r.Context(), p.Tenant, body.ClusterID, p.Subject)
	writeJSON(w, http.StatusAccepted, scan)
}

// RunScan executes one scan for a cluster: publishes scan lifecycle + posture
// events to SSE subscribers, runs the read-only Scanner, persists the report
// (which appends a history snapshot for drift), and writes an append-only audit
// entry. Shared by the on-demand POST /v1/scans handler and the cron Scheduler,
// so a scheduled scan continuously populates the same compliance/trend views.
// subject is the actor ("scheduler" for cron runs).
func (a *API) RunScan(ctx context.Context, tenant, clusterID, subject string) Scan {
	return a.runScanWithID(ctx, tenant, clusterID, subject, a.newID())
}

// runScanJob processes one queued job (worker pool).
func (a *API) runScanJob(ctx context.Context, j scanJob) {
	a.runScanWithID(ctx, j.tenant, j.clusterID, j.subject, j.scanID)
}

func (a *API) runScanWithID(ctx context.Context, tenant, clusterID, subject, scanID string) Scan {
	ctx, span := startSpan(ctx, "dashboard.RunScan")
	defer span.End()
	start := a.clock()

	a.broker.Publish(tenant, Event{Type: "scan_started", ClusterID: clusterID, ScanID: scanID})
	a.broker.Publish(tenant, Event{Type: "scan_progress", ClusterID: clusterID, ScanID: scanID, Progress: 0.5})

	rep, err := a.runScanner(ctx, clusterID)
	if err != nil {
		// Failed scan: nothing is persisted (no partial scan/history rows), so a
		// crash mid-scan can't corrupt the store. Only a failed-audit is written.
		a.broker.Publish(tenant, Event{Type: "scan_completed", ClusterID: clusterID, ScanID: scanID, Message: "failed"})
		a.audit.Write(AuditEntry{At: a.now(), Subject: subject, Tenant: tenant, Action: "scan.trigger", Resource: clusterID, Result: "failed"})
		a.metrics.recordScan(clusterID, "failure", a.clock().Sub(start), api.Report{})
		span.RecordError(err)
		return Scan{ID: scanID, ClusterID: clusterID, Status: ScanFailed}
	}
	scan := a.store.RecordScan(tenant, clusterID, scanID, rep, a.now())
	// Seed lifecycle rows for newly-seen findings so time-to-resolve is measured
	// from first detection (idempotent; existing triage state is untouched).
	a.store.SeedFindings(tenant, clusterID, rep.Findings, a.now())
	a.metrics.recordScan(clusterID, "success", a.clock().Sub(start), rep)
	a.audit.Write(AuditEntry{At: a.now(), Subject: subject, Tenant: tenant, Action: "scan.trigger", Resource: clusterID, Result: "allowed"})
	a.broker.Publish(tenant, Event{Type: "scan_completed", ClusterID: clusterID, ScanID: scanID, Progress: 1})
	a.broker.Publish(tenant, Event{Type: "posture_updated", ClusterID: clusterID})
	return scan
}

// runScanner invokes the read-only Scanner with bounded retries (reliability):
// a transient scan failure is retried before the job is marked failed. Scans are
// idempotent — each gets a fresh unique id and persistence is atomic — so a
// retry never double-counts or corrupts state.
func (a *API) runScanner(ctx context.Context, clusterID string) (api.Report, error) {
	const attempts = 3
	var err error
	for i := 0; i < attempts; i++ {
		var rep api.Report
		rep, err = a.scanner(ctx, clusterID)
		if err == nil {
			return rep, nil
		}
		if ctx.Err() != nil {
			return api.Report{}, ctx.Err()
		}
	}
	return api.Report{}, err
}

func (a *API) handleAudit(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"entries": a.audit.List(p.Tenant)})
}

// handleReport exports the current posture as SARIF, CSV, or a co-branded PDF.
// All formats carry the honest-metrics denominators; secrets are never included.
func (a *API) handleReport(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	cluster := r.URL.Query().Get("cluster")
	rep, ok := a.store.Report(p.Tenant, cluster)
	if !ok {
		writeError(w, http.StatusNotFound, "no scan for this scope yet")
		return
	}
	format := orDefault(r.URL.Query().Get("format"), "sarif")
	name := orDefault(cluster, "all-clusters")

	var (
		body        []byte
		err         error
		contentType string
		filename    string
	)
	switch format {
	case "sarif":
		body, err = ExportSARIF(rep)
		contentType, filename = "application/sarif+json", name+".sarif"
	case "csv":
		body, err = ExportCSV(rep)
		contentType, filename = "text/csv", name+"-findings.csv"
	case "pdf":
		body, err = ExportPDF(rep, Brand{Title: a.brand, Tenant: p.Tenant})
		contentType, filename = "application/pdf", name+"-report.pdf"
	default:
		writeError(w, http.StatusBadRequest, "format must be sarif, csv, or pdf")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (a *API) handleFindings(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	rep, ok := a.store.Report(p.Tenant, r.URL.Query().Get("cluster"))
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"findings": []api.Finding{}, "total": 0, "limit": 0, "offset": 0})
		return
	}
	q := parseFindingQuery(r)
	filtered := filterFindings(rep.Findings, q)
	sortFindings(filtered, q.sort, q.order)
	total := len(filtered)
	page := paginate(filtered, q.limit, q.offset)
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": page, "total": total, "limit": q.limit, "offset": q.offset,
	})
}

func (a *API) handlePosture(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	rep, ok := a.store.Report(p.Tenant, r.URL.Query().Get("cluster"))
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"posture":    api.PostureSummary{BySeverity: map[api.Severity]int{}},
			"compliance": []api.FrameworkResult{},
		})
		return
	}
	compliance := rep.Compliance
	if compliance == nil {
		compliance = []api.FrameworkResult{}
	}
	out := map[string]any{"posture": rep.Posture, "compliance": compliance}
	if rep.Coverage != nil {
		out["coverage"] = rep.Coverage
	}
	if rep.TopRisks != nil {
		out["topRisks"] = rep.TopRisks
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleAttackPaths(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	rep, ok := a.store.Report(p.Tenant, r.URL.Query().Get("cluster"))
	paths := []api.AttackPath{}
	if ok && rep.Paths != nil {
		paths = rep.Paths
	}
	writeJSON(w, http.StatusOK, map[string]any{"paths": paths})
}

func (a *API) handleHistory(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"snapshots": a.store.History(p.Tenant, r.URL.Query().Get("cluster")),
	})
}

// handleStream is the SSE endpoint: scan progress + posture updates for the
// caller's tenant. Closes when the client disconnects.
func (a *API) handleStream(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch, unsubscribe := a.broker.Subscribe(p.Tenant)
	defer unsubscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			data, _ := json.Marshal(ev)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
			flusher.Flush()
		}
	}
}

// --- finding filter/sort/paginate ----------------------------------------

type findingQuery struct {
	severities map[api.Severity]bool
	category   string
	framework  string
	namespace  string
	search     string
	sort       string
	order      string
	limit      int
	offset     int
}

func parseFindingQuery(r *http.Request) findingQuery {
	q := r.URL.Query()
	fq := findingQuery{
		category:  q.Get("category"),
		framework: strings.ToLower(q.Get("framework")),
		namespace: q.Get("namespace"),
		search:    strings.ToLower(q.Get("search")),
		sort:      orDefault(q.Get("sort"), "severity"),
		order:     orDefault(q.Get("order"), "desc"),
		limit:     queryInt(r, "limit", 50),
		offset:    queryInt(r, "offset", 0),
	}
	if sev := q.Get("severity"); sev != "" {
		fq.severities = map[api.Severity]bool{}
		for _, s := range strings.Split(sev, ",") {
			fq.severities[api.Severity(strings.ToLower(strings.TrimSpace(s)))] = true
		}
	}
	return fq
}

func filterFindings(in []api.Finding, q findingQuery) []api.Finding {
	out := make([]api.Finding, 0, len(in))
	for _, f := range in {
		if q.severities != nil && !q.severities[f.Severity] {
			continue
		}
		if q.category != "" && !strings.EqualFold(f.Category, q.category) {
			continue
		}
		if q.namespace != "" && !strings.EqualFold(f.Resource.Namespace, q.namespace) {
			continue
		}
		if q.framework != "" && !findingHasFramework(f, q.framework) {
			continue
		}
		if q.search != "" && !findingMatches(f, q.search) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func findingHasFramework(f api.Finding, fw string) bool {
	for _, ref := range f.Refs {
		if strings.Contains(strings.ToLower(ref.Framework), fw) {
			return true
		}
	}
	return false
}

func findingMatches(f api.Finding, term string) bool {
	hay := strings.ToLower(strings.Join([]string{
		f.ID, f.Title, f.Category, f.Resource.Kind, f.Resource.Namespace, f.Resource.Name,
	}, " "))
	return strings.Contains(hay, term)
}

// sortFindings orders findings by key in ascending order, then reverses for the
// default "desc". So severity-desc lists most-severe first; id-asc lists
// KG-001 first.
func sortFindings(f []api.Finding, key, order string) {
	ascLess := func(i, j int) bool {
		switch key {
		case "id":
			return f[i].ID < f[j].ID
		case "category":
			if f[i].Category != f[j].Category {
				return f[i].Category < f[j].Category
			}
			return f[i].ID < f[j].ID
		default: // severity — least severe first (ascending)
			if f[i].Severity.Rank() != f[j].Severity.Rank() {
				return f[i].Severity.Rank() < f[j].Severity.Rank()
			}
			return f[i].ID < f[j].ID
		}
	}
	sort.SliceStable(f, ascLess)
	if order != "asc" { // default desc
		for i, j := 0, len(f)-1; i < j; i, j = i+1, j-1 {
			f[i], f[j] = f[j], f[i]
		}
	}
}

func paginate(f []api.Finding, limit, offset int) []api.Finding {
	if offset > len(f) {
		offset = len(f)
	}
	end := offset + limit
	if limit <= 0 || end > len(f) {
		end = len(f)
	}
	return append([]api.Finding{}, f[offset:end]...)
}

// --- helpers --------------------------------------------------------------

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
