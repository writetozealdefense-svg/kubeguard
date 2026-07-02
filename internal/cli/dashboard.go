package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kubeguard/kubeguard/internal/analyzer"
	"github.com/kubeguard/kubeguard/internal/dashboard"
	"github.com/kubeguard/kubeguard/internal/dashboard/pg"
	"github.com/kubeguard/kubeguard/internal/loader/live"
	"github.com/kubeguard/kubeguard/internal/loader/offline"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/pkg/api"
	"github.com/spf13/cobra"
)

func newDashboardCmd() *cobra.Command {
	var (
		addr          string
		profile       string
		assumeBreach  bool
		clusterSpecs  []string
		adminToken    string
		tenant        string
		schedule      string
		brand         string
		postgresDSN   string
		retention     time.Duration
		tlsCert       string
		tlsKey        string
		allowedOrig   []string
		rateLimit     float64
		rateBurst     int
		otelEndpoint  string
		asyncWorkers  int
		oidcIssuer    string
		oidcAudience  string
		oidcJWKSURL   string
		oidcTenantCl  string
		oidcRoleClaim string
	)
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Run the multi-cluster web dashboard API (backend-for-frontend)",
		Long: "Serve the dashboard BFF: /v1/clusters, /v1/scans, /v1/findings (filter/sort/" +
			"paginate), /v1/posture, /v1/attack-paths, /v1/history, and an SSE /v1/stream — " +
			"described by docs/openapi.yaml. Read-only against clusters. Auth defaults to a " +
			"local-admin bearer token (air-gapped); Squad D3 adds OIDC/SSO.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(clusterSpecs) == 0 {
				return errors.New("dashboard requires at least one --cluster id=<manifest-path>")
			}
			// Secrets come from env when not passed as flags (never bake them into
			// an image or commit them). Flags take precedence for local dev.
			if adminToken == "" {
				adminToken = os.Getenv("KUBEGUARD_ADMIN_TOKEN")
			}
			if postgresDSN == "" {
				postgresDSN = os.Getenv("KUBEGUARD_POSTGRES_DSN")
			}
			// A cluster source is either an offline manifest path or a live cluster.
			// Live sources are written as "live" (current kubecontext) or
			// "live:<context>"; everything else is treated as an offline path.
			// The source map is owned by a mutex-guarded registrar so the dynamic
			// POST/DELETE /v1/clusters routes can add/remove sources at runtime and
			// the scanner reads the current set (was a captured closure map before).
			sources := newSourceRegistry()
			for _, spec := range clusterSpecs {
				id, path, ok := strings.Cut(spec, "=")
				if !ok || id == "" || path == "" {
					return fmt.Errorf("invalid --cluster %q, want id=<manifest-path|live[:context]>", spec)
				}
				if err := sources.AddSource(id, path); err != nil {
					return fmt.Errorf("invalid --cluster %q: %w", spec, err)
				}
			}

			// Storage backend: Postgres when --postgres is set (runs migrations,
			// persists scans/history/audit, supports retention + DPDP delete);
			// in-memory otherwise. Both satisfy the same Store/AuditLog seams.
			var (
				store    dashboard.Store
				auditLog dashboard.AuditLog
				pgStore  *pg.Store
			)
			if postgresDSN != "" {
				var err error
				pgStore, err = pg.Open(cmd.Context(), postgresDSN)
				if err != nil {
					return fmt.Errorf("postgres: %w", err)
				}
				defer pgStore.Close()
				store, auditLog = pgStore, pgStore
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "storage: postgres (migrations applied)")
			} else {
				store = dashboard.NewMemStore()
			}
			for _, id := range sources.ids() {
				store.RegisterCluster(tenant, dashboard.Cluster{ID: id, Name: id})
			}

			scanner := func(ctx context.Context, clusterID string) (api.Report, error) {
				path, ok := sources.source(clusterID)
				if !ok {
					return api.Report{}, fmt.Errorf("unknown cluster %q", clusterID)
				}
				var rs []model.Resource
				if path == "live" || strings.HasPrefix(path, "live:") {
					// Read-only live cluster ingest via client-go (same path used by
					// `scan --live`). Lists only — never writes to the cluster.
					kubeContext := strings.TrimPrefix(path, "live")
					kubeContext = strings.TrimPrefix(kubeContext, ":")
					cs, err := live.NewClientset(kubeContext)
					if err != nil {
						return api.Report{}, fmt.Errorf("live cluster %q: %w", clusterID, err)
					}
					rs, err = live.Load(ctx, cs)
					if err != nil {
						return api.Report{}, fmt.Errorf("live scan %q: %w", clusterID, err)
					}
				} else {
					var err error
					rs, err = offline.Load(path)
					if err != nil {
						return api.Report{}, fmt.Errorf("load %q: %w", path, err)
					}
				}
				rep, err := analyzer.Analyze(rs, profile, assumeBreach)
				if err != nil {
					return api.Report{}, err
				}
				rep.Source = clusterID
				return rep, nil
			}

			if adminToken == "" {
				adminToken = "local-admin"
			}
			// Local-admin authenticator — always available (air-gapped, no IdP).
			local := dashboard.NewStaticAuth(map[string]dashboard.Principal{
				adminToken: {Subject: "local-admin", Tenant: tenant, Role: dashboard.RoleAdmin},
			})
			// OIDC/SSO is the ready-to-connect seam: DEFAULT OFF. It is wired only
			// when --oidc-issuer + --oidc-jwks-url are provided, and is tried
			// before the local-admin fallback. No IdP is contacted otherwise.
			var auth dashboard.Authenticator = local
			if oidcIssuer != "" && oidcJWKSURL != "" {
				jwtAuth := dashboard.NewJWTAuth(
					dashboard.JWTConfig{
						Issuer: oidcIssuer, Audience: oidcAudience,
						TenantClaim: oidcTenantCl, RoleClaim: oidcRoleClaim,
					},
					dashboard.NewJWKSKeyfunc(oidcJWKSURL),
				)
				auth = dashboard.NewChainAuth(jwtAuth, local)
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OIDC enabled: issuer=%s jwks=%s\n", oidcIssuer, oidcJWKSURL)
			}
			a := dashboard.New(dashboard.Config{
				Store: store, Auth: auth, Scanner: scanner, BrandTitle: brand, Audit: auditLog,
				Registrar: sources,
				Security: dashboard.SecurityConfig{
					AllowedOrigins: allowedOrig,
					RatePerSecond:  rateLimit,
					Burst:          rateBurst,
					HSTS:           tlsCert != "",
				},
				AsyncWorkers: asyncWorkers,
			})
			defer a.Close()

			// Initial scan per cluster so the lenses have data immediately.
			for _, id := range sources.ids() {
				a.RunScan(cmd.Context(), tenant, id, "init")
			}

			// Optional cron scheduler — continuously re-scans every cluster so the
			// compliance/trend/attack-path views stay current without user action.
			if schedule != "" {
				ids := sources.ids()
				specs := make([]dashboard.ScheduleSpec, 0, len(ids))
				for _, id := range ids {
					specs = append(specs, dashboard.ScheduleSpec{Tenant: tenant, ClusterID: id, Cron: schedule})
				}
				sched := dashboard.NewScheduler(a, specs)
				if err := sched.Start(); err != nil {
					return fmt.Errorf("invalid --schedule %q: %w", schedule, err)
				}
				defer sched.Stop()
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()

			// OpenTelemetry tracing — DEFAULT OFF. Wired only when an OTLP endpoint
			// is configured; no collector is contacted otherwise.
			if otelEndpoint == "" {
				otelEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
			}
			if otelEndpoint != "" {
				shutdown, err := dashboard.InitTracing(ctx, otelEndpoint)
				if err != nil {
					return fmt.Errorf("otel: %w", err)
				}
				defer func() { _ = shutdown(context.Background()) }()
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "tracing: OTLP → %s\n", otelEndpoint)
			}

			// Configurable retention (Postgres only): prune scans/history older
			// than the window hourly. The latest scan per cluster is always kept.
			if pgStore != nil && retention > 0 {
				go func() {
					ticker := time.NewTicker(time.Hour)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							cutoff := time.Now().Add(-retention).UTC().Format(time.RFC3339)
							if n, err := pgStore.Retention(ctx, cutoff); err != nil {
								slog.Error("retention failed", "err", err)
							} else if n > 0 {
								slog.Info("retention pruned", "rows", n, "cutoff", cutoff)
							}
						}
					}
				}()
			}

			srv := &http.Server{Addr: addr, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second}
			go func() {
				<-ctx.Done()
				shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutCtx)
			}()
			scheme := "http"
			serve := srv.ListenAndServe
			if tlsCert != "" && tlsKey != "" {
				scheme = "https"
				serve = func() error { return srv.ListenAndServeTLS(tlsCert, tlsKey) }
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "kubeguard dashboard on %s://%s — tenant=%q\n", scheme, addr, tenant)
			if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve: %w", err)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&addr, "addr", ":8080", "address to listen on")
	f.StringVarP(&profile, "profile", "p", "zeal-default", "check profile: cis|zeal-default")
	f.BoolVar(&assumeBreach, "assume-breach", false, "seed every workload as reachable from an in-cluster foothold")
	f.StringArrayVar(&clusterSpecs, "cluster", nil, "register a cluster as id=<manifest-path> or id=live[:<kubecontext>] for read-only live scanning (repeatable)")
	f.StringVar(&adminToken, "admin-token", "", "local-admin bearer token (default \"local-admin\")")
	f.StringVar(&tenant, "tenant", "default", "tenant id for registered clusters")
	f.StringVar(&schedule, "schedule", "", "cron expression to re-scan every cluster, e.g. \"0 * * * *\"")
	f.StringVar(&brand, "brand", "", "co-brand title on exported PDF reports (default \"KubeGuard\")")
	f.StringVar(&postgresDSN, "postgres", "", "Postgres DSN to persist scans/history/audit (or KUBEGUARD_POSTGRES_DSN; default in-memory)")
	f.DurationVar(&retention, "retention", 0, "prune scans/history older than this (Postgres only), e.g. 720h")
	f.StringVar(&tlsCert, "tls-cert", "", "TLS certificate file (enables HTTPS + HSTS)")
	f.StringVar(&tlsKey, "tls-key", "", "TLS private key file")
	f.StringArrayVar(&allowedOrig, "allowed-origin", nil, "CSRF: allowed browser Origin for writes (repeatable)")
	f.Float64Var(&rateLimit, "rate-limit", 0, "per-tenant requests/sec (0 = unlimited)")
	f.IntVar(&rateBurst, "rate-burst", 20, "per-tenant rate-limit burst")
	f.StringVar(&otelEndpoint, "otel-endpoint", "", "OTLP/HTTP endpoint for traces (or OTEL_EXPORTER_OTLP_ENDPOINT; default off)")
	f.IntVar(&asyncWorkers, "async-workers", 0, "run scans on a worker pool of this size (0 = synchronous)")
	// OIDC/SSO seam — DEFAULT OFF. Set issuer + jwks-url to enable (see docs/auth.md).
	f.StringVar(&oidcIssuer, "oidc-issuer", "", "OIDC issuer (enables SSO; default off)")
	f.StringVar(&oidcAudience, "oidc-audience", "", "expected OIDC audience claim")
	f.StringVar(&oidcJWKSURL, "oidc-jwks-url", "", "OIDC JWKS URL for signature verification")
	f.StringVar(&oidcTenantCl, "oidc-tenant-claim", "tenant", "JWT claim carrying the tenant/org")
	f.StringVar(&oidcRoleClaim, "oidc-role-claim", "role", "JWT claim carrying the role")
	return cmd
}
