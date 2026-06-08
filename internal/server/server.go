package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/kubeguard/kubeguard/internal/analyzer"
	"github.com/kubeguard/kubeguard/internal/history"
	"github.com/kubeguard/kubeguard/internal/model"
	"github.com/kubeguard/kubeguard/internal/report"
	"github.com/kubeguard/kubeguard/pkg/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
)

// Loader ingests the resources to scan and a source label.
type Loader func(ctx context.Context) ([]model.Resource, string, error)

// Config configures the service.
type Config struct {
	Loader       Loader
	Profile      string
	AssumeBreach bool
	Schedule     string        // optional cron expression
	Store        history.Store // optional history backend
}

// Server is the KubeGuard service: scheduler + REST + dashboard + metrics
// (ARCHITECTURE.md §12).
type Server struct {
	cfg     Config
	mu      sync.RWMutex
	latest  api.Report
	hasScan bool

	reg      *prometheus.Registry
	passRate *prometheus.GaugeVec
	findings *prometheus.GaugeVec
	paths    prometheus.Gauge

	handler http.Handler
	cron    *cron.Cron
}

// New builds a Server. Loader is required; Profile defaults to zeal-default.
func New(cfg Config) (*Server, error) {
	if cfg.Loader == nil {
		return nil, errors.New("server: a Loader is required")
	}
	if cfg.Profile == "" {
		cfg.Profile = "zeal-default"
	}
	s := &Server{cfg: cfg, reg: prometheus.NewRegistry()}
	s.passRate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubeguard_compliance_pass_rate",
		Help: "Compliance control pass rate (passed of assessed) per framework.",
	}, []string{"framework"})
	s.findings = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kubeguard_findings_total",
		Help: "Number of findings by severity in the latest scan.",
	}, []string{"severity"})
	s.paths = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kubeguard_attack_paths_total",
		Help: "Number of attack paths in the latest scan.",
	})
	s.reg.MustRegister(s.passRate, s.findings, s.paths)
	s.handler = s.routes()
	return s, nil
}

// Handler exposes the HTTP handler (used by tests and Start).
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/scan", s.handleScan)
	mux.HandleFunc("/v1/findings", s.handleFindings)
	mux.HandleFunc("/v1/posture", s.handlePosture)
	mux.HandleFunc("/v1/report", s.handleReport)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.Handle("/metrics", promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", s.handleDashboard)
	return mux
}

// ScanOnce runs a scan, caches it as the latest report, and updates metrics and
// history.
func (s *Server) ScanOnce(ctx context.Context) (api.Report, error) {
	resources, source, err := s.cfg.Loader(ctx)
	if err != nil {
		return api.Report{}, err
	}
	rep, err := analyzer.Analyze(resources, s.cfg.Profile, s.cfg.AssumeBreach)
	if err != nil {
		return api.Report{}, err
	}
	rep.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	rep.Source = source

	s.mu.Lock()
	s.latest = rep
	s.hasScan = true
	s.mu.Unlock()

	s.updateMetrics(rep)
	if s.cfg.Store != nil {
		if err := s.cfg.Store.Append(history.FromReport(rep)); err != nil {
			slog.Error("history append failed", "err", err)
		}
	}
	return rep, nil
}

func (s *Server) updateMetrics(rep api.Report) {
	s.findings.Reset()
	for _, sev := range []api.Severity{api.SeverityCritical, api.SeverityHigh, api.SeverityMedium, api.SeverityLow} {
		s.findings.WithLabelValues(string(sev)).Set(float64(rep.Posture.BySeverity[sev]))
	}
	s.passRate.Reset()
	for _, fw := range rep.Compliance {
		s.passRate.WithLabelValues(fw.Framework).Set(fw.PassRate)
	}
	s.paths.Set(float64(len(rep.Paths)))
}

func (s *Server) snapshot() (api.Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest, s.hasScan
}

// --- handlers -------------------------------------------------------------

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	rep, err := s.ScanOnce(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleFindings(w http.ResponseWriter, _ *http.Request) {
	rep, ok := s.snapshot()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no scan yet"})
		return
	}
	writeJSON(w, http.StatusOK, rep.Findings)
}

func (s *Server) handlePosture(w http.ResponseWriter, _ *http.Request) {
	rep, ok := s.snapshot()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no scan yet"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"posture":    rep.Posture,
		"compliance": rep.Compliance,
	})
}

func (s *Server) handleReport(w http.ResponseWriter, _ *http.Request) {
	rep, ok := s.snapshot()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no scan yet"})
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if _, ok := s.snapshot(); !ok {
		http.Error(w, "no scan yet", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ready"))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	rep, ok := s.snapshot()
	if !ok {
		http.Error(w, "no scan yet", http.StatusServiceUnavailable)
		return
	}
	var hist []history.Record
	if s.cfg.Store != nil {
		if recs, err := s.cfg.Store.All(); err == nil {
			hist = recs
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := report.HTML(w, rep, hist); err != nil {
		slog.Error("render dashboard failed", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("encode response failed", "err", err)
	}
}

// Start runs an initial scan, optionally schedules recurring scans, and serves
// HTTP until ctx is cancelled.
func (s *Server) Start(ctx context.Context, addr string) error {
	if _, err := s.ScanOnce(ctx); err != nil {
		slog.Error("initial scan failed", "err", err)
	}
	if s.cfg.Schedule != "" {
		s.cron = cron.New()
		if _, err := s.cron.AddFunc(s.cfg.Schedule, func() {
			if _, err := s.ScanOnce(context.Background()); err != nil {
				slog.Error("scheduled scan failed", "err", err)
			}
		}); err != nil {
			return fmt.Errorf("invalid schedule %q: %w", s.cfg.Schedule, err)
		}
		s.cron.Start()
		defer s.cron.Stop()
	}

	srv := &http.Server{Addr: addr, Handler: s.handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	slog.Info("kubeguard serving", "addr", addr, "schedule", s.cfg.Schedule)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
