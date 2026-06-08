package dashboard

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// requestLogger emits a structured slog line per request with the request id,
// method, route, status, duration, and tenant (once authenticated). Secrets are
// never logged.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		tenant := ""
		if p, ok := PrincipalFrom(r.Context()); ok {
			tenant = p.Tenant
		}
		slog.Info("http",
			"request_id", middleware.GetReqID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"tenant", tenant,
		)
	})
}
