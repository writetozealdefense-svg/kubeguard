package dashboard

import (
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

// SecurityConfig hardens the HTTP surface (P2). Zero values are safe defaults:
// headers always on, body capped at 1 MiB, rate limiting and the CSRF origin
// allowlist disabled unless configured.
type SecurityConfig struct {
	// AllowedOrigins, when non-empty, enforces a CSRF Origin allowlist on unsafe
	// methods (POST/PUT/PATCH/DELETE). Empty = no browser cross-origin writes are
	// expected (e.g. same-origin or non-browser clients).
	AllowedOrigins []string
	// RatePerSecond + Burst enable a per-tenant token-bucket limiter. 0 = off.
	RatePerSecond float64
	Burst         int
	// MaxBodyBytes caps request bodies (default 1 MiB).
	MaxBodyBytes int64
	// HSTS emits Strict-Transport-Security (enable only when served over TLS).
	HSTS bool
}

const defaultMaxBody = 1 << 20 // 1 MiB

// securityHeaders sets defensive response headers on every route. The API
// returns only JSON, so the CSP is maximally restrictive.
func securityHeaders(hsts bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// limitBody rejects over-large requests (defense against memory-exhaustion) and
// caps the readable body as a backstop.
func limitBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// csrfOrigin enforces an Origin allowlist on unsafe methods. The API authenticates
// via a bearer token (not cookies), which browsers don't auto-attach cross-site —
// so this is defense-in-depth. A request whose Origin is present but not allowed
// is rejected; absent Origin (non-browser clients) passes.
func csrfOrigin(allowed []string) func(http.Handler) http.Handler {
	allow := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		allow[strings.TrimRight(o, "/")] = true
	}
	unsafe := map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allow) > 0 && unsafe[r.Method] {
				origin := strings.TrimRight(r.Header.Get("Origin"), "/")
				if origin != "" && !allow[origin] {
					writeError(w, http.StatusForbidden, "cross-origin request rejected")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// tenantRateLimiter is a per-tenant token-bucket limiter. Must run after auth so
// the principal's tenant is on the context.
type tenantRateLimiter struct {
	rps   rate.Limit
	burst int
	mu    sync.Mutex
	limit map[string]*rate.Limiter
}

func newTenantRateLimiter(rps float64, burst int) *tenantRateLimiter {
	return &tenantRateLimiter{rps: rate.Limit(rps), burst: burst, limit: map[string]*rate.Limiter{}}
}

func (t *tenantRateLimiter) limiterFor(tenant string) *rate.Limiter {
	t.mu.Lock()
	defer t.mu.Unlock()
	l := t.limit[tenant]
	if l == nil {
		l = rate.NewLimiter(t.rps, t.burst)
		t.limit[tenant] = l
	}
	return l
}

func (t *tenantRateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := "anon"
		if p, ok := PrincipalFrom(r.Context()); ok {
			tenant = p.Tenant
		}
		if !t.limiterFor(tenant).Allow() {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
