package dashboard

import (
	"context"
	"net/http"
	"strings"
)

// Role gates what a principal may do. Ranked viewer < analyst < admin.
type Role string

// Roles, ranked viewer < analyst < admin.
const (
	RoleViewer  Role = "viewer"
	RoleAnalyst Role = "analyst"
	RoleAdmin   Role = "admin"
)

func roleRank(r Role) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleAnalyst:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// Principal is the authenticated caller: which tenant and what role.
type Principal struct {
	Subject string
	Tenant  string
	Role    Role
	// SuperAdmin grants cross-tenant operator authority (tenant provisioning and
	// erasing a tenant other than the caller's own). It is orthogonal to Role —
	// a super-admin still acts as an admin within a tenant. Set from a dedicated
	// claim/token, never inferred from the tenant-scoped role.
	SuperAdmin bool
}

// Authenticator resolves a request to a Principal. D2 ships a static token
// authenticator; Squad D3 swaps in OIDC + local-admin + JWT behind this same
// interface. Returning ok=false means 401 (unauthenticated).
type Authenticator interface {
	Authenticate(r *http.Request) (Principal, bool)
}

// StaticAuth maps opaque bearer tokens to principals — enough to exercise
// tenancy + RBAC end-to-end in tests and local dev, with no external IdP.
type StaticAuth struct {
	tokens map[string]Principal
}

// NewStaticAuth builds a StaticAuth from token→principal pairs.
func NewStaticAuth(tokens map[string]Principal) *StaticAuth {
	return &StaticAuth{tokens: tokens}
}

// Authenticate reads the bearer token and looks up its principal.
func (s *StaticAuth) Authenticate(r *http.Request) (Principal, bool) {
	tok := bearerToken(r)
	if tok == "" {
		return Principal{}, false
	}
	p, ok := s.tokens[tok]
	return p, ok
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[len("bearer "):])
	}
	return ""
}

// ChainAuth tries each authenticator in order and accepts the first that
// authenticates the request. This is how OIDC/SSO (JWTAuth) and the air-gapped
// local-admin fallback (StaticAuth) coexist: configure JWT first, local-admin
// second. With no OIDC configured, only the local-admin authenticator is wired.
type ChainAuth struct {
	auths []Authenticator
}

// NewChainAuth composes authenticators, tried in order.
func NewChainAuth(auths ...Authenticator) *ChainAuth {
	return &ChainAuth{auths: auths}
}

// Authenticate returns the first successful principal, or ok=false if none match.
func (c *ChainAuth) Authenticate(r *http.Request) (Principal, bool) {
	for _, a := range c.auths {
		if p, ok := a.Authenticate(r); ok {
			return p, true
		}
	}
	return Principal{}, false
}

type principalKey struct{}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated principal placed on the context by the
// auth middleware.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// authMiddleware authenticates every request (fail-closed: no/invalid token →
// 401) and stashes the principal on the context.
func (a *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := a.auth.Authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// requireSuperAdmin returns middleware that admits only a super-admin principal
// (cross-tenant operator authority: tenant provisioning/erasure across tenants).
// A denied attempt on a privileged route is audited.
func (a *API) requireSuperAdmin(action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			if !p.SuperAdmin {
				a.audit.Write(AuditEntry{
					At: a.now(), Subject: p.Subject, Tenant: p.Tenant,
					Action: action, Result: "denied",
				})
				writeError(w, http.StatusForbidden, "super-admin required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireRole returns middleware that enforces a minimum role. A viewer hitting
// an analyst-only route (e.g. POST /v1/scans) gets 403 — authz is enforced
// server-side, never trusted from the client. A denied attempt on a privileged
// route is written to the append-only audit log.
func (a *API) requireRole(minRole Role, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			if roleRank(p.Role) < roleRank(minRole) {
				a.audit.Write(AuditEntry{
					At: a.now(), Subject: p.Subject, Tenant: p.Tenant,
					Action: action, Result: "denied",
				})
				writeError(w, http.StatusForbidden, "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
