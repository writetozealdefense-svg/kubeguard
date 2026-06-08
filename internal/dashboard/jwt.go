package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig configures real OIDC-style bearer-token verification (NFR-2).
type JWTConfig struct {
	Issuer      string // required iss claim
	Audience    string // required aud claim
	TenantClaim string // claim carrying the tenant/org (default "tenant")
	RoleClaim   string // claim carrying the role (default "role")
}

// JWTAuth verifies bearer tokens: real signature verification against a keyfunc,
// an allowlist of asymmetric algorithms (RS256/ES256) that rejects the `none`
// algorithm and HMAC algorithm-confusion attacks, and enforced issuer/audience/
// expiry. Claims map to a Principal (tenant + role).
type JWTAuth struct {
	keyfunc jwt.Keyfunc
	cfg     JWTConfig
}

// NewJWTAuth builds a verifier from config and a keyfunc (which resolves the
// signing key, e.g. from a JWKS — see NewJWKSKeyfunc). Defaults: tenant claim
// "tenant", role claim "role".
func NewJWTAuth(cfg JWTConfig, keyfunc jwt.Keyfunc) *JWTAuth {
	if cfg.TenantClaim == "" {
		cfg.TenantClaim = "tenant"
	}
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "role"
	}
	return &JWTAuth{keyfunc: keyfunc, cfg: cfg}
}

// Authenticate verifies the request's bearer token and maps it to a Principal.
func (j *JWTAuth) Authenticate(r *http.Request) (Principal, bool) {
	raw := bearerToken(r)
	if raw == "" {
		return Principal{}, false
	}
	claims := jwt.MapClaims{}
	opts := []jwt.ParserOption{
		// Only asymmetric algorithms — rejects "none" and HS* (algorithm
		// confusion where an attacker signs with the public key as an HMAC secret).
		jwt.WithValidMethods([]string{"RS256", "ES256", "RS384", "ES384", "RS512", "ES512"}),
		jwt.WithExpirationRequired(),
	}
	if j.cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(j.cfg.Issuer))
	}
	if j.cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(j.cfg.Audience))
	}
	tok, err := jwt.ParseWithClaims(raw, claims, j.keyfunc, opts...)
	if err != nil || !tok.Valid {
		return Principal{}, false
	}

	tenant, _ := claims[j.cfg.TenantClaim].(string)
	if tenant == "" {
		return Principal{}, false // every principal must be tenant-scoped
	}
	sub, _ := claims["sub"].(string)
	role := parseRole(claims[j.cfg.RoleClaim])
	return Principal{Subject: sub, Tenant: tenant, Role: role}, true
}

// parseRole maps a role claim (string) to a Role, defaulting to viewer (least
// privilege) when absent or unrecognized.
func parseRole(v any) Role {
	s, _ := v.(string)
	switch Role(s) {
	case RoleAdmin:
		return RoleAdmin
	case RoleAnalyst:
		return RoleAnalyst
	default:
		return RoleViewer
	}
}

// NewJWKSKeyfunc returns a jwt.Keyfunc backed by a remote JWKS endpoint (the
// OIDC/SSO seam). Keys are fetched once and cached; a token's `kid` header
// selects the verifying key. This is wired only when OIDC is configured
// (issuer + JWKS URL); with no OIDC config the dashboard runs local-admin only
// (air-gapped). See docs for the enable-step.
func NewJWKSKeyfunc(jwksURL string) jwt.Keyfunc {
	c := &jwksCache{url: jwksURL, client: &http.Client{Timeout: 5 * time.Second}}
	return c.keyfunc
}

type jwksCache struct {
	url    string
	client *http.Client
	mu     sync.RWMutex
	keys   *jose.JSONWebKeySet
}

func (c *jwksCache) keyfunc(tok *jwt.Token) (any, error) {
	kid, _ := tok.Header["kid"].(string)
	if k := c.lookup(kid); k != nil {
		return k, nil
	}
	if err := c.refresh(); err != nil {
		return nil, err
	}
	if k := c.lookup(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

func (c *jwksCache) lookup(kid string) any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.keys == nil {
		return nil
	}
	for _, k := range c.keys.Key(kid) {
		return k.Key // the parsed public key (e.g. *rsa.PublicKey)
	}
	return nil
}

func (c *jwksCache) refresh() error {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}
	c.mu.Lock()
	c.keys = &set
	c.mu.Unlock()
	return nil
}
