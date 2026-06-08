package dashboard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const (
	testIssuer = "https://idp.example.com"
	testAud    = "kubeguard"
)

func baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":    testIssuer,
		"aud":    testAud,
		"sub":    "user-1",
		"tenant": "acme",
		"role":   "analyst",
		"exp":    time.Now().Add(time.Hour).Unix(),
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func reqWith(token string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/clusters", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func staticKeyfunc(pub any) jwt.Keyfunc {
	return func(_ *jwt.Token) (any, error) { return pub, nil }
}

func TestJWTValidRS256(t *testing.T) {
	key := rsaKey(t)
	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, staticKeyfunc(&key.PublicKey))
	p, ok := auth.Authenticate(reqWith(signRS256(t, key, "", baseClaims())))
	if !ok {
		t.Fatal("valid RS256 token rejected")
	}
	if p.Tenant != "acme" || p.Role != RoleAnalyst || p.Subject != "user-1" {
		t.Fatalf("claims->principal wrong: %+v", p)
	}
}

func TestJWTValidES256(t *testing.T) {
	key := ecKey(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, baseClaims())
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, staticKeyfunc(&key.PublicKey))
	if _, ok := auth.Authenticate(reqWith(raw)); !ok {
		t.Fatal("valid ES256 token rejected")
	}
}

func TestJWTRejectsExpired(t *testing.T) {
	key := rsaKey(t)
	c := baseClaims()
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, staticKeyfunc(&key.PublicKey))
	if _, ok := auth.Authenticate(reqWith(signRS256(t, key, "", c))); ok {
		t.Fatal("expired token accepted")
	}
}

func TestJWTRejectsWrongIssuerAndAudience(t *testing.T) {
	key := rsaKey(t)
	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, staticKeyfunc(&key.PublicKey))

	c := baseClaims()
	c["iss"] = "https://evil.example.com"
	if _, ok := auth.Authenticate(reqWith(signRS256(t, key, "", c))); ok {
		t.Fatal("wrong issuer accepted")
	}
	c = baseClaims()
	c["aud"] = "someone-else"
	if _, ok := auth.Authenticate(reqWith(signRS256(t, key, "", c))); ok {
		t.Fatal("wrong audience accepted")
	}
}

func TestJWTRejectsNoneAlg(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud},
		func(_ *jwt.Token) (any, error) { return jwt.UnsafeAllowNoneSignatureType, nil })
	if _, ok := auth.Authenticate(reqWith(raw)); ok {
		t.Fatal("alg=none token accepted")
	}
}

// TestJWTRejectsAlgorithmConfusion proves an attacker cannot take the RSA public
// key (which is public), use it as an HMAC secret to sign an HS256 token, and
// have it accepted. The asymmetric-only allowlist rejects HS*.
func TestJWTRejectsAlgorithmConfusion(t *testing.T) {
	key := rsaKey(t)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
	})
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
	raw, err := forged.SignedString(pubPEM) // HMAC secret = the public key bytes
	if err != nil {
		t.Fatal(err)
	}
	// A naive verifier would return the public key here and accept HS256.
	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, staticKeyfunc(pubPEM))
	if _, ok := auth.Authenticate(reqWith(raw)); ok {
		t.Fatal("HS256 algorithm-confusion token accepted")
	}
}

func TestJWTRequiresTenantClaim(t *testing.T) {
	key := rsaKey(t)
	c := baseClaims()
	delete(c, "tenant")
	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, staticKeyfunc(&key.PublicKey))
	if _, ok := auth.Authenticate(reqWith(signRS256(t, key, "", c))); ok {
		t.Fatal("token without tenant claim accepted")
	}
}

func TestJWTUnknownRoleDefaultsViewer(t *testing.T) {
	key := rsaKey(t)
	c := baseClaims()
	delete(c, "role")
	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, staticKeyfunc(&key.PublicKey))
	p, ok := auth.Authenticate(reqWith(signRS256(t, key, "", c)))
	if !ok || p.Role != RoleViewer {
		t.Fatalf("missing role should default to viewer, got ok=%v role=%s", ok, p.Role)
	}
}

// TestJWKSKeyfuncEndToEnd serves a JWKS over HTTP (a stand-in IdP — no external
// network) and verifies a token whose kid selects the published RSA key.
func TestJWKSKeyfuncEndToEnd(t *testing.T) {
	key := rsaKey(t)
	jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	auth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, NewJWKSKeyfunc(srv.URL))
	p, ok := auth.Authenticate(reqWith(signRS256(t, key, "k1", baseClaims())))
	if !ok {
		t.Fatal("JWKS-verified token rejected")
	}
	if p.Tenant != "acme" {
		t.Fatalf("tenant claim lost: %+v", p)
	}
	// A token with an unknown kid must not verify.
	if _, ok := auth.Authenticate(reqWith(signRS256(t, key, "unknown-kid", baseClaims()))); ok {
		t.Fatal("token with unknown kid accepted")
	}
}

func TestChainAuthFallsBackToLocalAdmin(t *testing.T) {
	key := rsaKey(t)
	jwtAuth := NewJWTAuth(JWTConfig{Issuer: testIssuer, Audience: testAud}, staticKeyfunc(&key.PublicKey))
	local := NewStaticAuth(map[string]Principal{
		"local-admin": {Subject: "admin", Tenant: "default", Role: RoleAdmin},
	})
	chain := NewChainAuth(jwtAuth, local)

	// A JWT-verified caller authenticates via the first authenticator.
	if p, ok := chain.Authenticate(reqWith(signRS256(t, key, "", baseClaims()))); !ok || p.Tenant != "acme" {
		t.Fatal("chain should accept a valid JWT")
	}
	// A local-admin token (not a JWT) falls through to the static authenticator.
	if p, ok := chain.Authenticate(reqWith("local-admin")); !ok || p.Role != RoleAdmin {
		t.Fatal("chain should fall back to local-admin")
	}
	// An unknown credential is rejected by all.
	if _, ok := chain.Authenticate(reqWith("garbage")); ok {
		t.Fatal("chain accepted an unknown credential")
	}
}
