package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"policy-engine/pkg/auth"
)

func stubOIDCServer(t *testing.T, key *rsa.PrivateKey, keyID string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":   srv.URL,
				"jwks_uri": srv.URL + "/protocol/openid-connect/certs",
			})
		case "/protocol/openid-connect/certs":
			n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
			json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{"kty": "RSA", "use": "sig", "kid": keyID, "alg": "RS256", "n": n, "e": e},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func makeTestToken(key *rsa.PrivateKey, keyID, issuer, subject, email string, groups []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":    issuer,
		"sub":    subject,
		"aud":    jwt.ClaimStrings{"test-client"},
		"exp":    now.Add(ttl).Unix(),
		"iat":    now.Unix(),
		"email":  email,
		"groups": groups,
		"jti":    "test-jti-123",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = keyID
	return tok.SignedString(key)
}

func TestVerifier_Verify(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := stubOIDCServer(t, key, "key1")

	ctx := context.Background()
	v, err := auth.NewVerifier(ctx, srv.URL, "test-client", "")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeTestToken(key, "key1", srv.URL, "alice", "alice@example.com", []string{"dev"}, time.Hour)
	if err != nil {
		t.Fatalf("makeTestToken: %v", err)
	}

	claims, err := v.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != "alice" {
		t.Errorf("Sub: got %q want %q", claims.Sub, "alice")
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("Email: got %q want %q", claims.Email, "alice@example.com")
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "dev" {
		t.Errorf("Groups: got %v want [dev]", claims.Groups)
	}
	if claims.Jti != "test-jti-123" {
		t.Errorf("Jti: got %q want %q", claims.Jti, "test-jti-123")
	}
}

func TestVerifier_InvalidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := stubOIDCServer(t, key, "key1")

	ctx := context.Background()
	v, err := auth.NewVerifier(ctx, srv.URL, "test-client", "")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if _, err = v.Verify(ctx, "not.a.token"); err == nil {
		t.Error("Verify invalid token: expected error, got nil")
	}
}

func TestVerifier_WrongKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := stubOIDCServer(t, key, "key1")

	ctx := context.Background()
	v, err := auth.NewVerifier(ctx, srv.URL, "test-client", "")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeTestToken(otherKey, "key1", srv.URL, "alice", "alice@example.com", nil, time.Hour)
	if err != nil {
		t.Fatalf("makeTestToken: %v", err)
	}

	if _, err = v.Verify(ctx, token); err == nil {
		t.Error("Verify with wrong key: expected error, got nil")
	}
}

func TestNewVerifier_Unreachable(t *testing.T) {
	// NewRemoteKeySet is lazy - creation always succeeds; error surfaces on Verify.
	ctx := context.Background()
	v, err := auth.NewVerifier(ctx, "http://localhost:1", "test-client", "")
	if err != nil {
		t.Fatalf("NewVerifier: unexpected error: %v", err)
	}
	if _, err := v.Verify(ctx, "any.token.here"); err == nil {
		t.Error("Verify on unreachable JWKS: expected error, got nil")
	}
}
