package auth_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authpkg "policy-engine/pkg/auth"
)

const testSecret = "test-secret-32-bytes-long-padded"

func makeToken(sub string, ttl time.Duration) string {
	claims := jwt.MapClaims{
		"sub": sub,
		"exp": time.Now().Add(ttl).Unix(),
		"iat": time.Now().Unix(),
	}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	return tok
}

func TestVerify_Valid(t *testing.T) {
	tok := makeToken("alice", time.Hour)
	claims, err := authpkg.VerifyJWT(tok, testSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub != "alice" {
		t.Fatalf("got sub=%q, want alice", claims.Sub)
	}
}

func TestVerify_Expired(t *testing.T) {
	tok := makeToken("bob", -time.Minute)
	_, err := authpkg.VerifyJWT(tok, testSecret)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerify_BadSignature(t *testing.T) {
	tok := makeToken("carol", time.Hour)
	_, err := authpkg.VerifyJWT(tok, "wrong-secret")
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestVerify_EmptyToken(t *testing.T) {
	_, err := authpkg.VerifyJWT("", testSecret)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}
