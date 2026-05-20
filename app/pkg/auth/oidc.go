package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCClaims struct {
	Sub    string
	Email  string
	Groups []string
	Jti    string
}

type Verifier struct {
	verifier *oidc.IDTokenVerifier
}

// NewVerifier creates an OIDC verifier.
// discoveryURL  - internal cluster URL used to fetch JWKS (e.g. http://keycloak:8080/...)
// tokenIssuerURL - expected "iss" claim in tokens (external/frontendUrl, e.g. http://localhost:8081/...)
// When tokenIssuerURL differs from discoveryURL the JWKS endpoint is rewritten
// to use discoveryURL as the base, so the pod can reach it.
func NewVerifier(ctx context.Context, discoveryURL, clientID, tokenIssuerURL string) (*Verifier, error) {
	issuer := discoveryURL
	jwksURL := discoveryURL + "/protocol/openid-connect/certs"

	// If the token issuer is the external URL, we need to rewrite the JWKS URL to use the internal discovery URL, so the pod can fetch it.
	if tokenIssuerURL != "" && tokenIssuerURL != discoveryURL {
		issuer = tokenIssuerURL
	}

	keySet := oidc.NewRemoteKeySet(ctx, jwksURL)
	verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
		ClientID:          clientID,
		SkipClientIDCheck: true,
	})
	return &Verifier{verifier: verifier}, nil
}

func (v *Verifier) Verify(ctx context.Context, rawIDToken string) (*OIDCClaims, error) {
	token, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc verify: %w", err)
	}
	var extra struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
		Jti    string   `json:"jti"`
	}
	if err := token.Claims(&extra); err != nil {
		return nil, fmt.Errorf("oidc claims: %w", err)
	}
	return &OIDCClaims{
		Sub:    token.Subject,
		Email:  extra.Email,
		Groups: extra.Groups,
		Jti:    extra.Jti,
	}, nil
}
