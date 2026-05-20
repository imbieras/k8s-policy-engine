package auth

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Sub string
}

// VerifyJWT validates an HS256-signed JWT against secret and returns the claims.
func VerifyJWT(tokenString, secret string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}
	tok, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	mapClaims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token claims")
	}
	sub, _ := mapClaims["sub"].(string)
	return &Claims{Sub: sub}, nil
}
