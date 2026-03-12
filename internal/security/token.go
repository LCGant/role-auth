package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func GenerateToken(n int) (string, string, error) {
	if n < 32 {
		n = 32
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("token generation failed: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	hash := HashToken(raw)
	return raw, hash, nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
