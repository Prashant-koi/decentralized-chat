package client

import (
	"crypto/rand"
	"encoding/base64"
)

// this generates a random token of a given length and encodes it in base64
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
