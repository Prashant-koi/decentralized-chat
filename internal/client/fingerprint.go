package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// this function generates a short fingerprint of a base64 encoded public key for display purposes
func fingerprintPubKey(pubB64 string) string {
	if pubB64 == "" {
		return ""
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
