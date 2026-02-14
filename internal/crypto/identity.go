package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
)

func LoadOrCreateIdentity(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	/* we will first try load the private key first if it exists
	then if it doesn't we will just create it and store it for future use
	*/
	if b, err := os.ReadFile(path); err == nil {
		raw, err := base64.StdEncoding.DecodeString(string(b))
		if err != nil {
			return nil, nil, err
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, nil, errors.New("Bad private key size")
		}
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)), 0600); err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}
