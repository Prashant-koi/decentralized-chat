package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func newSession() *Session {
	return &Session{
		State: SessNone,
	}
}

// deriveSessionKeys derives symmetric session keys for an end-to-end encrypted
// connection using X25519 Diffie–Hellman key exchange and HKDF.
//
// This function takes the caller's X25519 private key and the peer's X25519
// public key, performs a Diffie–Hellman key agreement to compute a shared
// secret, and then uses HKDF-SHA256 to expand that shared secret into two
// independent 32-byte symmetric keys.
//
// The returned keys are intended to be used directionally:
//   - sendKey: used to encrypt messages sent to the peer
//   - recvKey: used to decrypt messages received from the peer
func deriveSessionKeys(myPriv, peerPub []byte) (sendKey, recvKey []byte, err error) {
	// Perform X25519 Diffie–Hellman key exchange to compute the shared secret.
	// Both peers independently compute the same shared value using their
	// private key and the other party's public key.
	if len(myPriv) != 32 || len(peerPub) != 32 {
		return nil, nil, fmt.Errorf("invalid x25519 key length")
	}

	shared, err := curve25519.X25519(myPriv, peerPub)
	if err != nil {
		return nil, nil, err
	}

	// Initialize HKDF using SHA-256 with the shared secret as input key material.
	h := hkdf.New(sha256.New, shared, nil, []byte("e2e-session"))

	// Read 64 bytes of output key material from HKDF.
	okm := make([]byte, 64)
	if _, err := io.ReadFull(h, okm); err != nil {
		return nil, nil, err
	}

	// Split the output key material into directional session keys.
	// The first half is used for sending, the second for receiving.
	sendKey = make([]byte, 32)
	recvKey = make([]byte, 32)
	copy(sendKey, okm[:32])
	copy(recvKey, okm[32:64])

	return sendKey, recvKey, nil
}

// startHandshake method initializes a session's cryptographic handshake by generating a
// fresh ephemeral keypair and moving the session into waiting state so it can negotiate
// encryption keys with another peer
func (s *Session) startHandshake() error {
	if s.State != SessNone {
		return nil
	}

	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return err
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return err
	}

	s.MyEphPriv = priv
	s.MyEphPub = pub
	s.State = SessWaiting
	return nil
}

// completeHandshake methods calls the deriveSessionKeys function to derive the shared
// symmetic keys from ephemeral key meterial, assignigng them based on who initiated the handshake
func (s *Session) completeHandshake(peerPub []byte, initiator bool) error {
	if len(peerPub) != 32 {
		return fmt.Errorf("invalid peer eph pub length")
	}
	if len(s.MyEphPriv) != 32 {
		return fmt.Errorf("local eph key not initialized")
	}

	send, recv, err := deriveSessionKeys(s.MyEphPriv, peerPub)
	if err != nil {
		return err
	}

	// the initiator is to check who initiated the handshake
	// the same sure both sides dervuve send, recv in the same order
	if initiator {
		s.SendKey = send
		s.RecvKey = recv
	} else {
		s.SendKey = recv
		s.RecvKey = send
	}

	s.PeerEphPub = append([]byte(nil), peerPub...)
	s.State = SessReady
	return nil
}

// encrypt function basically encrypts the message in the sender side before sending
// it to the reciever
func encrypt(key []byte, ctr uint64, msg []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	return aead.Seal(nil, nonce, msg, nil), nil
}

// decrypt function basically decrypts the message in the reciever side when they
// receive the message
func decrypt(key []byte, ctr uint64, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	return aead.Open(nil, nonce, ct, nil)
}
