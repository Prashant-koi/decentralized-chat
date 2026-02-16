package client

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/curve25519"
)

type SessionState int

const (
	SessNone SessionState = iota
	SessWaiting
	SessReady
)

type Session struct {
	State SessionState

	MyEphPriv  []byte //32 bytes
	MyEphPub   []byte // 32 bytes
	PeerEphPub []byte

	SendKey []byte
	RecvKey []byte

	SendCtr uint64
	RecvCtr uint64

	Outbox []string // queued plaintext while handshake
}

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
	sendKey = okm[:32]
	recvKey = okm[:32]

	return
}

// startHandshake method initializes a session's cryptographic handshake by generating a
// fresh ephemeral keypair and moving the session into waiting state so it can negotiate
// encryption keys with another peer
func (s *Session) startHandshake() error {
	if s.State != SessNone {
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	s.MyEphPriv = priv.Seed()
	s.MyEphPub = pub[:32]
	s.State = SessWaiting
	return nil
}

func (s *Session) completeHandshake(peerPub []byte, initiator bool) error {
	send, recv, err := deriveSessionKeys(s.MyEphPriv, peerPub)
	if err != nil {
		return nil
	}

	if initiator {
		s.SendKey = send
		s.RecvKey = recv
	} else {
		s.SendKey = recv
		s.RecvKey = send
	}

	s.PeerEphPub = peerPub
	s.State = SessReady
	return nil
}
