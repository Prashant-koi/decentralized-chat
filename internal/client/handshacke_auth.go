package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const maxHandshakeSkew = 5 * time.Minute

func canonicalHSBytes(env Envelope) []byte {
	// determinstic bytes for signing/verygying(Exclude sig)
	parts := []string{
		"hs-v1",
		env.Kind,
		env.HSKind,
		env.FromPub,
		env.Eph,
		env.ReplyQueue,
		env.MsgID,
		strconv.FormatInt(env.Ts, 10),
	}
	return []byte(strings.Join(parts, "|"))
}

func signHandshake(priv ed25519.PrivateKey, env Envelope) (string, error) {
	// this function will sign canonical handshake bytes and return the b64 signature
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}
	sig := ed25519.Sign(priv, canonicalHSBytes(env))
	return base64.StdEncoding.EncodeToString(sig), nil
}

func verifyHandshakeSig(pubB64 string, env Envelope) error {
	// this function will decode pinned pubkey and verify the signature of the handshake message
	// decode pinned pubkey from contact thier pubKey that is passed down to this func
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return fmt.Errorf("decode pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}

	// decode sig from env
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	// verify sig against canonical handshake bytes
	if !ed25519.Verify(ed25519.PublicKey(pub), canonicalHSBytes(env), sig) {
		return fmt.Errorf("invalid handshake signature")
	}
	return nil
}

func buildHS1(st *runtimeState, sess *Session, replyQueue string) (Envelope, error) {
	env := Envelope{
		Kind:       "hs",
		HSKind:     "hs1",
		FromPub:    st.myPubB64,
		Eph:        base64.StdEncoding.EncodeToString(sess.MyEphPub),
		ReplyQueue: replyQueue,
		MsgID:      randomToken(12),
		Ts:         time.Now().UnixMilli(),
	}
	sig, err := signHandshake(st.myPriv, env)
	if err != nil {
		return Envelope{}, err
	}
	env.Sig = sig
	return env, nil
}

func buildHS2(st *runtimeState, sess *Session, replyQueue string) (Envelope, error) {
	env := Envelope{
		Kind:       "hs",
		HSKind:     "hs2",
		FromPub:    st.myPubB64,
		Eph:        base64.StdEncoding.EncodeToString(sess.MyEphPub),
		ReplyQueue: replyQueue,
		MsgID:      randomToken(12),
		Ts:         time.Now().UnixMilli(),
	}
	sig, err := signHandshake(st.myPriv, env)
	if err != nil {
		return Envelope{}, err
	}
	env.Sig = sig
	return env, nil
}

func verifyHS1(st *runtimeState, alias string, env Envelope, c *Contact, sess *Session) error {
	// this function will enforce TOFU key match with signature and replay checks

	if env.Kind != "hs" || env.HSKind != "hs1" {
		return fmt.Errorf("invalid handshake kind or not hs1")
	}

	if sess == nil {
		return fmt.Errorf("nil session")
	}

	if sess.State != SessNone && sess.State != SessWaiting {
		return fmt.Errorf("invalid state for hs1: %v", sess.State)
	}

	return verifyHandshakeCommon(st, alias, env, c, sess)

}

func verifyHS2(st *runtimeState, alias string, env Envelope, c *Contact, sess *Session) error {
	// this function will enforce TOFU key match with signature and replay checks

	if env.Kind != "hs" || env.HSKind != "hs2" {
		return fmt.Errorf("invalid handshake kind or not hs2")
	}
	if sess == nil {
		return fmt.Errorf("nil session")
	}
	if sess.State != SessWaiting {
		return fmt.Errorf("invalid state for hs2: %v", sess.State)
	}
	return verifyHandshakeCommon(st, alias, env, c, sess)

}

func verifyHandshakeCommon(st *runtimeState, alias string, env Envelope, c *Contact, sess *Session) error {
	if c == nil {
		return fmt.Errorf("nil contact")
	}

	if env.FromPub == "" {
		return fmt.Errorf("missing from_pub")
	}

	if env.Sig == "" {
		return fmt.Errorf("missing signature")
	}

	if env.MsgID == "" {
		return fmt.Errorf("missing msg_id")
	}

	if env.Ts == 0 {
		return fmt.Errorf("missing timestamp")
	}

	if env.Eph == "" {
		return fmt.Errorf("missing eph")
	}

	// TOFU pin
	if c.TheirPubKey == "" {
		c.TheirPubKey = env.FromPub
		_ = saveContactsBook(st.contactsPath, st.contacts)
		fmt.Printf("[TOFU] pinned %s to %s\n", alias, fingerprintPubKey(c.TheirPubKey))
	} else if c.TheirPubKey != env.FromPub {
		return fmt.Errorf("TOFU mismatch for %s", alias)
	}

	// signature over cannonicl handshake bytes
	if err := verifyHandshakeSig(c.TheirPubKey, env); err != nil {
		return err
	}

	//timestamp skew check
	now := time.Now().UnixMilli()
	skew := now - env.Ts
	if skew < 0 {
		skew = -skew
	}
	if skew > maxHandshakeSkew.Milliseconds() {
		return fmt.Errorf("handshake timestamp outside allowed skew")
	}

	//eph pubkey shape check
	peerEph, err := base64.StdEncoding.DecodeString(env.Eph)
	if err != nil {
		return fmt.Errorf("invalid eph encoding: %w", err)
	}
	if len(peerEph) != 32 {
		return fmt.Errorf("invalid eph key length")
	}

	//reply check
	if sess.SeenMsgIDs == nil {
		sess.SeenMsgIDs = make(map[string]struct{})
	}
	if _, seen := sess.SeenMsgIDs[env.MsgID]; seen {
		return fmt.Errorf("replayed handshake msg_id")
	}
	sess.SeenMsgIDs[env.MsgID] = struct{}{}

	return nil
}
