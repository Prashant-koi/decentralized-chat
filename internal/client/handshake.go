package client

import (
	"bufio"
	"chat/internal/protocol"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
)

func solveChallenge(conn net.Conn, sc *bufio.Scanner, pub ed25519.PublicKey, priv ed25519.PrivateKey, handle string) error {
	/*
		since the server sends the client a challenge to find out if the client has the correct public key and
		they are who they say they are, we have to solve the challenge and send them back an "hello" message
		for this function we take the existing connection from Run() function to not create a dreadlock
		and the we also get our stored public key and private key for cross referencing and sending the
		public key and signature to the server for it to authenticate. NEVER send Private Key to the server
	*/
	var ch protocol.Msg
	if err := json.Unmarshal(sc.Bytes(), &ch); err != nil || ch.Type != "challenge" || ch.Nonce == "" {
		return fmt.Errorf("bad challenge from server")
	}

	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		return fmt.Errorf("bad nonce")
	}

	sig := ed25519.Sign(priv, nonce)

	hello := protocol.Msg{
		Type:   "hello",
		PubKey: base64.StdEncoding.EncodeToString(pub),
		Sig:    base64.StdEncoding.EncodeToString(sig),
		Handle: handle,
	}

	b, _ := json.Marshal(hello)
	b = append(b, '\n')

	if _, err := conn.Write(b); err != nil {
		return err
	}
	return nil
}
