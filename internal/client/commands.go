package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func handleCommand(st *runtimeState, line string) error {
	// this function is the one that handles the commands that the user enters in the terminal
	// it parses the command and then calls the appropriate function to handle it

	switch {
	case line == "/help":
		printHelp()
		return nil
	case line == "/contacts":
		st.mu.Lock()
		defer st.mu.Unlock()
		for alias, c := range st.contacts {
			fmt.Printf("- %s send=%s recv=%s key=%s\n", alias, c.SendQueue, c.RecvQueue, fingerprintPubKey(c.TheirPubKey))
		}
		return nil
	case strings.HasPrefix(line, "/invite "):
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("usage: /invite <alias>")
		}
		return cmdInvite(st, strings.TrimSpace(parts[1]))
	case strings.HasPrefix(line, "/connect "):
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			return fmt.Errorf("usage: /connect <alias> <invite-token>")
		}
		return cmdConnect(st, parts[1], parts[2])
	case strings.HasPrefix(line, "/to "):
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			return fmt.Errorf("usage: /to <alias> <message>")
		}
		return cmdSend(st, parts[1], parts[2])
	default:
		return fmt.Errorf("unknown command use /help")

	}
}

func cmdInvite(st *runtimeState, alias string) error {
	// this function creates an invite token for a given alias and prints it to the terminal
	// the invite token is a base64 encoded JSON string that contains the relay address, the queue name, and the public key of the user

	st.mu.Lock()
	defer st.mu.Unlock()

	c := st.contacts[alias]
	if c == nil {
		c = &Contact{Alias: alias}
		st.contacts[alias] = c
	}
	if c.RecvQueue == "" {
		c.RecvQueue = randomToken(18)
	}
	if err := saveContactsBook(st.contactsPath, st.contacts); err != nil {
		return err
	}

	inv := Invite{
		Relay: st.addr,
		Queue: c.RecvQueue,
		Pub:   st.myPubB64,
	}
	raw, _ := json.Marshal(inv)
	token := base64.RawURLEncoding.EncodeToString(raw)

	fmt.Println("Share this invite out-of-band")
	fmt.Println(token)
	return nil
}

func cmdConnect(st *runtimeState, alias, token string) error {
	// this function takes an invite token and imports the contact information from it, it also pins the public key to the alias if it's not already pinned
	// the invite token is a base64 encoded JSON string that contains the relay address, the queue name, and the public key of the user
	// we also check for TOFU mismatch here if the alias already exists with a different pubkey we will return an error to avoid impersonation
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("invalid invite encoding")
	}
	var inv Invite
	if err := json.Unmarshal(raw, &inv); err != nil {
		return fmt.Errorf("invalid invite payload")
	}
	if inv.Queue == "" || inv.Pub == "" {
		return fmt.Errorf("invite missing queue/pub")
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	c := st.contacts[alias]
	if c == nil {
		c = &Contact{Alias: alias}
		st.contacts[alias] = c
	}
	if c.TheirPubKey != "" && c.TheirPubKey != inv.Pub {
		return fmt.Errorf("TOFU mismatch for %s", alias)
	}
	c.TheirPubKey = inv.Pub
	c.SendQueue = inv.Queue
	if c.RecvQueue == "" {
		c.RecvQueue = randomToken(18)
	}

	if err := saveContactsBook(st.contactsPath, st.contacts); err != nil {
		return err
	}

	fmt.Printf("[TOFU] pinned %s to %s\n", alias, fingerprintPubKey(c.TheirPubKey))
	fmt.Println("Tip: run /invite", alias, "and share back so they can reply to your queue.")
	return nil
}

func cmdSend(st *runtimeState, alias, text string) error {
	// this function sends a message to a given alias, it handles the encryption of the message and the handshake process if there is no established session with the alias
	st.mu.Lock()
	c := st.contacts[alias]
	if c == nil {
		st.mu.Unlock()
		return fmt.Errorf("unknown contact")
	}
	if c.SendQueue == "" {
		st.mu.Unlock()
		return fmt.Errorf("contact has no send queue. run /connect first")
	}
	if c.TheirPubKey == "" {
		st.mu.Unlock()
		return fmt.Errorf("contact has no pinned pubkey. run /connect first")
	}
	if c.RecvQueue == "" {
		c.RecvQueue = randomToken(18)
	}

	sess := st.sessions[alias]
	if sess == nil {
		sess = newSession()
		st.sessions[alias] = sess
	}

	// if there is no session then we will start handshake and queue plaintext
	if sess.State == SessNone {
		if err := sess.startHandshake(); err != nil {
			st.mu.Unlock()
			return err
		}
		env, err := buildHS1(st, sess, c.RecvQueue)
		if err != nil {
			st.mu.Unlock()
			return err
		}
		payload, _ := json.Marshal(env)
		sess.Outbox = append(sess.Outbox, text)
		queue := c.SendQueue
		st.mu.Unlock()
		return relayPut(st.addr, queue, string(payload))
	}

	// if the session is not ready we queue the palintext messages to be sent after the handshake is complete
	if sess.State != SessReady || !sess.Authenticated {
		sess.Outbox = append(sess.Outbox, text)
		st.mu.Unlock()
		return nil
	}

	// if the session is ready we encrypt the message and send it to the peer
	ctr := sess.SendCtr
	ct, err := encrypt(sess.SendKey, ctr, []byte(text))
	if err != nil {
		st.mu.Unlock()
		return err
	}
	sess.SendCtr++ // we increment the send counter after using it for encryption to maintain the correct order of messages and ensure replay protection

	env := Envelope{ // this is the ciphertext message that we send to the peer after the handshake is complete
		Kind:       "ct",
		FromPub:    st.myPubB64,
		Ctr:        ctr,
		Body:       base64.StdEncoding.EncodeToString(ct),
		ReplyQueue: c.RecvQueue,
	}

	payload, _ := json.Marshal(env)
	queue := c.SendQueue
	st.mu.Unlock()

	return relayPut(st.addr, queue, string(payload))
}
