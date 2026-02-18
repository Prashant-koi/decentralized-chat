package client

import (
	"bufio"
	"chat/internal/crypto"
	"chat/internal/protocol"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Invite struct {
	Relay string `json:"relay"`
	Queue string `json:"queue"`
	Pub   string `json:"pub"`
}

type Envelope struct {
	Kind       string `json:"kind"` // "hs" or "ct"
	FromPub    string `json:"from_pub,omitempty"`
	Eph        string `json:"eph,omitempty"`
	Ctr        uint64 `json:"ctr,omitempty"`
	Body       string `json:"body,omitempty"`
	ReplyQueue string `json:"reply_queue,omitempty"`
}

type runtimeState struct {
	mu           sync.Mutex
	addr         string
	contactsPath string
	myPubB64     string
	contacts     map[string]*Contact
	sessions     map[string]*Session
}

func Run(addr, profile string) error {
	/*
		This functions is the one that establishes the main connection with the server to regulate talking with other client(s)
		this function also runs the challenge solver function and the connection loop function that reads memssages from sevrer and
		other clinets
	*/

	if profile == "" {
		profile = "default"
	}

	dir := "profiles/" + profile
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	idPath := dir + "/id.key"
	contactsPath := dir + "/contacts.json"

	// we load the key from the file right now because we don't have the right methods ot so so
	pub, _, err := crypto.LoadOrCreateIdentity(idPath)
	if err != nil {
		return err
	}
	myPubB64 := base64.StdEncoding.EncodeToString(pub)

	contacts, err := loadContactsBook(contactsPath)
	if err != nil {
		return err
	}

	st := &runtimeState{
		addr:         addr,
		contactsPath: contactsPath,
		myPubB64:     myPubB64,
		contacts:     contacts,
		sessions:     make(map[string]*Session),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pollLoop(ctx, st)

	// all commands
	printHelp()

	in := bufio.NewScanner(os.Stdin) //reads our keyboard input

	for {
		fmt.Print("> ")
		if !in.Scan() {
			return nil //if false we bail out like keyboard inturrupt
		}

		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}

		if err := handleCommand(st, line); err != nil {
			fmt.Println("[Error]", err)
		}
	}

}

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
		env := Envelope{ // this is the initial handshake message that we send to the peer to start the handshake process
			Kind:       "hs",
			FromPub:    st.myPubB64,
			Eph:        base64.StdEncoding.EncodeToString(sess.MyEphPub),
			ReplyQueue: c.RecvQueue,
		}
		payload, _ := json.Marshal(env)
		sess.Outbox = append(sess.Outbox, text)
		st.mu.Unlock()
		return relayPut(st.addr, c.SendQueue, string(payload))
	}

	// if the session is not ready we queue the plaintext messages to be sent after the handshake is complete
	if sess.State != SessReady {
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

func pollLoop(ctx context.Context, st *runtimeState) {
	// this function runs in a loop and polls the server for new messages for each contact that has a receive queue,
	// it also handles the incoming messages and sends acknowledgments to the server for the messages that have been successfully processed
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		type target struct {
			alias string
			queue string
		}

		var targets []target

		st.mu.Lock()
		for alias, c := range st.contacts { // we look for contacts that have a receive queue to poll from, if they don't have a receive queue we skip them
			if c.RecvQueue != "" {
				targets = append(targets, target{alias: alias, queue: c.RecvQueue})
			}
		}
		st.mu.Unlock()

		if len(targets) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}

		for _, t := range targets { // we loop through the targets and poll the server for new messages for each target
			resp, err := relayRequest(st.addr, protocol.Msg{Type: "poll", Queue: t.queue, Max: 32, WaitMS: 1200})
			if err != nil || resp.Type != "poll_resp" {
				continue
			}

			if len(resp.Items) == 0 {
				continue
			}

			// we handle each incoming message and if the handling is successful we acknowledge the message to the server to remove it from the queue
			ack := make([]string, 0, len(resp.Items))
			for _, it := range resp.Items {
				if err := handleEnvelope(st, t.alias, it.Payload); err == nil {
					ack = append(ack, it.MsgID)
				}
			}
			if len(ack) > 0 { // if we have any messages to acknowledge we send an ack request to the server with the message ids of the messages we have successfully processed
				_, _ = relayRequest(st.addr, protocol.Msg{
					Type:   "ack",
					Queue:  t.queue,
					AckIDs: ack,
				})
			}
		}
	}
}

func handleEnvelope(st *runtimeState, alias, payload string) error {
	// this function handles the incoming messages from the server for a given alias, it parses the message and then processes it based on the type of the message
	// for handshake messages we complete the handshake process and for ciphertext messages we decrypt them and print them to the terminal
	var env Envelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		return err
	}

	var toSend []struct {
		queue   string
		payload string
	}

	st.mu.Lock()
	c := st.contacts[alias]
	if c == nil {
		c = &Contact{Alias: alias}
		st.contacts[alias] = c
	}
	if env.FromPub != "" { // here we check the TOFU for inpersination
		if c.TheirPubKey == "" {
			c.TheirPubKey = env.FromPub
			_ = saveContactsBook(st.contactsPath, st.contacts)
			fmt.Printf("[TOFU] pinned %s to %s\n", alias, fingerprintPubKey(c.TheirPubKey))
		} else if c.TheirPubKey != env.FromPub {
			st.mu.Unlock()
			return fmt.Errorf("TOFU mismatch!!")
		}
	}
	if env.ReplyQueue != "" && c.SendQueue == "" {
		c.SendQueue = env.ReplyQueue
		_ = saveContactsBook(st.contactsPath, st.contacts)
	}

	// we check if there is a session if not then we start a new session
	sess := st.sessions[alias]
	if sess == nil {
		sess = newSession()
		st.sessions[alias] = sess
	}

	switch env.Kind {
	case "hs": // this is a handshake message that we receive from the peer to complete the handshake process
		peerEph, err := base64.StdEncoding.DecodeString(env.Eph)
		if err != nil {
			st.mu.Unlock()
			return err
		}

		responderStarted := false
		if sess.State == SessNone {
			if err := sess.startHandshake(); err != nil {
				st.mu.Unlock()
				return err
			}
			responderStarted = true

			replyEnv := Envelope{ // this is the handshake message that we send back to the peer to complete the handshake process if we are the responder
				Kind:       "hs",
				FromPub:    st.myPubB64,
				Eph:        base64.StdEncoding.EncodeToString(sess.MyEphPub),
				ReplyQueue: c.RecvQueue,
			}
			b, _ := json.Marshal(replyEnv)
			toSend = append(toSend, struct {
				queue   string
				payload string
			}{queue: c.SendQueue, payload: string(b)})
		}

		// if we recieve handshake we are the responder if we started handshake we are the initiator, this makes sure we derive the correct shared keys
		initiator := !responderStarted && sess.State == SessWaiting
		if err := sess.completeHandshake(peerEph, initiator); err != nil {
			st.mu.Unlock()
			return err
		}

		for _, msg := range sess.Outbox {
			ctr := sess.SendCtr
			ct, err := encrypt(sess.SendKey, ctr, []byte(msg))
			if err != nil {
				continue
			}
			sess.SendCtr++
			out := Envelope{ // this is the ciphertext message that we send to the peer after the handshake is complete
				Kind:       "ct",
				FromPub:    st.myPubB64,
				Ctr:        ctr,
				Body:       base64.StdEncoding.EncodeToString(ct),
				ReplyQueue: c.RecvQueue,
			}
			b, _ := json.Marshal(out)
			toSend = append(toSend, struct {
				queue   string
				payload string
			}{queue: c.SendQueue, payload: string(b)})
		}
		sess.Outbox = nil
	case "ct": // this is a ciphertext message that we receive from the peer and we need to decrypt it and print it to the terminal
		if sess.State != SessReady {
			st.mu.Unlock()
			return fmt.Errorf("cipher before ready session")
		}
		ct, err := base64.StdEncoding.DecodeString(env.Body)
		if err != nil {
			st.mu.Unlock()
			return err
		}
		pt, err := decrypt(sess.RecvKey, env.Ctr, ct)
		if err != nil {
			st.mu.Unlock()
			return err
		}
		if env.Ctr >= sess.RecvCtr {
			sess.RecvCtr = env.Ctr + 1
		}
		fmt.Printf("[%s] %s\n", alias, string(pt))
	}
	st.mu.Unlock()

	for _, s := range toSend {
		if s.queue == "" || s.payload == "" {
			continue
		}
		_ = relayPut(st.addr, s.queue, s.payload)
	}
	return nil

}

func relayPut(addr, queue, payload string) error {
	// this function is a helper function that sends a "put" request to the relay server to send a message to a given queue
	_, err := relayRequest(addr, protocol.Msg{
		Type:    "put",
		Queue:   queue,
		MsgID:   randomToken(12),
		Payload: payload,
	})
	return err
}

func relayRequest(addr string, req protocol.Msg) (protocol.Msg, error) {
	// this function is a helper function that sends a request to the relay server and waits for the response
	// this basically handels th low level details of connection to the server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return protocol.Msg{}, err
	}
	defer conn.Close()

	b, _ := json.Marshal(req)
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return protocol.Msg{}, err
	}

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	if !sc.Scan() {
		return protocol.Msg{}, fmt.Errorf("no response")
	}
	var resp protocol.Msg
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return protocol.Msg{}, err
	}
	if resp.Type == "error" {
		return resp, errors.New(resp.Text)
	}
	return resp, nil
}

// this generates a random token of a given length and encodes it in base64
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
