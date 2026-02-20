package client

import (
	"chat/internal/protocol"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type outbound struct {
	queue   string
	payload string
}

func appendOutboxEncrypted(st *runtimeState, c *Contact, sess *Session, toSend *[]outbound) {
	for _, msg := range sess.Outbox {
		ctr := sess.SendCtr
		ct, err := encrypt(sess.SendKey, ctr, []byte(msg))
		if err != nil {
			continue
		}
		sess.SendCtr++
		out := Envelope{
			Kind:       "ct",
			FromPub:    st.myPubB64,
			Ctr:        ctr,
			Body:       base64.StdEncoding.EncodeToString(ct),
			ReplyQueue: c.RecvQueue,
		}
		b, _ := json.Marshal(out)
		*toSend = append(*toSend, outbound{queue: c.SendQueue, payload: string(b)})
	}
	sess.Outbox = nil
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

	var toSend []outbound

	st.mu.Lock()
	c := st.contacts[alias]
	if c == nil {
		c = &Contact{Alias: alias}
		st.contacts[alias] = c
	}

	sess := st.sessions[alias]
	if sess == nil {
		sess = newSession()
		st.sessions[alias] = sess
	}

	switch env.Kind {
	case "hs": // this is a handshake message that we receive from the peer to complete the handshake process
		switch env.HSKind {
		case "hs1": // this is the first handshake message that we receive from the peer, we need to verify the signature and the replay protection
			if err := verifyHS1(st, alias, env, c, sess); err != nil {
				st.mu.Unlock()
				return err
			}
			if env.ReplyQueue != "" && c.SendQueue == "" {
				c.SendQueue = env.ReplyQueue
				_ = saveContactsBook(st.contactsPath, st.contacts)
			}

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
			}

			initiator := !responderStarted && sess.State == SessWaiting
			if err := sess.completeHandshake(peerEph, initiator); err != nil {
				st.mu.Unlock()
				return err
			}
			sess.Authenticated = true

			if responderStarted {
				hs2, err := buildHS2(st, sess, c.RecvQueue)
				if err != nil {
					st.mu.Unlock()
					return err
				}
				b, _ := json.Marshal(hs2)
				toSend = append(toSend, outbound{queue: c.SendQueue, payload: string(b)})
			}

			appendOutboxEncrypted(st, c, sess, &toSend)

		case "hs2": // this is the second handshake message that we receive from the peer, we need to verify the signature and complete the handshake process
			if err := verifyHS2(st, alias, env, c, sess); err != nil {
				st.mu.Unlock()
				return err
			}
			if env.ReplyQueue != "" && c.SendQueue == "" {
				c.SendQueue = env.ReplyQueue
				_ = saveContactsBook(st.contactsPath, st.contacts)
			}

			peerEph, err := base64.StdEncoding.DecodeString(env.Eph)
			if err != nil {
				st.mu.Unlock()
				return err
			}
			if err := sess.completeHandshake(peerEph, true); err != nil {
				st.mu.Unlock()
				return err
			}
			sess.Authenticated = true
			appendOutboxEncrypted(st, c, sess, &toSend)

		default:
			st.mu.Unlock()
			return fmt.Errorf("unknown handshake subtype")
		}

	case "ct": // this is a ciphertext message that we receive from the peer and we need to decrypt it and print it to the terminal
		if sess.State != SessReady || !sess.Authenticated {
			st.mu.Unlock()
			return fmt.Errorf("cipher before authenticated session")
		}
		if c.TheirPubKey != "" && env.FromPub != "" && env.FromPub != c.TheirPubKey {
			st.mu.Unlock()
			return fmt.Errorf("cipher from unexpected identity key")
		}

		ct, err := base64.StdEncoding.DecodeString(env.Body)
		if err != nil {
			st.mu.Unlock()
			return err
		}
		if env.Ctr < sess.RecvCtr {
			st.mu.Unlock()
			return fmt.Errorf("replayed/out-of-order counter")
		}
		pt, err := decrypt(sess.RecvKey, env.Ctr, ct)
		if err != nil {
			st.mu.Unlock()
			return err
		}
		sess.RecvCtr = env.Ctr + 1
		fmt.Printf("[%s] %s\n", alias, string(pt))

	default:
		st.mu.Unlock()
		return fmt.Errorf("unknown envelope kind")
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
