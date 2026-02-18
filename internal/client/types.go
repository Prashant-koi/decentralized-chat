package client

import "sync"

type SessionState int

type Invite struct { // this struct is used to encode the invite link as a JSON object before base64 encoding it for sharing
	Relay string `json:"relay"` // the relay address that the inviter is using
	Queue string `json:"queue"` // the mail id owned by the receiver that the inviter will send messages to
	Pub   string `json:"pub"`   // the inviter's pubkey in b64
}

type Envelope struct {
	Kind       string `json:"kind"`                  // "hs" or "ct" hs for handshake, ct for ciphertext
	FromPub    string `json:"from_pub,omitempty"`    // sender's pubkey in b64
	Eph        string `json:"eph,omitempty"`         // ephemeral pubkey in b64 for handshake messages
	Ctr        uint64 `json:"ctr,omitempty"`         // AEAD nonce/counter for ciphertext messages
	Body       string `json:"body,omitempty"`        // ciphertext in b64 for ciphertext messages
	ReplyQueue string `json:"reply_queue,omitempty"` // which queue the receiver should send responses to
}

type runtimeState struct { // this struct holds the runtime state of the client, including the contacts and sessions. It is protected by a mutex for concurrent access.
	mu           sync.Mutex
	addr         string              // relay address
	contactsPath string              // path to contacts JSON file
	myPubB64     string              // current client's pub key in b64
	contacts     map[string]*Contact // alias to contact info mapping
	sessions     map[string]*Session // alias to session mapping
}

type Session struct { // this struct holds the state of a session with a contact,
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

const (
	SessNone SessionState = iota
	SessWaiting
	SessReady
)
