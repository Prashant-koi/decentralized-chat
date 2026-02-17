package protocol

// Msg defines the structure of messages exchanged between clients and the server.
type RelayItem struct {
	MsgID   string `json:"msg_id,omitempty"`
	Payload string `json:"payload,omitempty"`
	TS      int64  `json:"ts,omitempty"`
}

type Msg struct {
	Type string `json:"type"`
	//Identity
	PubKey string `json:"pubkey,omitempty"`
	Nonce  string `json:"nonce,omitempty"` // base64 random nonce
	Sig    string `json:"sig,omitempty"`
	Handle string `json:"handle,omitempty"` // username handle for client an abstraction of Pubkey if you may

	// Routing
	To   string `json:"to,omitempty"`
	From string `json:"from,omitempty"`
	Text string `json:"text,omitempty"`
	ID   string `json:"id,omitempty"`

	// Who response
	Peers []Msg `json:"peers,omitempty"`

	//handshanke/encrypted filds
	Eph  string `json:"eph,omitempty"`  // base64 x25519 ephemeral pub
	Body string `json:"body,omitempty"` // base64 cipher text
	Ctr  uint64 `json:"ctr,omitempty"`  // replay protection counter

	// relay mailbox fields
	Queue   string      `json:"queue,omitempty"`  // which queue to push to or pull from
	MsgID   string      `json:"msg_id,omitempty"` // unique id for the message, client generated for send, server generated for recv
	Payload string      `json:"payload,omitempty"`
	AckIDs  []string    `json:"ask_ids,omitempty"` // for pull response, which msg ids are being acked by the client
	Items   []RelayItem `json:"items,omitempty"`
	Max     int         `json:"max,omitempty"`     // for pull, max number of messages to pull
	WaitMS  int         `json:"wait_ms,omitempty"` // for pull, how long to wait if no messages
}
