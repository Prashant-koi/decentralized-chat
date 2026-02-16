package protocol

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
}
