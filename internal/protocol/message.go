package protocol

type Msg struct {
	Type string `json:"type"`
	//Identity
	PubKey string `json:"pubkey,omitempty"`
	Nonce  string `json:"nonce,omitempty"` //base64 random nonce
	Sig    string `json:"sig,omitempty"`

	// Routing
	To   string `json:"to,omitempty"`
	From string `json:"from,omitempty"`
	Text string `json:"text,omitempty"`
	ID   string `json:"id,omitempty"`
}
