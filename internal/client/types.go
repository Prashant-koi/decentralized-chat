package client

import "sync"

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