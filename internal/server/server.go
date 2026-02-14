package server

import (
	"bufio"
	"chat/internal/protocol"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

type Client struct {
	pub    string
	handle string
	conn   net.Conn
	send   chan []byte
}

var (
	mu      sync.Mutex
	clients = map[string]*Client{}
	handle  = map[string]string{}
)

func addClient(c *Client) error {
	/*
		return false if a client that is already connected is
		trying to connect else true
	*/
	mu.Lock()
	defer mu.Unlock()

	if _, exists := clients[c.pub]; exists {
		return fmt.Errorf("pubkey already exists")
	}

	if _, exists := handle[c.handle]; exists {
		return fmt.Errorf("handle already taken")
	}

	clients[c.pub] = c
	handle[c.handle] = c.pub
	return nil
}

func removeClient(pub string) {
	mu.Lock()
	defer mu.Unlock()

	if c, ok := clients[pub]; ok {
		delete(handle, c.handle)
	}

	delete(clients, pub)
}

func getClient(pub string) (*Client, bool) {
	mu.Lock()
	defer mu.Unlock()
	c, ok := clients[pub]
	return c, ok
}

func listHandles() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(handle))
	for h := range handle {
		out = append(out, h)
		out = append(out, ",")
	}
	return out
}

func writeLoop(c *Client) {
	for b := range c.send {
		_, err := c.conn.Write(b)
		if err != nil {
			return
		}
	}
}

// while sending if their send buffer is full
// we drop to keep simple
func sendJSON(c *Client, m protocol.Msg) {
	b, _ := json.Marshal(m)
	b = append(b, '\n')
	select {
	case c.send <- b:
	default:

	}
}

func broadcast(fromID string, m protocol.Msg) {
	mu.Lock()
	defer mu.Unlock()

	for id, c := range clients {
		if id == fromID {
			continue
		}
		sendJSON(c, m)
	}
}

func clientAuth(c *Client, sc *bufio.Scanner) (protocol.Msg, error) {
	/*
		We need to make sure that the client is the one with the public key
		that is why we send a little challenge to the client expecting a hello
		with pubkey and signature and we crossvalidate those and then verify the
		signature at last after that in the handleConn function we proceed as normal
	*/

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return protocol.Msg{}, err
	}

	nonceb64 := base64.StdEncoding.EncodeToString(nonce)
	sendJSON(c, protocol.Msg{Type: "challenge", Nonce: nonceb64})

	if !sc.Scan() {
		return protocol.Msg{}, fmt.Errorf("scan failed")
	}

	var hello protocol.Msg
	if err := json.Unmarshal(sc.Bytes(), &hello); err != nil {
		sendJSON(c, protocol.Msg{Type: "error", Text: "bad JSON"})
		return protocol.Msg{}, err
	}

	if hello.Type != "hello" || hello.PubKey == "" || hello.Sig == "" {
		sendJSON(c, protocol.Msg{Type: "error", Text: "expected hello, didn't get"})
		return protocol.Msg{}, fmt.Errorf("didn't get hello")
	}

	pubBytes, err := base64.StdEncoding.DecodeString(hello.PubKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		sendJSON(c, protocol.Msg{Type: "error", Text: "Bad public key"})
		return protocol.Msg{}, err
	}

	sigBytes, err := base64.StdEncoding.DecodeString(hello.Sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		sendJSON(c, protocol.Msg{Type: "error", Text: "Bad Signature"})
		return protocol.Msg{}, err
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), nonce, sigBytes) {
		sendJSON(c, protocol.Msg{Type: "error", Text: "Signature not verified"})
		return protocol.Msg{}, fmt.Errorf("signature verification failed")
	}

	return hello, nil

}

func resolveToPub(to string) string {
	/*
		this function resolved handle to the publick key while sending a message
	*/
	mu.Lock()
	defer mu.Unlock()

	if pub, ok := handle[to]; ok {
		return pub
	}

	return to //we will allow raw public key too
}

// HandleConn manages a single client lifecycle.
func HandleConn(conn net.Conn) {
	/*
		first verify the client is actually the one who they say they are and
		then proceed normally
	*/
	defer conn.Close()

	c := &Client{
		pub:  "",
		conn: conn,
		send: make(chan []byte, 32),
	}

	go writeLoop(c)
	defer close(c.send)
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)

	hello, err := clientAuth(c, sc)
	if err != nil {
		sendJSON(c, protocol.Msg{Type: "error", Text: err.Error()})
		return
	}

	c.pub = hello.PubKey
	c.handle = hello.Handle
	if c.handle == "" {
		sendJSON(c, protocol.Msg{Type: "error", Text: "handle required"})
		return
	}

	if err := addClient(c); err != nil {
		sendJSON(c, protocol.Msg{Type: "error", Text: err.Error()})
		return
	}

	defer removeClient(c.pub)

	//welcome message and join message
	sendJSON(c, protocol.Msg{Type: "welcome", ID: c.pub, Text: "Use /all <msg> or /to <id> <msg> or /who"})

	broadcast(c.pub, protocol.Msg{Type: "msg", From: "server", Text: fmt.Sprintf("%s joined", c.handle)})

	for sc.Scan() {
		line := sc.Bytes()

		var m protocol.Msg
		if err := json.Unmarshal(line, &m); err != nil {
			sendJSON(c, protocol.Msg{Type: "error", Text: "bad json"})
			continue
		}

		if m.Type != "send" {
			sendJSON(c, protocol.Msg{Type: "error", Text: "unknown type"})
			continue
		}

		text := m.Text
		if text == "/who" {
			sendJSON(c, protocol.Msg{Type: "msg", From: "server", Text: fmt.Sprintf("online: %v", listHandles())})
			continue
		}

		//route
		if m.To != "" {
			toPub := resolveToPub(m.To)
			target, ok := getClient(toPub)
			if !ok {
				sendJSON(c, protocol.Msg{Type: "error", Text: "no such client"})
				continue
			}
			sendJSON(target, protocol.Msg{Type: "msg", From: c.pub, Text: text})
		} else {
			broadcast(c.pub, protocol.Msg{Type: "msg", From: c.pub, Text: text})
		}
	}

	//announce leave
	broadcast(c.pub, protocol.Msg{Type: "msg", From: "server", Text: fmt.Sprintf("%s left", c.pub)})
}
