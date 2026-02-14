package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
)

type Msg struct {
	Type string `json:"type"`
	To   string `json:"to,omitempty"`
	From string `json:"from,omitempty"`
	Text string `json:"text,omitempty"`
	ID   string `json:"id,omitempty"`
}

type Client struct {
	id   string
	conn net.Conn
	send chan []byte
}

var (
	mu      sync.Mutex
	nextID  int
	clients = map[string]*Client{}
)

// the server will create an unique client ID right now
// for communication
// reminder this implementation will probably chance later since
// we are going decentralized
func newClientID() string {
	mu.Lock()
	defer mu.Unlock()
	nextID++
	return fmt.Sprintf("c%d", nextID)
}

func addClient(c *Client) {
	mu.Lock()
	defer mu.Unlock()
	clients[c.id] = c
}

func removeClient(id string) {
	mu.Lock()
	defer mu.Unlock()
	delete(clients, id)
}

func getClient(id string) (*Client, bool) {
	mu.Lock()
	defer mu.Unlock()
	c, ok := clients[id]
	return c, ok
}

func listClient() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(clients))
	for id := range clients {
		out = append(out, id)
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
func sendJSON(c *Client, m Msg) {
	b, _ := json.Marshal(m)
	b = append(b, '\n')
	select {
	case c.send <- b:
	default:

	}
}

func broadcast(fromID string, m Msg) {
	mu.Lock()
	defer mu.Unlock()

	for id, c := range clients {
		if id == fromID {
			continue
		}
		sendJSON(c, m)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	c := &Client{
		id:   newClientID(),
		conn: conn,
		send: make(chan []byte, 32),
	}
	addClient(c)
	defer removeClient(c.id)

	go writeLoop(c)

	//welcome message and join  message
	sendJSON(c, Msg{Type: "welcome", ID: c.id, Text: "Use /all <msg> or /to <id> <msg> or /who"})

	broadcast(c.id, Msg{Type: "msg", From: "server", Text: fmt.Sprintf("%s joined", c.id)})

	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Bytes()

		var m Msg
		if err := json.Unmarshal(line, &m); err != nil {
			sendJSON(c, Msg{Type: "error", Text: "bad json"})
			continue
		}

		if m.Type != "send" {
			sendJSON(c, Msg{Type: "error", Text: "unknown type"})
			continue
		}

		text := m.Text
		if text == "/who" {
			sendJSON(c, Msg{Type: "msg", From: "server", Text: fmt.Sprintf("online: %v", listClient())})
			continue
		}

		//route
		if m.To != "" {
			target, ok := getClient(m.To)
			if !ok {
				sendJSON(c, Msg{Type: "error", Text: "no such client"})
				continue
			}
			sendJSON(target, Msg{Type: "msg", From: c.id, Text: text})
		} else {
			broadcast(c.id, Msg{Type: "msg", From: c.id, Text: text})
		}
	}

	//announce leave
	broadcast(c.id, Msg{Type: "msg", From: "server", Text: fmt.Sprintf("%s left", c.id)})
}

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:9000")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Server listening on 127.0.0.1:9000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}
		go handleConn(conn)
	}
}
