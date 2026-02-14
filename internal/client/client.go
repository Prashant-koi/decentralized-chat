package client

import (
	"bufio"
	"chat/internal/crypto"
	"chat/internal/protocol"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

func solveChallenge(conn net.Conn, sc *bufio.Scanner, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {

	var ch protocol.Msg
	if err := json.Unmarshal(sc.Bytes(), &ch); err != nil || ch.Type != "challenge" || ch.Nonce == "" {
		return fmt.Errorf("bad challenge from server")
	}

	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		return fmt.Errorf("bad nonce")
	}

	sig := ed25519.Sign(priv, nonce)

	hello := protocol.Msg{
		Type:   "hello",
		PubKey: base64.StdEncoding.EncodeToString(pub),
		Sig:    base64.StdEncoding.EncodeToString(sig),
	}

	b, _ := json.Marshal(hello)
	b = append(b, '\n')

	if _, err := conn.Write(b); err != nil {
		return err
	}
	return nil
}

func Run(addr string) error {
	path := os.Getenv("CHAT_ID_FILE")
	if path == "" {
		path = "./id.key"
	}
	pub, priv, err := crypto.LoadOrCreateIdentity(path)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	defer conn.Close()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)

	if !sc.Scan() {
		return fmt.Errorf("Server disconnected")
	}

	if err := solveChallenge(conn, sc, pub, priv); err != nil {
		return err
	}

	// read server messages
	go readLoop(sc)

	printHelp()

	in := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !in.Scan() {
			return nil
		}

		to, text, ok := parseCommand(strings.TrimSpace(in.Text()))
		if !ok {
			continue
		}

		m := protocol.Msg{Type: "send", To: to, Text: text}
		b, _ := json.Marshal(m)
		b = append(b, '\n')

		if _, err := conn.Write(b); err != nil {
			fmt.Println("disconnected")
			return err
		}
	}
}

func readLoop(sc *bufio.Scanner) {
	for sc.Scan() {
		var m protocol.Msg
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			fmt.Println("<< bad message from server >>")
			continue
		}
		switch m.Type {
		case "welcome":
			fmt.Printf("[server] your id: %s\n", m.ID)
			fmt.Printf("[server] %s\n", m.Text)
		case "msg":
			fmt.Printf("[%s] %s\n", m.From, m.Text)
		case "error":
			fmt.Printf("[error] %s\n", m.Text)
		default:
			fmt.Printf("[server] %+v\n", m)
		}
	}

	// server closed the connection
	os.Exit(0)
}

func printHelp() {
	fmt.Println("Commands:")
	fmt.Println("  /all <msg>           broadcast")
	fmt.Println("  /to <id> <msg>       send to one user")
	fmt.Println("  /who                 list online")
	fmt.Println()
}

func parseCommand(line string) (to string, text string, ok bool) {
	if line == "" {
		return "", "", false
	}

	if strings.HasPrefix(line, "/to ") {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			fmt.Println("usage: /to <id> <msg>")
			return "", "", false
		}
		return parts[1], parts[2], true
	}

	if strings.HasPrefix(line, "/all ") {
		return "", strings.TrimPrefix(line, "/all "), true
	}

	if line == "/who" {
		return "", "/who", true
	}

	fmt.Println("unknown command, use /all, /to, /who")
	return "", "", false
}
