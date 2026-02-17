package client

import (
	"bufio"
	"chat/internal/crypto"
	"chat/internal/protocol"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

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
	pub, priv, err := crypto.LoadOrCreateIdentity(idPath)
	if err != nil {
		return err
	}

	contacts, err := loadContacts(contactsPath)
	if err != nil {
		return err
	}

	//ask the user for handel before opening a connection
	handle, err := askHandle()
	if err != nil {
		return err
	}

	//whoCache is gonna be out temporary in memory directory of who is currently online and what pub key they claim
	//without this we could message users blindly
	whoCache := make(map[string]string)

	// shared per-peer E2E sessions (used by both goroutines)
	sessions := make(map[string]*Session)

	//open a network connection using tcp to server address
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close() //setup the connection to close after the function ends

	// wrapping the TCP connection(conn) with a scanner to read data more easily
	// also I have set a 1MB buffer for scanner
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	if !sc.Scan() {
		return fmt.Errorf("Server disconnected")
	}

	// when server first makes connection it sends challenege and this function runs to solve that challenge
	if err := solveChallenge(conn, sc, pub, priv, handle); err != nil {
		return err
	}

	// read server messages
	go readLoop(sc, conn, contactsPath, contacts, whoCache, sessions)

	// all commands
	printHelp()

	in := bufio.NewScanner(os.Stdin)                      //reads our keyboard input
	writeLoop(in, conn, contactsPath, contacts, whoCache, sessions) //this function will send whtever we write to the server if it is legal

	return nil
}

func writeLoop(in *bufio.Scanner, conn net.Conn, contactsPath string, contacts map[string]string, whoCache map[string]string, sessions map[string]*Session) error {
	for { // infinite for loop unless input stops, network error of function returns
		fmt.Print("> ")
		if !in.Scan() {
			return nil //if false we bail out like keyboard inturrupt
		}

		// we get the user line and if parsing succeeds we move ahead in the code
		// if parsing doesn't suceed we go to the next loop and ask again
		toHandle, text, ok := parseCommand(strings.TrimSpace(in.Text()))
		if !ok {
			continue
		}

		//if this is a DM(/to [Name]), enforce TOFU and rewrite To to pubkey
		to := toHandle
		if toHandle != "" {

			//the line below checks if the client I am trying to sends msg to is online or not
			//by checking it in the whoCache, while the server already does this right now, we need this
			//for the fututre
			pub, exists := whoCache[toHandle]
			if !exists {
				//just a little fallback so we don't have to use
				// /who everytime this only works while the server is
				// there tho so might need to fix this later
				if pinned, ok := contacts[toHandle]; ok {
					pub = pinned
				} else {
					fmt.Println("[error] unknow handle. Run /who first.")
					continue
				}
			}

			allowed, msg := tofuObserve(contacts, toHandle, pub)
			if msg != "" && msg != "unchanged" {
				fmt.Println(msg)
			}

			if !allowed {
				fmt.Println("[blocked] key mismatch")
				continue
			}

			//save on first sight
			if err := saveContacts(contactsPath, contacts); err != nil {
				fmt.Println("failed to save contacts: ", err)
			}

			//we do this because we are sendign to public key not handle
			//sending the message
			sess, ok := sessions[to]
			if !ok {
				sess = newSession()
				sessions[to] = sess
			}

			//starting the handshake if not doen already
			if sess.State == SessNone {
				sess.startHandshake()

				//sending the handshake message to the client
				hm := protocol.Msg{
					Type:   "handshake",
					To:     to,
					PubKey: base64.StdEncoding.EncodeToString(sess.MyEphPub),
				}

				b, _ := json.Marshal(hm)

				b = append(b, '\n')
				conn.Write(b)

				sess.Outbox = append(sess.Outbox, text)
				continue
			}

			if sess.State != SessReady {
				sess.Outbox = append(sess.Outbox, text)
				continue
			}

			//we will encrypt the message now
			ct, err := encrypt(sess.SendKey, sess.SendCtr, []byte(text))
			if err != nil {
				fmt.Println("encrypt failed")
				continue
			}
			sess.SendCtr++

			text = base64.StdEncoding.EncodeToString(ct)
		}

		// we create a message struct, Marshal converts it to JSON and then we add a new lin
		// most TCP connections are newline-delimited so message is seperated by new line
		m := protocol.Msg{Type: "send", To: to, Text: text}
		b, _ := json.Marshal(m)
		b = append(b, '\n')

		//we now send the message over TCP and if it fails we just disconnect
		if _, err := conn.Write(b); err != nil {
			fmt.Println("disconnected")
			return err
		}
	}

}

func readLoop(sc *bufio.Scanner, conn net.Conn, contactsPath string, contacts map[string]string, whoCache map[string]string, sessions map[string]*Session) {
	/*
		function that reads the stuff the server sends(what other client sends) and use the same connection as in Run() function
	*/

	//run as long as the server keeps sends or '\n' is there
	for sc.Scan() {
		var m protocol.Msg // gets the JSON message adn tries to decode it c
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			fmt.Println("<< bad message from server >>")
			continue
		}
		switch m.Type {
		case "welcome": // if first time tell use ID and welcome test from server
			fmt.Printf("[server] your id: %s\n", m.ID)
			fmt.Printf("[server] %s\n", m.Text)
		case "msg": // display message from normal user/other client
			sess, ok := sessions[m.From]
			if !ok || sess.State != SessReady {
				fmt.Println("[warning] there is a encrypted messaged but there is no session")
				continue
			}

			ct, _ := base64.StdEncoding.DecodeString(m.Text)
			pt, err := decrypt(sess.RecvKey, sess.RecvCtr, ct)
			if err != nil {
				fmt.Println("[decryption failed]")
				continue
			}
			sess.RecvCtr++

			fmt.Printf("[%s] %s\n", m.From, string(pt))
		case "who_resp":
			for _, p := range m.Peers {
				whoCache[p.Handle] = p.PubKey //add the online client with to whoCache

				allowed, msg := tofuObserve(contacts, p.Handle, p.PubKey)
				if msg != "" {
					fmt.Println(msg)
				}
				if allowed {
					saveContacts(contactsPath, contacts)
				}
			}
		case "handshake":
			peerPub, _ := base64.StdEncoding.DecodeString(m.PubKey)

			sess, ok := sessions[m.From]
			if !ok {
				sess = newSession()
				sessions[m.From] = sess
			}

			// Track whether we just created responder state.
			responderStarted := false

			//we will reply if we didn't initiate
			if sess.State == SessNone {
				sess.startHandshake()
				responderStarted = true

				reply := protocol.Msg{
					Type:   "handshake",
					To:     m.From,
					PubKey: base64.StdEncoding.EncodeToString(sess.MyEphPub),
				}
				b, _ := json.Marshal(reply)
				b = append(b, '\n')
				conn.Write(b)
			}

			// initiator iff we were already waiting before this inbound handshake
			initiator := !responderStarted && sess.State == SessWaiting
			sess.completeHandshake(peerPub, initiator)

			//we will flush queued messages now
			for _, msg := range sess.Outbox {
				ct, _ := encrypt(sess.SendKey, sess.SendCtr, []byte(msg))
				sess.SendCtr++

				send := protocol.Msg{
					Type: "send",
					To:   m.From,
					Text: base64.StdEncoding.EncodeToString(ct),
				}
				b, _ := json.Marshal(send)
				b = append(b, '\n')
				conn.Write(b)
			}
			sess.Outbox = nil
		case "error": // if there is any error that was returned
			fmt.Printf("[error] %s\n", m.Text)
		default:
			fmt.Printf("[server] %+v\n", m)
		}
	}

	// server closed the connection
	os.Exit(0)
}

func parseCommand(line string) (to string, text string, ok bool) {
	/*
		this function parses the input user inters input scanner in the Run() function
	*/

	//if user entered nothing
	if line == "" {
		return "", "", false
	}

	// if user wanted to send a message to a specific use then we return to, text and the if it was parsed or not
	if strings.HasPrefix(line, "/to ") {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			fmt.Println("usage: /to <id> <msg>")
			return "", "", false
		}
		return parts[1], parts[2], true
	}

	// if the user wanted to send it to everyone who is connected to server
	if strings.HasPrefix(line, "/all ") {
		return "", strings.TrimPrefix(line, "/all "), true
	}

	if line == "/who" {
		return "", "/who", true
	}

	fmt.Println("unknown command, use /all, /to, /who")
	return "", "", false
}
