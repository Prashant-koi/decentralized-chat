package client

import (
	"bufio"
	"chat/internal/crypto"
	"chat/internal/protocol"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

func solveChallenge(conn net.Conn, sc *bufio.Scanner, pub ed25519.PublicKey, priv ed25519.PrivateKey, handle string) error {
	/*
		since the server sends the client a challenge to find out if the client has the correct public key and
		they are who they say they are, we have to solve the challenge and send them back an "hello" message
		for this function we take the existing connection from Run() function to not create a dreadlock
		and the we also get our stored public key and private key for cross referencing and sending the
		public key and signature to the server for it to authenticate. NEVER send Private Key to the server
	*/
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
		Handle: handle,
	}

	b, _ := json.Marshal(hello)
	b = append(b, '\n')

	if _, err := conn.Write(b); err != nil {
		return err
	}
	return nil
}

func loadContacts(path string) (map[string]string, error) {
	/*
		this function will load contacts for Trust on First Use(TOFU)
		from contacts.json
	*/

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil // this runs when you have no contacts save aka the first run
		}
		return nil, err
	}

	var contacts map[string]string
	if len(data) > 0 {
		if err := json.Unmarshal(data, &contacts); err != nil {
			return nil, err
		}
	}

	if contacts == nil {
		contacts = make(map[string]string) //incase contacts are empty
	}

	return contacts, nil
}

func saveContacts(path string, contacts map[string]string) error {
	// saves new contacts to the contacts.json file
	data, err := json.MarshalIndent(contacts, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func fingerprintPubKey(pubB64 string) string {
	// creates a short identifier for human for the pub key
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return "invalid-pubkey"
	}

	sum := sha256.Sum256(pubBytes)
	return hex.EncodeToString(sum[:8])
}

func tofuObserve(contacts map[string]string, handle, pubB64 string) (bool, string) {
	// this pins the handle to pubkey on the first sight
	// returns allowed, message so if allowed = true ok to talk and if allowed = false
	// not okay to talk
	if handle == "" || pubB64 == "" {
		return false, "missing handle or pubkey"
	}

	old, exists := contacts[handle]
	if !exists {
		contacts[handle] = pubB64
		return true, fmt.Sprintf("[TOFU] pinned %s to %s", handle, fingerprintPubKey(pubB64))
	}

	if old == pubB64 {
		return true, "unchanged"
	}

	//incase of mismatch (potentially unsafe)
	return false, fmt.Sprintf("[WARNING] %s changed keys! old= %s new= %s", handle, fingerprintPubKey(old), fingerprintPubKey(pubB64))

}

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
	go readLoop(sc, contactsPath, contacts)

	// all commands
	printHelp()

	in := bufio.NewScanner(os.Stdin) //reads our keyboard input
	writeLoop(in, conn)              //this function will send whtever we write to the server if it is legal

	return nil
}

func writeLoop(in *bufio.Scanner, conn net.Conn) error {
	for { // infinite for loop unless input stops, network error of function returns
		fmt.Print("> ")
		if !in.Scan() {
			return nil //if false we bail out like keyboard inturrupt
		}

		// we get the user line and if parsing succeeds we move ahead in the code
		// if parsing doesn't suceed we go to the next loop and ask again
		to, text, ok := parseCommand(strings.TrimSpace(in.Text()))
		if !ok {
			continue
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

func readLoop(sc *bufio.Scanner, contactsPath string, contacts map[string]string) {
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
			fmt.Printf("[%s] %s\n", m.From, m.Text)
		case "who_resp":
			for _, p := range m.Peers {
				allowed, msg := tofuObserve(contacts, p.Handle, p.PubKey)
				if msg != "" {
					fmt.Println(msg)
				}
				if allowed {
					saveContacts(contactsPath, contacts)
				}
			}
		case "error": // if there is any error that was returned
			fmt.Printf("[error] %s\n", m.Text)
		default:
			fmt.Printf("[server] %+v\n", m)
		}
	}

	// server closed the connection
	os.Exit(0)
}

func printHelp() {
	//function which prints all commands avilable to user
	fmt.Println("Commands:")
	fmt.Println("  /all <msg>           broadcast")
	fmt.Println("  /to <id> <msg>       send to one user")
	fmt.Println("  /who                 list online")
	fmt.Println()
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

func askHandle() (string, error) {
	/*
		this function is gonna ask the user for the handle to make comminication easier for the user
		we need to ask it before opening the network connection in the Run() function
	*/

	fmt.Print("Choose a handle: ")
	in := bufio.NewScanner(os.Stdin)
	if !in.Scan() {
		return "", fmt.Errorf("no input")
	}
	h := strings.TrimSpace(in.Text())
	if h == "" {
		return "", fmt.Errorf("handle can't be empty")
	}

	return h, nil
}
