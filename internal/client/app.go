package client

import (
	"bufio"
	"chat/internal/crypto"
	"context"
	"encoding/base64"
	"fmt"
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
	pub, _, err := crypto.LoadOrCreateIdentity(idPath)
	if err != nil {
		return err
	}
	myPubB64 := base64.StdEncoding.EncodeToString(pub)

	contacts, err := loadContactsBook(contactsPath)
	if err != nil {
		return err
	}

	st := &runtimeState{
		addr:         addr,
		contactsPath: contactsPath,
		myPubB64:     myPubB64,
		contacts:     contacts,
		sessions:     make(map[string]*Session),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pollLoop(ctx, st)

	// all commands
	printHelp()

	in := bufio.NewScanner(os.Stdin) //reads our keyboard input

	for {
		fmt.Print("> ")
		if !in.Scan() {
			return nil //if false we bail out like keyboard inturrupt
		}

		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}

		if err := handleCommand(st, line); err != nil {
			fmt.Println("[Error]", err)
		}
	}

}
