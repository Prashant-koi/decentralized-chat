package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

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
