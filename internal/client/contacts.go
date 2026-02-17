package client

import (
	"encoding/json"
	"os"
)

type Contact struct {
	Alias       string `json:"alias"`
	TheirPubKey string `json:"their_pubkey,omitempty"` //pinned iddentity key fo this contact
	SendQueue   string `json:"send_queue,omitempty"`   // this is where we PUT to reach peer
	RecvQueue   string `json:"recv_queue,omitempty"`   // this is where we POLL to receive from peer
}

// loadContacts loads the contacts from a JSON file. If the file does not exist, it returns an empty map.
func loadContactsBook(path string) (map[string]*Contact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*Contact), nil // return empty contacts if file doesn't exist
		}
		return nil, err
	}
	if len(data) == 0 {
		return make(map[string]*Contact), nil // return empty contacts if file is empty
	}

	var out map[string]*Contact
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]*Contact{}
	}
	return out, nil
}

// saveContacts saves the contacts to a JSON file
func saveContactsBook(path string, contacts map[string]*Contact) error {
	data, err := json.MarshalIndent(contacts, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
