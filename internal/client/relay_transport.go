package client

import (
	"bufio"
	"chat/internal/protocol"
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

func relayPut(addr, queue, payload string) error {
	// this function is a helper function that sends a "put" request to the relay server to send a message to a given queue
	_, err := relayRequest(addr, protocol.Msg{
		Type:    "put",
		Queue:   queue,
		MsgID:   randomToken(12),
		Payload: payload,
	})
	return err
}

func relayRequest(addr string, req protocol.Msg) (protocol.Msg, error) {
	// this function is a helper function that sends a request to the relay server and waits for the response
	// this basically handels th low level details of connection to the server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return protocol.Msg{}, err
	}
	defer conn.Close()

	b, _ := json.Marshal(req)
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return protocol.Msg{}, err
	}

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	if !sc.Scan() {
		return protocol.Msg{}, fmt.Errorf("no response")
	}
	var resp protocol.Msg
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return protocol.Msg{}, err
	}
	if resp.Type == "error" {
		return resp, errors.New(resp.Text)
	}
	return resp, nil
}
