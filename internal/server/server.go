package server

import (
	"bufio"
	"chat/internal/protocol"
	"encoding/json"
	"net"
	"sync"
	"time"
)

// This is a simple in-memory relay server implementation.
type relayStore struct {
	mu    sync.Mutex
	data  map[string][]protocol.RelayItem
	dedup map[string]map[string]struct{}
}

// store is a global instance of relayStore
var store = &relayStore{
	data:  make(map[string][]protocol.RelayItem),
	dedup: make(map[string]map[string]struct{}),
}

// put adds a message to the specified queue if it hasn't been added before (deduplication based on msgID).
func (s *relayStore) put(queue string, msgID, payload string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.dedup[queue]; !exists {
		s.dedup[queue] = make(map[string]struct{})
	}

	if _, exists := s.dedup[queue][msgID]; exists {
		return
	}
	s.dedup[queue][msgID] = struct{}{}

	s.data[queue] = append(s.data[queue], protocol.RelayItem{
		MsgID:   msgID,
		Payload: payload,
		TS:      time.Now().UnixMilli(),
	})
}

// poll retrieves up to 'max' messages from the specified queue without removing them.
// It returns an empty slice if there are no messages.
func (s *relayStore) poll(queue string, max int) []protocol.RelayItem {
	s.mu.Lock()
	defer s.mu.Unlock()

	items := s.data[queue]
	if len(items) == 0 {
		return nil
	}

	if max <= 0 || max > len(items) {
		max = len(items)
	}

	out := make([]protocol.RelayItem, max)
	copy(out, items[:max])
	return out
}

// ack removes messages with the specified msgIDs from the queue, simulating acknowledgment of message processing by clients.
func (s *relayStore) ack(queue string, ackIDs []string) {
	if len(ackIDs) == 0 {
		return
	}

	ackSet := make(map[string]struct{}, len(ackIDs))
	for _, id := range ackIDs {
		ackSet[id] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.data[queue]
	if len(old) == 0 {
		return
	}

	kept := old[:0]
	for _, it := range old {
		if _, done := ackSet[it.MsgID]; !done {
			continue
		}
		kept = append(kept, it)
	}
	s.data[queue] = append([]protocol.RelayItem(nil), kept...)
}

func writeJSON(conn net.Conn, m protocol.Msg) {
	b, _ := json.Marshal(m)
	b = append(b, '\n')
	_, _ = conn.Write(b)
}

// HandleConn processes incoming connections to the relay server.
// It reads a JSON message from the connection, determines the type of request (put, poll, ack),
// and interacts with the relayStore accordingly
// It also sends back appropriate responses based on the request type and any errors encountered.
func HandleConn(conn net.Conn) {
	defer conn.Close()

	// Use a buffered scanner to read the incoming JSON message from the connection.
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)

	if !sc.Scan() {
		return
	}

	var req protocol.Msg
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		writeJSON(conn, protocol.Msg{Type: "error", Text: "bad json"})
		return
	}

	switch req.Type {
	case "put": // if the type is "put", the server expects a message to be added to a queue.
		if req.Queue == "" || req.MsgID == "" || req.Payload == "" {
			writeJSON(conn, protocol.Msg{Type: "error", Text: "missing queue, msg_id, or payload"})
			return
		}
		store.put(req.Queue, req.MsgID, req.Payload)
		writeJSON(conn, protocol.Msg{Type: "ok", MsgID: req.MsgID})
	case "poll": // if the type is "poll", the server expects a request to retrieve messages from a queue.
		if req.Queue == "" {
			writeJSON(conn, protocol.Msg{Type: "error", Text: "missing queue"})
			return
		}
		if req.WaitMS < 0 {
			req.WaitMS = 0
		}
		if req.Max <= 0 {
			req.Max = 32
		}

		deadline := time.Now().Add(time.Duration(req.WaitMS) * time.Millisecond)
		for {
			items := store.poll(req.Queue, req.Max)
			if len(items) > 0 || time.Now().After(deadline) || req.WaitMS == 0 {
				writeJSON(conn, protocol.Msg{Type: "poll_resp", Queue: req.Queue, Items: items})
				return
			}
			time.Sleep(100 * time.Millisecond)
		}

	case "ack": // if the type is "ack", the server expects a request to acknowledge the processing of messages, which will remove them from the queue.
		if req.Queue == "" {
			writeJSON(conn, protocol.Msg{Type: "error", Text: "missing queue"})
			return
		}
		store.ack(req.Queue, req.AckIDs)
		writeJSON(conn, protocol.Msg{Type: "ok"})
	default:
		writeJSON(conn, protocol.Msg{Type: "error", Text: "unknown type"})
	}

}
