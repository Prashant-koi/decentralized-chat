package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

type Msg struct {
	Type string `json:"type"`
	To   string `json:"to,omitempty"`
	From string `json:"from,omitempty"`
	Text string `json:"text,omitempty"`
	ID   string `json:"id,omitempty"`
}

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:9000")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// reading the server msg
	go func() {
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			var m Msg
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
		os.Exit(0)
	}()

	fmt.Println("Commands:")
	fmt.Println(" /all <msg>			broadcast")
	fmt.Println(" /to <id> <msg> 		send to one user")
	fmt.Println(" /who					list online")

	in := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("> ")
		if !in.Scan() {
			return
		}

		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}

		var to, text string

		if strings.HasPrefix(line, "/to ") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 3 {
				fmt.Println("usage: /to <id> <msg>")
				continue
			}
			to = parts[1]
			text = parts[2]
		} else if strings.HasPrefix(line, "/all ") {
			text = strings.TrimPrefix(line, "/all ")
		} else if line == "/who " {
			text = "/who "
		} else {
			fmt.Println("unknowm command, use /all, /to or /who")
			continue
		}

		m := Msg{Type: "send", To: to, Text: text}
		b, _ := json.Marshal(m)
		b = append(b, '\n')
		_, err := conn.Write(b)
		if err != nil {
			fmt.Println("disconnected")
			return
		}
	}
}
