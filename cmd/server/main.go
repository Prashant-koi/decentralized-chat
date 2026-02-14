package main

import (
	"log"
	"net"

	"chat/internal/server"
)

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
		go server.HandleConn(conn)
	}
}
