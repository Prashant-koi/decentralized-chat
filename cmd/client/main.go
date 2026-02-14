package main

import (
	"flag"
	"log"

	"chat/internal/client"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "server address")
	flag.Parse()

	if err := client.Run(*addr); err != nil {
		log.Fatal(err)
	}
}
