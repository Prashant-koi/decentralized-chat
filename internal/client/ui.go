package client

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func printHelp() {
	//function which prints all commands avilable to user
	fmt.Println("Commands:")
	fmt.Println("  /invite <alias>         create invite token (share out-of-band)")
	fmt.Println("  /connect <alias> <tok>  import peer invite")
	fmt.Println("  /to <alias> <msg>       send encrypted message via relay queue")
	fmt.Println("  /contacts               list local contacts/queues")
	fmt.Println("  /help                   show commands")
	fmt.Println()
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
