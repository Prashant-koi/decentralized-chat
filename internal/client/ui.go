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
	fmt.Println("  /all <msg>           broadcast")
	fmt.Println("  /to <id> <msg>       send to one user")
	fmt.Println("  /who                 list online")
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
