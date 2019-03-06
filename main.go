package main

import (
	"github.com/polyverse/ropoly/cmd"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		println("Usage: \"" + os.Args[0] + " server\" or \"" + os.Args[0] + " daemon\"")
	}
	cmd.Execute()
}
