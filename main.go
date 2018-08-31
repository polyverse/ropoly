package main

import (
	"github.com/polyverse/ropoly/server"
	"github.com/polyverse/ropoly/wiring"
)

func main() {
	cfg := wiring.ParseFlags()
	server.ServeOverHttp(cfg.HttpAddress)
}
