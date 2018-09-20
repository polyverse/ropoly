package wiring

import "flag"

type Config struct {
	HttpAddress string
}

func ParseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.HttpAddress, "http-serve-address", ":8008", "When set, services ropoly over HTTP")
	flag.Parse()
	return cfg
}
