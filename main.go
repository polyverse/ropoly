package main

import (
	"encoding/json"
	"fmt"
	"github.com/polyverse/ropoly/lib"
	"github.com/polyverse/ropoly/server"
	"github.com/polyverse/ropoly/wiring"
	log "github.com/sirupsen/logrus"
	"os"
)

const webServerArg = "server"
const passiveScanArg = "scan"
const loggingArg = "log"
const prometheusArg = "prometheus"

func webServer() {
	cfg := wiring.ParseFlags()
	server.ServeOverHttp(cfg.HttpAddress)
}

func directoryScan(logging bool, prometheus bool) {
	for true {
		b, err := json.MarshalIndent(lib.DirectoryScan(), "", "    ")
		if logging {
			if err != nil {
				log.Error(err)
			}
			log.Info("\nDirectories:\n" + string(b[:]) + "\n")
		}
	}
}

func processScan(logging bool, prometheus bool) {
	for true {
		b, err := json.MarshalIndent(lib.ProcessScan(), "", "    ")
		if logging {
			if err != nil {
				log.Error(err)
			}
			log.Info("\nProcesses:\n" + string(b[:]) + "\n")
		}
	}
}

func help() {
	print("Usage: {" + webServerArg + "} {" + passiveScanArg + "} {" + loggingArg + "} {" + prometheusArg + "}\n")
}

func main() {
	args := os.Args
	runWebServer := false
	runPassiveScan := false
	logging := false
	prometheus := false
	for i := 1; i < len(args); i++ {
		switch arg := args[i]; arg {
		case webServerArg:
			if runWebServer {
				print(webServerArg + " used more than once\n")
				help()
				return
			}
			runWebServer = true
		case passiveScanArg:
			if runPassiveScan {
				print(passiveScanArg + " used more than once\n")
				help()
				return
			}
			runPassiveScan = true
		case loggingArg:
			if logging {
				print(loggingArg + " used more than once\n")
				help()
				return
			}
			logging = true
		case prometheusArg:
			if prometheus {
				print(prometheusArg + " used more than once\n")
				help()
				return
			}
			prometheus = true
		default:
			println("Unrecognized token", arg)
			help()
			return
		}
	}

	if !runWebServer && !runPassiveScan {
		print("Use \"" + webServerArg + "\", \"" + passiveScanArg + "\", or both\n")
		help()
		return
	}

	if logging && !runPassiveScan {
		println(loggingArg, "selected without", passiveScanArg)
		help()
		return
	}
	if prometheus && !runPassiveScan {
		println(prometheusArg, "selected without", passiveScanArg)
		help()
		return
	}

	if prometheus {
		log.Warn("Prometheus metrics are not yet implemented.")
	}

	if runWebServer {
		go webServer()
	}
	if runPassiveScan {
		go directoryScan(logging, prometheus)
		go processScan(logging, prometheus)
	}

	fmt.Scanln()
}
