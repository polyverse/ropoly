package main

import (
	"crypto/rand"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/polyverse-security/framework/monitoring/polyverse-log-formatter"
	"github.com/polyverse-security/polysploit/handlers"
	"net/http"
)

func pseudo_uuid() (uuid string) {

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	uuid = fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	return
}

func main() {
	log.SetFormatter(polyverse_log_formatter.NewFormatter())

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", handlers.DefaultHandler)
	router.HandleFunc("/health", handlers.HealthHandler)
	router.HandleFunc("/event", handlers.EventHandler)
	router.HandleFunc("/infect", handlers.InfectHandler)
	router.HandleFunc("/reflect", handlers.ReflectHandler)
	router.HandleFunc("/proxy", handlers.ProxyHandler)
	router.HandleFunc("/docker", handlers.DockerHandler)
	router.HandleFunc("/panic", handlers.PanicHandler)

	api := router.PathPrefix("/api/v0").Subrouter()
	api.HandleFunc("/test", handlers.ROPTestHandler)
	api.HandleFunc("/pids", handlers.ROPPIdsHandler)

	pid := api.PathPrefix("/pid/{pid}").Subrouter()
	pid.HandleFunc("/libraries", handlers.ROPLibrariesHandler)

	mem := pid.PathPrefix("/memory").Subrouter()
	mem.HandleFunc("/safe", handlers.ROPMemorySafeHandler)
	mem.HandleFunc("/regions", handlers.ROPMemoryRegionsHandler)
	mem.HandleFunc("/search", handlers.ROPMemorySearchHandler)
	mem.HandleFunc("/disasm", handlers.ROPMemoryDisAsmHandler)
	mem.HandleFunc("/gadget", handlers.ROPMemoryGadgetHandler)
	mem.HandleFunc("/fingerprint", handlers.ROPMemoryFingerprintHandler)
	mem.HandleFunc("/overflow", handlers.ROPMemoryOverflowHandler)

	// Dump the actual routes that the router knows about
	router.Walk(
		func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			t, err := route.GetPathTemplate()
			if err != nil {
				return err
			}
			fmt.Println(t)
			return nil
		})

	log.Fatal(http.ListenAndServe(":8080", router))
}
