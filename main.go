package main

import (
	"fmt"
	"log"
	"github.com/gorilla/mux"
	"net/http"

	"github.com/polyverse-security/ropoly/handlers"
)

func main() {
	router := mux.NewRouter().StrictSlash(true)

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

	log.Fatal(http.ListenAndServe(":8008", router))
}
