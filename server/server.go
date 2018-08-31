package server

import (
	"github.com/gorilla/mux"
	"github.com/polyverse/ropoly/handlers"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func ServeOverHttp(address string) error {
	router := mux.NewRouter().StrictSlash(true)

	api := router.PathPrefix("/api/v0").Subrouter()
	api.HandleFunc("/test", handlers.ROPTestHandler)
	api.HandleFunc("/pids", handlers.ROPPIdsHandler)

	pid := api.PathPrefix("/pid/{pid}").Subrouter()
	pid.HandleFunc("/libraries", handlers.ROPLibrariesHandler)

	mem := pid.PathPrefix("/memory").Subrouter()
	mem.HandleFunc("/regions", handlers.ROPMemoryRegionsHandler)
	mem.HandleFunc("/search", handlers.ROPMemorySearchHandler)
	mem.HandleFunc("/disasm", handlers.ROPMemoryDisAsmHandler)
	mem.HandleFunc("/gadget", handlers.ROPMemoryGadgetHandler)
	mem.HandleFunc("/fingerprint", handlers.ROPMemoryFingerprintHandler)

	log.Infof("Running server on address: %s", address)
	log.Infof("Listing supported API")
	// Dump the actual routes that the router knows about
	router.Walk(
		func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			t, err := route.GetPathTemplate()
			if err != nil {
				return err
			}
			log.Infof("Exposing Route: %s", t)
			return nil
		})

	return http.ListenAndServe(address, router)
}
