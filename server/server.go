package server

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/polyverse/ropoly/handlers"
	log "github.com/sirupsen/logrus"
	"net/http"
	"sort"
	"strings"
)

func ServeOverHttp(address string) error {
	router := mux.NewRouter()
	root := subLister(router, "")

	api := subLister(root, "/api")
	v1 := subLister(api, "/v1")

	addHandleFunc(v1, "/health", handlers.ROPHealthHandler)
	addHandleFunc(v1, "/pids", handlers.ROPPIdsHandler)

	pid := subLister(v1, "/pids/{pid}")
	addHandleFunc(pid, "/libraries", handlers.ROPLibrariesHandler)

	mem := subLister(pid, "/memory")
	addHandleFunc(mem, "/regions", handlers.ROPMemoryRegionsHandler)
	addHandleFunc(mem, "/search", handlers.ROPMemorySearchHandler)
	addHandleFunc(mem, "/disasm", handlers.ROPMemoryDisAsmHandler)
	addHandleFunc(mem, "/gadget", handlers.ROPMemoryGadgetHandler)
	addHandleFunc(mem, "/fingerprint", handlers.ROPMemoryFingerprintHandler)
	addHandleFunc(mem, "/isPolyverseBin", handlers.ROPMemoryIsPolyverseBinHandler)

	directoryLister(v1, "/files", handlers.ROPFileHandler)
	directoryLister(v1, "/is-file-polyverse", handlers.ROPIsPolyverseFileHandler)

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

func directoryLister(router *mux.Router, path string, handlerFunc http.HandlerFunc) *mux.Router {
	subrouter := router
	if path != "" && path != "/" {
		subrouter = router.PathPrefix(path).Subrouter()
	}
	subrouter.HandleFunc("/{path:.*}", handlerFunc)
	subrouter.HandleFunc("", handlerFunc)
	return subrouter
}

func subLister(router *mux.Router, path string) *mux.Router {
	subrouter := router
	if path != "" && path != "/" {
		subrouter = router.PathPrefix(path).Subrouter()
	}

	handler := subHandler(subrouter)
	subrouter.HandleFunc("", handler)
	subrouter.HandleFunc("/", handler)
	return subrouter
}

func addHandleFunc(router *mux.Router, path string, handlerFunc http.HandlerFunc) {
	path = strings.TrimSuffix(path, "/")
	router.HandleFunc(path, handlerFunc)
	router.HandleFunc(path+"/", handlerFunc)
}

func subHandler(router *mux.Router) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		paths := map[string]string{}

		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			t, err := route.GetPathTemplate()
			if err != nil {
				return err
			}
			path := strings.TrimSuffix(t, "/")
			if path != "" {
				paths[path] = ""
			}

			return nil
		})

		list := make([]string, 0, len(paths))
		for path, _ := range paths {
			list = append(list, path)
		}

		sort.Strings(list)

		liststr, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			writer.WriteHeader(500)
			writer.Write([]byte(err.Error()))
			return
		}

		writer.WriteHeader(200)
		writer.Write(liststr)

	}
}
