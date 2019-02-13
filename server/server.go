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

	addHandleFunc(v1, "/health", handlers.HealthHandler)

	addHandleFunc(v1, "/pids", handlers.PidListingHandler)
	addHandleFunc(v1, "/pids/{pid}", handlers.PidHandler)

	directoryLister(v1, "/files", handlers.FileHandler)

	addHandleFunc(v1, "/fingerprints", handlers.FingerprintListingHandler)
	addHandleFunc(v1, "/fingerprints/{fingerprint}", handlers.StoredFingerprintHandler)
	addHandleFunc(v1, "/fingerprints/{fingerprint}/compare", handlers.StoredFingerprintComparisonHandler)
	addHandleFunc(v1, "/fingerprints/{fingerprint}/eqi", handlers.StoredFingerprintEqiHandler)
	addHandleFunc(v1, "/fingerprints/{fingerprint}/format", handlers.FingerprintFormatHandler)
	addHandleFunc(v1, "/fingerprints/{fingerprint}/survival", handlers.StoredFingerprintSurvivalHandler)
	addHandleFunc(v1, "/fingerprints/{fingerprint}/killrate", handlers.StoredFingerprintKillRateHandler)

	addPostHandleFunc(router, "/api/v1/fingerprints/{fingerprint}", handlers.PostFingerprintHandler)

	addHandleFunc(v1, "/uploadedfiles", handlers.UploadedFileHandler)
	addHandleFunc(v1, "/uploadedfiles/{path:.*}", handlers.UploadedFileHandler)

	addPostHandleFunc(router, "/api/v1/uploadedfiles/{path:.*}", handlers.PostFileHandler)

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
	handleFuncByMethod(subrouter, "/{path:.*}", handlerFunc, "GET")
	handleFuncByMethod(subrouter, "", handlerFunc, "GET")
	return subrouter
}

func subLister(router *mux.Router, path string) *mux.Router {
	subrouter := router
	if path != "" && path != "/" {
		subrouter = router.PathPrefix(path).Subrouter()
	}

	handler := subHandler(subrouter)
	handleFuncByMethod(subrouter, "", handler, "GET")
	return subrouter
}

func addHandleFunc(router *mux.Router, path string, handlerFunc http.HandlerFunc) {
	path = strings.TrimSuffix(path, "/")
	handleFuncByMethod(router, path, handlerFunc, "GET")
}

func addPostHandleFunc(router *mux.Router, path string, handlerFunc http.HandlerFunc) {
	path = strings.TrimSuffix(path, "/")
	handleFuncByMethod(router, path, handlerFunc, "POST")
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

func handleFuncByMethod(r *mux.Router, uri string, handler http.HandlerFunc, method string) {
	r.Path(uri).Methods(method).HandlerFunc(handler)
	r.Path(uri + "/").Methods(method).HandlerFunc(handler)
}
