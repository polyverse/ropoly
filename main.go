package main

import (
	"net/http"
	"fmt"
	"crypto/rand"
	"github.com/polyverse-security/framework/monitoring/polyverse-log-formatter"
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/polysploit/handlers"
	"github.com/ant0ine/go-json-rest/rest"
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

	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)
	router, err := rest.MakeRouter(
		rest.Get("/memory/test", handlers.ROPMemoryTestHandler),
		rest.Get("/memory/safe", handlers.ROPMemorySafeHandler),
		rest.Get("/memory/libraries", handlers.ROPMemoryLibrariesHandler),
		rest.Get("/memory/regions", handlers.ROPMemoryRegionsHandler),
		rest.Get("/memory/search", handlers.ROPMemorySearchHandler),
		rest.Get("/memory/disasm", handlers.ROPMemoryDisAsmHandler),
		rest.Get("/memory/gadget", handlers.ROPMemoryGadgetHandler),
		rest.Get("/memory/overflow", handlers.ROPMemoryOverflowHandler),
	)
	if err != nil {
		log.Fatal(err)
	}
	api.SetApp(router)

	http.Handle("/api/v0/", http.StripPrefix("/api/v0", api.MakeHandler()))

	http.HandleFunc("/", handlers.DefaultHandler)
	http.HandleFunc("/health", handlers.HealthHandler)
	http.HandleFunc("/event", handlers.EventHandler)
	http.HandleFunc("/infect", handlers.InfectHandler)
	http.HandleFunc("/reflect", handlers.ReflectHandler)
	http.HandleFunc("/proxy", handlers.ProxyHandler)
	http.HandleFunc("/docker", handlers.DockerHandler)
	http.HandleFunc("/panic", handlers.PanicHandler)

	log.Fatal(http.ListenAndServe(":8088", nil))
}
