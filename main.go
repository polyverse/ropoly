package main

import (
	"net/http"
	"fmt"
	"crypto/rand"
	"github.com/polyverse-security/framework/monitoring/polyverse-log-formatter"
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/polysploit/handlers"
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

	http.HandleFunc("/", handlers.DefaultHandler)

	http.HandleFunc("/health", handlers.HealthHandler)
	http.HandleFunc("/infect", handlers.InfectHandler)
	http.HandleFunc("/reflect", handlers.ReflectHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
