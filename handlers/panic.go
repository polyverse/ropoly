package handlers

import (
	"net/http"
	log "github.com/Sirupsen/logrus"
)

func PanicHandler(w http.ResponseWriter, r *http.Request) {
	log.Panicf("User-requested panic.")
}
