package handlers

import (
	"fmt"
	"io"
	"net/http"
	log "github.com/Sirupsen/logrus"
)

func EventHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "200"
	}

	log.WithFields(log.Fields{"log_type":"access_log","Status":code}).Infof("%s?%s", r.URL.Path, r.URL.RawQuery)
	io.WriteString(w, fmt.Sprintf("%s %s", code, r.URL.RawQuery))
}
