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

	msg := fmt.Sprintf("{\"log_type\":\"access_log\",\"Status\":\"%s\",\"RawQuery\":\"%s\"}", code, r.URL.RawQuery)
	
	log.Infof("%s", msg)
	io.WriteString(w, fmt.Sprintf("%s",msg))
}
