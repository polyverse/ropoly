package handlers

import (
	"fmt"
	"io"
	"net/http"
)

func EventHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		code = "200"
	}

	msg := fmt.Sprintf("{\"log_type\":\"access_log\",\"Status\":\"%s\"}", code)
	
	fmt.Printf("%s", msg)
	io.WriteString(w, fmt.Sprintf("%s",msg))
}
