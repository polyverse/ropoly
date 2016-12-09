package handlers

import (
	"io"
	"net/http"
)

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "healthy")
}
