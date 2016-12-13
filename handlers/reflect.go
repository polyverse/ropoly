package handlers

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
)

type jsonSafeRequest struct {
	Method string
	Url url.URL
	Proto string
	Header http.Header
	Body io.ReadCloser
	ContentLength int64
	TransferEncoding []string
	Host string
	Form url.Values
	PostForm url.Values
	Trailer http.Header
	RemoteAddr string
	RequestURI string
}

func ReflectHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	req := &jsonSafeRequest{Method:r.Method,Url:*r.URL,Proto:r.Proto,Header:r.Header,Body:r.Body,ContentLength:r.ContentLength,TransferEncoding:r.TransferEncoding,Host:r.Host,Form:r.Form,PostForm:r.PostForm,Trailer:r.Trailer,RemoteAddr:r.RemoteAddr,RequestURI:r.RequestURI}

	b, err := json.Marshal(req)
	if err != nil {
		log.WithFields(log.Fields{"err":err}).Errorf("Encountered error marshaling to JSON.")
		io.WriteString(w, fmt.Sprintf("Error: %s\n", err))
	} else {
		log.Infof("%s", string(b))
		io.WriteString(w, fmt.Sprintf("%s\n", string(b)))
	}
}
