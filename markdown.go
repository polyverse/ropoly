package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/russross/blackfriday"
	"io"
	"io/ioutil"
	"net/http"
)

func markdownHandler(w http.ResponseWriter, r *http.Request) {
	fileread, err := ioutil.ReadFile("/wwwroot/" + r.URL.Path[1:])
	if err != nil {
		log.Errorf("Error occurred reading file: %s", err)
	}

	body := string(blackfriday.MarkdownCommon([]byte(fileread)))

	io.WriteString(w, body)

	//logRequest(r)
}
