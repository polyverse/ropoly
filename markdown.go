package main

import (
  "io"
  "net/http"
  "io/ioutil"
  "github.com/russross/blackfriday"
  log "github.com/Sirupsen/logrus"
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
