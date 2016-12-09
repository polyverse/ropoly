package handlers

import (
	"net/http"
)

func DefaultHandler(w http.ResponseWriter, r *http.Request) {
        p := r.URL.Path[1:]

        //if (p == "") {
        //        p = "/"
        //}

        //if strings.HasSuffix(p, "/") {
        //        p = p + "default.htm"
        //}

        //log.WithFields(log.Fields{"r.URL.Path":r.URL.Path,"p":p}).Infof("defaultHandler()")
        //logRequest(r)
        //if strings.HasSuffix(p, ".md") {
        //        markdownHandler(w, r)
        //} else {
                http.ServeFile(w, r, "/wwwroot/" + p)
        //}
}
