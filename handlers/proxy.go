package handlers

import (
	"fmt"
	"net/http"
	"crypto/tls"
	//"net/http/httputil"
	"bytes"
	"io"
	"regexp"
	log "github.com/Sirupsen/logrus"
)

// https://play.golang.org/p/pOHnNPSZpv
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	url := r.FormValue("url")

	log.Infof("url = %s", url)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		fmt.Printf("error: %s", err)
	}
	req.Host = r.URL.Host

	tr := &http.Transport{
        	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
	  fmt.Printf("err: %s", err)
	}
	defer resp.Body.Close()


	buffer := make([]byte,102400)
	io.ReadFull(resp.Body, buffer)

	str := string(buffer)

	index := regexp.MustCompile(`(?i)<BODY[^>]*>`).FindStringSubmatchIndex(str)


	var buff bytes.Buffer
	buff.WriteString(str[:index[1]])
	buff.WriteString(`<img src="http://localhost:8888/img/skull.png" style="position: absolute; z-index: 2; width: 600px;"/>`)
	buff.WriteString(str[index[1]:])
	//fmt.Printf("\n\n%s\n", buffer.String())

	fmt.Fprintf(w, buff.String())
}
