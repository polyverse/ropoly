package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"crypto/tls"
	"github.com/polyverse-security/framework/strings"
	"io/ioutil"
	"regexp"
	log "github.com/Sirupsen/logrus"
)

// https://play.golang.org/p/pOHnNPSZpv
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	url, err := url.Parse(r.FormValue("url"))
	if err != nil {
		log.Errorf("Error parsing url form value: '%s'. Error: %s", r.FormValue("url"), err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, err)
		return
	}

	urlstr := fmt.Sprintf("%s://%s/", url.Scheme, url.Host)
	mystr := fmt.Sprintf("%v://%s/", r.TLS, r.Host)
	log.Infof("GET %s", urlstr + url.Path)
	log.Infof("i am %s", mystr)
	req, err := http.NewRequest("GET", urlstr + url.Path, nil)
	if err != nil {
		log.Errorf("Error creating new request object. Error: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err)
		return
	}

	tr := &http.Transport{
        	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error performing server-side http request. Error: %s", err)	
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err)
		return
	}
	defer resp.Body.Close()


	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body. Error: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err)
		return
	}

	str := string(html)

	log.Infof("html length = %v", len(str))

	var newstr string
	n := regexp.MustCompile(`\"\/[a-zA-Z]`).FindAllStringSubmatchIndex(str, -1)
	if len(n) > 0 {
		for i := 0; i < len(n); i++ {
			if i == 0 {
				newstr = str[0:n[i][0]] + urlstr + url.Path
			} else {
				newstr = newstr + str[n[i-1][1]-1:n[i][0]+1] + urlstr + url.Path
			}

			if i == (len(n) - 1) {
				newstr = newstr + str[n[i][0]+1:] 
			}
		}
	} else {
		newstr = str
	}

	f1, _ := ioutil.ReadDir("/tmp")
	if len(f1) > 0 {
		var scheme string
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}

		index := regexp.MustCompile(`(?i)<BODY[^>]*>`).FindStringSubmatchIndex(newstr)
		owned := `<img src="` + scheme + `://` + r.Host + `/img/skull.png" style="position:absolute;margin:auto;top:0;right:0;left:0;bottom:0;height:95%%;z-index:999;opacity:0.8;"></img>`
		fmt.Fprintf(w, strings.Insert(newstr,owned, index[1]))
	} else {
		fmt.Fprintf(w, newstr)
	}
}
