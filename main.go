package main

import (
	"io"
	"net/http"
	"fmt"
        "io/ioutil"
	//"time"
	"crypto/rand"
	//"encoding/json"
	"strings"
	log "github.com/Sirupsen/logrus"
)

func hello(w http.ResponseWriter, r *http.Request) {
	//b, err := json.Marshal(r)
	//if err != nil {
	//	log.WithFields(log.Fields{"err":err}).Errorf("Error marshaling request object to JSON.")
	//}
	//log.Infof("%s", string(b[:]))
	fmt.Printf("Request:\n%v\n", r)
	io.WriteString(w, "Hello world!")
}

func pseudo_uuid() (uuid string) {

    b := make([]byte, 16)
    _, err := rand.Read(b)
    if err != nil {
        fmt.Println("Error: ", err)
        return
    }

    uuid = fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

    return
}

func logRequest(r *http.Request) {
	log.WithFields(log.Fields{"Cookies":r.Cookies()}).Infof("r.URL.Path = %s", r.URL.Path)
}

func infectHandler(w http.ResponseWriter, r *http.Request) {
	f1, _ := ioutil.ReadDir("/tmp")
	d1 := []byte("foo")
	err := ioutil.WriteFile(fmt.Sprintf("/tmp/data%03d", len(f1) + 1), d1, 0644)
	if err != nil {
		log.Fatalf("err: %s", err)
	}
	files, _ := ioutil.ReadDir("/tmp")

	io.WriteString(w, fmt.Sprintf("Found %v unauthorized file(s):\n", len(files)))
	for _, f := range files {
		fmt.Println(f.Name())
		io.WriteString(w, fmt.Sprintf("%s\n", f.Name()))
	}  
	logRequest(r)
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path[1:]

	if (p == "") {
		p = "/"
	}

	if strings.HasSuffix(p, "/") {
		p = p + "default.htm"
	}

	log.WithFields(log.Fields{"r.URL.Path":r.URL.Path,"p":p}).Infof("defaultHandler()")
	logRequest(r)
        if strings.HasSuffix(p, ".md") {
		markdownHandler(w, r)
	} else {
		http.ServeFile(w, r, "/wwwroot/" + p)
	}
}

func main() {
	//formatter := &log.TextFormatter{TimestampFormat: time.RFC3339Nano, DisableColors: true, DisableTimestamp: false}
        log.SetFormatter(&log.JSONFormatter{})

	http.HandleFunc("/", defaultHandler)

	http.HandleFunc("/infect", infectHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
