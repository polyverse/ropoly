package handlers

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/polyverse/ropoly/lib"
	log "github.com/sirupsen/logrus"
)

func PostFileHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["path"]
	path := NormalizePath(UploadedFilesDirectory() + name)
	i := 0
	for ;i < len(name); i++ {
		if path[len(path) - 1 - i] == byte('/') {
			break
		}
	}
	lib.EnsureDirectory(path[:len(path) - i])

	if r.FormValue("overwrite") != "true" {
		exists, err := lib.Exists(path)
		if err != nil {
			logErrors(err, nil)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if exists {
			b := []byte("File already exists. Use \"overwrite=true\" to overwrite.")
			w.Write(b)
			return
		}
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var b bytes.Buffer
	io.Copy(&b, file)
	ioutil.WriteFile(path, b.Bytes(), 0666)
}

func UploadedFileHandler(w http.ResponseWriter, r *http.Request) {
	path := NormalizePath(UploadedFilesDirectory() + getFilepath(r, "api/v1/uploadedfiles")[1:])

	fi, err := os.Stat(path)
	if err != nil {
		log.WithError(err).Warningf("Unable to stat path %s. Not handling it like a directory.", path)
	} else if fi.IsDir() {
		DirectoryListingHandler(w, r, FileSystemRoot + path)
		return
	}

	query := r.FormValue("query")
	switch query {
	case "taints":
		PolyverseTaintedFileHandler(w, r, path)
	case "disasm":
		FileDisasmHandler(w, r, path)
	case "gadgets":
		GadgetsFromFileHandler(w, r, path)
	case "fingerprint":
		FingerprintForFileHandler(w, r, path)
	case "search":
		FileGadgetSearchHandler(w, r, path)
	default:
		PolyverseTaintedFileHandler(w, r, path)
	} // switch
}