package handlers

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
	"github.com/polyverse/ropoly/lib"
	"github.com/polyverse/ropoly/lib/types"
	"io/ioutil"
	"net/http"
)

func FingerprintComparisonHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	oldPath := r.Form.Get("old")
	newPath := r.Form.Get("new")

	// Read old fingerprint from file
	oldContents, err := ioutil.ReadFile(oldPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var old types.Fingerprint
	err = json.Unmarshal(oldContents, &old)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Read new fingerprint from file
	newContents, err := ioutil.ReadFile(newPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var new types.Fingerprint
	err = json.Unmarshal(newContents, &new)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	comparison := lib.CompareFingerprints(old, new)
	b, err := json.MarshalIndent(comparison, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

func ComparisonListingHandler(w http.ResponseWriter, r *http.Request) {
	if DataDirectory == "" {
		err := errors.New("Persistent data directory not provided.")
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	comparisonFiles, err := ioutil.ReadDir(ComparisonsDirectory())
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	comparisons := make([]string, len(comparisonFiles))
	for i := 0; i < len(comparisonFiles); i++ {
		comparisons[i] = comparisonFiles[i].Name()
	}

	b, err := json.MarshalIndent(comparisons, "", indent)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func StoredComparisonHandler(w http.ResponseWriter, r *http.Request) {
	comparison := mux.Vars(r)["comparison"]
	b, err := ioutil.ReadFile(ComparisonsDirectory() + comparison)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

func StoredComparisonEqiHandler(w http.ResponseWriter, r *http.Request) {
	if DataDirectory == "" {
		err := errors.New("Persistent data directory not provided.")
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	handleEqi(w, r, ComparisonsDirectory() + mux.Vars(r)["comparison"])
}