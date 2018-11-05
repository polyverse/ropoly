package handlers

import (
	"encoding/json"
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
