package handlers

import (
	"encoding/json"
	"net/http"
	"io/ioutil"
	"github.com/polyverse/ropoly/lib"
)

func FingerprintComparisonHandler(w http.ResponseWriter, r *http.Request) {
	error := r.ParseForm()
	if error != nil {
		http.Error(w, error.Error(), http.StatusBadRequest)
		return
	}

	oldPath := r.Form.Get("old")
	newPath := r.Form.Get("new")

	// Read old fingerprint from file
	oldContents, error := ioutil.ReadFile(oldPath)
	if error != nil {
		http.Error(w, error.Error(), http.StatusBadRequest)
		return
	}
	var oldPrintable lib.PrintableFingerprintResult
	error = json.Unmarshal(oldContents, &oldPrintable)
	if error != nil {
		http.Error(w, error.Error(), http.StatusBadRequest)
		return
	}
	old, error := lib.ParseFingerprintResult(oldPrintable)
	if error != nil {
		http.Error(w, error.Error(), http.StatusBadRequest)
		return
	}

	// Read new fingerprint from file
	newContents, error := ioutil.ReadFile(newPath)
	if error != nil {
		http.Error(w, error.Error(), http.StatusBadRequest)
		return
	}
	var newPrintable lib.PrintableFingerprintResult
	error = json.Unmarshal(newContents, &newPrintable)
	if error != nil {
		http.Error(w, error.Error(), http.StatusBadRequest)
		return
	}
	new, error := lib.ParseFingerprintResult(newPrintable)
	if error != nil {
		http.Error(w, error.Error(), http.StatusBadRequest)
		return
	}

	comparison := lib.CompareFingerprints(old, new)
	printableComparison := lib.PrintableComparison(&comparison)

	b, error := json.MarshalIndent(printableComparison, "", indent)
	if error != nil {
		http.Error(w, error.Error(), http.StatusBadRequest)
		return
	}
	w.Write(b)
}