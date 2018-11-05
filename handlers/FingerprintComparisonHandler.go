package handlers

/*
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var oldPrintable types.Fingerprint
	err = json.Unmarshal(oldContents, &oldPrintable)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	old, err := lib.ParseFingerprintResult(oldPrintable)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Read new fingerprint from file
	newContents, err := ioutil.ReadFile(newPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var newPrintable lib.PrintableFingerprintResult
	err = json.Unmarshal(newContents, &newPrintable)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	new, err := lib.ParseFingerprintResult(newPrintable)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	comparison := lib.CompareFingerprints(old, new)
	printableComparison := lib.PrintableComparison(&comparison)

	b, err := json.MarshalIndent(printableComparison, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(b)
}

*/
