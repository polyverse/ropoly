package handlers

import (
	"encoding/json"
	"github.com/polyverse/ropoly/lib"
	"io/ioutil"
	"net/http"
)

func EqiHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	comparisonPath := r.Form.Get("comparison")
	contents, err := ioutil.ReadFile(comparisonPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var readComparison lib.PrintableFingerprintComparison
	err = json.Unmarshal(contents, &readComparison)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	comparison, err := lib.ParseComparison(readComparison)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	eqiFunc := r.Form.Get("func")

	eqiResult, err := lib.Eqi(comparison, eqiFunc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	b, err := json.MarshalIndent(eqiResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(b)
}