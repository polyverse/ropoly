package handlers

import (
	"encoding/json"
	"github.com/polyverse/ropoly/lib/types"
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
	var readComparison types.FingerprintComparison
	err = json.Unmarshal(contents, &readComparison)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	/*
	eqiFunc := r.Form.Get("func")

	eqiResult, err := lib.Eqi(comparison, eqiFunc, r.Form)
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
	*/
}
