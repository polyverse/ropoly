package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/gorilla/mux"
	"github.com/polyverse/ropoly/lib"
	"github.com/polyverse/ropoly/lib/fingerprint"
	"github.com/polyverse/ropoly/lib/types"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
)

func FingerprintForFileHandler(w http.ResponseWriter, r *http.Request, path string) {
	fingerprintHandler(w, r, true, 0, path)
}

func FingerprintForPidHandler(w http.ResponseWriter, r *http.Request, pid int) {
	fingerprintHandler(w, r, false, pid, "")
}

func fingerprintHandler(w http.ResponseWriter, r *http.Request, isFile bool, pid int, path string) {
	var gadgetLen uint64 = 2 // Gadgets longer than 2 instructions must be requested explicitly
	var err error
	lenStr := r.Form.Get("len")
	if lenStr != "" {
		gadgetLen, err = strconv.ParseUint(lenStr, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} // if
	} // else if

	outputFile := r.Form.Get("out")

	var gadgets []*types.Gadget
	var softerrors []error
	if isFile {
		gadgets, err = lib.GadgetsFromExecutable(path, int(gadgetLen))
	} else {
		gadgets, err, softerrors = lib.GadgetsFromProcess(pid, int(gadgetLen))
	}
	if err != nil {
		logErrors(err, softerrors)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fingerprint, err := fingerprint.FingerprintFromGadgets(gadgets)
	if err != nil {
		logErrors(err, softerrors)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.MarshalIndent(fingerprint, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if outputFile == "" {
		w.Write(b)
	} else {
		if DataDirectory == "" {
			err := errors.New("Requested to save file, but persistent data directory not set.")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}

		filepath := FingerprintsDirectory() + outputFile

		if r.Form.Get("overwrite") != "true" {
			exists, err := lib.Exists(filepath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				logErrors(err, nil)
				return
			}
			if exists {
				b := []byte("File already exists. Use \"overwrite=true\" to overwrite.")
				w.Write(b)
				return
			}
		}

		err := ioutil.WriteFile(FingerprintsDirectory()+outputFile, b, 0666)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}
	}
}

func FingerprintListingHandler(w http.ResponseWriter, r *http.Request) {
	if DataDirectory == "" {
		err := errors.New("Persistent data directory not provided.")
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fingerprintFiles, err := ioutil.ReadDir(FingerprintsDirectory())
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fingerprints := make([]string, len(fingerprintFiles))
	for i := 0; i < len(fingerprintFiles); i++ {
		fingerprints[i] = fingerprintFiles[i].Name()
	}

	b, err := json.MarshalIndent(fingerprints, "", indent)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func StoredFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	fingerprint := mux.Vars(r)["fingerprint"]
	b, err := ioutil.ReadFile(FingerprintsDirectory() + fingerprint)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

func PostFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["fingerprint"]
	path := FingerprintsDirectory() + name

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

	file, _, err := r.FormFile("fingerprint")
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var b bytes.Buffer
	io.Copy(&b, file)
	ioutil.WriteFile(path, b.Bytes(), 0666)
}

func StoredFingerprintComparisonHandler(w http.ResponseWriter, r *http.Request) {
	f1Name := mux.Vars(r)["fingerprint"]
	f2Name := r.FormValue("second")

	f1Bytes, err := ioutil.ReadFile(FingerprintsDirectory() + f1Name)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f2Bytes, err := ioutil.ReadFile(FingerprintsDirectory() + f2Name)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var f1 types.Fingerprint
	err = json.Unmarshal(f1Bytes, &f1)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var f2 types.Fingerprint
	err = json.Unmarshal(f2Bytes, &f2)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	comparison := lib.CompareFingerprints(f1, f2)
	b, err := json.MarshalIndent(comparison, "", indent)
	if err != nil {
		logErrors(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	outputFile := r.Form.Get("out")

	if outputFile == "" {
		w.Write(b)
	} else {
		if DataDirectory == "" {
			err := errors.New("Requested to save file, but persistent data directory not set.")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}

		filepath := ComparisonsDirectory() + outputFile

		if r.Form.Get("overwrite") != "true" {
			exists, err := lib.Exists(filepath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				logErrors(err, nil)
				return
			}
			if exists {
				b := []byte("File already exists. Use \"overwrite=true\" to overwrite.")
				w.Write(b)
				return
			}
		}

		err := ioutil.WriteFile(filepath, b, 0666)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}
	}
}
