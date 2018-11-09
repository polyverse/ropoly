package handlers

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"github.com/polyverse/ropoly/lib"
	"github.com/polyverse/ropoly/lib/types"
	"github.com/polyverse/disasm"
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

	var gadgets []*disasm.Gadget
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

	fingerprint := types.FingerprintFromGadgets(gadgets)

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

		err := ioutil.WriteFile(DataDirectory + "/" + outputFile, b, 0666)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			logErrors(err, nil)
			return
		}
	}
}