package handlers

import (
	"encoding/json"
	"github.com/polyverse/ropoly/lib/types"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/polyverse/masche/memaccess"

	"github.com/polyverse/disasm"
	"github.com/polyverse/ropoly/lib"

	"errors"
)

const indent string = "    "

func logErrors(hardError error, softErrors []error) {
	if hardError != nil {
		//log.Fatal(hardError)
		log.Print(hardError)
	}

	for _, softError := range softErrors {
		log.Print(softError)
	}
} // logErrors

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("Ropoly API Healthy")
} // ROPTestHandler()

func getFilepath(r *http.Request, uri string) string {
	splitUri := strings.Split(r.RequestURI, uri)
	return strings.SplitN(splitUri[len(splitUri)-1], "?", 2)[0]
}

func FileHandler(w http.ResponseWriter, r *http.Request) {
	filepath := getFilepath(r, "api/v1/files")

	mode := r.FormValue("mode")
	switch mode {
	case "directory":
		ROPDirectoryHandler(w, r, filepath)
	case "signature":
		ROPIsPolyverseFileHandler(w, r, filepath)
	case "disasm":
		ROPDiskDisAsmHandler(w, r, filepath)
	case "gadget":
		ROPFileGadgetHandler(w, r, filepath)
	case "fingerprint":
		FingerprintHandler(false, w, r, 0, filepath)
	default:
		http.Error(w, "Mode should be directory, signature, disasm, gadget, or fingerprint.", http.StatusBadRequest)
	} // switch
}

func ROPMemoryHandler(w http.ResponseWriter, r *http.Request) {
	pid, err := getPid(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pidN := int(pid)

	mode := r.FormValue("mode")
	switch mode {
	case "disasm":
		ROPMemoryDisAsmHandler(w, r, pidN)
	case "gadget":
		ROPMemoryGadgetHandler(w, r, pidN)
	case "fingerprint":
		FingerprintHandler(true, w, r, pidN, "")
	default:
		http.Error(w, "Mode should be regions, search, disasm, gadget, or fingerprint.", http.StatusBadRequest)
	}
} // ROPMemoryHandler()

func ROPDirectoryHandler(w http.ResponseWriter, r *http.Request, filepath string) {
	filesResult, harderror := lib.GetFiles(filepath)
	if harderror != nil {
		logErrors(harderror, make([]error, 0))
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&filesResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPFileHandler

func ROPIsPolyverseFileHandler(w http.ResponseWriter, r *http.Request, filepath string) {
	signatureResult, err := lib.HasPVSignature(filepath)
	if err != nil {
		logErrors(err, make([]error, 0))
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	b, err := json.MarshalIndent(&signatureResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPisPolyverseFileHandler

func ROPPIdsHandler(w http.ResponseWriter, r *http.Request) {
	pIdsResult, harderror, softerrors := lib.GetAllPids()
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&pIdsResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPPIdsHandler()

func getPid(r *http.Request) (uint64, error) {
	var err error

	var pidN uint64 = uint64(os.Getpid())
	pid := mux.Vars(r)["pid"]
	if (pid != "") && (pid != "0") {
		pidN, err = strconv.ParseUint(pid, 0, 64)
		if err != nil {
			err = errors.New("Cannot parse PID.")
		}
	}
	return pidN, err
}

func ROPLibrariesHandler(w http.ResponseWriter, r *http.Request) {
	pidN, err := getPid(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	checkSignatures := false
	signatures := r.Form.Get("signatures")
	if signatures == "true" {
		checkSignatures = true
	}

	librariesResult, harderror, softerrors := lib.GetLibrariesForPid(int(pidN), checkSignatures)

	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&librariesResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPLibrariesHandler()

func FileDisAsmHandler(w http.ResponseWriter, r *http.Request, filepath string) {
	disAsmResult, harderror, _ := lib.DisAsmForFile(filepath, startN, endN, limitN, all)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&disAsmResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // DiskDisAsmHandler

func ROPMemoryDisAsmHandler(w http.ResponseWriter, r *http.Request, pidN int) {
	disAsmResult, harderror, softerrors := lib.MemoryDisAsmForPid(pidN, startN, endN, limitN, all)
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&disAsmResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemoryDisAsmHandler()

func ROPMemoryGadgetHandler(w http.ResponseWriter, r *http.Request, pidN int) {
	GadgetHandler(true, w, r, pidN, "")
} //ROPMemoryGadgetHandler

func ROPFileGadgetHandler(w http.ResponseWriter, r *http.Request, filepath string) {
	GadgetHandler(false, w, r, 0, filepath)
}

func GadgetsFromPidHandler(w http.ResponseWriter, r *http.Request, pidN int) {
	var instructionsN uint64 = 2 // Gadgets longer than 2 instructions have to be explicitly requested
	instructions := r.Form.Get("instructions")
	if instructions == "instructions" {
		instructionsN = 5
	} else if instructions != "" {
		instructionsN, err = strconv.ParseUint(instructions, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var octetsN uint64 = math.MaxInt32
	octets := r.Form.Get("octets")
	if octets == "octets" {
		octetsN = 100
	} else if octets != "" {
		octetsN, err = strconv.ParseUint(octets, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

} // GadgetHandler()

func FingerprintForPidHandler(inMemory bool, w http.ResponseWriter, r *http.Request, pidN int) {
	var instructionsN int = 2 // Gadgets longer than 2 instructions must be requested explicitly
	instructions := r.Form.Get("instructions")
	if instructions == "instructions" {
		instructionsN = 5
	} else if instructions != "" {
		instructionsN, err = strconv.ParseUint(instructions, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	fingerprint := types.FingerprintFromGadgets(lib.GadgetsFromProcess(pidN, instructionsN))
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(fingerprint), "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	w.Write(b)
} // FingerprintHandler()

func GadgetMemorySearchHandler(w http.ResponseWriter, r *http.Request, pidN int) {
	search := r.Form.Get("string")
	if search == "" {
		search = r.Form.Get("regexp")
		if search == "" {
			err := errors.New("Search with no or empty target given.")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} // if

	searchResult, harderror, softerrors := lib.ROPMemorySearch(pidN, search, disasm.Ptr(startN), disasm.Ptr(endN), uint(limitN), r.Form.Get("regexp") != "")
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if
	logErrors(harderror, softerrors)

	b, err := json.MarshalIndent(&searchResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemorySearchHandler()
