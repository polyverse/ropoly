package handlers

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/polyverse/ropoly/lib"
	"github.com/polyverse/ropoly/lib/types"
	log "github.com/sirupsen/logrus"
)

const indent string = "    "

type DirectoryListingEntryType string

const (
	EntryTypeDir  DirectoryListingEntryType = "Directory"
	EntryTypeFile DirectoryListingEntryType = "File"
)

type DirectoryListingEntry struct {
	Path            string                    `json:"path"`
	Type            DirectoryListingEntryType `json:"type"`
	PolyverseTained bool                      `json:"polyverseTainted"`
}

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
		DirectoryListingHandler(w, r, filepath)
	case "signature":
		PolyverseTaintedFileHandler(w, r, filepath)
	case "gadget":
		ROPFileGadgetHandler(w, r, filepath)
	case "fingerprint":
		FingerprintHandler(false, w, r, 0, filepath)
	default:
		http.Error(w, "Mode should be directory, signature, disasm, gadget, or fingerprint.", http.StatusBadRequest)
	} // switch
}

func ProcessHandler(w http.ResponseWriter, r *http.Request) {
	pid, err := getPid(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pidN := int(pid)

	mode := r.FormValue("mode")
	switch mode {
	case "gadget":
		ROPMemoryGadgetHandler(w, r, pidN)
	case "fingerprint":
		FingerprintForPidHandler(w, r, pidN)
	default:
		http.Error(w, "Mode should be regions, search, disasm, gadget, or fingerprint.", http.StatusBadRequest)
	}
} // ROPMemoryHandler()

func DirectoryListingHandler(w http.ResponseWriter, r *http.Request, dirpath string) {
	listing := []*DirectoryListingEntry{}

	err := filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.WithError(err).Error("Unable to walk filesystem path %s", path)
			return nil
		}
		entry := &DirectoryListingEntry{
			Path: path,
		}
		if info.IsDir() {
			entry.Type = EntryTypeDir
		} else {
			entry.Type = EntryTypeFile
			pvTaint, err := lib.HasPVSignature(info)
			if err != nil {
				log.WithError(err).Errorf("Error when checking for Polyverse taint on path %s", path)
			} else {
				entry.PolyverseTained = pvTaint
			}
		}
		listing = append(listing, entry)
		return nil
	})
	if err != nil {
		logErrors(err, make([]error, 0))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	b, err := json.MarshalIndent(&listing, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if

	w.Write(b)
} // ROPFileHandler

func PolyverseTaintedFileHandler(w http.ResponseWriter, r *http.Request, path string) {
	fileinfo, err := os.Stat(path)
	if err != nil {
		logErrors(err, make([]error, 0))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signatureResult, err := lib.HasPVSignature(fileinfo)
	if err != nil {
		logErrors(err, make([]error, 0))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	b, err := json.MarshalIndent(&signatureResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPisPolyverseFileHandler

func PidListingHandler(w http.ResponseWriter, r *http.Request) {
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

func PidLibrariesHandler(w http.ResponseWriter, r *http.Request) {
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

func FingerprintForPidHandler(w http.ResponseWriter, r *http.Request, pid int) {
	var gadgetLen uint64 = 2 // Gadgets longer than 2 instructions must be requested explicitly
	var err error
	lenStr := r.Form.Get("len")
	if lenStr != "" {
		gadgetLen, err = strconv.ParseUint(lenStr, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	gadgets, err, softerrors := lib.GadgetsFromProcess(pid, int(gadgetLen))
	if err != nil {
		logErrors(err, softerrors)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} // if

	fingerprint := types.FingerprintFromGadgets(gadgets)

	b, err := json.MarshalIndent(fingerprint, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

	http.Error(w, "This functionality is not yet implemented.", http.StatusNotImplemented)
} // ROPMemorySearchHandler()
