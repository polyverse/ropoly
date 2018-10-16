package handlers

import (
	"encoding/json"
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

const safeEndAddress uint64 = 0x7fffffffffff
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

func ROPHealthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("Ropoly API Healthy")
} // ROPTestHandler()

func getFilepath(r *http.Request, uri string) string {
	splitUri := strings.Split(r.RequestURI, uri)
	return strings.SplitN(splitUri[len(splitUri)-1], "?", 2)[0]
}

func ROPFileHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Mode should be directory, signature, gadget, or disasm.", http.StatusBadRequest)
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
	case "regions":
		ROPMemoryRegionsHandler(w, r, pidN)
	case "search":
		ROPMemorySearchHandler(w, r, pidN)
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
	signatureResult, err := lib.DiskSignatureSearch(filepath)
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

func ROPDiskDisAsmHandler(w http.ResponseWriter, r *http.Request, filepath string) {
	var startN uint64 = 0
	start := r.Form.Get("start")
	if start == "start" {
		startN = 0
	} else if start != "" {
		var err error
		startN, err = strconv.ParseUint(start, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var endN uint64 = math.MaxUint64
	end := r.Form.Get("end")
	if end == "end" {
		endN = uint64(safeEndAddress)
	} else if end != "" {
		var err error
		endN, err = strconv.ParseUint(end, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var limitN uint64 = math.MaxInt32
	limit := r.Form.Get("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
		var err error
		limitN, err = strconv.ParseUint(limit, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	all := r.Form.Get("all") == "true"

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
	var startN uint64 = 0
	start := r.Form.Get("start")
	if start == "start" {
		startN = 0
	} else if start != "" {
		var err error
		startN, err = strconv.ParseUint(start, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var endN uint64 = math.MaxUint64
	end := r.Form.Get("end")
	if end == "end" {
		endN = uint64(safeEndAddress)
	} else if end != "" {
		var err error
		endN, err = strconv.ParseUint(end, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var limitN uint64 = math.MaxInt32
	limit := r.Form.Get("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
		var err error
		limitN, err = strconv.ParseUint(limit, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	all := r.Form.Get("all") == "true"

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

const jsonGadgetsEnd = "\n    ]\n}"

func GadgetHandler(inMemory bool, w http.ResponseWriter, r *http.Request, pidN int, filepath string) {
	var startN uint64 = 0
	start := r.Form.Get("start")
	var err error
	if start == "start" {
		startN = 0
	} else if start != "" {
		startN, err = strconv.ParseUint(start, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var endN uint64 = math.MaxUint64
	end := r.Form.Get("end")
	if end == "end" {
		endN = uint64(safeEndAddress)
	} else if end != "" {
		endN, err = strconv.ParseUint(end, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var limitN uint64 = math.MaxInt32
	limit := r.Form.Get("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
		limitN, err = strconv.ParseUint(limit, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // else if
	} // if

	var instructionsN uint64 = math.MaxInt32
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

	spec := lib.GadgetSearchSpec {
		InMemory:       inMemory,
		PidN:           pidN,
		Filepath:       filepath,
		StartN:         startN,
		EndN:           endN,
		LimitN:         limitN,
		InstructionsN:  instructionsN,
		OctetsN:        octetsN,
	} // GadgetSearchSpec

	firstRegion := true
	var firstGadget bool

	w.Write([]byte("{\n" + indent + "\"regions\": ["))
	harderror, softerrors := lib.OperateOnGadgets(spec, func(region memaccess.MemoryRegion) {
		b, _ := json.MarshalIndent(&region, indent + indent + indent, indent)
		b = append([]byte("\n" + indent + indent + "{\n" + indent + indent + indent + "\"region\": "), b...)
		b = append(b, []byte(",\n" + indent + indent + indent + "\"gadgets\": [\n" + indent + indent + indent + indent)...)
		if !firstRegion {
			b = append([]byte("\n" + indent + indent + indent + "]\n" + indent + indent + "},"), b...)
		}
		firstRegion = false

		w.Write(b)

		firstGadget = true
	}, func(gadget lib.Gadget) {
		b, _ := json.MarshalIndent(&gadget, indent + indent + indent + indent, indent)
		if !firstGadget {
			b = append([]byte(",\n" + indent + indent + indent + indent), b...)
		}
		firstGadget = false
		w.Write(b)
	}) //lib.OperateOnGadgets
	logErrors(harderror, softerrors)
	w.Write([]byte("\n" + indent + indent + indent + "]\n" + indent + indent + "}\n" + indent + "]\n}"))
} // GadgetHandler()

func FingerprintHandler(inMemory bool, w http.ResponseWriter, r *http.Request, pidN int, filepath string) {
	var startN uint64 = 0
	start := r.Form.Get("start")
	var err error
	if start == "start" {
		startN = 0
	} else if start != "" {
		startN, err = strconv.ParseUint(start, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var endN uint64 = math.MaxUint64
	end := r.Form.Get("end")
	if end == "end" {
		endN = uint64(safeEndAddress)
	} else if end != "" {
		endN, err = strconv.ParseUint(end, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var limitN uint64 = math.MaxInt32
	limit := r.Form.Get("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
		limitN, err = strconv.ParseUint(limit, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // else if
	} // if

	var instructionsN uint64 = math.MaxInt32
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

	spec := lib.GadgetSearchSpec {
		InMemory:       inMemory,
		PidN:           pidN,
		Filepath:       filepath,
		StartN:         startN,
		EndN:           endN,
		LimitN:         limitN,
		InstructionsN:  instructionsN,
		OctetsN:        octetsN,
	} // spec

	fingerprintResult, harderror, softerrors := lib.Fingerprint(spec)
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(lib.Printable(&fingerprintResult), "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	w.Write(b)
} // FingerprintHandler()

func ROPMemoryRegionsHandler(w http.ResponseWriter, r *http.Request, pidN int) {
	var access memaccess.Access = memaccess.None

	accessS := strings.ToUpper(r.Form.Get("access"))
	if accessS == "NONE" {
		access = memaccess.None
	} else if accessS == "" {
		access = memaccess.Readable
	} else {
		if i := strings.Index(accessS, "R"); i != -1 {
			access |= memaccess.Readable
			accessS = strings.Replace(accessS, "R", "", 1)
		} // if
		if i := strings.Index(accessS, "W"); i != -1 {
			access |= memaccess.Writable
			accessS = strings.Replace(accessS, "W", "", 1)
		} // if
		if i := strings.Index(accessS, "X"); i != -1 {
			access |= memaccess.Executable
			accessS = strings.Replace(accessS, "X", "", 1)
		} // if
		if i := strings.Index(accessS, "F"); i != -1 {
			access |= memaccess.Free
			accessS = strings.Replace(accessS, "F", "", 1)
		} // if
		if accessS != "" {
			http.Error(w, "Improper Access specification.", http.StatusBadRequest)
			return
		} // if
	} // else

	regionsResult, harderror, softerrors := lib.ROPMemoryRegions(pidN, access)
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&regionsResult, "", indent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemoryRegionsHandler()

func ROPMemorySearchHandler(w http.ResponseWriter, r *http.Request, pidN int) {
	var startN uint64 = 0
	start := r.Form.Get("start")
	var err error
	if start == "start" {
		startN = 0
	} else if start != "" {
		startN, err = strconv.ParseUint(start, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var endN uint64 = math.MaxUint64
	end := r.Form.Get("end")
	if end == "end" {
		endN = uint64(safeEndAddress)
	} else if end != "" {
		endN, err = strconv.ParseUint(end, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var limitN uint64 = math.MaxInt32
	limit := r.Form.Get("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
		limitN, err = strconv.ParseUint(limit, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

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