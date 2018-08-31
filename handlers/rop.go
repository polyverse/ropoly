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
)

const safeStartAddress uint64 = 0
const safeEndAddress uint64 = 0x7fffffffffff

func logErrors(hardError error, softErrors []error) {
	if hardError != nil {
		log.Fatal(hardError)
	}

	for _, softError := range softErrors {
		log.Print(softError)
	}
} // logErrors

func ROPTestHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("Test")
} // ROPTestHandler()

func ROPPIdsHandler(w http.ResponseWriter, r *http.Request) {
	pIdsResult, harderror, softerrors := lib.GetAllPids()
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&pIdsResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPPIdsHandler()

func ROPLibrariesHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	var pidN uint64 = uint64(os.Getpid())
	pid := mux.Vars(r)["pid"]
	if (pid != "") && (pid != "0") {
		pidN, err = strconv.ParseUint(pid, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // if

	librariesResult, harderror, softerrors := lib.GetLibrariesForPid(int(pidN))

	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&librariesResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPLibrariesHandler()

func ROPMemoryHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("ROPMemoryHandler")
} // ROPMemoryHandler()

func ROPMemoryDisAsmHandler(w http.ResponseWriter, r *http.Request) {
	var pidSelf = uint64(os.Getpid())
	var err error

	pidN := pidSelf
	pid := mux.Vars(r)["pid"]
	if (pid != "") && (pid != "0") {
		pidN, err = strconv.ParseUint(pid, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // if

	var startN uint64 = 0
	start := r.FormValue("start")
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
	end := r.FormValue("end")
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
	limit := r.FormValue("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
		limitN, err = strconv.ParseUint(limit, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	disAsmResult, harderror, softerrors := lib.MemoryDisAsmForPid(int(pidN), startN, endN, limitN)
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&disAsmResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemoryDisAsmHandler()

func ROPMemoryGadgetHandler0(w http.ResponseWriter, r *http.Request, fingerprinting bool) {
	var pidSelf = uint64(os.Getpid())
	var err error

	pidN := pidSelf
	pid := mux.Vars(r)["pid"]
	if (pid != "") && (pid != "0") {
		pidN, err = strconv.ParseUint(pid, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // if

	var startN uint64 = 0
	start := r.FormValue("start")
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
	end := r.FormValue("end")
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
	limit := r.FormValue("limit")
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
	instructions := r.FormValue("instructions")
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
	octets := r.FormValue("octets")
	if octets == "octets" {
		octetsN = 100
	} else if octets != "" {
		octetsN, err = strconv.ParseUint(octets, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	var b []byte
	if fingerprinting {
		fingerprintResult, harderror, softerrors := lib.GadgetFingerprintssInMemoryForPid(int(pidN), instructions, startN, endN, limitN, instructionsN, octetsN)
		logErrors(harderror, softerrors)
		if harderror != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if

		b, err = json.MarshalIndent(&fingerprintResult, "", "    ")
	} else {
		gadgetResult, harderror, softerrors := lib.GadgetsInMemoryForPid(int(pidN), instructions, startN, endN, limitN, instructionsN, octetsN)
		logErrors(harderror, softerrors)
		if harderror != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if

		b, err = json.MarshalIndent(&gadgetResult, "", "    ")
	} // else

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemoryGadgetHandler()

func ROPMemoryGadgetHandler(w http.ResponseWriter, r *http.Request) {
	ROPMemoryGadgetHandler0(w, r, false)
} // ROPMemoryGadgetHandler()

func ROPMemoryFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	ROPMemoryGadgetHandler0(w, r, true)
} // ROPMemoryFingerprintHandler()

func ROPMemoryRegionsHandler(w http.ResponseWriter, r *http.Request) {
	var pidSelf = uint64(os.Getpid())
	var err error

	pidN := pidSelf
	pid := mux.Vars(r)["pid"]
	if (pid != "") && (pid != "0") {
		pidN, err = strconv.ParseUint(pid, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // if

	var access memaccess.Access = memaccess.None

	accessS := strings.ToUpper(r.FormValue("access"))
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

	regionsResult, harderror, softerrors := lib.ROPMemoryRegions(int(pidN), access)
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	b, err := json.MarshalIndent(&regionsResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemoryRegionsHandler()

func ROPMemorySearchHandler(w http.ResponseWriter, r *http.Request) {
	var pidSelf = uint64(os.Getpid())
	var err error

	pidN := pidSelf
	pid := mux.Vars(r)["pid"]
	if (pid != "") && (pid != "0") {
		pidN, err = strconv.ParseUint(pid, 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // if

	var startN uint64 = 0
	start := r.FormValue("start")
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
	end := r.FormValue("end")
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
	limit := r.FormValue("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
		limitN, err = strconv.ParseUint(limit, 0, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} // if
	} // else if

	search := r.FormValue("string")
	if search == "" {
		search = r.FormValue("regexp")
	} // if

	searchResult, harderror, softerrors := lib.ROPMemorySearch(int(pidN), search, disasm.Ptr(startN), disasm.Ptr(endN), uint(limitN), r.FormValue("regexp") != "")
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if
	logErrors(harderror, softerrors)

	b, err := json.MarshalIndent(&searchResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemorySearchHandler()
