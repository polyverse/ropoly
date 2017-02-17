package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/polyverse-security/masche/listlibs"
	"github.com/polyverse-security/masche/memaccess"
	"github.com/polyverse-security/masche/memsearch"
	"github.com/polyverse-security/masche/process"

	"github.com/polyverse-security/disasm"
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

type PIdsResult struct {
	NumPIds int   `json:"numPIds"`
	PIds    []int `json:"pIds"`
}

func ROPPIdsHandler(w http.ResponseWriter, r *http.Request) {
	pIds, harderror, softerrors := process.GetAllPids()
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	pIdsResult := PIdsResult{NumPIds: len(pIds), PIds: pIds}

	b, err := json.MarshalIndent(&pIdsResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPPIdsHandler()

type LibrariesResult struct {
	NumLibraries int      `json:"numLibraries"`
	Libraries    []string `json:"libraries"`
}

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

        process, harderror, softerrors := process.OpenFromPid(int(pidN))
        logErrors(nil, softerrors)
        if harderror != nil {
                http.Error(w, harderror.Error(), http.StatusBadRequest)
                return
        } // if
        defer process.Close()

	libraries, harderror, softerrors := listlibs.ListLoadedLibraries(process)
	logErrors(harderror, softerrors)
	if harderror != nil {
		http.Error(w, harderror.Error(), http.StatusBadRequest)
		return
	} // if

	librariesResult := LibrariesResult{NumLibraries: len(libraries), Libraries: libraries}

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

type DisAsmResult struct {
	NumInstructions disasm.Len           `json:"numInstructions"`
	Instructions    []disasm.Instruction `json:"instructions"`
}

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

        process, harderror, softerrors := process.OpenFromPid(int(pidN))
        logErrors(nil, softerrors)
        if harderror != nil {
                http.Error(w, harderror.Error(), http.StatusBadRequest)
                return
        } // if
	defer process.Close()

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

	var instructions []disasm.Instruction

	for pc := startN; (pc <= endN) && (len(instructions) < int(limitN)); {
		region, hardError, softErrors := memaccess.NextMemoryRegionAccess(process, uintptr(pc), memaccess.Readable+memaccess.Executable)
		logErrors(hardError, softErrors)

		if region == memaccess.NoRegionAvailable {
			break
		} // if

		if pc < uint64(region.Address) {
			pc = uint64(region.Address)
		} // if

		if pc > endN {
			break
		} // if

		var info disasm.Info
		var bytes []byte // Scope is important here. Unsafe pointers are taken in disasm.InfoInitBytes(). Store must survive next block.

		if pid != "0" {
			bytes = make([]byte, region.Size, region.Size)
			memaccess.CopyMemory(process, region.Address, bytes)
			info = disasm.InfoInitBytes(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1), bytes)
		} else {
			info = disasm.InfoInit(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1))
		} // else

		for (pc <= endN) && pc < uint64((region.Address+uintptr(region.Size))) && (len(instructions) < int(limitN)) {
			instruction, err := disasm.DecodeInstruction(info, disasm.Ptr(pc))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			} // if

			instructions = append(instructions, *instruction)
			pc = pc + uint64(instruction.NumOctets)
		} // for
	} // for

	disAsmResult := DisAsmResult{NumInstructions: disasm.Len(len(instructions)), Instructions: instructions}

	b, err := json.MarshalIndent(&disAsmResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemoryDisAsmHandler()

type GadgetResult struct {
	NumGadgets disasm.Len      `json:"numGadgets"`
	Gadgets    []disasm.Gadget `json:"gadgets"`
}

type FingerprintResult struct {
	NumGadgets disasm.Len `json:"numGadgets"`
	Gadgets    []string   `json:"gadgets"`
}

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

        process, harderror, softerrors := process.OpenFromPid(int(pidN))
        logErrors(nil, softerrors)
        if harderror != nil {
                http.Error(w, harderror.Error(), http.StatusBadRequest)
                return
        } // if
        defer process.Close()

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

	var numGadgets int
	var gadgetResult GadgetResult
	var fingerprintResult FingerprintResult

	for pc := startN; (pc <= endN) && (numGadgets < int(limitN)); {
		region, hardError, softErrors := memaccess.NextMemoryRegionAccess(process, uintptr(pc), memaccess.Readable+memaccess.Executable)
		logErrors(hardError, softErrors)

		if region == memaccess.NoRegionAvailable {
			break
		} // if

		if pc < uint64(region.Address) {
			pc = uint64(region.Address)
		} // if

		if pc > endN {
			break
		} // if

		var info disasm.Info
		var bytes []byte // Scope is important here. Unsafe pointers are taken in disasm.InfoInitBytes(). Store must survive next block.

		if pid != "0" {
			bytes = make([]byte, region.Size, region.Size)
			memaccess.CopyMemory(process, region.Address, bytes)
			info = disasm.InfoInitBytes(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1), bytes)
		} else {
			info = disasm.InfoInit(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1))
		} // else

		fmt.Printf("Searching region: %v\n", region)

		for ; (pc <= endN) && pc < uint64((region.Address+uintptr(region.Size))) && (numGadgets < int(limitN)); pc++ {
			if (pc % 0x100000) == 0 {
				fmt.Printf("pc: %x\n", pc)
			} // if

			gadget, err := disasm.DecodeGadget(info, disasm.Ptr(pc), int(instructionsN), int(octetsN))
			if err == nil {
				if fingerprinting {
					fingerprintResult.Gadgets = append(fingerprintResult.Gadgets, gadget.String())
				} else {
					gadgetResult.Gadgets = append(gadgetResult.Gadgets, *gadget)
				} // else
				numGadgets++
			} // if
		} // for
	} // for

	var b []byte

	if fingerprinting {
		fingerprintResult.NumGadgets = disasm.Len(numGadgets)

		b, err = json.MarshalIndent(&fingerprintResult, "", "    ")
	} else {
		gadgetResult.NumGadgets = disasm.Len(numGadgets)

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

type RegionsResult struct {
	Span       *memaccess.MemoryRegion  `json:"span"`
	Size       uint                     `json:"size"`
	NumRegions int                      `json:"numRegions"`
	Regions    []memaccess.MemoryRegion `json:"regions"`
}

func (rr *RegionsResult) MarshalJSON() ([]byte, error) {
	type Alias RegionsResult
	return json.Marshal(&struct {
		Span *memaccess.MemoryRegion `json:"span"`
		Size string                  `json:"size"`
		*Alias
	}{
		Span:  rr.Span,
		Size:  "0x" + strconv.FormatUint(uint64(rr.Size), 16),
		Alias: (*Alias)(rr),
	})
}

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

        process, harderror, softerrors := process.OpenFromPid(int(pidN))
        logErrors(nil, softerrors)
        if harderror != nil {
                http.Error(w, harderror.Error(), http.StatusBadRequest)
                return
        } // if
        defer process.Close()

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
		if accessS != "" {
			http.Error(w, "Improper Access specification.", http.StatusBadRequest)
			return
		} // if
	} // else

	var regions []memaccess.MemoryRegion
	var size uint = 0

	for address := disasm.Ptr(0); ; {
		region, hardError, softErrors := memaccess.NextMemoryRegionAccess(process, uintptr(address), access)
		logErrors(hardError, softErrors)

		if region == memaccess.NoRegionAvailable {
			break
		} // if

		regions = append(regions, region)

		size += region.Size
		address = disasm.Ptr(region.Address + uintptr(region.Size))
	} // for

	numRegions := len(regions)

	span := memaccess.NoRegionAvailable
	span.Access = memaccess.Readable
	span.Kind = "Span"

	if numRegions > 0 {
		span.Address = regions[0].Address
		span.Size = uint((regions[numRegions-1].Address + uintptr(regions[numRegions-1].Size)) - span.Address)
	} // if

	regionsResult := RegionsResult{Span: &span, Size: size, NumRegions: numRegions, Regions: regions}

	b, err := json.MarshalIndent(&regionsResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemoryRegionsHandler()

func ROPMemorySearch(p process.Process, search string, startN disasm.Ptr, endN disasm.Ptr, limitN uint, useRegexp bool) ([]string, error) {
	var addresses []string

	for start, i := uintptr(startN), uint(0); i < limitN; {
		var found bool
		var address uintptr
		var err error

		if search == "" {
			found, address = true, start
		} else if useRegexp {
			r, e := regexp.Compile(search)
			if e != nil {
				return nil, e
			} // if
			found, address, err, _ = memsearch.FindRegexpMatch(p, uintptr(start), r)
			if err != nil {
				return nil, err
			} // if
		} else {
			found, address, err, _ = memsearch.FindBytesSequence(p, uintptr(start), []byte(search))
			if err != nil {
				return nil, err
			} // if
		} // else

		if found && address <= uintptr(endN) {
			start = address + 1
			addresses = append(addresses, disasm.Ptr(address).String())
			i = i + 1
		} else {
			i = limitN
		} // else
	} // for

	return addresses, nil
} // ROPMemorySearch()

type SearchResult struct {
	NumAddresses int      `json:"numAddresses"`
	Addresses    []string `json:"addresses"`
}

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

        process, harderror, softerrors := process.OpenFromPid(int(pidN))
        logErrors(nil, softerrors)
        if harderror != nil {
                http.Error(w, harderror.Error(), http.StatusBadRequest)
                return
        } // if
        defer process.Close()

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

	addresses, err := ROPMemorySearch(process, search, disasm.Ptr(startN), disasm.Ptr(endN), uint(limitN), r.FormValue("regexp") != "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if

	searchResult := SearchResult{NumAddresses: len(addresses), Addresses: addresses}

	b, err := json.MarshalIndent(&searchResult, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} // if
	w.Write(b)
} // ROPMemorySearchHandler()
