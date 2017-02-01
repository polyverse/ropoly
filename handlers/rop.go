package handlers

import (
	"fmt"
	"github.com/ant0ine/go-json-rest/rest"
	"math"
	"net/http"
	"os"
        log "github.com/Sirupsen/logrus"
	"regexp"
	"strconv"
	"unsafe"

	"github.com/polyverse-security/masche/listlibs"
	"github.com/polyverse-security/masche/memaccess"
	"github.com/polyverse-security/masche/memsearch"
	"github.com/polyverse-security/masche/process"

	"github.com/polyverse-security/disasm"
)

type AddressType uintptr
type AddressListType []AddressType

func logErrors(hardError error, softErrors []error) {
	if hardError != nil {
		log.Fatal(hardError)
	}

	for _, softError := range softErrors {
		log.Print(softError)
	}
} // logErrors

func ROPMemoryTestHandler(w rest.ResponseWriter, r *rest.Request) {
       	w.WriteJson("Test")
} // ROPMemoryTestHandler()

type SafeResult struct {
	StartAddress disasm.Ptr
	EndAddress   disasm.Ptr
}

func ROPMemorySafeHandler(w rest.ResponseWriter, r *rest.Request) {
       	w.WriteJson(SafeResult{StartAddress: disasm.SafeStartAddress(), EndAddress: disasm.SafeEndAddress()})
} // ROPMemorySafeHandler()

type InstructionListResult struct {
	NumInstructions disasm.Len
        InstructionList disasm.InstructionList
}

func ROPMemoryDisAsmHandler(w rest.ResponseWriter, r *rest.Request) {
	var err error

	var startN uint64 = 0
        start := r.FormValue("start")
	if start == "start" {
		startN = uint64(disasm.SafeStartAddress())
	} else if start != "" {
        	startN, err = strconv.ParseUint(start, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	} // if
	} // else if

	var endN uint64 = math.MaxUint64
        end := r.FormValue("end")
	if end == "end" {
		endN = uint64(disasm.SafeEndAddress())
	} else if end != "" {
        	endN, err = strconv.ParseUint(end, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
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
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	} // if
	} // else if

        var instructionList disasm.InstructionList

        process, hardError, softErrors := process.OpenFromPid(uint(os.Getpid()))
	logErrors(hardError, softErrors)

        for pc := startN; (pc <= endN) && (len(instructionList) < int(limitN)); {
		region, hardError, softErrors := memaccess.NextMemoryRegionAccess(process, uintptr(pc), memaccess.Readable + memaccess.Executable)
		logErrors(hardError, softErrors)

		if region == memaccess.NoRegionAvailable {
			break;
		} // if

		if pc < uint64(region.Address) {
			pc = uint64(region.Address)
		} // if

		if pc > endN {
			break
		} // if

	        info := disasm.InfoInit(disasm.Ptr(region.Address), disasm.Ptr(region.Address + uintptr(region.Size) - 1))

        	for ; (pc <= endN) && pc < uint64((region.Address + uintptr(region.Size))) && (len(instructionList) < int(limitN)); {
                	instruction, err := disasm.DecodeInstruction(info, disasm.Ptr(pc))
                	if err != nil {
				rest.Error(w, err.Error(), http.StatusBadRequest)
				return
                	} // if

                	instructionList = append(instructionList, *instruction)
			pc = pc + uint64(instruction.Octets)
        	} // for
	} // for

       	w.WriteJson(InstructionListResult{NumInstructions: disasm.Len(len(instructionList)), InstructionList: instructionList})
} // ROPMemoryDisAsmHandler()

type GadgetListResult struct {
	NumGadgets disasm.Len
        GadgetList disasm.GadgetList
}

func ROPMemoryGadgetHandler(w rest.ResponseWriter, r *rest.Request) {
	var err error

	var startN uint64 = 0
        start := r.FormValue("start")
	if start == "start" {
		startN = uint64(disasm.SafeStartAddress())
	} else if start != "" {
        	startN, err = strconv.ParseUint(start, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	} // if
	} // else if

	var endN uint64 = math.MaxUint64
        end := r.FormValue("end")
	if end == "end" {
		endN = uint64(disasm.SafeEndAddress())
	} else if end != "" {
        	endN, err = strconv.ParseUint(end, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
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
                	rest.Error(w, err.Error(), http.StatusBadRequest)
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
                	rest.Error(w, err.Error(), http.StatusBadRequest)
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
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	} // if
	} // else if

        var gadgetList disasm.GadgetList

        process, hardError, softErrors := process.OpenFromPid(uint(os.Getpid()))
	logErrors(hardError, softErrors)

        for pc := startN; (pc <= endN) && (len(gadgetList) < int(limitN)); {
		region, hardError, softErrors := memaccess.NextMemoryRegionAccess(process, uintptr(pc), memaccess.Readable + memaccess.Executable)
		logErrors(hardError, softErrors)

		if region == memaccess.NoRegionAvailable {
			break;
		} // if

		if pc < uint64(region.Address) {
			pc = uint64(region.Address)
		} // if

		if pc > endN {
			break
		} // if

	        info := disasm.InfoInit(disasm.Ptr(region.Address), disasm.Ptr(region.Address + uintptr(region.Size) - 1))

fmt.Printf("Searching region: %v\n", region)
        	for ; (pc <= endN) && pc < uint64((region.Address + uintptr(region.Size))) && (len(gadgetList) < int(limitN)); pc++ {
if (pc % 1000000) == 0 {
	fmt.Printf("pc: %v\n", pc)
}
	                gadget, err := disasm.DecodeGadget(info, disasm.Ptr(pc), disasm.Len(instructionsN), disasm.Len(octetsN))
		 	if err == nil {
                        	gadgetList = append(gadgetList, *gadget)
			} // if
        	} // for
	} // for

       	w.WriteJson(GadgetListResult{NumGadgets: disasm.Len(len(gadgetList)), GadgetList: gadgetList})
} // ROPMemoryGadgetHandler()

type RegionList []memaccess.MemoryRegion
type RegionListResult struct {
	NumRegions int
        RegionList RegionList
}

func ROPMemoryRegionsHandler(w rest.ResponseWriter, r *rest.Request) {
        var regionsList []memaccess.MemoryRegion

        process, hardError, softErrors := process.OpenFromPid(uint(os.Getpid()))
		logErrors(hardError, softErrors)

	for address := AddressType(0);; {
		region, hardError, softErrors := memaccess.NextMemoryRegionAccess(process, uintptr(address), memaccess.Readable)
			logErrors(hardError, softErrors)

		if region == memaccess.NoRegionAvailable {
			break
		} // if

		regionsList = append(regionsList, region)
		address = AddressType(region.Address + uintptr(region.Size))
	} // for

       	w.WriteJson(RegionListResult{NumRegions: len(regionsList), RegionList: regionsList})
} // ROPMemoryRegionsHandler()

func ROPMemorySearch(p process.Process, search string, startN AddressType, endN AddressType, limitN uint, useRegexp bool) (AddressListType, error) {
	var addressList AddressListType

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
			addressList = append(addressList, AddressType(address))
			i = i + 1
                } else {
                        i = limitN
                } // else
        } // for

	return addressList, nil
} // ROPMemorySearch()

type AddressListResult struct {
	NumAddresses int
        AddressList AddressListType
}

func ROPMemorySearchHandler(w rest.ResponseWriter, r *rest.Request) {
	var err error

	var startN uint64 = 0
        start := r.FormValue("start")
	if start == "start" {
		startN = uint64(disasm.SafeStartAddress())
	} else if start != "" {
        	startN, err = strconv.ParseUint(start, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	} // if
	} // else if

	var endN uint64 = math.MaxUint64
        end := r.FormValue("end")
	if end == "end" {
		endN = uint64(disasm.SafeEndAddress())
	} else if end != "" {
        	endN, err = strconv.ParseUint(end, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
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
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	} // if
	} // else if

	search := r.FormValue("string")
	if search == "" {
		search = r.FormValue("regexp")
	} // if

        p, harderror, softerrors := process.OpenFromPid(uint(os.Getpid()))
        logErrors(harderror, softerrors)
        if harderror != nil { 
                rest.Error(w, err.Error(), http.StatusBadRequest)
                return
        } // if

	addressList, err := ROPMemorySearch(p, search, AddressType(startN), AddressType(endN), uint(limitN), r.FormValue("regexp") != "")
        if err != nil {
                rest.Error(w, err.Error(), http.StatusBadRequest)
		return
        } // if

        w.WriteJson(AddressListResult{NumAddresses: len(addressList), AddressList: addressList})
} // ROPMemorySearchHandler()

type LibraryListType []string

func ROPMemoryLibraryList(p process.Process) (LibraryListType, error) {
        p, harderror, softerrors := process.OpenFromPid(uint(os.Getpid()))
        logErrors(harderror, softerrors)
        if harderror != nil {
                return nil, harderror
        } // if

        libraryList, harderror, softerrors := listlibs.ListLoadedLibraries(p)
        logErrors(harderror, softerrors)
        if harderror != nil {
                return nil, harderror
        } // if

        return libraryList, nil
} // ROPMemoryLibraryList()

type LibraryListResult struct {
	NumLibraries int
        LibraryList LibraryListType
}
func ROPMemoryLibrariesHandler(w rest.ResponseWriter, r *rest.Request) {
        p, harderror, softerrors := process.OpenFromPid(uint(os.Getpid()))
        logErrors(harderror, softerrors)
        if harderror != nil {
                rest.Error(w, harderror.Error(), http.StatusBadRequest)
                return
        } // if

        libraryList, err := ROPMemoryLibraryList(p)
        if err != nil {
                rest.Error(w, err.Error(), http.StatusBadRequest)
                return
        } // if

        w.WriteJson(LibraryListResult{NumLibraries: len(libraryList), LibraryList: libraryList})
} // ROPLibrariesHandler()

func ROPMemoryOverflowHandler(w rest.ResponseWriter, r *rest.Request) {
	chain := r.FormValue("chain")

	var u uint64 = 255
        bytes := (*[100]byte)(unsafe.Pointer(&u))

	fmt.Printf("before: %v\n", bytes)
  	for j, v := range chain {
		bytes[j] = byte(v)
	} // for
	fmt.Printf("after: %v\n", bytes)

} // ROPMemoryOverflowHandler()
