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
	"github.com/polyverse-security/masche/memsearch"
	"github.com/polyverse-security/masche/process"

	"github.com/polyverse-security/disasm"
)

type addressType uintptr // unsafe.Pointer
type addressesType []addressType

func logErrors(harderror error, softerrors []error) {
	if harderror != nil {
		log.Fatal(harderror)
	}
	for _, soft := range softerrors {
		log.Print(soft)
	}
} // logErrors

type safeType struct {
	StartAddress disasm.Ptr
	EndAddress   disasm.Ptr
}

func ROPMemorySafeHandler(w rest.ResponseWriter, r *rest.Request) {
       	w.WriteJson(safeType{disasm.SafeStartAddress(), disasm.SafeEndAddress()})
} // ROPMemorySafeHandler()

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
        	}
	}

	var endN uint64 = math.MaxUint64
        end := r.FormValue("end")
	if end == "end" {
		endN = uint64(disasm.SafeEndAddress())
	} else if end != "" {
        	endN, err = strconv.ParseUint(end, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	}
	}

	var limitN uint64 = math.MaxInt32
        limit := r.FormValue("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
        	limitN, err = strconv.ParseUint(limit, 0, 32)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	}
	}

        info := disasm.InfoInit(disasm.Ptr(startN), disasm.Len(endN-startN))

        var instructions disasm.InstructionList

        for pc := startN; (pc < endN) && (len(instructions) < int(limitN)); {
                instruction, err := disasm.DecodeInstruction(info, disasm.Ptr(pc))
                if err != nil {
			rest.Error(w, err.Error(), http.StatusBadRequest)
			return
                } // if

                instructions = append(instructions, *instruction)
		pc = pc + uint64(instruction.Octets)
        } // for

       	w.WriteJson(instructions)
} // ROPMemoryDisAsmHandler()

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
        	}
	}

	var endN uint64 = math.MaxUint64
        end := r.FormValue("end")
	if end == "end" {
		endN = uint64(disasm.SafeEndAddress())
	} else if end != "" {
        	endN, err = strconv.ParseUint(end, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	}
	}

	var limitN uint64 = math.MaxInt32
        limit := r.FormValue("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
        	limitN, err = strconv.ParseUint(limit, 0, 32)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	}
	}

	var instructionsN uint64 = math.MaxInt32
        instructions := r.FormValue("instructions")
	if instructions == "instructions" {
		instructionsN = 5
	} else if instructions != "" {
        	instructionsN, err = strconv.ParseUint(instructions, 0, 32)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	}
	}

	var octetsN uint64 = math.MaxInt32
        octets := r.FormValue("octets")
	if octets == "octets" {
		octetsN = 100
	} else if octets != "" {
        	octetsN, err = strconv.ParseUint(octets, 0, 32)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	}
	}

        info := disasm.InfoInit(disasm.Ptr(startN), disasm.Len(endN-startN))

        var gadgets disasm.GadgetList

        for pc := startN; (pc < endN) && (len(gadgets) < int(limitN)); pc = pc + 1 {
                gadget, err := disasm.DecodeGadget(info, disasm.Ptr(pc))
                if err == nil {
			 if (len(gadget.Instructions) < int(instructionsN)) && (gadget.Octets < int(octetsN)) {
                        	gadgets = append(gadgets, *gadget)
			} // if
                } // if
        } // for

        w.WriteJson(gadgets)
} // ROPMemoryGadgetHandler()

func ROPMemorySearch(p process.Process, search string, startN addressType, limitN uint, useRegexp bool) (addressesType, error) {
	var addresses addressesType

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
                        }
                        found, address, err, _ = memsearch.FindRegexpMatch(p, uintptr(start), r)
                        if err != nil {
                                return nil, err
                        }
		} else {
			found, address, err, _ = memsearch.FindBytesSequence(p, uintptr(start), []byte(search))
                        if err != nil {
                                return nil, err
                        }
		}

                if found {
			//bytes := *(*[10]byte)(unsafe.Pointer(address))
			//chars := string(bytes[:])
			//fmt.Printf("address: %x, contents: %v, chars: %s\n", address, bytes, chars)
                        start = address + 1
			addresses = append(addresses, addressType(address))
			i = i + 1
                } else {
                        i = limitN
                }
        } // for

	return addresses, nil
} // ROPMemorySearch()

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
        	}
	}

/*
	var endN uint64 = math.MaxUint64
        end := r.FormValue("end")
	if end == "end" {
		endN = uint64(disasm.SafeEndAddress())
	} else if end != "" {
        	endN, err = strconv.ParseUint(end, 0, 64)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	}
	}
*/
	var limitN uint64 = math.MaxInt32
        limit := r.FormValue("limit")
	if limit == "limit" {
		limitN = 100
	} else if limit != "" {
        	limitN, err = strconv.ParseUint(limit, 0, 32)
        	if err != nil {
                	rest.Error(w, err.Error(), http.StatusBadRequest)
                	return
        	}
	}

	search := r.FormValue("string")
	if search == "" {
		search = r.FormValue("regexp")
	}

        p, harderror, softerrors := process.OpenFromPid(uint(os.Getpid()))
        logErrors(harderror, softerrors)
        if harderror != nil { 
                rest.Error(w, err.Error(), http.StatusBadRequest)
                return
        }

	addresses, err := ROPMemorySearch(p, search, addressType(startN), uint(limitN), r.FormValue("regexp") != "")
        if err != nil {
                rest.Error(w, err.Error(), http.StatusBadRequest)
		return
        }

        w.WriteJson(addresses)
} // ROPMemorySearchHandler()

type librariesType []string

func ROPMemoryLibraryList(p process.Process) (librariesType, error) {
        p, harderror, softerrors := process.OpenFromPid(uint(os.Getpid()))
        logErrors(harderror, softerrors)
        if harderror != nil {
                return nil, harderror
        }

        libraries, harderror, softerrors := listlibs.ListLoadedLibraries(p)
        logErrors(harderror, softerrors)
        if harderror != nil {
                return nil, harderror
        }

        return libraries, nil
} // ROPMemoryLibraryList()

func ROPMemoryLibraryHandler(w rest.ResponseWriter, r *rest.Request) {
        p, harderror, softerrors := process.OpenFromPid(uint(os.Getpid()))
        logErrors(harderror, softerrors)
        if harderror != nil {
                rest.Error(w, harderror.Error(), http.StatusBadRequest)
                return
        }

        libraries, err := ROPMemoryLibraryList(p)
        if err != nil {
                rest.Error(w, err.Error(), http.StatusBadRequest)
                return
        }

        w.WriteJson(libraries)
} // ROPLibraryHandler()

func ROPMemoryOverflowHandler(w rest.ResponseWriter, r *rest.Request) {
	chain := r.FormValue("chain")

	var u uint64
	u = 255
        bytes := (*[100]byte)(unsafe.Pointer(&u))
	fmt.Printf("before: %v\n", bytes)
	for j, v := range chain {
		bytes[j] = byte(v)
	}
	fmt.Printf("after: %v\n", bytes)
} // ROPMemoryOverflowHandler()
