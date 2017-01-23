package handlers

import (
	"fmt"
	"github.com/ant0ine/go-json-rest/rest"
	"net/http"
	"os"
        log "github.com/Sirupsen/logrus"
	"regexp"
	"strconv"
	"unsafe"

	"github.com/polyverse-security/masche/listlibs"
	"github.com/polyverse-security/masche/memsearch"
	"github.com/polyverse-security/masche/process"
)

//type Address struct {
//	Address	uintptr `json: "address"`
//	Content string  `json: "content"`
//}

type addressType uintptr // unsafe.Pointer
type addressesType []addressType

func logErrors(harderror error, softerrors []error) {
	if harderror != nil {
		log.Fatal(harderror)
	}
	for _, soft := range softerrors {
		log.Print(soft)
	}
}

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
			bytes := *(*[10]byte)(unsafe.Pointer(address))
			chars := string(bytes[:])
			fmt.Printf("address: %x, contents: %v, chars: %s\n", address, bytes, chars)
                        start = address + 1
			addresses = append(addresses, addressType(address))
			i = i + 1
                } else {
                        i = limitN
                }
        } // for

	return addresses, nil
}

func ROPMemorySearchHandler(w rest.ResponseWriter, r *rest.Request) {
	search := r.FormValue("string")
	if search == "" {
		search = r.FormValue("regexp")
	}

        start := r.FormValue("start")
        if start == "" {
		start = "0"
	}
	startN, err := strconv.ParseUint(start, 0, 64)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

        limit := r.FormValue("limit")
	if limit == "" {
		limit = "10"
	}
	limitN, err := strconv.ParseUint(limit, 0, 32)
        if err != nil {
                rest.Error(w, err.Error(), http.StatusBadRequest)
		return
        }
	if limitN > 1000 {
		limitN = 1000
	}

	fmt.Printf("search: %s\n", search)
	fmt.Printf("start: %v\n", start)
	fmt.Printf("limit: %v\n", limit)

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

func ROPLibraryList(p process.Process) (librariesType, error) {
        p, harderror, softerrors := process.OpenFromPid(uint(os.Getpid()))
        logErrors(harderror, softerrors)
        if harderror != nil {
                return nil, harderror
        }

        libraries, harderror, softerrors := listlibs.ListLoadedLibraries(p)
fmt.Printf("libraries: %v\n", libraries)
        logErrors(harderror, softerrors)
        if harderror != nil {
                return nil, harderror
        }

        return libraries, nil
}

func ROPLibraryHandler(w rest.ResponseWriter, r *rest.Request) {
        p, harderror, softerrors := process.OpenFromPid(uint(os.Getpid()))
        logErrors(harderror, softerrors)
        if harderror != nil {
                rest.Error(w, harderror.Error(), http.StatusBadRequest)
                return
        }

        libraries, err := ROPLibraryList(p)
        if err != nil {
                rest.Error(w, err.Error(), http.StatusBadRequest)
                return
        }

        w.WriteJson(libraries)
}

func ROPOverflowHandler(w rest.ResponseWriter, r *rest.Request) {
	chain := r.FormValue("chain")

	var u uint64
	u = 255
        bytes := (*[100]byte)(unsafe.Pointer(&u))
	fmt.Printf("before: %v\n", bytes)
	for j, v := range chain {
		bytes[j] = byte(v)
	}
	fmt.Printf("after: %v\n", bytes)
}
