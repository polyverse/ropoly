package lib

import (
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memsearch"
	"github.com/polyverse/masche/process"
	"regexp"
)

func ROPMemorySearch(pidN int, search string, startN disasm.Ptr, endN disasm.Ptr, limitN uint, useRegexp bool) (SearchResult, error, []error) {
	p, harderror, softerrors := process.OpenFromPid(int(pidN))
	if harderror != nil {
		return SearchResult{}, harderror, softerrors
	} // if
	defer p.Close()

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
				return SearchResult{}, e, softerrors
			} // if
			found, address, err, _ = memsearch.FindRegexpMatch(p, uintptr(start), r)
			if err != nil {
				return SearchResult{}, err, softerrors
			} // if
		} else {
			found, address, err, _ = memsearch.FindBytesSequence(p, uintptr(start), []byte(search))
			if err != nil {
				return SearchResult{}, err, softerrors
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

	searchResult := SearchResult{
		Addresses: addresses,
	}

	return searchResult, nil, softerrors
} // ROPMemorySearch()
