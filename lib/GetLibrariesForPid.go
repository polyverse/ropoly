package lib

import (
	"github.com/polyverse/masche/listlibs"
	"github.com/polyverse/masche/process"
)

func GetLibrariesForPid(pidN int) (LibrariesResult, error, []error) {
	process, harderror1, softerrors1 := process.OpenFromPid(pidN)
	if harderror1 != nil {
		return LibrariesResult{}, harderror1, softerrors1
	} // if
	defer process.Close()

	libraries, harderror2, softerrors2 := listlibs.ListLoadedLibraries(process)
	if harderror2 != nil {
		return LibrariesResult{}, harderror2, joinerrors(softerrors1, softerrors2)
	} // if

	librariesResult := LibrariesResult{
		Libraries: libraries,
	}

	return librariesResult, nil, joinerrors(softerrors1, softerrors2)
}
