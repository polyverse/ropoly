package lib

import (
	"github.com/polyverse/masche/listlibs"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/ropoly/lib/types"
)

func GetLibrariesForPid(pid int, checkSignatures bool) ([]*types.Library, error, []error) {
	libraries, harderror2, softerrors2 := listlibs.ListLoadedLibraries(process.LinuxProcess(pid))
	if harderror2 != nil {
		return nil, harderror2, softerrors2
	} // if

	libInfos := []*types.Library{}

	softerrors3 := []error{}

	for _, library := range libraries {
		libInfo := &types.Library{
			Path: library,
		}

		if checkSignatures {
			taint, err := HasPolyverseTaint(library)
			if err != nil {
				softerrors3 = append(softerrors3, err)
				continue
			}

			libInfo.PolyverseTained = taint
		}
		libInfos = append(libInfos, libInfo)
	}

	return libInfos, nil, joinerrors(softerrors2, softerrors3)
}
