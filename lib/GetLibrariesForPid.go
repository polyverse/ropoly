package lib

import (
	"github.com/polyverse/masche/listlibs"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/ropoly/constants"
	"github.com/polyverse/ropoly/lib/types"
	"os/exec"
	"strings"
)

func GetLibrariesForPid(pidN int, checkSignatures bool) ([]*types.Library, error, []error) {
	process, harderror1, softerrors1 := process.OpenFromPid(pidN)
	if harderror1 != nil {
		return nil, harderror1, softerrors1
	} // if
	defer process.Close()

	libraries, harderror2, softerrors2 := listlibs.ListLoadedLibraries(process)
	if harderror2 != nil {
		return nil, harderror2, joinerrors(softerrors1, softerrors2)
	} // if

	libInfos := []*types.Library{}

	softerrors3 := []error{}

	for _, library := range libraries {
		libInfo := &types.Library{
			Path: library,
		}

		if checkSignatures {
			stringsOutput, error := exec.Command("strings", library).Output()
			if error != nil {
				softerrors3 = append(softerrors3, error)
				continue
			}

			if strings.Contains(string(stringsOutput), constants.PolyverseSignature) {
				libInfo.PolyverseTained = true
			}
		}
		libInfos = append(libInfos, libInfo)
	}

	return libInfos, nil, joinerrors(softerrors1, softerrors2, softerrors3)
}
