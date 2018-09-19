package lib

import (
	"github.com/polyverse/masche/listlibs"
	"github.com/polyverse/masche/process"
	"os/exec"
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
		Libraries: make([]Library, len(libraries)),
	}

	softerrors3 := make([]error, 0)
	for i := 0; i < len(libraries); i++ {
		librariesResult.Libraries[i].Filepath = libraries[i]

		stringsOutput, error := exec.Command("strings", libraries[i]).Output()
		if error != nil {
			softerrors3 = append(softerrors3, error)
			continue
		}
		/*DEBUG*/ println(string(stringsOutput))
		found := false
		for i := 0; i < len(stringsOutput) - len(signature) + 1; i++ {
			match := true
			for char := 0; char < len(signature); char++ {
				if stringsOutput[i+char] != signature[char] {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
		librariesResult.Libraries[i].Polyverse = found
	}

	return librariesResult, nil, joinerrors(softerrors1, softerrors2, softerrors3)
}
