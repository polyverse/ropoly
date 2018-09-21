package lib

import (
	"time"
)

type file struct {
	Dir string
	Name string
}

func DirectoryScan() (DirectoryScanResult, []error) {
	ret := DirectoryScanResult{
		Files: make([]FileScan, 0),
	}
	ret.Start = time.Now()

	stack := make([]file, 1)
	stack[0] = file {
		Dir: "",
		Name: "",
	}

	errors := make([]error, 0)
	for len(stack) > 0 {
		next := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		filesResult, _ := GetFiles(next.Dir + next.Name)
		for i := 0; i < len(filesResult.Files); i++ {
			stack = append(stack, file {
				Dir: next.Dir + next.Name + "/",
				Name: filesResult.Files[i].Filename,
			})
		}
		signatureResult, error := DiskSignatureSearch(next.Dir + next.Name)
		if error == nil {
			ret.Files = append(ret.Files, FileScan{
				Path:      next.Dir + next.Name,
				Signature: signatureResult.Signature,
			})
		} else {
			errors = append(errors, error)
		}
	}

	ret.End = time.Now()
	return ret, errors
}