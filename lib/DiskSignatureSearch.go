package lib

import (
	"bytes"
	"errors"
	"os/exec"
)

const signature string = "\\-PV\\-"

func DiskSignatureSearch(path string) (SignatureResult, error) {
	objdump := exec.Command("objdump", "-s", "-j", ".comment", path)
	var stderr bytes.Buffer
	objdump.Stderr = &stderr
	objdumpResult, error := objdump.Output()
	if error != nil {
		/*DEBUG*/ println("Error when running objdump:", error.Error() + ":", stderr.String())
		return SignatureResult{}, errors.New(stderr.String())
	}

	found := false
	for i := 0; i < len(objdumpResult) - len(signature) + 1; i++ {
		match := true
		for char := 0; char < len(signature); char++ {
			if objdumpResult[i+char] != signature[char] {
				match = false
				break
			}
		}
		if match {
			found = true
			break
		}
	}

	result := SignatureResult {
		Signature: found,
	}
	return result, error
}