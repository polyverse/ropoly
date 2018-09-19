package lib

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

const signature = "-PV-"
const objdumpStartJunkLines = 4
const objdumpEndJunkLines = 1
const objdumpTextStart = 43

func DiskSignatureSearch(path string) (SignatureResult, error) {
	objdump := exec.Command("objdump", "-s", "-j", ".comment", path)
	var stderr bytes.Buffer
	objdump.Stderr = &stderr
	objdumpResult, error := objdump.Output()
	if error != nil {
		/*DEBUG*/ println("Error when running objdump:", error.Error() + ":", stderr.String())
		return SignatureResult{}, errors.New(stderr.String())
	}

	/* objdumpText is just the text portion of the result of the objdump command, the portion
	displayed on the right. All the hex and newlines are stripped out. */
	objdumpText := ""
	objdumpLines := strings.Split(string(objdumpResult), "\n")
	for i := objdumpStartJunkLines; i < len(objdumpLines) - objdumpEndJunkLines; i++ {
		objdumpText += objdumpLines[i][objdumpTextStart:]
	}

	found := false
	for i := 0; i < len(objdumpText) - len(signature) + 1; i++ {
		match := true
		for char := 0; char < len(signature); char++ {
			if objdumpText[i+char] != signature[char] {
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