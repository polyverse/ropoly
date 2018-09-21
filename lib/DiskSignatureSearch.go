package lib

import (
	"bytes"
	"os/exec"
	"strings"
)

const signature = "-PV-"
const objdumpTextStart = 43

func DiskSignatureSearch(path string) (SignatureResult, error) {
	objdump := exec.Command("objdump", "-s", "-j", ".comment", path)
	var stderr bytes.Buffer
	objdump.Stderr = &stderr
	objdumpResult, error := objdump.Output()
	found := false
	if error == nil {
		/* objdumpText is just the text portion of the result of the objdump command, the portion
		displayed on the right. All the hex and newlines are stripped out. */
		objdumpText := ""
		objdumpLines := strings.Split(string(objdumpResult), "\n")
		var objdumpContentStart int
		for i := 0; i < len(objdumpLines); i++ {
			if objdumpLines[i] == "Contents of section .comment:" {
				objdumpContentStart = i + 1
			}
		}
		objdumpContentEnd := len(objdumpLines)
		for i := objdumpContentStart; i < len(objdumpLines); i++ {
			if objdumpLines[i] == "" {
				objdumpContentEnd = i
				break
			}
		}
		for i := objdumpContentStart; i < objdumpContentEnd; i++ {
			objdumpText += objdumpLines[i][objdumpTextStart:]
		}
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
	}

	result := SignatureResult {
		Signature: found,
	}
	return result, error
}