package lib

import (
	"bytes"
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/constants"
	"os/exec"
	"strings"
)

func HasPVSignature(path string) (bool, error) {
	objdump := exec.Command("objdump", "-s", "-j", ".comment", path)
	var stderr bytes.Buffer
	objdump.Stderr = &stderr
	objdumpResult, err := objdump.Output()
	if err != nil {
		return false, errors.Wrapf(err, "Error whem executing objdump on file %s", path)
	}
	return strings.Contains(string(objdumpResult), constants.PolyverseSignature), nil
}
