package lib

import (
	"bytes"
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/constants"
	"os"
	"os/exec"
	"strings"
)

func HasPVSignature(info os.FileInfo) (bool, error) {
	objdump := exec.Command("objdump", "-s", "-j", ".comment", info.Name())
	var stderr bytes.Buffer
	objdump.Stderr = &stderr
	objdumpResult, err := objdump.Output()
	if err != nil {
		return false, errors.Wrapf(err, "Error whem executing objdump on file %s", info.Name())
	}
	return strings.Contains(string(objdumpResult), constants.PolyverseSignature), nil
}
