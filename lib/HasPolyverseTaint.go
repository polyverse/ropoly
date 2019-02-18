package lib

import (
	"debug/elf"
	"github.com/pkg/errors"
	"github.com/polyverse/ropoly/constants"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

// File identification, must be 0x7f + "ELF".
var elfHeader = string([]byte{0x7f, 'E', 'L', 'F'})

func HasPolyverseTaint(path string) (bool, error) {
	log.Debugf("Checking file %s for Polyverse taint", path)
	rawFile, err := os.Open(path)
	if err != nil {
		return false, errors.Wrapf(err, "Unable to open file at path %s", path)
	}
	defer rawFile.Close()

	buffer := make([]byte, 4)
	count, err := rawFile.Read(buffer)
	if err != nil {
		return false, errors.Wrapf(err, "Unable to Check whether file is an ELF binary at path %s", path)
	}
	if count != 4 {
		log.Debugf("File %s is not an ELF binary because it does not have a 4-byte header", path)
		return false, nil // Not an elf binary
	}
	if elfHeader != string(buffer) {
		log.Debugf("File %s is not an ELF binary because it does not have the expected 4-byte header", path)
		return false, nil // Not an elf binary
	}

	elfFile, err := elf.Open(path)
	if err != nil {
		return false, errors.Wrapf(err, "Unable to open ELF file at path %s", path)
	}
	defer elfFile.Close()
	
	for _, section := range elfFile.Sections {
		sectionData, err := section.Data()
		if err != nil {
			continue
		}
		sectionStr := string(sectionData)
		if strings.Contains(sectionStr, constants.PolyverseSignature) {
			return true, nil
		}
	}
	log.Debugf("File %s is not Polyverse tainted", path)
	return false, nil
}
