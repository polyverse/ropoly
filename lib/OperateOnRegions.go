package lib

import (
	"bytes"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/disasm"
	"os"
	"os/exec"
	"strconv"
)

func OperateOnRegions(spec GadgetSearchSpec, operation func(memaccess.MemoryRegion, disasm.Info, uint64, uint64)bool) (error, []error) {
	if spec.InMemory {
		return operateOnMemoryRegions(spec, operation)
	} else {
		return operateOnTextSections(spec, operation), nil
	}
}

func operateOnMemoryRegions(spec GadgetSearchSpec, operation func(memaccess.MemoryRegion, disasm.Info, uint64, uint64)bool) (error, []error) {
	softerrors := []error{}
	process, harderror1, softerrors1 := process.OpenFromPid(int(spec.PidN))
	if harderror1 != nil {
		return harderror1, softerrors1
	}
	defer process.Close()
	softerrors = append(softerrors, softerrors1...)

	numInstructions := 0

	for pc := spec.StartN; (pc <= spec.EndN) && (numInstructions < int(spec.LimitN)); {
		region, harderror2, softerrors2 := memaccess.NextMemoryRegionAccess(process, uintptr(pc), memaccess.Readable+memaccess.Executable)
		if harderror2 != nil {
			return harderror2, joinerrors(softerrors1, softerrors2)
		}
		softerrors = append(softerrors, softerrors2...)

		if region == memaccess.NoRegionAvailable {
			break
		}

		if pc < uint64(region.Address) {
			pc = uint64(region.Address)
		}

		if pc > spec.EndN {
			break
		}

		var info disasm.Info
		var bytes []byte // Scope is important here. Unsafe pointers are taken in disasm.InfoInitBytes(). Store must survive next block.

		if spec.PidN != 0 {
			bytes = make([]byte, region.Size, region.Size)
			memaccess.CopyMemory(process, region.Address, bytes)
			info = disasm.InfoInitBytes(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1), bytes)
		} else {
			info = disasm.InfoInit(disasm.Ptr(region.Address), disasm.Ptr(region.Address+uintptr(region.Size)-1))
		}

		end := uint64((region.Address + uintptr(region.Size)))
		if end > spec.EndN {
			end = spec.EndN
		}

		keepGoing := operation(region, info, pc, end)
		if !keepGoing {
			break
		}

		pc = end
	}

	return nil, softerrors
}

func operateOnTextSections(spec GadgetSearchSpec, operation func(memaccess.MemoryRegion, disasm.Info, uint64, uint64)bool) (error) {
	command := exec.Command("readelf", "--section-details", spec.Filepath)
	readelfResult, error := command.Output()
	if error != nil {
		return error
	}

	file, error := os.Open(spec.Filepath)
	if error != nil {
		return error
	}

	sectionInfo := bytes.Split(readelfResult, []byte("] "))
	for i := 0; i < len(sectionInfo); i++ {
		found, sectionStart, sectionLength := sectionLocation(sectionInfo[i], []byte(".text"))
		if found {
			binary := make([]byte, sectionLength)
			file.ReadAt(binary, int64(sectionStart))

			start := spec.StartN
			if start < sectionStart {
				start = sectionStart
			}

			end := spec.EndN
			if end > sectionStart + sectionLength {
				end = sectionStart + sectionLength
			}

			region := memaccess.MemoryRegion {
				Address: uintptr(sectionStart),
				Size: uint(sectionLength),
				Kind: string(bytes.SplitN(sectionInfo[i], []byte("\n"), 2)[0]),
			}

			info := disasm.InfoInitBytes(disasm.Ptr(sectionStart), disasm.Ptr(sectionStart + sectionLength - 1), binary)
			keepGoing := operation(region, info, start, end)
			if !keepGoing {
				break
			}
		}
	}

	file.Close()
	return nil
}

func sectionLocation(header []byte, target []byte) (bool, uint64, uint64) {
	if len(header) < len(target) {
		return false, 0, 0
	}
	for i := 0; i < len(target); i++ {
		if header[i] != target[i] {
			return false, 0, 0
		}
	}

	headerLines := bytes.Split(header, []byte("\n"))

	offsetQueue := noEmptyByteArraysQueue {
		Items: bytes.Split(headerLines[readelfOffsetLine], []byte(" ")),
		Index: 0,
	}
	for i := 0; i < readelfOffsetToken; i++ {
		dequeueByteArray(&offsetQueue)
	}
	offset, err := strconv.ParseUint(string(dequeueByteArray(&offsetQueue)), 16, 64)
	if err != nil {
		return false, 0, 0
	}

	sizeQueue := noEmptyByteArraysQueue {
		Items: bytes.Split(headerLines[readelfSizeLine], []byte(" ")),
		Index: 0,
	}
	size, err := strconv.ParseUint(string(dequeueByteArray(&sizeQueue)), 16, 64)
	if err != nil {
		return false, 0, 0
	}

	return true, offset, size
}