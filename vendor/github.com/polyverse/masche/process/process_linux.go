package process

import (
	"bufio"
	"fmt"
	"github.com/polyverse/masche/common"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type linuxProcess int

func getProcess(pid int) linuxProcess {
	return linuxProcess(pid)
}

func (p linuxProcess) Pid() int {
	return int(p)
}

func (p linuxProcess) Name() (name string, harderror error, softerrors []error) {
	name, err := ProcessExe(p.Pid())

	if err != nil {
		// If the exe link doesn't take us to the real path of the binary of the process maybe it's not present anymore
		// or the process didn't started from a file. We mimic this ps(1) trick and take the name form
		// /proc/<pid>/status in that case.

		statusPath := filepath.Join("/proc", fmt.Sprintf("%d", p.Pid()), "status")
		statusFile, err := os.Open(statusPath)
		if err != nil {
			return name, err, nil
		}
		defer statusFile.Close()

		r := bufio.NewReader(statusFile)
		for line, _, err := r.ReadLine(); err != io.EOF; line, _, err = r.ReadLine() {
			if err != nil {
				return name, err, nil
			}

			namePrefix := "Name:"
			if strings.HasPrefix(string(line), namePrefix) {
				name := strings.Trim(string(line[len(namePrefix):]), " \t")

				// We add the square brackets to be consistent with ps(1) output.
				return "[" + name + "]", nil, nil
			}
		}

		return name, fmt.Errorf("No name found for pid %v", p.Pid()), nil
	}

	return name, err, nil
}

func (p linuxProcess) Close() (harderror error, softerrors []error) {
	return nil, nil
}

func (p linuxProcess) Handle() uintptr {
	return uintptr(p)
}

func getAllPids() (pids []int, harderror error, softerrors []error) {
	files, err := ioutil.ReadDir("/proc/")
	if err != nil {
		return nil, err, nil
	}

	pids = make([]int, 0)

	for _, f := range files {
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}
		pids = append(pids, int(pid))
	}

	return pids, nil, nil
}

func openFromPid(pid int) (p Process, harderror error, softerrors []error) {
	// Check if we have permissions to read the process memory
	memPath := common.MemFilePathFromPid(uint(pid))
	memFile, err := os.Open(memPath)
	if err != nil {
		harderror = fmt.Errorf("Permission denied to access memory of process %v", pid)
		return
	}
	defer memFile.Close()

	return linuxProcess(pid), nil, nil
}
