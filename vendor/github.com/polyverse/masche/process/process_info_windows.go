package process

import (
	"bytes"
	"errors"
	"os/exec"
	"strconv"
)

func processInfo(pid int) (*LinuxProcessInfo, error) {
	lpi := &LinuxProcessInfo{}
	lpi.Id = pid
	var err error
	lpi.Command, lpi.Executable, lpi.ParentProcessId, err = commandExecutableAndPPId(pid)
	if err != nil {
		return lpi, err
	}
	lpi.UserName, err = userName(pid)
	if err != nil {
		return lpi, err
	}
	return lpi, nil
}

func processExe(pid int) (string, error) {
	_, executable, _, err := commandExecutableAndPPId(pid)
	return executable, err
}

func commandExecutableAndPPId(pid int) (string, string, int, error) {
	wmicCommand := exec.Command("wmic", "path", "win32_process", "where", "processid=" +
		strconv.FormatUint(uint64(pid), 10), "get", "commandline,", "executablepath,", "parentprocessid")
	wmicOutput, err := wmicCommand.Output()
	if err != nil {
		return "", "", 0, err
	}

	wmicLines := bytes.Split(wmicOutput, []byte("\n"))
	headingLine := wmicLines[0]
	processLine := wmicLines[1]

	charIndex := 0
	var executableIndex int
	for ; charIndex < len(headingLine); charIndex++ {
		if len(headingLine) < charIndex + 14 {
			return "", "", 0, errors.New("ExecutablePath column missing in WMIC output")
		}
		if bytes.Equal(headingLine[charIndex:charIndex + 14], []byte("ExecutablePath")) {
			executableIndex = charIndex
			charIndex += 14
			break
		}
	}
	var pPIdIndex int
	for ; charIndex < len(headingLine); charIndex++ {
		if len(headingLine) < charIndex + 15 {
			return "", "", 0, errors.New("ParentProcessId column missing in WMIC output")
		}
		if bytes.Equal(headingLine[charIndex:charIndex + 15], []byte("ParentProcessId")) {
			pPIdIndex = charIndex
			break
		}
	}

	command := string(bytes.TrimSpace(processLine[:executableIndex]))
	executable := string(bytes.TrimSpace(processLine[executableIndex:pPIdIndex]))
	pPIdString := string(bytes.TrimSpace(processLine[pPIdIndex:]))
	pPId, err := strconv.ParseInt(pPIdString, 10, 64)
	if err != nil {
		pPId = -1
	}
	return command, executable, int(pPId), nil
}

func userName(pid int) (string, error) {
	tasklistCommand := exec.Command("tasklist", "/v", "/fi", "PID eq " + string(pid))
	tasklistOutput, err := tasklistCommand.Output()
	if err != nil {
		return "", err
	}
	lines := bytes.Split(tasklistOutput, []byte("\n"))

	var headingLine []byte
	var processLine []byte
	var separatorLineTokens [][]byte
	for index, line := range lines {
		if len(line) >= 10 && bytes.Equal(line[:10], []byte("Image Name")) {
			headingLine = line
			processLine = lines[index + 2]
			separatorLineTokens = bytes.Split(lines[index + 1], []byte(" "))
			break
		}
	}

	var position int
	var separatorToken []byte
	for index, token := range separatorLineTokens {
		position = index
		for _, preceedingToken := range separatorLineTokens[:index] {
			position += len(preceedingToken)
		}
		if bytes.Equal(headingLine[position:position+9], []byte("User Name")) {
			separatorToken = token
			break
		}
	}

	userNameBytes := bytes.TrimSpace(processLine[position:position + len(separatorToken)])
	userNameTokens := bytes.Split(userNameBytes, []byte("\\"))
	return string(userNameTokens[len(userNameTokens) - 1]), nil
}