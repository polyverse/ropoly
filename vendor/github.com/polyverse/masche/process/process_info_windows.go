package process

import (
	"bytes"
	"errors"
	"os/exec"
	"strconv"
)

type windowsProcessInfo struct {
	Id              int     `json:"id" statusFileKey:"Pid"`
	Handle          int     `json:"handle"`
	Command         string  `json:"command" statusFileKey:"Name"`
	UserName        string  `json:"userName" statusFileKey:""`
	ParentProcessId int     `json:"parentProcessId" statusFileKey:"PPid"`
	Executable      string  `json:"executable"`
	SessionId       int     `json:"sessionId" statusFileKey:"Sid"`
}

func (wpi windowsProcessInfo) GetId() int {
	return wpi.Id
}

func (wpi windowsProcessInfo) GetCommand() string {
	return wpi.Command
}

func (wpi windowsProcessInfo) GetParentProcessId() int {
	return wpi.ParentProcessId
}

func (wpi windowsProcessInfo) GetExecutable() string {
	return wpi.Executable
}

func processInfo(pid int) (windowsProcessInfo, error) {
	lpi := windowsProcessInfo{}
	lpi.Id = pid
	var err error
	lpi.Command, lpi.Executable, lpi.ParentProcessId, lpi.Handle, lpi.SessionId, err =
		commandExecutablePPIdPPIdHandleAndSessionId(pid)
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
	_, executable, _, _, _, err := commandExecutablePPIdPPIdHandleAndSessionId(pid)
	return executable, err
}

func commandExecutablePPIdPPIdHandleAndSessionId(pid int) (string, string, int, int, int, error) {
	wmicCommand := exec.Command("wmic", "path", "win32_process", "where", "processid=" +
		strconv.FormatUint(uint64(pid), 10), "get", "commandline,", "executablepath,",
		"handle,", "parentprocessid,", "sessionid")
	wmicOutput, err := wmicCommand.Output()
	if err != nil {
		return "", "", 0, 0, 0, err
	}

	wmicLines := bytes.Split(wmicOutput, []byte("\n"))
	headingLine := wmicLines[0]
	processLine := wmicLines[1]

	charIndex := 0
	executableIndex, charIndex := findHeading(headingLine, []byte("ExecutablePath"), charIndex)
	if executableIndex == -1 {
		return "", "", 0, 0, 0, errors.New("\"ExecutablePath\" not found in heading line.")
	}
	handleIndex, charIndex := findHeading(headingLine, []byte("Handle"), charIndex)
	if handleIndex == -1 {
		return "", "", 0, 0, 0, errors.New("\"Handle\" not found in heading line.")
	}
	pPIdIndex, charIndex := findHeading(headingLine, []byte("ParentProcessId"), charIndex)
	if pPIdIndex == -1 {
		return "", "", 0, 0, 0, errors.New("\"ParentProcessId\" not found in heading line.")
	}
	sessionIdIndex, charIndex := findHeading(headingLine, []byte("SessionId"), charIndex)
	if sessionIdIndex == -1 {
		return "", "", 0, 0, 0, errors.New("\"SessionId\" not found in heading line.")
	}

	command := string(bytes.TrimSpace(processLine[:executableIndex]))
	executable := string(bytes.TrimSpace(processLine[executableIndex:handleIndex]))
	handleString := string(bytes.TrimSpace(processLine[handleIndex:pPIdIndex]))
	handle, err := strconv.ParseInt(handleString, 10, 64)
	if err != nil {
		handle = -1
	}
	pPIdString := string(bytes.TrimSpace(processLine[pPIdIndex:sessionIdIndex]))
	pPId, err := strconv.ParseInt(pPIdString, 10, 64)
	if err != nil {
		pPId = -1
	}
	sessionIdString := string(bytes.TrimSpace(processLine[sessionIdIndex:]))
	sessionId, err := strconv.ParseInt(sessionIdString, 10, 64)
	return command, executable, int(pPId), int(handle), int(sessionId), nil
}

func findHeading(headingLine []byte, targetHeading []byte, searchStart int) (start int, end int) {
	for charIndex := searchStart; charIndex < len(headingLine); charIndex++ {
		if len(headingLine) < charIndex + len(targetHeading) {
			return -1, -1
		}
		if bytes.Equal(headingLine[charIndex:charIndex + len(targetHeading)], targetHeading) {
			return charIndex, charIndex + len(targetHeading)
		}
	}
	return -1, -1
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