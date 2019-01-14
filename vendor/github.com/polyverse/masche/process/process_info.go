package process

type ProcessInfo interface {
	GetId() int
	GetCommand() string
	GetParentProcessId() int
	GetExecutable() string
}

func GetProcessInfo(pid int) (*ProcessInfo, error) {
	var info ProcessInfo
	info, err := processInfo(pid)
	return &info, err
}

func ProcessExe(pid int) (string, error) {
	return processExe(pid)
}