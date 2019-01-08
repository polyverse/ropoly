package process

type LinuxProcessInfo struct {
	Id              int    `json:"id" statusFileKey:"Pid"`
	Command         string `json:"command" statusFileKey:"Name"`
	UserId          int    `json:"userId" statusFileKey:"Uid"`
	UserName        string `json:"userName" statusFileKey:""`
	GroupId         int    `json:"groupId" statusFileKey:"Gid"`
	GroupName       string `json:"groupName" statusFileKey:""`
	ParentProcessId int    `json:"parentProcessId" statusFileKey:"PPid"`
	Executable      string `json:"executable"`
}

func ProcessInfo(pid int) (*LinuxProcessInfo, error) {
	return processInfo(pid)
}

func ProcessExe(pid int) (string, error) {
	return processExe(pid)
}