package types

type Process struct {
	Info      ProcessInfo `json:"info"`
	Libraries []Library   `json:"libraries"`
}

type ProcessInfo struct {
	Id              int    `json:"id"`
	Command         string `json:"name"`
	UserId          int    `json:"userId"`
	UserName        string `json:"userName"`
	GroupId         int    `json:"groupId"`
	GroupName       string `json:"groupName"`
	ParentProcessId int    `json:"parentProcessId"`
	ThreadId        int    `json:"threadId"`
	SessionId       int    `json:"sessionId"`
}

type Library struct {
	Path               string `json:"path"`
	PolyverseGenerated bool   `json:"polyverseGenerated"`
}
