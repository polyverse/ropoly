package lib

import (
	"github.com/polyverse/masche/process"
	"os/exec"
	"strconv"
	"strings"
)

func attributeByPid(pid int, attribute string) string {
	ret, _ := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", attribute+"=").Output()
	return strings.Replace(string(ret), "\n", "", 1)
}

func intAttributeByPid(pid int, attribute string) int {
	strVal := attributeByPid(pid, attribute)
	ret, _ := strconv.Atoi(strVal)
	return ret
}

func GetAllPids() (PIdsResult, error, []error) {
	pids, harderror, softerrors := process.GetAllPids()
	if harderror != nil {
		return PIdsResult{}, harderror, softerrors
	} // if

	pidresult := PIdsResult{
		Processes: make([]PIdsResultEntry, len(pids)),
	}
	for i := 0; i < len(pids); i++ {
		pidresult.Processes[i].PId = pids[i]
		pidresult.Processes[i].PName = attributeByPid(pids[i], "comm")
		pidresult.Processes[i].UId = intAttributeByPid(pids[i], "uid")
		pidresult.Processes[i].UName = attributeByPid(pids[i], "user")
		pidresult.Processes[i].GId = intAttributeByPid(pids[i], "gid")
		pidresult.Processes[i].GName = attributeByPid(pids[i], "group")
		pidresult.Processes[i].PpId = intAttributeByPid(pids[i], "ppid")
		pidresult.Processes[i].TId = intAttributeByPid(pids[i], "tid")
		pidresult.Processes[i].SId = intAttributeByPid(pids[i], "sid")
	} // for

	return pidresult, harderror, softerrors
}
