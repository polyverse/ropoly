package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/masche/process"
	"github.com/polyverse/ropoly/lib/types"
	"os/exec"
	"strconv"
	"strings"
)

// TODO: Replace with non-command
func attributeByPid(pid int, attribute string) (string, error) {
	ret, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", attribute+"=").Output()
	if err != nil {
		return "", errors.Wrapf(err, "Unable to get process attribute %s for pid %d, by calling the 'ps' command.", attribute, pid)
	}
	return strings.Replace(string(ret), "\n", "", 1), nil
}

func intAttributeByPid(pid int, attribute string) (int, error) {
	strVal, err := attributeByPid(pid, attribute)
	if err != nil {
		return 0, errors.Wrapf(err, "Unable to get integer value of attribute %s for pid %d due to underlying error", attribute, pid)
	}

	ret, err := strconv.Atoi(strVal)
	if err != nil {
		return 0, errors.Wrapf(err, "Unable to parse integer from value %s of attribute %s for pid %d due to underlying error", strVal, attribute, pid)
	}

	return ret, nil
}

func GetAllPids() ([]*types.ProcessInfo, error, []error) {
	pids, harderror, softerrors := process.GetAllPids()
	if harderror != nil {
		return nil, errors.Wrapf(harderror, "Unable to list PIDs on this host."), softerrors
	} // if

	pidinfos := []*types.ProcessInfo{}

	for _, pid := range pids {
		pinfo, errs := getProcInfo(pid)
		softerrors = append(softerrors, errs...)
		pidinfos = append(pidinfos, pinfo)
	}

	return pidinfos, harderror, softerrors
}

func getProcInfo(pid int) (*types.ProcessInfo, []error) {
	errs := []error{}

	command, err := attributeByPid(pid, "comm")
	errs = appendError(errs, err, "Unable to get attribute comm for Pid %d", pid)

	userid, err := intAttributeByPid(pid, "uid")
	errs = appendError(errs, err, "Unable to get attribute uid for Pid %d", pid)

	username, err := attributeByPid(pid, "user")
	errs = appendError(errs, err, "Unable to get attribute user for Pid %d", pid)

	groupId, err := intAttributeByPid(pid, "gid")
	errs = appendError(errs, err, "Unable to get attribute gid for Pid %d", pid)

	groupName, err := attributeByPid(pid, "group")
	errs = appendError(errs, err, "Unable to get attribute group for Pid %d", pid)

	parentProcessId, err := intAttributeByPid(pid, "ppid")
	errs = appendError(errs, err, "Unable to get attribute ppid for Pid %d", pid)

	threadId, err := intAttributeByPid(pid, "tid")
	errs = appendError(errs, err, "Unable to get attribute tid for Pid %d", pid)

	sessionId, err := intAttributeByPid(pid, "sid")
	errs = appendError(errs, err, "Unable to get attribute sid for Pid %d", pid)

	return &types.ProcessInfo{
		Id:              pid,
		Command:         command,
		UserId:          userid,
		UserName:        username,
		GroupId:         groupId,
		GroupName:       groupName,
		ParentProcessId: parentProcessId,
		ThreadId:        threadId,
		SessionId:       sessionId,
	}, errs
}

func appendError(errs []error, err error, format string, params ...interface{}) []error {
	if err == nil {
		return errs
	}

	wrappedErr := errors.Wrapf(err, format, params)
	errs = append(errs, wrappedErr)
	return errs
}
