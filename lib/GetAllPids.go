package lib

import (
	"github.com/pkg/errors"
	"github.com/polyverse/masche/process"
)

func GetAllPids() ([]*process.ProcessInfo, error, []error) {
	pids, harderror, softerrors := process.GetAllPids()
	if harderror != nil {
		return nil, errors.Wrapf(harderror, "Unable to list PIDs on this host."), softerrors
	} // if

	pidinfos := []*process.ProcessInfo{}

	for _, pid := range pids {
		pinfo, err := process.GetProcessInfo(pid)
		softerrors = append(softerrors, err)
		pidinfos = append(pidinfos, pinfo)
	}

	return pidinfos, harderror, softerrors
}
