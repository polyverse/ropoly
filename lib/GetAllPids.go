package lib

import "github.com/polyverse/masche/process"

func GetAllPids() (PIdsResult, error, []error) {
	pids, harderror, softerrors := process.GetAllPids()
	if harderror != nil {
		return PIdsResult{}, harderror, softerrors
	} // if

	pidresult := PIdsResult{
		PIds: pids,
	}

	return pidresult, harderror, softerrors
}
