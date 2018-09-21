package lib

import "time"

func ProcessScan() (ProcessScanResult, error, []error) {
	ret := ProcessScanResult{
		Processes: make([]ProcessScanEntry, 0),
	}
	ret.Start = time.Now()

	pidsResult, harderror, softerrors := GetAllPids()
	if harderror != nil {
		return ProcessScanResult{}, harderror, softerrors
	}

	for i := 0; i < len(pidsResult.Processes); i++ {
		process := pidsResult.Processes[i]
		librariesResult, error, softerrors2 := GetLibrariesForPid(process.PId)
		if error != nil {
			softerrors = append(softerrors, error)
		}
		softerrors = append(softerrors, softerrors2...)

		ret.Processes = append(ret.Processes, ProcessScanEntry {
			Process: process,
			Libraries: librariesResult.Libraries,
		})
	}

	ret.End = time.Now()
	return ret, harderror, softerrors
}