package lib

import (
	log "github.com/sirupsen/logrus"
	"time"
)

func ProcessScan() ProcessScanResult {
	ret := ProcessScanResult{
		Processes: make([]ProcessScanEntry, 0),
	}
	ret.Start = time.Now()

	pidsResult, harderror, softerrors := GetAllPids()
	if harderror != nil {
		log.Error(harderror)
		return ProcessScanResult{}
	}
	for i := 0; i < len(softerrors); i++ {
		log.Error(softerrors[i])
	}

	for i := 0; i < len(pidsResult.Processes); i++ {
		process := pidsResult.Processes[i]
		librariesResult, error, softerrors := GetLibrariesForPid(process.PId, true)
		if error != nil {
			log.Error(error)
		}
		for i := 0; i < len(softerrors); i++ {
			log.Error(softerrors[i])
		}

		ret.Processes = append(ret.Processes, ProcessScanEntry{
			Process:   process,
			Libraries: librariesResult.Libraries,
		})
	}

	ret.End = time.Now()
	return ret
}
