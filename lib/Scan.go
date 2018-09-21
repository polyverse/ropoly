package lib

func Scan() (ScanResult, error, []error) {
	ret := ScanResult{}
	var softerrors []error
	var softerrors2 []error
	var harderror error
	ret.Root, softerrors = DirectoryScan()
	ret.Running, harderror, softerrors2 = ProcessScan()
	return ret, harderror, append(softerrors, softerrors2...)
}