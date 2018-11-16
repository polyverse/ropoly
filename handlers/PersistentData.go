package handlers

const (
	fingerprintsDirectory string = "fingerprints"
	comparisonsDirectory string = "comparisons"
)

var DataDirectory string

func FingerprintsDirectory() string {
	return DataDirectory + "/" + fingerprintsDirectory + "/"
}

func ComparisonsDirectory() string {
	return DataDirectory + "/" + comparisonsDirectory + "/"
}