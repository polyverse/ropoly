package handlers

const (
	fingerprintsDirectory string = "fingerprints"
)

var DataDirectory string

func FingerprintsDirectory() string {
	return DataDirectory + "/" + fingerprintsDirectory + "/"
}