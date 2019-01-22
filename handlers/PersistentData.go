package handlers

const (
	fingerprintsDirectory string = "fingerprints"
	uploadedFilesDirectory string = "uploadedfiles"
)

var DataDirectory string

func FingerprintsDirectory() string {
	return DataDirectory + "/" + fingerprintsDirectory + "/"
}

func UploadedFilesDirectory() string {
	return DataDirectory + "/" + uploadedFilesDirectory + "/"
}