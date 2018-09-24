package lib

import (
	"os"
	"path/filepath"
	"time"
	log "github.com/sirupsen/logrus"
)

type file struct {
	Dir string
	Name string
}

func DirectoryScan() (DirectoryScanResult) {
	ret := DirectoryScanResult{
		Files: make([]FileScan, 0),
	}
	ret.Start = time.Now()

	filepath.Walk("/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error(err)
		}

		if path == "/proc" {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			signatureResult, sigErr := DiskSignatureSearch(path)
			if err != nil {
				log.Error(sigErr)
			}
			ret.Files = append(ret.Files, FileScan {
				Path: path,
				Signature: signatureResult.Signature,
			})
		}
		return err
	})

	ret.End = time.Now()
	return ret
}