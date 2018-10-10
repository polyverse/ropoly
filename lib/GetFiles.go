package lib

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func GetFiles(dir string) (FilesResult, error) {
	if dir == "" {
		dir = "/"
	}
	lsResult, error := exec.Command("ls", "-l", dir).Output()
	if error != nil {
		return FilesResult{}, errors.New("File or directory not found.")
	}
	lsEntriesRaw := strings.Split(string(lsResult), "\n")
	lsEntries := lsEntriesRaw[1 : len(lsEntriesRaw)-1]
	filesresult := FilesResult{
		Files: make([]File, len(lsEntries)),
	}
	for i := 0; i < len(lsEntries); i++ {
		splitStrings := strings.Split(lsEntries[i], " ")
		queue := noEmptyStringsQueue{
			Items: splitStrings,
			Index: 0,
		}
		filesresult.Files[i].Permissions = dequeueString(&queue)
		filesresult.Files[i].NumLink = dequeueString(&queue)
		filesresult.Files[i].Owner = dequeueString(&queue)
		filesresult.Files[i].Group = dequeueString(&queue)
		filesresult.Files[i].Size = dequeueString(&queue)
		filesresult.Files[i].DateTime.Month = dequeueString(&queue)
		filesresult.Files[i].DateTime.Day = dequeueString(&queue)
		rawTime := dequeueString(&queue)
		if strings.Contains(rawTime, ":") {
			filesresult.Files[i].DateTime.Year = strconv.Itoa(time.Now().Year())
			filesresult.Files[i].DateTime.Time = rawTime
		} else {
			filesresult.Files[i].DateTime.Year = rawTime
		}
		filesresult.Files[i].Filename = dequeueString(&queue)
	}
	return filesresult, error
}
