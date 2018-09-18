package lib

import (
	"os/exec"
	"strconv"
	"strings"
	"errors"
	"time"
)

type noEmptiesQueue struct {
	Items []string
	Index int
}

func dequeue(queue *noEmptiesQueue) (string) {
	ret := ""
	for ret == "" {
		ret = queue.Items[queue.Index]
		queue.Index++
	}
	return ret
}

func GetFiles(dir string) (FilesResult, error) {
	if dir == "" {
		dir = "/"
	}
	lsResult, error := exec.Command("ls", "-l", dir).Output()
	if error != nil {
		return FilesResult{}, errors.New("File or directory not found.")
	}
	lsEntriesRaw := strings.Split(string(lsResult), "\n")
	lsEntries := lsEntriesRaw[1:len(lsEntriesRaw)-1]
	filesresult := FilesResult {
		Files: make([]File, len(lsEntries)),
	}
	for i := 0; i < len(lsEntries); i++ {
		splitStrings := strings.Split(lsEntries[i], " ")
		queue := noEmptiesQueue {
			Items: splitStrings,
			Index: 0,
		}
		filesresult.Files[i].Permissions = dequeue(&queue)
		filesresult.Files[i].NumLink = dequeue(&queue)
		filesresult.Files[i].Owner = dequeue(&queue)
		filesresult.Files[i].Group = dequeue(&queue)
		filesresult.Files[i].Size = dequeue(&queue)
		filesresult.Files[i].DateTime.Month = dequeue(&queue)
		filesresult.Files[i].DateTime.Day = dequeue(&queue)
		rawTime := dequeue(&queue)
		if strings.Contains(rawTime, ":") {
			filesresult.Files[i].DateTime.Year = strconv.Itoa(time.Now().Year())
			filesresult.Files[i].DateTime.Time = rawTime
		} else {
			filesresult.Files[i].DateTime.Year = rawTime
		}
		filesresult.Files[i].Filename = dequeue(&queue)
	}
	return filesresult, error
}