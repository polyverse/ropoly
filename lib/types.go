package lib

import (
	"encoding/json"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"strconv"
)

type SignatureResult struct {
	Signature bool `json:signature`
}

type Timestamp struct {
	Year string `json:year`
	Month string `json:month`
	Day string `json:day`
	Time string `json:time`
}

type File struct {
	Permissions string `json:permissions`
	NumLink string `json:numLink`
	Owner string `json:owner`
	Group string `json:group`
	Size string `json:size`
	DateTime Timestamp `json:dateTime`
	Filename string `json:filename`
}

type FilesResult struct {
	Files []File `json:files`
}

type PIdsResultEntry struct {
    PId int `json:pId`
    PName string `json:pName`
    UId int `json:uId`
    UName string `json:uName`
    GId int `json:gId`
    GName string `json:gName`
    PpId int `json:ppId`
    TId int `json:tId`
    SId int `json:sId`
}

type PIdsResult struct {
    Processes []PIdsResultEntry `json:processes`
}

type LibrariesResult struct {
	Libraries []string `json:"libraries"`
}

type GadgetResult struct {
	Gadgets []disasm.Gadget `json:"gadgets"`
}

type FingerprintResult struct {
	Gadgets []string `json:"gadgets"`
}

type DisAsmResult struct {
	Instructions []disasm.Instruction `json:"instructions"`
}

type RegionsResult struct {
	Span    *memaccess.MemoryRegion  `json:"span"`
	Size    uint                     `json:"size"`
	Regions []memaccess.MemoryRegion `json:"regions"`
}

func (rr *RegionsResult) MarshalJSON() ([]byte, error) {
	type Alias RegionsResult
	return json.Marshal(&struct {
		Span *memaccess.MemoryRegion `json:"span"`
		Size string                  `json:"size"`
		*Alias
	}{
		Span:  rr.Span,
		Size:  "0x" + strconv.FormatUint(uint64(rr.Size), 16),
		Alias: (*Alias)(rr),
	})
}

type SearchResult struct {
	Addresses []string `json:"addresses"`
}
