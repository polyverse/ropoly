package lib

import (
	"encoding/json"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"strconv"
)

type PIdsResult struct {
	PIds []int `json:"pIds"`
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
