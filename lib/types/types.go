package types

import (
	"encoding/json"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"strconv"
	"time"
)

type Sig uint

type GadgetSearchRequest struct {
	InMemory      bool
	PidN          int
	Filepath      string
	StartN        uint64
	EndN          uint64
	LimitN        uint64
	InstructionsN uint64
	OctetsN       uint64
}

type FingerprintComparison struct {
	RemovedRegions          []memaccess.MemoryRegion      `json:"removed sections"`
	AddedRegions            []memaccess.MemoryRegion      `json:"added sections"`
	SharedRegionComparisons []FingerprintRegionComparison `json:"shared region comparisons"`
}

type FingerprintRegionComparison struct {
	Region              memaccess.MemoryRegion `json:"region (original address)"`
	Displacement        int64                  `json:"displacement"`
	GadgetDisplacements map[disasm.Ptr][]int64 `json:"gadget displacements"`
	AddedGadgets        map[Sig][]disasm.Ptr   `json:"added gadgets"`
	NumOldGadgets       int                    `json:"total gadgets in original"`
	GadgetsByOffset     map[int64]int          `json:"number of gadgets findable at each displacement"`
}

type AddedGadget struct {
	Gadget    string   `json:"signature"`
	Addresses []string `json:"addresses"`
}

func formatHexInt(i int64) string {
	if i < 0 {
		return "-0x" + strconv.FormatInt(-i, 16)
	} else {
		return "0x" + strconv.FormatInt(i, 16)
	}
}

type File struct {
	Permissions string    `json:"permissions"`
	NumLink     string    `json:"numLink"`
	Owner       string    `json:"owner"`
	Group       string    `json:"group"`
	Size        string    `json:"size"`
	DateTime    time.Time `json:"time"`
	Filename    string    `json:"filename"`
}

type FilesResult struct {
	Files []File `json:"files"`
}

type GadgetResult struct {
	Regions []GadgetRegion `json:"regions"`
}

type GadgetRegion struct {
	Region  memaccess.MemoryRegion `json:"region"`
	Gadgets []Gadget               `json:"gadgets"`
}

type FingerprintResult struct {
	Regions map[string]*FingerprintRegion
}

type FingerprintRegion struct {
	Region  memaccess.MemoryRegion `json:"region"`
	Gadgets map[Sig][]disasm.Ptr
}

type MemoryRegion struct {
	Address string `json:"address"`
	Size    string `json:"size"`
	Kind    string `json:"kind"`
}

type DisAsmResult struct {
	Regions []MemoryRegionDisAsm `json:"regions"`
}

type MemoryRegionDisAsm struct {
	Region       memaccess.MemoryRegion `json:"region"`
	Instructions []disasm.Instruction   `json:"instructions"`
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
