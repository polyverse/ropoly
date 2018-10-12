package lib

import (
	"encoding/json"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"strconv"
	"time"
	"strings"
)

type GadgetSearchSpec struct {
	InMemory        bool
	PidN            int
	Filepath        string
	StartN          uint64
	EndN            uint64
	LimitN          uint64
	InstructionsN   uint64
	OctetsN         uint64
}

type ScanResult struct {
	Root    DirectoryScanResult `json:"file scan"`
	Running ProcessScanResult   `json:"library scan"`
}

type FileScan struct {
	Path      string `json:"path"`
	Signature bool   `json:"signature"`
}

type DirectoryScanResult struct {
	Start time.Time  `json:"start"`
	End   time.Time  `json:"end"`
	Files []FileScan `json:"files"`
}

type ProcessScanEntry struct {
	Process   PIdsResultEntry `json:"process"`
	Libraries []Library       `json:"libraries"`
}

type ProcessScanResult struct {
	Start     time.Time          `json:"start"`
	End       time.Time          `json:"end"`
	Processes []ProcessScanEntry `json:"processes"`
}

type SignatureResult struct {
	Signature bool `json:"signature"`
}

type Timestamp struct {
	Year  string `json:"year"`
	Month string `json:"month"`
	Day   string `json:"day"`
	Time  string `json:"time"`
}

type File struct {
	Permissions string    `json:"permissions"`
	NumLink     string    `json:"numLink"`
	Owner       string    `json:"owner"`
	Group       string    `json:"group"`
	Size        string    `json:"size"`
	DateTime    Timestamp `json:"dateTime"`
	Filename    string    `json:"filename"`
}

type FilesResult struct {
	Files []File `json:"files"`
}

type PIdsResultEntry struct {
	PId   int    `json:"pId"`
	PName string `json:"pName"`
	UId   int    `json:"uId"`
	UName string `json:"uName"`
	GId   int    `json:"gId"`
	GName string `json:"gName"`
	PpId  int    `json:"ppId"`
	TId   int    `json:"tId"`
	SId   int    `json:"sId"`
}

type PIdsResult struct {
	Processes []PIdsResultEntry `json:"processes"`
}

type Library struct {
	Filepath  string `json:"filepath"`
	Polyverse bool   `json:"polyverse"`
}

type LibrariesResult struct {
	Libraries []Library `json:"libraries"`
}

type GadgetResult struct {
	Gadgets []Gadget `json:"gadgets"`
}

type Sig uint16

func (s Sig) String() string {
	str := strconv.FormatUint(uint64(s), 16)
	return "0x" + strings.Repeat("0", 4-len(str)) + str
}

type Gadget struct {
	Address         disasm.Ptr           `json:"address"`
	NumInstructions int                  `json:"numInstructions"`
	NumOctets       int                  `json:"numOctets"`
	Signature       Sig                  `json:"signature"`
	Instructions    []disasm.Instruction `json:"instructions"`
}

func (g *Gadget) MarshalJSON() ([]byte, error) {
	type Alias Gadget
	return json.Marshal(&struct {
		Address   string `json:"address"`
		Signature string `json:"signature"`
		*Alias
	}{
		Address:   g.Address.String(),
		Signature: g.Signature.String(),
		Alias:     (*Alias)(g),
	})
}

type FingerprintResult struct {
	Gadgets     map[Sig][]disasm.Ptr
}

func Printable(f *FingerprintResult) []FingerprintGadget {
	ret :=  make([]FingerprintGadget, 0)

	for signature, addresses := range f.Gadgets {
		addressStrings := make([]string, len(addresses))
		for i := 0; i < len(addresses); i++ {
			addressStrings[i] = addresses[i].String()
		}
		ret = append(ret, FingerprintGadget {
			Signature: signature.String(),
			Addresses: addressStrings,
		})
	}

	return ret
}

type PrintableFingerprintResult struct {
	Gadgets     FingerprintResult   `json:"gadgets"`
}

type FingerprintGadget struct {
	Signature   string      `json:"signature"`
	Addresses   []string    `json:"addresses"`
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
