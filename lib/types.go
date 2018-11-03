package lib

import (
	"encoding/json"
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"strconv"
	"strings"
	"time"
)

type EqiResult struct {
	Eqi        float64     `json:"overall EQI"`
	RegionEqis []RegionEqi `json:"region EQIs"`
}

type RegionEqi struct {
	Region memaccess.MemoryRegion `json:"region"`
	Eqi    float64                `json:"EQI"`
}

type GadgetSearchSpec struct {
	InMemory      bool
	PidN          int
	Filepath      string
	StartN        uint64
	EndN          uint64
	LimitN        uint64
	InstructionsN uint64
	OctetsN       uint64
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

type PrintableFingerprintComparison struct {
	RemovedRegions          []ParseableMemoryRegion     `json:"removed sections"`
	AddedRegions            []ParseableMemoryRegion     `json:"added sections"`
	SharedRegionComparisons []PrintableRegionComparison `json:"shared region comparisons"`
}

type PrintableRegionComparison struct {
	Region              ParseableMemoryRegion `json:"region (original address)"`
	Displacement        string                `json:"displacement"`
	GadgetDisplacements map[string][]string   `json:"gadget displacements"`
	AddedGadgets        []AddedGadget         `json:"added gadgets"`
	NumOldGadgets       int                   `json:"total gadgets in original"`
	GadgetsByOffset     map[string]int        `json:"number of gadgets findable at each displacement"`
}

type AddedGadget struct {
	Signature string   `json:"signature"`
	Addresses []string `json:"addresses"`
}

func PrintableComparison(c *FingerprintComparison) PrintableFingerprintComparison {
	ret := PrintableFingerprintComparison{
		RemovedRegions:          make([]ParseableMemoryRegion, len(c.RemovedRegions)),
		AddedRegions:            make([]ParseableMemoryRegion, len(c.AddedRegions)),
		SharedRegionComparisons: make([]PrintableRegionComparison, len(c.SharedRegionComparisons)),
	}

	for i := 0; i < len(c.RemovedRegions); i++ {
		ret.RemovedRegions[i] = Parseable(&c.RemovedRegions[i])
	}

	for i := 0; i < len(c.AddedRegions); i++ {
		ret.AddedRegions[i] = Parseable(&c.AddedRegions[i])
	}

	for i := 0; i < len(c.SharedRegionComparisons); i++ {
		readRegion := c.SharedRegionComparisons[i]
		ret.SharedRegionComparisons[i] = printableFingerprintRegionComparison(&readRegion)
	}

	return ret
}

func ParseComparison(c PrintableFingerprintComparison) (FingerprintComparison, error) {
	parsed := FingerprintComparison{
		RemovedRegions:          make([]memaccess.MemoryRegion, len(c.RemovedRegions)),
		AddedRegions:            make([]memaccess.MemoryRegion, len(c.AddedRegions)),
		SharedRegionComparisons: make([]FingerprintRegionComparison, len(c.SharedRegionComparisons)),
	}

	for i := 0; i < len(c.RemovedRegions); i++ {
		var err error = nil
		parsed.RemovedRegions[i], err = ParseRegion(c.RemovedRegions[i])
		if err != nil {
			return FingerprintComparison{}, err
		}
	}

	for i := 0; i < len(c.AddedRegions); i++ {
		var err error = nil
		parsed.AddedRegions[i], err = ParseRegion(c.AddedRegions[i])
		if err != nil {
			return FingerprintComparison{}, err
		}
	}

	for i := 0; i < len(c.SharedRegionComparisons); i++ {
		var err error = nil
		parsed.SharedRegionComparisons[i], err = parseFingerprintRegionComparison(c.SharedRegionComparisons[i])
		if err != nil {
			return FingerprintComparison{}, err
		}
	}

	return parsed, nil
}

func printableFingerprintRegionComparison(c *FingerprintRegionComparison) PrintableRegionComparison {
	ret := PrintableRegionComparison{
		Region:              Parseable(&c.Region),
		Displacement:        formatHexInt(c.Displacement),
		GadgetDisplacements: map[string][]string{},
		AddedGadgets:        make([]AddedGadget, 0),
		NumOldGadgets:       c.NumOldGadgets,
		GadgetsByOffset:     map[string]int{},
	}

	for origin, displacements := range c.GadgetDisplacements {
		displacementStrings := make([]string, len(displacements))
		for i := 0; i < len(displacements); i++ {
			displacementStrings[i] = formatHexInt(displacements[i])
		}
		ret.GadgetDisplacements[origin.String()] = displacementStrings
	}

	for sig, addresses := range c.AddedGadgets {
		addressStrings := make([]string, len(addresses))
		for i := 0; i < len(addresses); i++ {
			addressStrings[i] = addresses[i].String()
		}
		ret.AddedGadgets = append(ret.AddedGadgets, AddedGadget{
			Signature: sig.String(),
			Addresses: addressStrings,
		})
	}

	for offset, count := range c.GadgetsByOffset {
		ret.GadgetsByOffset[formatHexInt(offset)] = count
	}

	return ret
}

func parseFingerprintRegionComparison(c PrintableRegionComparison) (FingerprintRegionComparison, error) {
	parsed := FingerprintRegionComparison{
		GadgetDisplacements: map[disasm.Ptr][]int64{},
		AddedGadgets:        map[Sig][]disasm.Ptr{},
		NumOldGadgets:       c.NumOldGadgets,
		GadgetsByOffset:     map[int64]int{},
	}

	var err error
	parsed.Region, err = ParseRegion(c.Region)
	if err != nil {
		return FingerprintRegionComparison{}, err
	}

	parsed.Displacement, err = strconv.ParseInt(c.Displacement, 0, 64)
	if err != nil {
		return FingerprintRegionComparison{}, err
	}

	for originString, displacementStrings := range c.GadgetDisplacements {
		origin, err := strconv.ParseUint(originString, 0, 64)
		if err != nil {
			return FingerprintRegionComparison{}, err
		}
		displacements := make([]int64, len(displacementStrings))
		for i := 0; i < len(displacements); i++ {
			displacements[i], err = strconv.ParseInt(displacementStrings[i], 0, 64)
			if err != nil {
				return FingerprintRegionComparison{}, err
			}
		}
		parsed.GadgetDisplacements[disasm.Ptr(origin)] = displacements
	}

	for i := 0; i < len(c.AddedGadgets); i++ {
		gadget := c.AddedGadgets[i]
		sig, err := strconv.ParseUint(gadget.Signature, 0, 64)
		if err != nil {
			return FingerprintRegionComparison{}, err
		}
		addresses := make([]disasm.Ptr, len(gadget.Addresses))
		for j := 0; j < len(addresses); j++ {
			address, err := strconv.ParseUint(gadget.Addresses[j], 0, 64)
			if err != nil {
				return FingerprintRegionComparison{}, err
			}
			addresses[j] = disasm.Ptr(address)
		}
		parsed.AddedGadgets[Sig(sig)] = addresses
	}

	for offsetString, count := range c.GadgetsByOffset {
		offset, err := strconv.ParseInt(offsetString, 0, 64)
		if err != nil {
			return FingerprintRegionComparison{}, err
		}
		parsed.GadgetsByOffset[offset] = count
	}

	return parsed, nil
}

func formatHexInt(i int64) string {
	if i < 0 {
		return "-0x" + strconv.FormatInt(-i, 16)
	} else {
		return "0x" + strconv.FormatInt(i, 16)
	}
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
	Regions []GadgetRegion `json:"regions"`
}

type GadgetRegion struct {
	Region  memaccess.MemoryRegion `json:"region"`
	Gadgets []Gadget               `json:"gadgets"`
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
	Regions map[string]*FingerprintRegion
}

type FingerprintRegion struct {
	Region  memaccess.MemoryRegion `json:"region"`
	Gadgets map[Sig][]disasm.Ptr
}

func Parseable(r *memaccess.MemoryRegion) ParseableMemoryRegion {
	return ParseableMemoryRegion{
		Address: "0x" + strconv.FormatUint(uint64(r.Address), 16),
		Size:    "0x" + strconv.FormatUint(uint64(r.Size), 16),
		Kind:    r.Kind,
	}
}

func ParseRegion(r ParseableMemoryRegion) (memaccess.MemoryRegion, error) {
	address, error := strconv.ParseUint(r.Address, 0, 64)
	if error != nil {
		return memaccess.MemoryRegion{}, error
	}

	size, error := strconv.ParseUint(r.Address, 0, 64)
	if error != nil {
		return memaccess.MemoryRegion{}, error
	}

	return memaccess.MemoryRegion{
		Address: uintptr(address),
		Size:    uint(size),
		Kind:    r.Kind,
	}, nil
}

func Printable(f *FingerprintResult) PrintableFingerprintResult {
	regions := make([]PrintableFingerprintRegion, 0)

	for _, mapping := range f.Regions {
		region := mapping.Region
		contents := mapping.Gadgets
		gadgets := make([]PrintableFingerprintGadget, 0)
		for sig, addresses := range contents {
			addressStrings := make([]string, len(addresses))
			for i := 0; i < len(addresses); i++ {
				addressStrings[i] = addresses[i].String()
			}
			gadgets = append(gadgets, PrintableFingerprintGadget{
				Signature: sig.String(),
				Addresses: addressStrings,
			})
		}

		regions = append(regions, PrintableFingerprintRegion{
			Region:  Parseable(&region),
			Gadgets: gadgets,
		})
	}

	return PrintableFingerprintResult{
		Regions: regions,
	}
}

func ParseFingerprintResult(f PrintableFingerprintResult) (FingerprintResult, error) {
	regions := map[string]*FingerprintRegion{}

	for i := 0; i < len(f.Regions); i++ {
		readRegion := f.Regions[i]

		parsedRegion, error := ParseRegion(readRegion.Region)
		if error != nil {
			return FingerprintResult{}, error
		}
		region := FingerprintRegion{
			Region:  parsedRegion,
			Gadgets: map[Sig][]disasm.Ptr{},
		}

		for i := 0; i < len(readRegion.Gadgets); i++ {
			readGadget := readRegion.Gadgets[i]

			readGadgetSignature, error := strconv.ParseUint(readGadget.Signature, 0, 64)
			if error != nil {
				return FingerprintResult{}, error
			}

			addresses := make([]disasm.Ptr, len(readGadget.Addresses))
			for i := 0; i < len(addresses); i++ {
				address, error := strconv.ParseUint(readGadget.Addresses[i], 0, 64)
				if error != nil {
					return FingerprintResult{}, error
				}
				addresses[i] = disasm.Ptr(address)
			}

			region.Gadgets[Sig(readGadgetSignature)] = addresses
		}
		regions[region.Region.Kind] = &region
	}

	return FingerprintResult{regions}, nil
}

type PrintableFingerprintResult struct {
	Regions []PrintableFingerprintRegion `json:"regions"`
}

type PrintableFingerprintRegion struct {
	Region  ParseableMemoryRegion        `json:"region"`
	Gadgets []PrintableFingerprintGadget `json:"gadgets"`
}

type ParseableMemoryRegion struct {
	Address string `json:"address"`
	Size    string `json:"size"`
	Kind    string `json:"kind"`
}

type PrintableFingerprintGadget struct {
	Signature string   `json:"signature"`
	Addresses []string `json:"addresses"`
}

type DisAsmResult struct {
	Regions []DisAsmRegion `json:"regions"`
}

type DisAsmRegion struct {
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
