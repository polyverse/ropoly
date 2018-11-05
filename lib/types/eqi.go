package types

import "github.com/polyverse/masche/memaccess"

type EntropyQualityIndex float64

type Eqi struct {
	Aggregate EntropyQualityIndex `json:"aggregate"`
	Regional  []RegionalEqi       `json:"regional"`
}

type RegionalEqi struct {
	Region memaccess.MemoryRegion `json:"region"`
	Eqi    EntropyQualityIndex    `json:"eqi"`
}
