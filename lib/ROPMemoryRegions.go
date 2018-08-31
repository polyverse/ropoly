package lib

import (
	"github.com/polyverse/disasm"
	"github.com/polyverse/masche/memaccess"
	"github.com/polyverse/masche/process"
)

func ROPMemoryRegions(pidN int, access memaccess.Access) (RegionsResult, error, []error) {
	softerrors := []error{}
	process, harderror, softerrors1 := process.OpenFromPid(int(pidN))
	softerrors = joinerrors(softerrors, softerrors1)
	if harderror != nil {
		return RegionsResult{}, harderror, softerrors1
	} // if
	defer process.Close()

	var regions []memaccess.MemoryRegion
	var size uint = 0

	for address := disasm.Ptr(0); ; {
		region, harderror, softerrors2 := memaccess.NextMemoryRegionAccess(process, uintptr(address), access)
		if harderror != nil {
			return RegionsResult{}, harderror, softerrors2
		} // if
		softerrors = joinerrors(softerrors, softerrors2)

		if region == memaccess.NoRegionAvailable {
			break
		} // if

		regions = append(regions, region)

		size += region.Size
		address = disasm.Ptr(region.Address + uintptr(region.Size))
	} // for

	numRegions := len(regions)

	span := memaccess.NoRegionAvailable
	span.Access = memaccess.Readable
	span.Kind = "Span"

	if numRegions > 0 {
		span.Address = regions[0].Address
		span.Size = uint((regions[numRegions-1].Address + uintptr(regions[numRegions-1].Size)) - span.Address)
	} // if

	regionsResult := RegionsResult{
		Span: &span, Size: size,
		Regions: regions}

	return regionsResult, harderror, softerrors
}
