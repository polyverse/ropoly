package types

import (
	"github.com/pkg/errors"
	"github.com/polyverse/masche/memaccess"
	"strconv"
	"strings"
)

type FingerprintComparison struct {
	Survived            int                             `json:"survived"`
	Moved               int                             `json:"moved"`
	Dead                int                             `json:"dead"`
	GadgetsByOffset     map[Offset]int                  `json:"gadgetCountsByOffset"`
	GadgetDisplacements map[Addr]map[GadgetId][]Offset  `json:"gadgetDisplacements"`
	NewGadgets          map[GadgetId][]Addr             `json:"newGadgets"`
}

type InstructionInstance struct {
	Address Addr    `json:"address"`
	Octets  Octets  `json:"octets"`
	DisAsm  string  `json:"disasm"`
}

func MakeInstructionInstance(instruction *Instruction, address Addr) *InstructionInstance {
	ret := InstructionInstance {
		Address:    address,
		Octets:     instruction.Octets,
		DisAsm:     instruction.DisAsm,
	}
	return &ret
}

type Offset int64

func (o Offset) String() string {
	negative := o < 0
	str := ""
	if negative {
		o = -o
	}
	str += strconv.FormatInt(int64(o), 16)
	ret := "0x" + strings.Repeat("0", 12-len(str)) + str
	if negative {
		ret = "-" + ret
	}
	return ret
}

func (o *Offset) UnmarshalJSON(b []byte) error {
	if o == nil {
		return errors.Errorf("Offset Unmarshall cannot operate on a nil pointer.")
	}

	str := string(b)
	str = strings.TrimPrefix(str, "\"")
	str = strings.TrimSuffix(str, "\"")

	negative := strings.HasPrefix(str, "-")
	if negative {
		str = strings.TrimPrefix(str, "-")
	}

	if !strings.HasPrefix(str, "0x") {
		return errors.Errorf("Cannot unmarshall string %s into an offset. "+
			"It must be a hexadecimal value prefixed by 0x", str)
	}

	str = strings.TrimPrefix(str, "0x")
	val, err := strconv.ParseInt(str, 16, 64)
	if negative {
		val = -val
	}
	if err != nil {
		return errors.Wrapf(err, "Unable to parse hexadecimal value %s", str)
	}
	vo := Offset(val)
	*o = vo
	return nil
}

func (o Offset) MarshalJSON() ([]byte, error) {
	return []byte("\"" + o.String() + "\""), nil
}

func (o *Offset) UnmarshalText(b []byte) error {
	return o.UnmarshalJSON(b)
}

func (o Offset) MarshalText() ([]byte, error) {
	return []byte(o.String()), nil
}

type GadgetId string

type Fingerprint map[GadgetId][]Addr

func FingerprintFromGadgets(gadgetInstances []*GadgetInstance) (Fingerprint, error) {
	gadgetLocations := map[GadgetId]map[Addr]bool{}
	fingerprint := Fingerprint{}
	for _, gadget := range gadgetInstances {
		hash := GadgetId(gadget.Gadget.InstructionString())
		if gadgetLocations[hash] == nil {
			gadgetLocations[hash] = map[Addr]bool{}
		}
		if !gadgetLocations[hash][gadget.Address] {
			if _, ok := fingerprint[hash]; !ok {
				fingerprint[hash] = []Addr{gadget.Address}
			} else {
				fingerprint[hash] = append(fingerprint[hash], gadget.Address)
			}
		}
		gadgetLocations[hash][gadget.Address] = true
	}

	return fingerprint, nil
}

func (f1 Fingerprint) CompareTo(f2 Fingerprint, includeSurvived bool) FingerprintComparison {
	ret := FingerprintComparison{
		GadgetDisplacements:   map[Addr]map[GadgetId][]Offset{},
		NewGadgets:            map[GadgetId][]Addr{},
		GadgetsByOffset:       map[Offset]int{},
	}

	for gadget, oldAddresses := range f1 {
		newAddresses := f2[gadget]
		newAddressIndex := 0
		survivedAddresses := map[Addr]bool{}
		for _, oldAddress := range oldAddresses {
			for newAddressIndex < len(newAddresses) && oldAddress > newAddresses[newAddressIndex] {
				newAddressIndex++
			}
			if newAddressIndex < len(newAddresses) && oldAddress == newAddresses[newAddressIndex] {
				survivedAddresses[oldAddress] = true
			}
		}
		for _, oldAddress := range oldAddresses {
			survived := survivedAddresses[oldAddress]
			if (!includeSurvived) && survived {
				continue
			}
			offsets := []Offset{}   // Changing this to a nil slice declaration changes the way
									// dead gadgets' (empty) offset lists are displayed, which
									// breaks test.sh because test.sh requires an exact string match.
			for _, newAddress := range newAddresses {
				if (!includeSurvived) && survivedAddresses[newAddress] {
					continue
				}
				offset := Offset(newAddress) - Offset(oldAddress)
				offsets = append(offsets, offset)
				ret.GadgetsByOffset[offset]++
			}
			if survived {
				ret.Survived++
			} else if len(newAddresses) > 0 {
				ret.Moved++
			} else {
				ret.Dead++
			}
			if ret.GadgetDisplacements[oldAddress] == nil {
				ret.GadgetDisplacements[oldAddress] = map[GadgetId][]Offset{}
			}
			ret.GadgetDisplacements[oldAddress][gadget] = offsets
		}
	}

	for gadget, addresses := range f2 {
		if f1[gadget] == nil {
			ret.NewGadgets[gadget] = addresses
		}
	}

	return ret
}

func smallestOffset(offsets []Offset) Offset {
	smallest := offsets[0]
	for i := 1; i < len(offsets); i++ {
		offset := offsets[i]
		if abs(offset) < abs(smallest) {
			smallest = offset
		}
	}
	return smallest
}

func abs(o Offset) Offset {
	if o < 0 {
		return -o
	} else {
		return o
	}
}

type RegionsResult struct {
	Span    *memaccess.MemoryRegion  `json:"span"`
	Size    uint                     `json:"size"`
	Regions []memaccess.MemoryRegion `json:"regions"`
}