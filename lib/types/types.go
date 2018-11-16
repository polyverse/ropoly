package types

import (
	"github.com/pkg/errors"
	"github.com/polyverse/disasm"
	"strconv"
	"strings"
)

type FingerprintComparison struct {
	GadgetDisplacements     map[disasm.Ptr][]Offset     `json:"gadgetDisplacements"`
	NewGadgets              map[GadgetId][]disasm.Ptr   `json:"newGadgets"`
	GadgetsByOffset         map[Offset]int              `json:"gadgetCountsByOffset"`
	DeadGadgetCount         int                         `json:"deadGadgetCount"`
	SurvivedGadgetCount     int                         `json:"survivedGadgetCount"`
	SingleDisplacements     map[disasm.Ptr]Offset       `json:"bestGadgetDisplacements"`
	GadgetsBySingleOffset   map[Offset]int              `json:"gadgetCountsByBestOffset"`
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
		str = strings.TrimPrefix(str,"-")
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

type Fingerprint map[GadgetId][]disasm.Ptr

func FingerprintFromGadgets(gadgets []*disasm.Gadget) Fingerprint {
	fingerprint := Fingerprint{}
	for _, gadget := range gadgets {
		hash := GadgetId(gadget.InstructionString())
		if _, ok := fingerprint[hash]; !ok {
			fingerprint[hash] = []disasm.Ptr{gadget.Address}
		} else {
			fingerprint[hash] = append(fingerprint[hash], gadget.Address)
		}
	}

	return fingerprint
}

func (f1 Fingerprint) CompareTo(f2 Fingerprint) FingerprintComparison {
	ret := FingerprintComparison{
		GadgetDisplacements:    map[disasm.Ptr][]Offset{},
		NewGadgets:             map[GadgetId][]disasm.Ptr{},
		GadgetsByOffset:        map[Offset]int{},
		DeadGadgetCount:        0,
		SurvivedGadgetCount:    0,
		SingleDisplacements:    map[disasm.Ptr]Offset{},
		GadgetsBySingleOffset:  map[Offset]int{},
	}

	for gadget, oldAddresses := range f1 {
		newAddresses := f2[gadget]
		for _, oldAddress := range oldAddresses {
			offsets := make([]Offset, len(newAddresses))
			for j, newAddress := range newAddresses {
				offset := Offset(newAddress) - Offset(oldAddress)
				offsets[j] = offset
				ret.GadgetsByOffset[offset]++
			}
			if len(offsets) == 0 {
				ret.DeadGadgetCount++
			} else {
				bestOffset := smallestOffset(offsets)
				if bestOffset == 0 {
					ret.SurvivedGadgetCount++
				} else {
					ret.SingleDisplacements[oldAddress] = bestOffset
					ret.GadgetsBySingleOffset[bestOffset]++
				}
			}
			ret.GadgetDisplacements[oldAddress] = offsets
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