package types

import (
	"fmt"
	"github.com/pkg/errors"
	"strconv"
	"strings"
)

type Addr uint64

func (a Addr) String() string {
	str := strconv.FormatUint(uint64(a), 16)
	return "0x" + strings.Repeat("0", 12-len(str)) + str
}

func (a *Addr) UnmarshalJSON(b []byte) error {
	if a == nil {
		return errors.Errorf("Addr Unmarshall cannot operate on a nil pointer.")
	}

	str := string(b)
	str = strings.TrimPrefix(str, "\"")
	str = strings.TrimSuffix(str, "\"")

	if !strings.HasPrefix(str, "0x") {
		return errors.Errorf("Cannot unmarshall string %s into an address. " +
			"It must be a hexadecimal value prefixed by 0x", str)
	}

	str = strings.TrimPrefix(str, "0x")
	val, err := strconv.ParseUint(str, 16, 64)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse hexadecimal value %s", str)
	}
	va := Addr(val)
	*a = va
	return nil
}

func (a Addr) MarshalJSON() ([]byte, error) {
	return []byte("\"" + a.String() + "\""), nil
}

type Octets []byte

func (o Octets) String() string {
	buffer := &strings.Builder{}
	first := true
	for _, b := range o {
		if !first {
			fmt.Fprint(buffer, " ")
		}
		str := strconv.FormatUint(uint64(b), 16)
		buffer.WriteString("0x" + strings.Repeat("0", 2-len(str)) + str)
		first = false
	}
	return buffer.String()
}

func (o *Octets) UnmarshalJSON(b []byte) error {
	if o == nil {
		return errors.Errorf("Octets Unmarshall cannot operate on a nil pointer.")
	}

	sanitizedStr := string(b)
	sanitizedStr = strings.TrimPrefix(sanitizedStr, "\"")
	sanitizedStr = strings.TrimSuffix(sanitizedStr, "\"")

	octetsStr := strings.Split(sanitizedStr, " ")
	newOctect := make([]byte, 0, len(octetsStr))
	for _, octetStr := range octetsStr {
		if !strings.HasPrefix(octetStr, "0x") {
			return errors.Errorf("Octet %s is not prefixed with 0x. Only hexadecimal Octets are allowed.", octetStr)
		}
		octetVal, err := strconv.ParseUint(strings.TrimPrefix(octetStr, "0x"), 16, 8)
		if err != nil {
			return errors.Wrapf(err, "Unable to parse octect %s into an 8-bit unsigned integer", octetStr)
		}
		newOctect = append(newOctect, byte(octetVal))
	}
	*o = newOctect
	return nil
}

func (o Octets) MarshalJSON() ([]byte, error) {
	return []byte("\"" + o.String() + "\""), nil
}

type Instruction struct {
	Octets  Octets `json:"octets"`
	DisAsm  string `json:"disasm"`
}

type Gadget []*Instruction

type GadgetInstance struct {
	Address Addr `json:"address"`
	Gadget Gadget `json:"gadget"`
}

func (i *Instruction) String() string {
	return i.Octets.String() + " (" + i.DisAsm + ")"
}

func (g Gadget) InstructionString() string {
	buffer := &strings.Builder{}
	for _, instr := range g {
		if instr == nil {
			fmt.Fprint(buffer, "(nil)")
		} else {
			fmt.Fprint(buffer, instr.DisAsm)
		}
		fmt.Fprint(buffer, "\n")
	}
	return buffer.String()
}


