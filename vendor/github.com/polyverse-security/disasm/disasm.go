package disasm

// #include "disasm.h"
// #cgo CFLAGS: -std=c99
import "C"

import "encoding/json"
import "errors"
import "runtime"
import "strings"
import "strconv"
import "regexp"

type Ptr uintptr
type Len uint64

type iInfo struct {
	info *C.struct_DisAsmInfo
}

type Info struct {
	info *iInfo
}

type Instruction struct {
	Address Ptr    `json:"address,string"`
	Octets  int    `json:"octets"`
	DisAsm  string `json:"disasm"`
}
type InstructionList []Instruction

type Gadget struct {
	Address      Ptr             `json:"address,string"`
	Octets       int             `json:"octets"`
	Instructions InstructionList `json:"instructions"`
}
type GadgetList []Gadget

func (p Ptr) String() string {
	return "0x" + strconv.FormatUint(uint64(p), 16)
}

func (i *Instruction) MarshalJSON() ([]byte, error) {
        type Alias Instruction
        return json.Marshal(&struct {
                Address string `json:"address"`
                *Alias
        }{
                Address: i.Address.String(),
                Alias:   (*Alias)(i),
        })
}

func (g *Gadget) MarshalJSON() ([]byte, error) {
        type Alias Gadget
        return json.Marshal(&struct {
                Address string `json:"address"`
                *Alias
        }{
                Address: g.Address.String(),
                Alias:   (*Alias)(g),
        })
}

func SafeStartAddress() Ptr {
	return Ptr(C.DisAsmSafeStartAddress())
} // SafeStartAddress()

func InfoInit(start Ptr, end Ptr) Info {
	cinfo := C.DisAsmInfoInit(start, C.DisAsmLen(end - start + 1))
	iinfo := &iInfo{cinfo}
	runtime.SetFinalizer(iinfo, InfoFree)
	info := Info{iinfo}

	return info
} // InfoInit()

func AccessByte(info Info, pc Ptr) (byte, error) {
	return byte(C.DisAsmAccessByte(info.info.info, pc)), nil
} // AccessByte()

func DecodeInstruction(info Info, pc Ptr) (instruction *Instruction, err error) {
        disAsmInfoPtr := info.info.info

        octets := int(C.DisAsmDecodeInstruction(disAsmInfoPtr, pc))
	if octets > 0 {
		s := C.GoStringN(&disAsmInfoPtr.disAsmPrintBuffer.data[0], disAsmInfoPtr.disAsmPrintBuffer.index)
		if !strings.Contains(s, "(bad)") {
			s = strings.TrimSpace(s)
			r := regexp.MustCompile(" +")
			s = r.ReplaceAllString(s, " ")

        		return &Instruction{pc, octets, s}, nil
		} // if
	} // if

	return nil, errors.New("Error with disassembly")
} // DecodeInstruction()

func DecodeGadget(info Info, pc Ptr, instructions int, octets int) (gadget *Gadget, err error) {
        disAsmInfoPtr := info.info.info
	g := Gadget{Address: pc, Octets: 0, Instructions: nil}

        for pc0 := pc; pc0 <= Ptr(disAsmInfoPtr.end); {
                var b byte = byte(C.DisAsmAccessByte(disAsmInfoPtr, pc0))
                var good bool = ((b == 0xC2) || (b == 0xC3) || (b == 0xCA) || (b == 0xCB) || (b == 0xEA))
                var bad bool = ((b == 0xE9) || (b == 0xEB) || (b == 0xFF)) // Need to add CALL ABSOLUTE here

                instruction, err := DecodeInstruction(info, pc0)
		if err != nil {
			return nil, err
		}

		g.Octets += instruction.Octets
                g.Instructions = append(g.Instructions, *instruction)

		if (g.Octets > octets) || (len(g.Instructions) > instructions) {
			return nil, errors.New("Limits exceeded")
		} // if
 
                pc0 = Ptr(uintptr(pc0) + uintptr(instruction.Octets))

                if good {
                        return &g, nil
                } else if bad {
                        return nil, errors.New("Encountered jmp instruction")
                }
        } // for

	return nil, errors.New("Nothing found")
} // DecodeGadget()

func InfoFree(i *iInfo) {
	C.DisAsmInfoFree(i.info)
	i.info = nil
} // InfoFree()

func SafeEndAddress() Ptr {
	return Ptr(C.DisAsmSafeEndAddress())
} // SafeEndAddress()

