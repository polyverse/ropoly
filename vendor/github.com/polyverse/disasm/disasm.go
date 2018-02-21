package disasm

// #include "disasm.h"
// #cgo CFLAGS: -std=c99
import "C"

import "encoding/json"
import "errors"
import "hash/crc32"
import "math"
import "runtime"
import "strings"
import "strconv"
import "unsafe"

type Ptr uintptr
type Len uint64
type Sig uint16

type iInfo struct {
	info *C.struct_DisAsmInfo
}

type Info struct {
	info *iInfo
	start  Ptr
	end    Ptr
	length Len
	memory []byte
}

type Instruction struct {
	Address   Ptr     `json:"address,string"`
	NumOctets int     `json:"numOctets"`
	Octets    []byte  `json:"octets"`
	DisAsm    string  `json:"disasm"`
}

type Gadget struct {
	Address         Ptr           `json:"address,string"`
	Signature       Sig           `json:"signature"`
	NumInstructions int           `json:"numInstructions"`
	NumOctets       int           `json:"numOctets"`
	Instructions    []Instruction `json:"instructions"`
}

func (p Ptr) String() string {
	str := strconv.FormatUint(uint64(p), 16)
	return "0x" + strings.Repeat("0", 12-len(str)) + str
}

func (s Sig) String() string {
	str := strconv.FormatUint(uint64(s), 16)
	return "0x" + strings.Repeat("0", 4-len(str)) + str
}

func (i *Instruction) String() string {

	b := i.Octets
	s := i.Address.String() + " "

	for o := 0; o < 8; o++ {
		if o < i.NumOctets {
			if b[o] < 16 {
				s += "0"
			} // if
			s += strconv.FormatUint(uint64(b[o]), 16)
		} else {
			s += "  "
		} // else
	} // for

        return s + " " + i.DisAsm

	//return i.DisAsm
}

/*
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
*/
func (i *Instruction) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
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

func (g *Gadget) String() string {
	sAdr := strconv.FormatUint(uint64(g.Address), 16)
	sSig := strconv.FormatUint(uint64(g.Signature), 16)
	return "0x" + strings.Repeat("0", 12-len(sAdr)) + sAdr + strings.Repeat("0", 4-len(sSig)) + sSig
}

func InfoInit(s Ptr, e Ptr) Info {
	l := Len(e - s + 1)

	cinfo := C.DisAsmInfoInit(C.DisAsmPtr(s), C.DisAsmPtr(e))
	iinfo := &iInfo{cinfo}
	runtime.SetFinalizer(iinfo, InfoFree)
	info := Info{info: iinfo, start: s, end: e, length: l, memory: C.GoBytes(unsafe.Pointer(s), C.int(l))}		

	return info
} // InfoInit()

func InfoInitBytes(s Ptr, e Ptr, b []byte) Info {
	l := Len(e - s + 1)
	if l != Len(len(b)) {
		panic("Disallowed assertion")
	}

	cinfo := C.DisAsmInfoInitBytes(C.DisAsmPtr(s), C.DisAsmPtr(e), unsafe.Pointer(&b[0]))
	iinfo := &iInfo{cinfo}
	runtime.SetFinalizer(iinfo, InfoFree)
	info := Info{info: iinfo, start: s, end: e, length: l, memory: b}

	return info
} // InfoInitBytes()

func DecodeInstruction(info Info, pc Ptr) (instruction *Instruction, err error) {
        disAsmInfoPtr := info.info.info

        numOctets := int(C.DisAsmDecodeInstruction(disAsmInfoPtr, C.DisAsmPtr(pc)))
	if numOctets > 0 {
		s := C.GoStringN(&disAsmInfoPtr.disAsmPrintBuffer.data[0], disAsmInfoPtr.disAsmPrintBuffer.index)
		s = strings.TrimRight(s, " ")

		octets := info.memory[pc-info.start:pc+Ptr(numOctets)-info.start]
       		return &Instruction{Address: pc, NumOctets: numOctets, Octets: octets, DisAsm: s}, nil
	} // if

	return nil, errors.New("Error with disassembly")
} // DecodeInstruction()

func DecodeGadget(info Info, pc Ptr, instructions int, numOctets int) (gadget *Gadget, err error) {
	g := Gadget{Address: pc, NumInstructions: 0, NumOctets: 0, Instructions: nil}

        for pc0 := pc; pc0 <= info.end; {
		var b = info.memory[pc0-info.start]
                var good bool = ((b == 0xC2) || (b == 0xC3) || (b == 0xCA) || (b == 0xCB))
                var bad bool = ((b == 0xE9) || (b == 0xEA) || (b == 0xEB) || (b == 0xFF)) // JMP, JMP, JMP, 0xFF

                instruction, err := DecodeInstruction(info, pc0)
		if err != nil {
			return nil, err
		}
		if strings.Contains(instruction.DisAsm, "(bad)") {
                        return nil, errors.New("Encountered (bad) instruction")
		} // if

		g.NumInstructions++ 
		g.NumOctets += instruction.NumOctets
                g.Instructions = append(g.Instructions, *instruction)

		if (g.NumOctets > numOctets) || (len(g.Instructions) > instructions) {
			return nil, errors.New("Limits exceeded")
		} // if
 
                pc0 = Ptr(uintptr(pc0) + uintptr(instruction.NumOctets))

                if good {
			signature := crc32.ChecksumIEEE(info.memory[pc-info.start:pc+Ptr(g.NumOctets)-info.start])
			g.Signature = Sig((signature / math.MaxUint16) ^ (signature % math.MaxUint16))
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
