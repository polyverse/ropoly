package disasm

import "encoding/json"
import "fmt"
import "testing"
import "unsafe"

/* Chunk of disassembly from /bin/ls
100003e7a:	8b 8d 48 ff ff ff 	movl	-184(%rbp), %ecx
100003e80:	48 8b 05 81 11 00 00 	movq	4481(%rip), %rax
100003e87:	48 8b 00 	movq	(%rax), %rax
100003e8a:	48 3b 45 d0 	cmpq	-48(%rbp), %rax
100003e8e:	75 14 	jne	20 <__mh_execute_header+3EA4>
100003e90:	89 c8 	movl	%ecx, %eax
100003e92:	48 81 c4 98 00 00 00 	addq	$152, %rsp
100003e99:	5b 	popq	%rbx
100003e9a:	41 5c 	popq	%r12
100003e9c:	41 5d 	popq	%r13
100003e9e:	41 5e 	popq	%r14
100003ea0:	41 5f 	popq	%r15
100003ea2:	5d 	popq	%rbp
100003ea3:	c3 	retq
*/

// These are the bytes
var bytes = [...]byte{0x8b, 0x8d, 0x48, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x05, 0x81, 0x11, 0x00, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x3b, 0x45, 0xd0, 0x75, 0x14, 0x89, 0xc8, 0x48, 0x81, 0xc4, 0x98, 0x00, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3}

func TestDisAsm(t *testing.T) {
	start := Ptr(unsafe.Pointer(&bytes[0]))
	length := len(bytes)
	end := Ptr(unsafe.Pointer(&bytes[length-1]))

	info := InfoInit(start, end)

	var instructions []Instruction

	for pc := start; pc <= end; {
		instruction, err := DecodeInstruction(info, pc)
		if err != nil {
			break;
		} // if
		instructions = append(instructions, *instruction)
		pc = Ptr(uintptr(pc) + uintptr(instruction.NumOctets))
	} //for

	numInstructions := len(instructions)

	fmt.Printf("INSTRUCTION COUNT BETWEEN %s and %s: %d\n", start, end, numInstructions )
	is, err := json.MarshalIndent(instructions, "", "    ")
	if err == nil {
		fmt.Printf("%s\n", is)
	} // if

	var gadgets []Gadget

	for pc := start; pc <= end; pc = pc + 1 {
		gadget, err := DecodeGadget(info, pc, length, length)
		if err == nil {
			gadgets = append(gadgets, *gadget)
		} // if
	} // for

	numGadgets := len(gadgets)
	fmt.Printf("GADGET COUNT BETWEEN %s and %s: %d (%d%%)\n", start, end, numGadgets, numGadgets*100/int((uintptr(end)-uintptr(start))))
	gs, err := json.MarshalIndent(gadgets, "", "    ")
	if err == nil {
		fmt.Printf("%s\n", gs)
	}
} // TestDisAsm()
