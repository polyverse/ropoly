package amd64

import (
	"testing"
)

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
var opcodes = []byte{0x8b, 0x8d, 0x48, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x05, 0x81, 0x11, 0x00, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x3b, 0x45, 0xd0, 0x75, 0x14, 0x89, 0xc8, 0x48, 0x81, 0xc4, 0x98, 0x00, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3}

func TestInstructionDecoder(t *testing.T) {
	instr, err := InstructionDecoder(opcodes)
	if err != nil {
		t.Fatalf("Error when decoding instruction: %v", err)
	}
	if instr == nil {
		t.Fatalf("Instruction Nil when decoding")
	}
	expectedStr := "0x8b 0x8d 0x48 0xff 0xff 0xff (MOV ECX, [RBP+0xffffff48])"
	if instr.String() != expectedStr {
		t.Fatalf("Expected %s, but found: %s", expectedStr, instr.String())
	}
}

func TestGadgetDecoder(t *testing.T) {
	gadget, err := GadgetDecoder(opcodes)
	if err != nil {
		t.Fatalf("Error when decoding gadget: %v", err)
	}
	if gadget == nil {
		t.Fatalf("Gadget Nil when decoding")
	}
	if len(gadget) == 0 {
		t.Fatalf("Gadget empty when decoding")
	}

	expectedStr := `MOV ECX, [RBP+0xffffff48]
MOV RAX, [RIP+0x1181]
MOV RAX, [RAX]
CMP RAX, [RBP-0x30]
JNE .+20
MOV EAX, ECX
ADD RSP, 0x98
POP RBX
POP R12
POP R13
POP R14
POP R15
POP RBP
RET
`
	if gadget.InstructionString() != expectedStr {
		t.Fatalf("Expected %s, but found: %s", expectedStr, gadget.InstructionString())
	}
}
