package gadgets

import (
	"fmt"
	"github.com/polyverse/ropoly/lib/architectures/amd64"
	log "github.com/sirupsen/logrus"
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

func TestFindDepth10(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	defer log.SetLevel(log.InfoLevel)

	gadgets, err, _ := Find(opcodes, amd64.GadgetSpecs, amd64.GadgetDecoder, 0, 10)
	if err != nil {
		t.Fatalf("Error when decoding instruction: %v", err)
	}
	if gadgets == nil {
		t.Fatalf("Instruction Nil when decoding")
	}
	log.Infof("For depth 10 found %d gadgets\n", len(gadgets))
	log.Infof("%v", gadgets)
}

func TestFindDepth2(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	defer log.SetLevel(log.InfoLevel)

	gadgets, err, _ := Find(opcodes, amd64.GadgetSpecs, amd64.GadgetDecoder, 0, 2)
	if err != nil {
		t.Fatalf("Error when decoding instruction: %v", err)
	}
	if gadgets == nil {
		t.Fatalf("Instruction Nil when decoding")
	}
	log.Infof("For depth 2 found %d gadgets\n", len(gadgets))
	log.Infof("%v", gadgets)
}
