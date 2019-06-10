package thumb

import "github.com/polyverse/ropoly/lib/types"

// Adapted from:
// 	https://github.com/JonathanSalwan/ROPgadget/blob/master/ropgadget/gadgets.py
// https://github.com/polyverse/EnVisen/blob/master/internaljs/instruction_gadget_worker.js
var GadgetSpecs = []*types.GadgetSpec{
	// SYS Gadgets
	{types.MustCompile("\x00-\xff]{1}\xef"), 2, 2},

	// JOP Gadgets
	{types.MustCompile("[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47"), 2, 2},
	{types.MustCompile("[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47"), 2, 2},
	{types.MustCompile("[\x00-\xff]{1}\xbd"), 2, 2},

	// No ROP Gadgets
}