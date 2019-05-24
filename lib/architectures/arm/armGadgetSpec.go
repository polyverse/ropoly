package arm

import "github.com/polyverse/ropoly/lib/types"

// Adapted from:
// 	https://github.com/JonathanSalwan/ROPgadget/blob/master/ropgadget/gadgets.py
// https://github.com/polyverse/EnVisen/blob/master/internaljs/instruction_gadget_worker.js
var GadgetSpecs = []*types.GadgetSpec{
	// SYS Gadgets
	{types.MustCompile("\x00-\xff]{3}\xef"), 4, 4},
	{types.MustCompile("\x00-\xff]{1}\xef"), 2, 2},

	// JOP Gadgets
	{types.MustCompile("[\x10-\x19\x1e]{1}\xff\x2f\xe1"), 4, 4},
	{types.MustCompile("[\x30-\x39\x3e]{1}\xff\x2f\xe1"), 4, 4},
	{types.MustCompile("[\x00-\xff][\x80-\xff][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe][\xe8\xe9]"), 4, 4},
	{types.MustCompile("[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00-\x03]{1}[\x1f\x5f]{1}\xd6"), 4, 4},
	{types.MustCompile("[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00-\x03]{1}?\xd6"), 4, 4},
	{types.MustCompile("[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47"), 2, 2},
	{types.MustCompile("[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47"), 2, 2},
	{types.MustCompile("[\x00-\xff]{1}\xbd"), 2, 2},

	// ROP Gadgets
	{types.MustCompile("\xc0\x03\x5f\xd6"), 4, 4},
}