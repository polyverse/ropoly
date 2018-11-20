package amd64

import "github.com/polyverse/ropoly/lib/types"

// Adapted from:
// 	https://github.com/JonathanSalwan/ROPgadget/blob/master/ropgadget/gadgets.py
// https://github.com/polyverse/EnVisen/blob/master/internaljs/instruction_gadget_worker.js
var GadgetSpecs = []types.GadgetSpec{
	// SYS Gadgets
	{types.MustCompile("\xcd\x80"), 2, 1},
	{types.MustCompile("\xcd\x80"), 2, 1},
	{types.MustCompile("\x0f\x34"), 2, 1},
	{types.MustCompile("\x0f\x05"), 2, 1},
	{types.MustCompile("\x65\xff\x15\x10\x00\x00\x00"), 7, 1},
	{types.MustCompile("\xcd\x80\xc3"), 3, 1},
	{types.MustCompile("\x0f\x34\xc3"), 3, 1},
	{types.MustCompile("\x0f\x05\xc3"), 3, 1},
	{types.MustCompile("\x65\xff\x15\x10\x00\x00\x00\xc3"), 8, 1},

	// JOP Gadgets
	{types.MustCompile("\xff[\x20\x21\x22\x23\x26\x27]{1}"), 2, 1},
	{types.MustCompile("\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}"), 2, 1},
	{types.MustCompile("\xff[\x10\x11\x12\x13\x16\x17]{1}"), 2, 1},
	{types.MustCompile("\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}"), 2, 1},
	{types.MustCompile("\xf2\xff[\x20\x21\x22\x23\x26\x27]{1}"), 3, 1},
	{types.MustCompile("\xf2\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}"), 3, 1},
	{types.MustCompile("\xf2\xff[\x10\x11\x12\x13\x16\x17]{1}"), 3, 1},
	{types.MustCompile("\xf2\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}"), 3, 1},

	// ROP Gadgets
	{types.MustCompile("\xc3"), 1, 1},
	{types.MustCompile("\xc2[\x00-\xff]{2}"), 3, 1},
	{types.MustCompile("\xcb"), 1, 1},
	{types.MustCompile("\xca[\x00-\xff]{2}"), 3, 1},
	{types.MustCompile("\xf2\xc3"), 2, 1},
	{types.MustCompile("\xf2\xc2[\x00-\xff]{2}"), 4, 1},
}
