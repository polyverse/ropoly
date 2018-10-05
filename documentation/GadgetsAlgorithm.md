WIP

# Algorithm for finding gadgets
Given a list of instructions making up a binary, return a list of gadgets.
List is assumed to be sorted by address. Output will also be sorted by address.
List does not need to be complete, but the algorithm can only find gadgets for which all instructions are present in input.

### Steps
For each instruction, starting from the first, check if it is a branching instruction.
If it is, find all gadgets ending with the instruction.

## Algorithm for finding all gadgets ending with a given instruction
Just like the larger algorithm for finding all gadgets, takes a sorted list of instructions making up a binary, and returns a list of gadgets.
Also takes an instruction in the list to use as the last instruction for all gadgets.

### Steps
Starting from the branching instruction (inclusive), for each instruction going backwards in the list, up to the instruction limit:
Check if the instruction is a branching instruction (and not the one we originally started from)--a gadget only has one branching instruction, at the end.
If it is, we're done--return without looking at any more instructions.
If not, check whether the instruction is adjacent to the last one we checked (unless we're still on the first one).
If it is, it's part of the gadget; add it to the list of instructions for the gadget.
Otherwise, if it's overlapping, then it can't be part of the same gadget, but the next one could be; move on to checking the next instruction.
If it's not overlapping or adjacent, then we're out of instructions with which to make gadgets ending with the given instruction. Return.
Check if the total number of bytes in the instructions we've added to the list for gadgets exceeds the given maximum.
If it exceeds the maximum, this gadget is too large, and the rest that we would add are larger, so return.
Otherwise, prepend the gadget consisting of the found range of adjacent instructions to the list of gadgets to return. Prepend rather than append because the most recently found gadget has the lowest starting address, and we're sorting by address.
Check if over the total number of gadgets allowed to be returned (for the entire gadget search).
If over the limit, drop the least recently added gadget from the list of gadgets (with the same final instruction that we're checking for) from the list.

