loop_start = 0x5c0
loop_size = 0x222
split_address = 0xf2
ropoly_start = 0x401d60
ropoly_size = 0x296912
new_center = 0x10000
offsets = [0x10, 0x10010]

loop = open("TestFiles/loop", "rb")
loop_bytes = bytearray(loop.read())
loop.close()
loop_text_bytes = loop_bytes[loop_start : loop_start + loop_size]
loop_text_bytes_halves = [loop_text_bytes[0 : split_address], loop_text_bytes[split_address : loop_size]]

ropoly = open("bin/ropoly-libc-x86_64", "rb")
new_file_bytes = bytearray(ropoly.read())
ropoly.close()

new_file_bytes[ropoly_start : ropoly_start + ropoly_size] = [0xff] * ropoly_size
new_file_bytes[ropoly_start + new_center : ropoly_start + new_center + loop_size] = loop_text_bytes

test_file0 = open("TestFiles/envisen_test0", "wb")
test_file0.write(new_file_bytes)
test_file0.close()

size = len(new_file_bytes)
new_file_bytes[ropoly_start: ropoly_start + ropoly_size] = [0xff] * ropoly_size
assert(len(new_file_bytes)==size)
size = len(new_file_bytes)
new_file_bytes[ropoly_start + new_center + offsets[0] : ropoly_start + new_center + offsets[0] + split_address] = loop_text_bytes_halves[0]
assert(len(new_file_bytes)==size)
size = len(new_file_bytes)
new_file_bytes[ropoly_start + new_center + offsets[1] + split_address : ropoly_start + new_center + offsets[1] + loop_size] = loop_text_bytes_halves[1]
assert(len(new_file_bytes)==size)

test_file1 = open("TestFiles/envisen_test1", "wb")
test_file1.write(new_file_bytes)
test_file1.close()

print("Created TestFiles/envisen_test0 and TestFiles/envisen_test1")
