#!/usr/bin/python

import sys
import struct

EHDR_SIZE = 0x34
OFFSET_E_PHOFF = 0x1C
OFFSET_E_PHNUM = 0x2C
PHDR_SIZE = 0x20
OFFSET_P_OFFSET = 0x4
OFFSET_P_FILESZ = 0x10

def main():
	if len(sys.argv) != 3:
		return
	name = sys.argv[1]
	out_file = sys.argv[2]
	mdt_file = open("%s.mdt" % (name), "rb")
	elf_header = mdt_file.read(EHDR_SIZE)
	phoff, = struct.unpack("<I", elf_header[OFFSET_E_PHOFF:OFFSET_E_PHOFF+4])
	mdt_file.seek(phoff, 0)
	out_file = open(out_file, "wb")
	phnum, = struct.unpack("<H", elf_header[OFFSET_E_PHNUM:OFFSET_E_PHNUM+2])
	for i in range(0, phnum):
		phdr = mdt_file.read(PHDR_SIZE)
		filesz, = struct.unpack("<I", phdr[OFFSET_P_FILESZ:OFFSET_P_FILESZ+4])
		offset, = struct.unpack("<I", phdr[OFFSET_P_OFFSET:OFFSET_P_OFFSET+4])
		if filesz == 0:
			continue
		data = open("%s.b%02d" % (name, i), "rb").read()
		out_file.seek(offset, 0)
		out_file.write(data)
	out_file.close()
	mdt_file.close()

if __name__ == "__main__":
	main()