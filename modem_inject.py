#!/usr/bin/python

import sys
import struct
import lief
from lief import ELF

OFFSET_E_PHOFF = 0x1C
OFFSET_E_PHENTSIZE = 0x2A
OFFSET_E_PHNUM = 0x2C
PHDR_SIZE = 0x20
OFFSET_P_OFFSET = 0x4
OFFSET_P_FILESZ = 0x10

QEMU_EXEC_PAGE_SIZE = 0x10000
QEMU_EXEC_PAGE_MASK = (QEMU_EXEC_PAGE_SIZE - 1)

# Assumptions:
#   a. When QEMU loads an ELF file, it requires
#      phdr->p_vaddr - phdr->p_offset aligned to TARGET_EXEC_PAGE_SIZE.
#   b. HEXAGON binary compiled from hexagon-unknown-linux-musl-clang.
#   c. Modem segments are 0x1000 aligned, while clang generated are
#      0x10000 aligned.
#   d. LIEF ELF writer cannot handle this.
#   e. So simply add a new segment with some paddings at the end of
#      file, and then the program header.

class QElf:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        e_phoff, = struct.unpack("<I", self.data[OFFSET_E_PHOFF:OFFSET_E_PHOFF+4])
        self.e_phentsize, = struct.unpack("<H", self.data[OFFSET_E_PHENTSIZE:OFFSET_E_PHENTSIZE+2])
        self.e_phnum, = struct.unpack("<H", self.data[OFFSET_E_PHNUM:OFFSET_E_PHNUM+2])
        self.phdr = self.data[e_phoff:e_phoff+self.e_phentsize*self.e_phnum]
        self.p_offset = len(self.data)
        # Check if ELF file was modified by this
        if e_phoff+self.e_phentsize*self.e_phnum == len(self.data):
            self.p_offset -= self.e_phentsize*self.e_phnum
            self.data = self.data[0:self.p_offset]

    def add(self, seg):
        if ((seg.virtual_address - self.p_offset) & QEMU_EXEC_PAGE_MASK) != 0:
            padding = QEMU_EXEC_PAGE_SIZE + \
                (seg.virtual_address & QEMU_EXEC_PAGE_MASK) - \
                (self.p_offset & QEMU_EXEC_PAGE_MASK)
            if padding > QEMU_EXEC_PAGE_SIZE:
                padding -= QEMU_EXEC_PAGE_SIZE
            self.data += b"\x00" * padding
            self.p_offset += padding
        p_filesz = len(seg.content)
        self.phdr += \
            struct.pack("<IIIIIIII", \
                1, \
                self.p_offset, \
                seg.virtual_address, \
                seg.physical_address, \
                p_filesz, \
                seg.virtual_size, \
                7, \
                seg.alignment)
        if p_filesz > 0:
            self.data += seg.content
            self.p_offset += p_filesz
        self.e_phnum += 1

    def write(self):
        # Make PT_PHDR aligned
        if (self.p_offset % QEMU_EXEC_PAGE_SIZE) != 0:
            padding = QEMU_EXEC_PAGE_SIZE - (self.p_offset % QEMU_EXEC_PAGE_SIZE)
            self.data += b"\x00" * padding
            self.p_offset += padding
        # Fix ELF header
        self.e_phnum += 1
        self.data = self.data[:OFFSET_E_PHNUM] + \
            struct.pack("<H", self.e_phnum) + self.data[OFFSET_E_PHNUM+2:]
        self.data = self.data[:OFFSET_E_PHOFF] + \
            struct.pack("<I", self.p_offset) + self.data[OFFSET_E_PHOFF+4:]
        # Fix program header
        base = 0
        i = 0
        while i < len(self.phdr):
            p_type, _, p_vaddr = struct.unpack("<III", self.phdr[i:i+12])
            if p_type == 1:
                base = p_vaddr
                break
            i += self.e_phentsize
        pt_load = struct.pack("<IIIIIIII", \
            1, \
            self.p_offset, \
            base + self.p_offset, \
            base + self.p_offset, \
            self.e_phnum*self.e_phentsize, \
            self.e_phnum*self.e_phentsize, \
            4, \
            QEMU_EXEC_PAGE_SIZE)
        self.phdr += pt_load
        i = 0
        while i < len(self.phdr):
            p_type, = struct.unpack("<I", self.phdr[i:i+4])
            if p_type == 6:
                pt_phdr = struct.pack("<IIIIIIII", \
                    6, \
                    self.p_offset, \
                    base + self.p_offset, \
                    base + self.p_offset, \
                    self.e_phnum*self.e_phentsize, \
                    self.e_phnum*self.e_phentsize, \
                    4, \
                    4)
                self.phdr = self.phdr[:i] + \
                    pt_phdr + self.phdr[i+self.e_phentsize:]
                break
            i += self.e_phentsize
        self.data += self.phdr
        with open(self.path, "wb") as f:
            f.write(self.data)

def to_seg(addr, binary):
    for seg in binary.segments:
        if seg.virtual_size > 0 and \
           addr >= seg.virtual_address and \
           addr < seg.virtual_address + seg.virtual_size:
            return seg
    return None

def main():
    if len(sys.argv) != 3:
        return
    target_path = sys.argv[1]
    target_elf = QElf(target_path)
    modem_path = sys.argv[2]
    # Collect necessary segments.
    modem_binary = lief.parse(modem_path)
    mdm_text = []
    mdm_rodata = []
    for seg in modem_binary.segments:
        if lief.ELF.SEGMENT_FLAGS.X in seg and seg.physical_size > 0:
            mdm_text.append(seg)
        if lief.ELF.SEGMENT_FLAGS.R in seg and \
            lief.ELF.SEGMENT_FLAGS.W not in seg and \
            lief.ELF.SEGMENT_FLAGS.X not in seg and \
            seg.physical_size > 0:
            mdm_rodata.append(seg)
    dlp_rx = None
    dlp_rw = None
    for seg in modem_binary.segments:
        if ELF.SEGMENT_FLAGS.W in seg and \
            ELF.SEGMENT_FLAGS.X in seg:
            continue
        if seg.physical_size < 48:
            continue
        dlp_found = False
        offset = 16
        while offset < seg.physical_size - 32:
            test1, test2, test3 = struct.unpack("<III", seg.content[offset:offset+12])
            if test1 != 0xD0000000 or test2 <= test1:
                offset += 4
                continue
            if test3 > 0xD0000000:
                text_s, text_e, data_s, data_e = struct.unpack("<IIII", seg.content[offset-16:offset])
                xext_s, xext_e, xata_s, xata_e = struct.unpack("<IIII", seg.content[offset:offset+16])
            else:
                xext_s, xext_e, text_s, text_e = struct.unpack("<IIII", seg.content[offset:offset+16])
                xata_s, xata_e, data_s, data_e = struct.unpack("<IIII", seg.content[offset+16:offset+32])
            if to_seg(text_s, modem_binary) is not None and \
               to_seg(data_s, modem_binary) is not None:
                print("DLPAGE: Found at 0x%lx" % (seg.virtual_address + offset))
                print("DLPAGE: Q6ZIP RO = 0x%lx-0x%lx(0x%lx), RW = 0x%lx-0x%lx(0x%lx)" % \
                    (text_s, text_e, text_e - text_s, data_s, data_e, data_e - data_s))
                print("DLPAGE: PLAIN RO = 0x%lx-0x%lx(0x%lx), RW = 0x%lx-0x%lx(0x%lx)" % \
                    (xext_s, xext_e, xext_e - xext_s, xata_s, xata_e, xata_e - xata_s))
                x = lief.ELF.Segment()
                x.type = lief.ELF.SEGMENT_TYPES.LOAD
                x.physical_address = xext_s
                x.physical_size = 0
                x.virtual_address = xext_s
                x.virtual_size = xext_e - xext_s
                x.add(lief.ELF.SEGMENT_FLAGS.R)
                x.add(lief.ELF.SEGMENT_FLAGS.W)
                # x.content = [0] * x.virtual_size
                x.alignment = 4
                dlp_rx = x
                x = lief.ELF.Segment()
                x.type = lief.ELF.SEGMENT_TYPES.LOAD
                x.physical_address = xata_s
                x.physical_size = 0
                x.virtual_address = xata_s
                x.virtual_size = xata_e - xata_s
                x.add(lief.ELF.SEGMENT_FLAGS.R)
                x.add(lief.ELF.SEGMENT_FLAGS.W)
                # x.content = [0] * seg.virtual_size
                x.alignment = 4
                dlp_rw = x
                dlp_found = True
                break
            offset += 4
        if dlp_found:
            break
    q6zip_ro = to_seg(text_s, modem_binary)
    q6zip_rw = to_seg(data_s, modem_binary)
    # Inject segments.
    for x in mdm_text:
        target_elf.add(x)
    for x in mdm_rodata:
        target_elf.add(x)
    target_elf.add(q6zip_ro)
    target_elf.add(q6zip_rw)
    target_elf.add(dlp_rx)
    target_elf.add(dlp_rw)
    target_elf.write()

if __name__ == "__main__":
    main()
