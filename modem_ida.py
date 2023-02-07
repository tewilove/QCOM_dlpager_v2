
 #/bin/env python

# These addresses has to be extracted from device.

from idautils import *
from idaapi import *
from ida_bytes import *
from ida_segment import *

def main():
    print("Loading file into IDA...")

    f = open("dlpage_rx.bin", "rb")
    data_rx = f.read()
    f.close()
    s = segment_t()
    s.start_ea = 0xD0000000
    s.end_ea = s.start_ea + len(data_rx)
    s.perm = SEGPERM_READ | SEGPERM_EXEC
    ida_segment.add_segm_ex(s, "DLPAGER_RX", None, ADDSEG_QUIET)
    ida_bytes.put_bytes(s.start_ea, data_rx)

    f = open("dlpage_rw.bin", "rb")
    data_rw = f.read()
    f.close()
    s = segment_t()
    # Need to check actual memory layout!!!
    s.start_ea = 0xD0000000 + len(data_rx)
    s.end_ea = s.start_ea + len(data_rw)
    s.perm = SEGPERM_READ | SEGPERM_WRITE
    ida_segment.add_segm_ex(s, "DLPAGER_RW", None, ADDSEG_QUIET)
    ida_bytes.put_bytes(s.start_ea, data_rw)

    print("Done.")

if __name__ == "__main__":
    main()
