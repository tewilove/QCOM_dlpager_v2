# How to analyze QUALCOMM modem?
## Prepare
- Knowledge to hexagon instruction set
- [IDA hexagon processor module](https://github.com/gsmk/hexagon) or [binja hexagon](https://github.com/google/binja-hexagon)
- [Hexagon toolchain](https://github.com/quic/toolchain_for_hexagon)
- QEMU, version 6.2 confirmed working
## Assemble the FULL modem image
- Extract modem.mdt, modem.bxx files from the deivce or firmware.
```
cd modem_files
# This will generate modem.elf
./modem_join.py modem
```
- Analyze modem.elf in IDA/binary ninja/..., to figure out:
  - Where the compressed RO/RW data segment is
  - The function addresses responsible for decompressing RO/RW data

- Modify and compile [dlpage_extractor.c](dlpage_extractor.c) accordingly.
```
hexagon-unknown-linux-musl-clang -static -o dlpage_extractor -Wall dlpage_extractor.c
```
- Inject necessary modem segments into dlpage_extractor.
```
./modem_inject.py dlpage_extractor modem.elf
```
- Run dlpage_extractor in qemu-hexagon,  if everything goes fine, decompressed segments can be dumped in QEMU.
```
gdb qemu-hexagon
> set args ./dlpage_extractor
> run
...
# Note that the dlpage range starts from VA 0xD0000000, but dlpage_extractor starts from 0x10000.
> dump binary memory q6zip_ro.bin 0xD0010000 0xDxxxxxxx
```
- Load the dumped range into IDA.
## Logging strings
TODO.
## OEM DIAG command handlers
Search for u16_1 u16_2 u32, where u16_1 == u16_2 and u32 belongs to modem text range.
## OEM QMI handlers
TODO.
## Reference
[SECURITY PROBE OF QUALCOMM MSM DATA SERVICES](https://research.checkpoint.com/2021/security-probe-of-qualcomm-msm/)