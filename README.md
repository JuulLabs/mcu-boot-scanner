# mcu-boot-scanner

Prints out info for MCU Boot Image binaries.

See [Mcu Bootloader Spec](https://github.com/mcu-tools/mcuboot/blob/main/docs/design.md) for details.

# Build

```
% make
```

# Example Usage

```
% ./mcuscanner < example.img

HEADER:
  Magic: 0x96f3b83d (isLegacy = false)
  Load address: 0x0
  Header size: 0x20 (32 bytes)
  Protected TLV size: 0x18 (24 bytes)
  Image size: 0x11468 (70760 bytes)
  Flags: 0x0
  Version: 1.6.2-0
IMAGE BINARY: 70760 bytes
PROTECTED TLV INFO HEADER:
  Magic: 0x6908 (isProtected = true)
  Total size (including this header): 0x18 (24 bytes)
PROTECTED TLV ENTRY:
  Type: 0x60 (RSA2048 of hash output)
  Size: 0x4 (4 bytes)
  Data: 1000
PROTECTED TLV ENTRY:
  Type: 0x50 (SHA256 of image hdr and body)
  Size: 0x8 (8 bytes)
  Data: 7b05f0ae70b0bc95
UNPROTECTED TLV INFO HEADER:
  Magic: 0x6907 (isProtected = false)
  Total size (including this header): 0x28 (40 bytes)
UNPROTECTED TLV ENTRY:
  Type: 0x10 (SHA256 of image hdr and body)
  Size: 0x20 (32 bytes)
  Data: 03388a43d6194a5c64e6e87e5fe7c70b58f477bb8776521205be2a47b6e02102
END
```
