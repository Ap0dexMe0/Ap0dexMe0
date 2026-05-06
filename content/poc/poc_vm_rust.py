#!/usr/bin/env python3
"""
PoC / Key Recovery for vm-rust.exe CTF Crackme
================================================
Binary: vm-rust.exe (PE32+ x86-64, Rust, ~1.4 MB)
Author: Reverse Engineering Analysis

This script recovers the internal 128-bit key used by the crackme's
validation logic by reimplementing the key-derivation algorithm that
hashes the .text section of the binary with multiple FNV-1a variants.

Two solution paths are provided:
  1. Key Recovery  – recompute the key purely from the on-disk binary.
  2. Binary Patch – patch two conditional jumps to bypass anti-debug
     and key-check logic so the crackme always succeeds.

Usage:
    python3 poc_vm_rust.py vm-rust.exe
"""

import struct
import sys
import os

# ─────────────────────────────────────────────────────────────────────────────
# Constants extracted from disassembly
# ─────────────────────────────────────────────────────────────────────────────
FNV_OFFSET_BASIS = 0x811C9DC5
FNV_PRIME         = 0x01000193

# Seeds used in the three-part hash (function @ 0x140006150)
SEED_PART1 = 0x811C9DC5          # XOR'd with part-length
SEED_PART2 = 0xA55AA55A          # XOR'd with third-part size
SEED_PART3 = 0x1F123BB5          # XOR'd with third-part size

# Magic values from the key-gen preamble
INIT_R14       = 0xDEADBEEF
MAGIC_CAFEBABE = 0xCAFEBABE
MAGIC_1337C0DE = 0x1337C0DE

# Constants for function @ 0x140006740  (complex integrity hash)
INIT_EDI_740 = 0x5A5A5A5A
INIT_ESI_740 = 0xC3C33C3C
EDI_PASS     = 0xA5A5A5A5         # set when ntdll export VirtualSize >= 0x20
ESI_ALT      = 0x3C3CC3C3

# PE section header offsets
PE_MAGIC_OFFSET   = 0x3C
PE_SIG_OFFSET     = 0x00
PE_NUM_SECTORS    = 0x06
PE_OPT_HDR_SIZE   = 0x14

# ─────────────────────────────────────────────────────────────────────────────
# Helper: 32-bit rotate-left
# ─────────────────────────────────────────────────────────────────────────────
def rol32(val, n):
    n &= 31
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

# ─────────────────────────────────────────────────────────────────────────────
# Standard FNV-1a (used in multiple places)
# ─────────────────────────────────────────────────────────────────────────────
def fnv1a_32(data: bytes, seed: int = FNV_OFFSET_BASIS) -> int:
    h = seed
    for b in data:
        h = (h ^ b) & 0xFFFFFFFF
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h

# ─────────────────────────────────────────────────────────────────────────────
# Custom hash for part 1 of .text  (from function @ 0x140006150)
# Processes first `part_len` bytes.  Seed = part_len ^ 0x811C9DC5.
# Two bytes are consumed per iteration; a running counter increments by 0x22.
# ─────────────────────────────────────────────────────────────────────────────
def custom_hash_part1(text_data: bytes, part_len: int) -> int:
    h = (part_len ^ SEED_PART1) & 0xFFFFFFFF
    counter = 0x11
    n = len(text_data)
    i = 0

    limit = part_len & 0x7FFFFFFE  # round down to even
    while i < limit:
        b1 = text_data[i]
        b2 = text_data[i + 1]

        # --- first byte ---
        tmp = (b1 + counter + 0xFFFFFFEF) & 0xFFFFFFFF   # b1 + counter - 17
        tmp ^= h
        rot = (i & 0x06) + 3
        tmp = rol32(tmp, rot)
        h1 = (tmp * FNV_PRIME) & 0xFFFFFFFF

        # --- second byte ---
        tmp = (b2 + counter) & 0xFFFFFFFF
        tmp ^= h1
        rot = ((i + 1) & 0x07) + 3
        tmp = rol32(tmp, rot)
        h = (tmp * FNV_PRIME) & 0xFFFFFFFF

        counter += 0x22
        i += 2

    if part_len & 1:  # odd-length tail
        b = text_data[i]
        tmp = ((i << 4) + i + b) & 0xFFFFFFFF
        tmp ^= h
        rot = (i & 0x07) + 3
        tmp = rol32(tmp, rot)
        h = (tmp * FNV_PRIME) & 0xFFFFFFFF

    return h

# ─────────────────────────────────────────────────────────────────────────────
# Custom hash for part 2  (second loop in @ 0x140006150)
# Processes bytes at offset `part_len` for `third_size` bytes.
# Seed = third_size ^ 0xA55AA55A.
# ─────────────────────────────────────────────────────────────────────────────
def custom_hash_part2(text_data: bytes, part_len: int, third_size: int) -> int:
    h = (third_size ^ SEED_PART2) & 0xFFFFFFFF
    counter = 0x11
    off = part_len
    i = 0

    limit = third_size & 0x7FFFFFFE
    while i < limit:
        b1 = text_data[off + i]
        b2 = text_data[off + i + 1]

        tmp = (b1 + counter + 0xFFFFFFEF) & 0xFFFFFFFF
        tmp ^= h
        rot = (i & 0x06) + 3
        tmp = rol32(tmp, rot)
        h1 = (tmp * FNV_PRIME) & 0xFFFFFFFF

        tmp = (b2 + counter) & 0xFFFFFFFF
        tmp ^= h1
        rot = ((i + 1) & 0x07) + 3
        tmp = rol32(tmp, rot)
        h = (tmp * FNV_PRIME) & 0xFFFFFFFF

        counter += 0x22
        i += 2

    if third_size & 1:
        b = text_data[off + i]
        tmp = ((i << 4) + i + b) & 0xFFFFFFFF
        tmp ^= h
        rot = (i & 0x07) + 3
        tmp = rol32(tmp, rot)
        h = (tmp * FNV_PRIME) & 0xFFFFFFFF

    return h

# ─────────────────────────────────────────────────────────────────────────────
# Custom hash for part 3  (third loop in @ 0x140006150)
# Same offset as part 2; seed = third_size ^ 0x1F123BB5.
# ─────────────────────────────────────────────────────────────────────────────
def custom_hash_part3(text_data: bytes, part_len: int, third_size: int) -> int:
    h = (third_size ^ SEED_PART3) & 0xFFFFFFFF
    counter = 0x11
    off = part_len
    i = 0

    limit = third_size & 0x7FFFFFFE
    while i < limit:
        b1 = text_data[off + i]
        b2 = text_data[off + i + 1]

        tmp = (b1 + counter + 0xFFFFFFEF) & 0xFFFFFFFF
        tmp ^= h
        rot = (i & 0x06) + 3
        tmp = rol32(tmp, rot)
        h1 = (tmp * FNV_PRIME) & 0xFFFFFFFF

        tmp = (b2 + counter) & 0xFFFFFFFF
        tmp ^= h1
        rot = ((i + 1) & 0x07) + 3
        tmp = rol32(tmp, rot)
        h = (tmp * FNV_PRIME) & 0xFFFFFFFF

        counter += 0x22
        i += 2

    if third_size & 1:
        b = text_data[off + i]
        tmp = ((i << 4) + i + b) & 0xFFFFFFFF
        tmp ^= h
        rot = (i & 0x07) + 3
        tmp = rol32(tmp, rot)
        h = (tmp * FNV_PRIME) & 0xFFFFFFFF

    return h

# ─────────────────────────────────────────────────────────────────────────────
# PEB-based API hash resolver  (@ 0x1400069E0)
# Used to resolve GetModuleHandleA / GetProcAddress by hash of their names.
# ─────────────────────────────────────────────────────────────────────────────
def fnv1a_lowercase(data: bytes) -> int:
    """FNV-1a with forced lower-case for a-z range."""
    h = FNV_OFFSET_BASIS
    for b in data:
        if 0x41 <= b <= 0x5A:
            b = b | 0x20  # tolower
        h = (h ^ b) & 0xFFFFFFFF
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h

# Known API hashes
HASH_GetModuleHandleA = fnv1a_lowercase(b"GetModuleHandleA")
HASH_GetProcAddress   = fnv1a_lowercase(b"GetProcAddress")

# ─────────────────────────────────────────────────────────────────────────────
# Key derivation  (@ 0x140005FD0  →  called from @ 0x140008154 / @ 0x14000964B)
#
# Produces 4 × u32  →  16 bytes stored at [rsi]:
#   key[0] = rol(h2, 5) ^ h1        where h1, h2, h3 come from the
#   key[1] = fnv1a(.text)             three-part hash @ 0x140006150
#   key[2] = fnv1a(.text) ^ rol(h3, 11)
#   key[3] = 0xC3C3C3C3 ^ 0xA5A5A5A5 ^ rol(fnv1a(.text), 9)
# ─────────────────────────────────────────────────────────────────────────────
def derive_key(text_data: bytes) -> list[int]:
    text_size = len(text_data)
    part_len   = (text_size + 2) // 3       # ceiling-div by 3
    third_size = text_size - 2 * part_len

    h1 = custom_hash_part1(text_data, part_len)
    h2 = custom_hash_part2(text_data, part_len, third_size)
    h3 = custom_hash_part3(text_data, part_len, third_size)

    fnv = fnv1a_32(text_data)

    key0 = rol32(h2, 5) ^ h1
    key1 = fnv
    key2 = fnv ^ rol32(h3, 11)
    key3 = 0xC3C3C3C3 ^ 0xA5A5A5A5 ^ rol32(fnv, 9)

    return [key0, key1, key2, key3]

# ─────────────────────────────────────────────────────────────────────────────
# Extract the .text section from a PE file
# ─────────────────────────────────────────────────────────────────────────────
def extract_text_section(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        pe = f.read()

    pe_off = struct.unpack_from("<I", pe, PE_MAGIC_OFFSET)[0]
    num_sections = struct.unpack_from("<H", pe, pe_off + PE_NUM_SECTORS)[0]
    opt_size = struct.unpack_from("<H", pe, pe_off + PE_OPT_HDR_SIZE)[0]
    sec_table = pe_off + 0x18 + opt_size

    for i in range(num_sections):
        sh = sec_table + i * 40
        name = pe[sh:sh + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize     = struct.unpack_from("<I", pe, sh + 0x08)[0]
        raw_size  = struct.unpack_from("<I", pe, sh + 0x10)[0]
        raw_off   = struct.unpack_from("<I", pe, sh + 0x14)[0]
        if name == ".text":
            # The binary hashes VirtualSize bytes, not RawSize
            return pe[raw_off : raw_off + min(vsize, raw_size)]

    raise RuntimeError(".text section not found")

# ─────────────────────────────────────────────────────────────────────────────
# Binary patching – bypass anti-debug & key check
#
# Patch 1 (anti-debug):  At VMA 0x14001EF03  the binary calls IsDebuggerPresent
#   and branches when the debugger IS present.  We patch the conditional jump
#   at 0x14001EF35 (`cmp ebx, 1 / je success`) to an unconditional jump.
#
# Patch 2 (key-check):   At VMA 0x1400096A8  the binary compares the generated
#   key with the embedded expected key and jumps to the success path only when
#   they match.  We patch `je 0x1400096FF` → `jmp 0x1400096FF` (0x74 → 0xEB).
# ─────────────────────────────────────────────────────────────────────────────
# The 'cmp ebx, 1' instruction at 0x14001EF35 is 3 bytes (83 fb 01),
# followed by 'je +8' at 0x14001EF38.  We patch the je.
PATCH_ANTI_DEBUG_VMA  = 0x14001EF38
PATCH_ANTI_DEBUG_ORIG = b"\x74\x08"       # je +8
PATCH_ANTI_DEBUG_NEW  = b"\xEB\x08"       # jmp +8

PATCH_KEY_CHECK_VMA   = 0x1400096A8
PATCH_KEY_CHECK_FILE  = None   # computed at runtime
PATCH_KEY_CHECK_ORIG  = b"\x74\x55"       # je +0x55
PATCH_KEY_CHECK_NEW   = b"\xEB\x55"       # jmp +0x55

def patch_binary(filepath: str, outpath: str):
    with open(filepath, "rb") as f:
        pe = bytearray(f.read())

    text_off = struct.unpack_from("<I", pe, PE_MAGIC_OFFSET)[0]
    text_off = 0  # ImageBase is 0x140000000, .text VMA 0x140001000, file 0x400
    # Convert VMAs to file offsets: file_off = VMA - 0x140000000 + header_size
    # Actually: .text VMA 0x140001000, file offset 0x400. Offset in .text = VMA - 0x140001000
    def vma_to_foff(vma):
        return 0x400 + (vma - 0x140001000)

    off1 = vma_to_foff(PATCH_ANTI_DEBUG_VMA)
    off2 = vma_to_foff(PATCH_KEY_CHECK_VMA)

    assert pe[off1:off1+2] == PATCH_ANTI_DEBUG_ORIG, \
        f"Anti-debug patch mismatch at 0x{off1:x}: expected {PATCH_ANTI_DEBUG_ORIG.hex()}, got {pe[off1:off1+2].hex()}"
    assert pe[off2:off2+2] == PATCH_KEY_CHECK_ORIG, \
        f"Key-check patch mismatch at 0x{off2:x}: expected {PATCH_KEY_CHECK_ORIG.hex()}, got {pe[off2:off2+2].hex()}"

    pe[off1:off1+2] = PATCH_ANTI_DEBUG_NEW
    pe[off2:off2+2] = PATCH_KEY_CHECK_NEW

    with open(outpath, "wb") as f:
        f.write(pe)

    print(f"[+] Patched binary written to: {outpath}")
    print(f"    Patch 1 (anti-debug bypass): file offset 0x{off1:x}  "
          f"({PATCH_ANTI_DEBUG_ORIG.hex()} → {PATCH_ANTI_DEBUG_NEW.hex()})")
    print(f"    Patch 2 (key-check bypass):  file offset 0x{off2:x}  "
          f"({PATCH_KEY_CHECK_ORIG.hex()} → {PATCH_KEY_CHECK_NEW.hex()})")

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <vm-rust.exe> [output_patched.exe]")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    print("=" * 70)
    print("  vm-rust.exe  CTF Crackme – Key Recovery & Patch PoC")
    print("=" * 70)

    # ── Step 1: Extract .text section ──────────────────────────────────────
    print("\n[*] Extracting .text section …")
    text_data = extract_text_section(filepath)
    print(f"    .text size: {len(text_data)} bytes (0x{len(text_data):x})")

    # ── Step 2: Verify known API hashes ────────────────────────────────────
    print("\n[*] Verifying API name hashes …")
    print(f"    GetModuleHandleA hash: 0x{HASH_GetModuleHandleA:08x}  "
          f"(binary uses 0x0a3e6f6c3)")
    print(f"    GetProcAddress   hash: 0x{HASH_GetProcAddress:08x}  "
          f"(binary uses 0x0e463da3c)")

    # ── Step 3: Derive the 128-bit key ─────────────────────────────────────
    print("\n[*] Deriving key from .text section hashes …")
    key = derive_key(text_data)
    key_bytes = struct.pack("<IIII", *key)

    print(f"    Part 1 hash (h1): 0x{custom_hash_part1(text_data, (len(text_data)+2)//3):08x}")
    print(f"    Part 2 hash (h2): 0x{custom_hash_part2(text_data, (len(text_data)+2)//3, len(text_data)-2*((len(text_data)+2)//3)):08x}")
    fnv = fnv1a_32(text_data)
    print(f"    FNV-1a of .text:   0x{fnv:08x}")
    print(f"    ┌──────────────────────────────────────────────────┐")
    print(f"    │  Derived 128-bit key:  {key_bytes.hex()}  │")
    print(f"    │  DWORDs: {', '.join(f'0x{k:08x}' for k in key):36s} │")
    print(f"    └──────────────────────────────────────────────────┘")

    # ── Step 4: Patch the binary (optional) ────────────────────────────────
    if len(sys.argv) >= 3:
        outpath = sys.argv[2]
        print("\n[*] Patching binary …")
        patch_binary(filepath, outpath)
    else:
        print(f"\n[*] To create a patched binary, run:")
        print(f"    python3 {sys.argv[0]} {filepath} <output_path>")

    # ── Step 5: Summary ────────────────────────────────────────────────────
    print("\n[*] Summary of protection mechanisms:")
    print("    1. Anti-debugging:  IsDebuggerPresent + QueryPerformanceCounter")
    print("       Used in CRT init; checks for attached debugger at startup.")
    print("    2. API obfuscation:  GetModuleHandleA / GetProcAddress resolved")
    print("       via PEB walking + FNV-1a name hash comparison")
    print("       (GetModuleHandleA → 0x0A3E6F6C3, GetProcAddress → 0x0E463DA3C)")
    print("    3. String obfuscation: CRACKME_LIVE_CONTEXT used as validation")
    print("       token; actual strings decrypted with key derived from .text hash")
    print("    4. Key derivation: 4 × u32 computed from three custom FNV-1a")
    print("       variants over the .text section (see above)")
    print("    5. VM-based validation: 3 bytecode interpreters (vm1, vm2, vm3)")
    print("       at 0x140006DB0, 0x14000C370, 0x14000E290 process user input")
    print("    6. Integrity checks: .text section hash ensures binary is not")
    print("       modified; if patched, the key derivation will produce wrong")
    print("       values and validation will fail")

    print("\n[+] Done.")


if __name__ == "__main__":
    main()
