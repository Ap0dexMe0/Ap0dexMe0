#!/usr/bin/env python3
"""
Unicorn emulation: extract key from packer, then implement decryption in Python.
"""
from unicorn import *
from unicorn.x86_const import *
import pefile, struct

pe = pefile.PE('/home/z/my-project/upload/CrackMe_packed.exe')
with open('/home/z/my-project/upload/CrackMe_packed.exe', 'rb') as f:
    filedata = f.read()

IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
ENTRY_VA = IMAGE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint

STACK_BASE = 0x7FF000000
STACK_SIZE = 0x400000
FAKE_API_BASE = 0x800000000
FAKE_API_SIZE = 0x100000
HEAP_BASE = 0x900000000
HEAP_SIZE = 0x8000000

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map regions
image_size = max(pe.OPTIONAL_HEADER.SizeOfImage, 0x500000)
mu.mem_map(IMAGE_BASE, image_size, UC_PROT_ALL)
mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
mu.mem_map(FAKE_API_BASE, FAKE_API_SIZE, UC_PROT_ALL)
mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)

# Load PE sections properly
mu.mem_write(IMAGE_BASE, filedata[:0x400])
for section in pe.sections:
    va = IMAGE_BASE + section.VirtualAddress
    raw_data = section.get_data()
    if len(raw_data) > 0:
        mu.mem_write(va, raw_data)

# Set up stack
stack_top = STACK_BASE + STACK_SIZE - 0x100000
mu.reg_write(UC_X86_REG_RSP, stack_top)
mu.reg_write(UC_X86_REG_RBP, stack_top)
mu.reg_write(UC_X86_REG_RDI, 0)
mu.reg_write(UC_X86_REG_RSI, 0)

# Fake APIs
gtc1_addr = FAKE_API_BASE + 0x100
mu.mem_write(gtc1_addr, b'\x0f\x31\xc3')  # rdtsc; ret

gtc2_addr = FAKE_API_BASE + 0x200
mu.mem_write(gtc2_addr, b'\x0f\x31\x83\x64\x00\x00\x00\xc3')  # rdtsc; add eax, 100

sleep_addr = FAKE_API_BASE + 0x300
mu.mem_write(sleep_addr, b'\xc3')

va_addr = FAKE_API_BASE + 0x400
mu.mem_write(va_addr, b'\x48\xb8' + struct.pack('<Q', HEAP_BASE + 0x100000) + b'\xc3')

vp_addr = FAKE_API_BASE + 0x500
mu.mem_write(vp_addr, b'\xb8\x01\x00\x00\x00\xc3')

gsh_addr = FAKE_API_BASE + 0x600
mu.mem_write(gsh_addr, b'\x48\xb8' + struct.pack('<Q', 0xFFFFFFFFFFFFFFF5) + b'\xc3')

idp_addr = FAKE_API_BASE + 0x700
mu.mem_write(idp_addr, b'\x31\xc0\xc3')

wca_addr = FAKE_API_BASE + 0x800
mu.mem_write(wca_addr, b'\xb8\x01\x00\x00\x00\xc3')

gcm_addr = FAKE_API_BASE + 0xB00
mu.mem_write(gcm_addr, b'\xb8\x01\x00\x00\x00\xc3')  # Returns 1 (non-zero)

scm_addr = FAKE_API_BASE + 0xC00
mu.mem_write(scm_addr, b'\xb8\x01\x00\x00\x00\xc3')

def patch_resolver(rva, return_addr):
    va = IMAGE_BASE + rva
    code = b'\x48\xb8' + struct.pack('<Q', return_addr) + b'\xc3'
    mu.mem_write(va, code)

patch_resolver(0x7740, gtc1_addr)
patch_resolver(0x1ab0, gtc2_addr)
patch_resolver(0x4270, gtc2_addr)
patch_resolver(0x2d40, sleep_addr)
patch_resolver(0x2e54e0, idp_addr)
patch_resolver(0x5d60, gcm_addr)
patch_resolver(0x5b80, gsh_addr)
patch_resolver(0x3b30, FAKE_API_BASE + 0xD00)
patch_resolver(0x3ed0, FAKE_API_BASE + 0xD00)
patch_resolver(0x6dd0, FAKE_API_BASE + 0xD00)
patch_resolver(0x6120, va_addr)
patch_resolver(0x6a30, vp_addr)
for rva in [0x3200, 0x4e70]:
    patch_resolver(rva, wca_addr)

# Function pointer table
mu.mem_write(0x140413e00, struct.pack('<Q', gtc1_addr))
mu.mem_write(0x140413e10, struct.pack('<Q', gtc2_addr))
mu.mem_write(0x140413e18, struct.pack('<Q', gtc1_addr))
mu.mem_write(0x140413e20, struct.pack('<Q', gtc2_addr))

# State
key_extracted = [False]
decryption_reached = [False]

def hook_code_fn(mu, address, size, user_data):
    # Detect when we reach the decryption start
    if 0x1402a866f <= address <= 0x1402a8670 and not decryption_reached[0]:
        decryption_reached[0] = True
        rsp = mu.reg_read(UC_X86_REG_RSP)
        print(f"\n[!] Reached decryption entry at 0x{address:x}")

        # Extract key
        try:
            key_bytes = mu.mem_read(rsp + 0x12110, 8)
            key_val = struct.unpack('<Q', bytes(key_bytes))[0]
            print(f"    Key at [rsp+0x12110]: 0x{key_val:016x}")

            sum_val = struct.unpack('<I', bytes(mu.mem_read(rsp + 0x5c, 4)))[0]
            print(f"    Sum at [rsp+0x5c]: 0x{sum_val:x}")

            key_extracted[0] = True
        except Exception as e:
            print(f"    Error extracting key: {e}")

def hook_mem_invalid_fn(mu, access, address, size, value, user_data):
    page = address & ~0xFFF
    try:
        if page > 0x10000 and page < 0x7FFFFFFFFFFF:
            mu.mem_map(page, 0x10000, UC_PROT_ALL)
            return True
    except:
        pass
    return False

mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid_fn)
mu.hook_add(UC_HOOK_CODE, hook_code_fn)

print("[*] Starting emulation to extract key...")
try:
    mu.emu_start(ENTRY_VA, 0x1402a8670, timeout=60*UC_SECOND_SCALE, count=50000000)
    print(f"[+] Stopped. RIP=0x{mu.reg_read(UC_X86_REG_RIP):x}")

    if key_extracted[0]:
        rsp = mu.reg_read(UC_X86_REG_RSP)
        key_bytes = mu.mem_read(rsp + 0x12110, 8)
        key_val = struct.unpack('<Q', bytes(key_bytes))[0]
        print(f"[+] Key extracted: 0x{key_val:016x}")

        # Dump .data section state at this point (after Layer 1 block cipher decryption)
        print("[*] Dumping .data section state...")
        data = bytes(mu.mem_read(IMAGE_BASE + 0x3ad000, 0x67000))
        with open('/home/z/my-project/download/data_after_layer1.bin', 'wb') as f:
            f.write(data)
        print(f"    Saved {len(data)} bytes")
        print(f"    First 32 bytes: {data[:32].hex()}")
        print(f"    Starts with MZ: {data[:2] == b'MZ'}")
    else:
        print("[!] Key not extracted - decryption entry not reached")
except UcError as e:
    rip = mu.reg_read(UC_X86_REG_RIP)
    print(f"\n[!] Error at RIP=0x{rip:x}: {e}")
    if not key_extracted[0]:
        print("    Did not reach decryption entry")
