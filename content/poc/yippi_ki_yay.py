#!/usr/bin/env python3
"""
PoC / Keygen for crackmes.one challenge: b.exe
================================================
Binary: b.exe (PE32+ x86-64, MinGW-w64 GCC 14.2.0, stripped)

This script reverses the obfuscation layers in the binary to recover
the hardcoded password WITHOUT patching or modifying the original binary.

Author: CTF Reverse Engineering Analysis
"""

import struct
import ctypes


def xor_decrypt(data: bytes, key: int) -> bytes:
    """XOR each byte of data with the given key."""
    return bytes([b ^ key for b in data])


def main():
    print("=" * 60)
    print("  b.exe - CrackMe Keygen / PoC (No Patching)")
    print("=" * 60)
    print()

    # ====================================================================
    # STEP 1: Extract encrypted data blobs from the .data section
    # ====================================================================
    # The binary stores its strings XOR-encrypted in the .data section.
    # These were located at the following virtual addresses:
    #
    #   0x140004030: Encrypted "Enter password: " prompt (16 bytes)
    #   0x140004010: Encrypted password string (13 bytes)
    #   0x140005058: XOR key reference (0xAAAA word)

    print("[*] Step 1: Extracting encrypted data from .data section...")

    # Encrypted prompt at VA 0x140004030
    encrypted_prompt = bytes.fromhex("efc4decfd88adacbd9d9ddc5d8ce908a")

    # Encrypted password at VA 0x140004010
    encrypted_password = bytes.fromhex("f3c3dadac3cf87e1c387f3cbd3")

    # XOR key used throughout the binary
    xor_key = 0xAA

    print(f"    Encrypted prompt  @0x4030: {encrypted_prompt.hex()}")
    print(f"    Encrypted password @0x4010: {encrypted_password.hex()}")
    print(f"    XOR key: 0x{xor_key:02X}")
    print()

    # ====================================================================
    # STEP 2: Decrypt the prompt string ("Enter password: ")
    # ====================================================================
    # The main function (at 0x140003420) uses SSE2 SIMD to decrypt:
    #   mov eax, 0xAAAAAAAA
    #   pshufd xmm0, xmm0, 0          ; fill xmm0 with 0xAA bytes
    #   pxor xmm0, [rip + 0xbcc]      ; XOR with encrypted data at 0x4030
    #
    # This produces: "Enter password: " (15 printable chars + trailing space)

    print("[*] Step 2: Decrypting prompt string (SIMD XOR path)...")
    decrypted_prompt = xor_decrypt(encrypted_prompt, xor_key)
    # Strip trailing space/null
    prompt_str = decrypted_prompt.rstrip(b'\x00').rstrip()
    print(f"    Decrypted prompt: \"{prompt_str.decode('ascii')}\"")
    print()

    # ====================================================================
    # STEP 3: Decrypt the password string ("Yippie-Ki-Yay")
    # ====================================================================
    # The password is decrypted in the subroutine at 0x140001770:
    #   movzx edx, byte ptr [r8 + rax]
    #   xor   edx, 0xFFFFFFAA
    #   mov   byte ptr [rcx + rax], dl
    #   loop for 13 bytes
    #
    # Before the XOR loop, the function also contains a DEAD CODE hash
    # chain (anti-analysis obfuscation) that is computed but never used:
    #   val = 0x1337
    #   val ^= 0x12345678
    #   val -= 0x65432110
    #   val = (val * 8) ^ (val >> 5)
    #   val ^= 0x35014541
    #   val *= 129
    #   val ^= (val >> 11)
    # This hash value is stored on the stack but never read again.

    print("[*] Step 3: Decrypting password string (byte-by-byte XOR)...")
    decrypted_password = xor_decrypt(encrypted_password, xor_key)
    password_str = decrypted_password.rstrip(b'\x00').decode('ascii')
    print(f"    Decrypted password: \"{password_str}\"")
    print()

    # ====================================================================
    # STEP 4: Verify the anti-analysis dead code hash chain
    # ====================================================================
    # This complex hash computation in the decrypt function is pure
    # obfuscation - the result is never used for anything.

    print("[*] Step 4: Tracing the dead-code hash chain (anti-analysis)...")

    val = 0x1337
    print(f"    Initial seed:     0x{val:08X}")

    val = ctypes.c_uint32(val ^ 0x12345678).value
    print(f"    After XOR 0x12345678: 0x{val:08X}")

    val = ctypes.c_uint32(val - 0x65432110).value
    print(f"    After SUB 0x65432110: 0x{val:08X}")

    edx = ctypes.c_uint32(val * 8).value
    eax_s = ctypes.c_uint32(val >> 5).value
    val = edx ^ eax_s
    print(f"    After hash mix 1:  0x{val:08X}")

    val ^= 0x35014541
    print(f"    After XOR 0x35014541: 0x{val:08X}")

    val = ctypes.c_uint32(val * 129).value
    print(f"    After *129:        0x{val:08X}")

    eax_s = ctypes.c_uint32(val >> 11).value
    val = val ^ eax_s
    print(f"    After hash mix 2:  0x{val:08X}")
    print(f"    >> This value is computed but NEVER used (dead code)")
    print()

    # ====================================================================
    # STEP 5: Reconstruct the success/failure messages
    # ====================================================================
    # The binary constructs output messages from XOR'd word values:
    #   movzx edx, word [0x140004020]  ; edx = 0xC1C5
    #   movzx ebx, word [0x14000401E]  ; ebx = 0xC5C4
    #   movzx eax, word [0x140005058]  ; eax = 0xAAAA (XOR key)
    #   xor edx, eax  -> 0xC1C5 ^ 0xAAAA = 0x6B6F -> "ok"
    #   xor eax, ebx  -> 0xAAAA ^ 0xC5C4 = 0x6F6E -> "no"

    print("[*] Step 5: Reconstructing obfuscated status messages...")
    msg_edx = 0xC1C5
    msg_ebx = 0xC5C4
    msg_eax = 0xAAAA

    success_msg_word = msg_edx ^ msg_eax
    failure_msg_word = msg_eax ^ msg_ebx

    # Words are stored in little-endian byte order
    success_msg = struct.pack('<H', success_msg_word).decode('ascii')
    failure_msg = struct.pack('<H', failure_msg_word).decode('ascii')
    print(f"    Success message: \"{success_msg}\"")
    print(f"    Failure message: \"{failure_msg}\"")
    print()

    # ====================================================================
    # RESULT
    # ====================================================================
    print("=" * 60)
    print(f"  PASSWORD: {password_str}")
    print("=" * 60)
    print()
    print("The binary's complete validation logic:")
    print(f"  1. Print \"{prompt_str.decode('ascii')}\"")
    print(f"  2. Read user input (max 63 chars via scanf \"%63s\")")
    print(f"  3. Decrypt internal password via XOR 0xAA")
    print(f"  4. Compare: strcmp(input, \"{password_str}\")")
    print(f"  5. If match -> print \"{success_msg}\", else -> print \"{failure_msg}\"")
    print()
    print("Obfuscation techniques identified:")
    print("  - XOR string encryption (key: 0xAA)")
    print("  - SSE2 SIMD pxor for prompt decryption")
    print("  - Dead-code hash chain as anti-analysis distraction")
    print("  - Dynamic DLL loading via TLS callback")
    print("  - Indirect API calls through IAT jumps")
    print("  - XOR-obfuscated success/failure message words")
    print()


if __name__ == "__main__":
    main()
