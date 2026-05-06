#!/usr/bin/env python3
"""
TenzoCrackme.exe – Solver / Proof of Concept
=============================================

Statically recovers the password by reversing the verification routine.
No execution of the binary is required. Anti-debug checks are sidestepped
because we never run the program under a debugger.

Run:
    python3 solve_tenzo.py

Expected output:
    Password: wowyoufoundit
    All checks pass.
"""

from __future__ import annotations

import struct


# ---------------------------------------------------------------------------
# String decoder used throughout main() to decrypt prompts/messages.
# Reverse-engineered from the function at 0x140002eb0.
#
# Recurrence (per byte i):
#   out[i] = ((i * 13) + key_i) ^ src[i]
#   key_{i+1} = (3 * key_i + 0x11) mod 256        ; key_0 = 0x5A
#
# The "(i * 13)" term comes from `imul r14d, eax, 0xd`, where `eax` is loaded
# from a stack slot that holds the loop counter (the original code overwrote
# `al` with the counter via `mov rax, [rsp+0x90]` right before jumping back
# to the loop top, so at iteration i, al = i).
# ---------------------------------------------------------------------------
def decode_string(src: bytes) -> bytes:
    out = bytearray()
    key = 0x5A
    for i, b in enumerate(src):
        v = ((i * 13) + key) & 0xFF
        out.append(v ^ b)
        key = (3 * key + 0x11) & 0xFF
    return bytes(out)


# ---------------------------------------------------------------------------
# Encoded strings, copied as little-endian dwords/words/bytes from main().
# Each blob is built up by a series of `mov [rbp+disp], imm` instructions.
# ---------------------------------------------------------------------------
ENCODED_STRINGS: dict[str, bytes] = {
    "title": (
        struct.pack("<I", 0xD6A81167) + struct.pack("<I", 0xA1BED633)
        + struct.pack("<I", 0xFBF287F2) + struct.pack("<I", 0x83D13BAD)
        + struct.pack("<H", 0x616A) + bytes([0x45])
    ),
    "prompt": (
        struct.pack("<I", 0xE7FC421F) + struct.pack("<I", 0xAFB49824)
        + struct.pack("<I", 0xF5F7B7A1) + struct.pack("<I", 0xC68634BC)
    ),
    "success": (
        struct.pack("<I", 0xE5E64319) + struct.pack("<I", 0xBDB0D924)
        + struct.pack("<I", 0xF9C1E4F3) + struct.pack("<I", 0x95CF35AD)
        + struct.pack("<I", 0xD30A3B6A) + struct.pack("<I", 0x9AD19C28)
        + struct.pack("<I", 0xA529D4EC) + struct.pack("<I", 0x79CAA0CB)
        + struct.pack("<I", 0xC20CE24F) + struct.pack("<I", 0x0EC17042)
        + struct.pack("<I", 0x92074DC0) + struct.pack("<I", 0x27EC90DA)
        + struct.pack("<I", 0x7D2FCF59) + struct.pack("<H", 0x2C54)
        + bytes([0xBA])
    ),
    "failure": (
        struct.pack("<I", 0xE7F84314) + struct.pack("<I", 0xA6909878)
        + struct.pack("<I", 0xEAA0B0B3) + struct.pack("<I", 0x91CF23AF)
        + struct.pack("<I", 0x921C2E25) + struct.pack("<I", 0x89949B2F)
        + struct.pack("<I", 0xAD1E9BB0) + bytes([0x90])
    ),
    "antidebug": (
        struct.pack("<I", 0xF7EA491E) + struct.pack("<I", 0xBCA1DF31)
        + struct.pack("<I", 0xEEE5A0F2) + struct.pack("<I", 0x83C833AB)
        + struct.pack("<I", 0xF158722E) + struct.pack("<I", 0xDED18529)
        + struct.pack("<I", 0xA11395A0) + struct.pack("<I", 0x62C5F79E)
        + struct.pack("<I", 0x961DE352) + struct.pack("<I", 0x4FD66C16)
        + struct.pack("<I", 0x94094ADB) + struct.pack("<I", 0x2EEB90C9)
        + struct.pack("<I", 0x6134D94F) + bytes([0x08])
    ),
}


# ---------------------------------------------------------------------------
# Per-byte check (located at 0x140004106 – 0x1400041B6 in main).
#
# A small dispatch state machine iterates 13 times. On each iteration i:
#
#     t  = input[i] ^ table1[i]
#     t  = (t + ((i + 3) * 0x11)) & 0xFF
#     t  = ror8(t, 5)
#     t ^= (0xA5 - i * 7) & 0xFF
#     t ^= table2[i]
#     accumulator |= t            ; r9b in the binary
#
# After all 13 rounds, the accumulator must be 0 — meaning every round must
# produce 0. Because the relation is invertible, this uniquely determines
# every byte of the password.
# ---------------------------------------------------------------------------
TABLE1 = (
    struct.pack("<I", 0x87654321) + struct.pack("<I", 0x4F3D2B19)
    + struct.pack("<I", 0x84736251) + bytes([0x95])
)
TABLE2 = (
    struct.pack("<I", 0xB3AC1DE9) + struct.pack("<I", 0x22DCB5E6)
    + struct.pack("<I", 0x86F8A093) + bytes([0x56])
)
assert len(TABLE1) == 13 and len(TABLE2) == 13


def ror8(x: int, n: int) -> int:
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF


def rol8(x: int, n: int) -> int:
    return ror8(x, -n & 7)


def recover_password() -> bytes:
    """Invert the per-byte check directly. Returns 13 bytes."""
    pwd = bytearray(13)
    for i in range(13):
        # We need: ror8(z, 5) ^ ((0xA5 - 7*i) & 0xFF) ^ table2[i] == 0
        # so   z = rol8(((0xA5 - 7*i) & 0xFF) ^ table2[i], 5)
        # and  input[i] ^ table1[i] = (z - (i + 3)*0x11) & 0xFF
        rhs = ((0xA5 - 7 * i) & 0xFF) ^ TABLE2[i]
        z = rol8(rhs, 5)
        pwd[i] = ((z - (i + 3) * 0x11) & 0xFF) ^ TABLE1[i]
    return bytes(pwd)


# ---------------------------------------------------------------------------
# Verification stage 2: function at 0x140003920.
#
# Stage layout:
#   * Phase 1: 13 rounds. For each input byte, mix it into state1[i & 3] and
#              then self-mix state1[(i+1) & 3].
#   * Phase 2: 24 rounds of state1/state2 cross-mixing (no input involvement).
#   * Final  : compute hash_final(input) (fn at 0x140003670), distribute it
#              into state1 via four different rotations, and demand equality
#              with a fixed 4-dword target.
#
# Required result: state1 == TARGET_STATE  after the whole procedure.
# ---------------------------------------------------------------------------
TARGET_STATE = (0x8C6B0B39, 0xA7F1FE86, 0x9F811A0A, 0xC86DA593)
PHASE1_INIT_STATE1 = (0x13572468, 0x89ABCDEF, 0x10203040, 0x55667788)
PHASE2_INIT_STATE2 = (0xA5C31F27, 0xC3D2E1F0, 0x1BADC0DE, 0x0F1E2D3C)


def rol32(x: int, n: int) -> int:
    n &= 31
    if n == 0:
        return x & 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def ror32(x: int, n: int) -> int:
    n &= 31
    if n == 0:
        return x & 0xFFFFFFFF
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def hash_final(s: bytes) -> int:
    """Function at 0x140003670 — produces a 32-bit hash of the input."""
    r10 = 0xC001D00D
    for i, b in enumerate(s):
        # cl = i mod 5  (computed via the divide-by-10 idiom + *5)
        d = ((i * 0xCCCCCCCCCCCCCCCD) >> 64) >> 2     # i // 10
        d_low = d & 0xFF
        dl_const = (d_low + ((d_low << 2) & 0xFF)) & 0xFF
        cl = ((i & 0xFF) - dl_const + 3) & 0xFF
        edx = (b * 0x45D9F3B) & 0xFFFFFFFF
        edx = rol32(edx, cl)
        edx ^= r10
        ecx = (i * 0x1021) & 0xFFFFFFFF
        r10 = edx
        edx = (edx + 0x9E3779B9) & 0xFFFFFFFF
        r10 = ror32(r10, 7)
        edx = (edx + ecx) & 0xFFFFFFFF
        r10 ^= edx
    return r10


def verify_full(s: bytes) -> bool:
    """Faithful simulation of the function at 0x140003920."""
    if len(s) != 13:
        return False

    state1 = list(PHASE1_INIT_STATE1)

    # --- Phase 1: 13 rounds, each round mixes input[i] into state1 -------
    for i in range(13):
        # mix step (case 0x23 at 0x1400039D1)
        r9 = i & 3
        d = ((i * 0xCCCCCCCCCCCCCCCD) >> 64) >> 2
        d_low = d & 0xFF
        dl_const = (d_low + ((d_low << 2) & 0xFF)) & 0xFF
        cl = ((i & 0xFF) - dl_const + 3) & 0xFF
        edx = s[i] ^ state1[r9]
        eax = ((i * 0x45D9F3B) & 0xFFFFFFFF) ^ 0x9E3779B9
        edx = rol32((edx + eax) & 0xFFFFFFFF, cl)
        state1[r9] = edx

        # self-mix step (case 0x34 at 0x1400039A1)
        ecx = (i * 0x1021) & 0xFFFFFFFF
        ecx = (ecx + ((state1[i & 3] + 0x7F4A7C15) & 0xFFFFFFFF)) & 0xFFFFFFFF
        state1[(i + 1) & 3] = (state1[(i + 1) & 3] ^ ecx) & 0xFFFFFFFF

    # --- Phase 2: 24 rounds of state-only cross-mixing -------------------
    state2 = list(PHASE2_INIT_STATE2)
    r11 = 0
    for r10 in range(0x18):
        # branch B (case 0x92 at 0x140003AE8): r10 // 7 idiom
        r9 = r10 & 3
        d7 = (r10 * 0x24924925) >> 32
        v = (((r10 - d7) >> 1) + d7) >> 2
        cl = ((r10 & 0xFF) - ((v & 0xFF) * 7)) & 0xFF
        idx = (r9 + 1) & 3
        edx = state1[idx]
        edx = (edx ^ state2[r9]) & 0xFFFFFFFF
        edx = (edx + r11) & 0xFFFFFFFF
        edx = (edx + state1[r9]) & 0xFFFFFFFF
        state1[r9] = rol32(edx, (cl + 5) & 0xFF)

        # branch A (case 0xA3 at 0x140003A9A): r10 // 10 idiom
        d = ((r10 * 0xCCCCCCCD) >> 32) >> 2
        d_low = d & 0xFF
        dl_const = (d_low + ((d_low << 2) & 0xFF)) & 0xFF
        cl = ((r10 & 0xFF) - dl_const + 3) & 0xFF
        idx_p1 = (r9 + 1) & 3
        edx = (state2[idx_p1] + state1[r9]) & 0xFFFFFFFF
        edx = ror32(edx, cl)
        state1[idx_p1] = (state1[idx_p1] ^ edx) & 0xFFFFFFFF

        r11 = (r11 + 0x1F123BB5) & 0xFFFFFFFF

    # --- Final: combine hash_final(s) into state1 and compare ------------
    h = hash_final(s)
    state1[0] = (state1[0] ^ ror32(h, 0x1D)) & 0xFFFFFFFF
    state1[1] = (state1[1] + ror32(h, 0x15)) & 0xFFFFFFFF
    state1[2] = (state1[2] ^ ror32(h, 0x07)) & 0xFFFFFFFF
    state1[3] = (state1[3] + ror32(h, 0x0D)) & 0xFFFFFFFF

    return tuple(state1) == TARGET_STATE


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def main() -> None:
    print("=== TenzoCrackme.exe — Solver ===\n")

    print("Decoded strings (sanity check on the cipher model):")
    for name, blob in ENCODED_STRINGS.items():
        print(f"  {name:10s} {decode_string(blob)!r}")
    print()

    pwd = recover_password()
    print(f"Recovered password : {pwd.decode('ascii')!r}")
    print(f"Length             : {len(pwd)}")
    print()

    print("Re-running every check against the candidate:")

    # Length check
    length_ok = (len(pwd) == 13)
    print(f"  [1] length == 13               -> {length_ok}")

    # Per-byte check
    acc = 0
    for i in range(13):
        t = pwd[i] ^ TABLE1[i]
        t = (t + ((i + 3) * 0x11)) & 0xFF
        t = ror8(t, 5)
        t ^= (0xA5 - i * 7) & 0xFF
        t ^= TABLE2[i]
        acc |= t
    bytewise_ok = (acc == 0)
    print(f"  [2] per-byte accumulator == 0  -> {bytewise_ok}")

    # Full state check
    state_ok = verify_full(pwd)
    print(f"  [3] full state == target       -> {state_ok}")

    print()
    if length_ok and bytewise_ok and state_ok:
        print(f"SUCCESS — password is: {pwd.decode('ascii')}")
    else:
        print("FAIL — solver did not converge.")


if __name__ == "__main__":
    main()
