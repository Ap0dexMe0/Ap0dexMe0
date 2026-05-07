#!/usr/bin/env python3
from __future__ import annotations

import sys
from dataclasses import dataclass


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _rol32(x: int, r: int) -> int:
    r &= 31
    x = _u32(x)
    return _u32((x << r) | (x >> (32 - r)))


def _ror32(x: int, r: int) -> int:
    r &= 31
    x = _u32(x)
    return _u32((x >> r) | (x << (32 - r)))


def _imul32(a: int, b: int) -> int:
    """Low 32 bits of signed multiply (matches MSVC x86 IMUL on DWORD operands)."""
    sa = _u32(a)
    sb = _u32(b)
    sa = sa - 0x100000000 if sa >= 0x80000000 else sa
    sb = sb - 0x100000000 if sb >= 0x80000000 else sb
    return _u32(sa * sb)


def hash_username_secret(username: str, secret_code: str) -> int:
    """
    FUN_1400025a0 — feeds FUN_140002910.

    Builds: UPPER(username) + chr(len(secret_code) ^ 0x5A) + secret_code,
    then runs the XOR/rotate mixing loop (odd indices swap the two accumulators).
    """
    blob = username.upper() + chr(len(secret_code) ^ 0x5A) + secret_code
    a = 0xA3B1C2D3
    b = 0x1F2E3D4C
    for i, c in enumerate(blob):
        o = ord(c)
        a = _u32(a ^ (o + i * 0x11))
        a = _rol32(a, (i % 5) + 3)
        a = _u32(a + (b ^ 0x9E3779B9))
        b = _u32(b ^ (a + o * 0x83))
        b = _ror32(b, (i % 7) + 2)
        b = _u32(b + _u32((a << 3) ^ 0x7F4A7C15))
        if i & 1:
            a, b = b, a

    x = _u32(a ^ b ^ _u32((a ^ b) >> 16))
    x = _imul32(x, (-0x7A143595) & 0xFFFFFFFF)
    x = _u32(x ^ (x >> 13))
    x = _imul32(x, (-0x3D4D51CB) & 0xFFFFFFFF)
    return _u32(x ^ (x >> 16)) & 0x7FFFFFFF


_BASE36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _encode_base36_fixed(value: int, width: int) -> str:
    if value == 0:
        return "0" * width
    digits: list[str] = []
    v = value
    while v:
        v, r = divmod(v, 36)
        digits.append(_BASE36[r])
    body = "".join(reversed(digits))
    return body.rjust(width, "0")[-width:]


def derive_secret_code(username: str) -> str:
    """
    FUN_140002100 — derive ####-#####-### from uppercase username statistics.

    local_104 = Σ ord(c) * (index + 1)
    local_100 = xor fold of (ord(c) + index)
    local_108 = Π (ord(c) + 3) mod 100_000, seeded with 1

    Segment targets:
      A = (local_104 ^ 0x5A5A) % 0xB640
      B = (local_108 + local_100 * 0x539) % 0x39AA400
      C = (local_104 + local_108 + local_100) % 0xB640
    """
    u = username.upper()
    local_104 = 0
    local_100 = 0
    local_108 = 1
    for i, ch in enumerate(u):
        o = ord(ch)
        local_104 += o * (i + 1)
        local_100 ^= o + i
        local_108 = (local_108 * (o + 3)) % 100_000

    a = (local_104 ^ 0x5A5A) % 0xB640
    b = (local_108 + local_100 * 0x539) % 0x39AA400
    c = (local_104 + local_108 + local_100) % 0xB640
    return f"{_encode_base36_fixed(a, 4)}-{_encode_base36_fixed(b, 5)}-{_encode_base36_fixed(c, 3)}"


def derive_verification_pin(username: str, secret_code: str) -> int:
    """PIN must equal FUN_1400025a0; FUN_140002910 XOR-check reduces to this equality."""
    return hash_username_secret(username, secret_code)


def validate_username(username: str) -> tuple[bool, str]:
    if not username.isascii():
        return False, "username must be ASCII"
    n = len(username)
    if not (3 <= n < 16):
        return False, "username length must be between 3 and 15 (inclusive)"
    return True, ""


@dataclass(frozen=True)
class Credentials:
    username: str
    secret_code: str
    verification_pin: int

    def pin_string(self) -> str:
        return str(self.verification_pin)


def generate(username: str) -> Credentials:
    ok, msg = validate_username(username)
    if not ok:
        raise ValueError(msg)
    secret = derive_secret_code(username)
    pin = derive_verification_pin(username, secret)
    if pin > 0x7FFFFFFF:
        raise ValueError("derived PIN exceeds binary limit (unexpected)")
    return Credentials(username=username, secret_code=secret, verification_pin=pin)


def print_bundle(username: str) -> None:
    cred = generate(username)

    print("=" * 72)
    print("KeygenMe_3_SWD")
    print("=" * 72)
    print(f"Username         : {cred.username}")
    print(f"Secret code      : {cred.secret_code}")
    print(f"Verification PIN : {cred.pin_string()}")
    print("=" * 72)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("Usage: python KeygenMe_3_SWD.py <username>\n")
        return 1

    try:
        print_bundle(argv[1])
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
