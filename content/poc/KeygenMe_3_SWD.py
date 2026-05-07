#!/usr/bin/env python3
"""
KeygenMe_3_SWD — key generator (username + secret code + verification PIN).

Recovered from PE64 Ghidra decompilation of KeygenMe_3_SWD.exe:

  • Username: 3–15 chars (prompt loops until length in range).
  • Secret code: 14 chars, pattern ####-#####-### (hyphens at indices 4 and 10).
    Each segment is base-36 (0–9A–Z), validated by FUN_140001ec0 / FUN_140002100.
  • Verification PIN: decimal digits only, length < 11, value ≤ 0x7FFFFFFF.
    Checked by FUN_140002910 against a 32-bit mix of uppercase username + secret.

PIN equals the 31-bit hash from FUN_1400025a0 because FUN_1400028d0 applies

    ROL32(x ^ 0xA5A5A5A5, 7) + 0x3C6EF372

to both sides of the XOR equality, which forces equality of the raw hashes.

Usage:
    python KeygenMe_3_SWD.py <username>
    python KeygenMe_3_SWD.py --interactive
    python KeygenMe_3_SWD.py --demo
"""

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


def _mix_pin_transform(x: int) -> int:
    """FUN_1400028d0 — matches both PIN and FUN_1400025a0 output in the binary."""
    return _u32(_rol32(_u32(x ^ 0xA5A5A5A5), 7) + 0x3C6EF372)


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
    x = _u32(x * _u32(-2059196821))  # uint32(-0x7A143595)
    x = _u32(x ^ (x >> 13))
    x = _u32(x * _u32(-1027426187))  # uint32(-0x3D4D51CB)
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
    h = hash_username_secret(username, cred.secret_code)
    assert h == cred.verification_pin
    assert _mix_pin_transform(h) == _mix_pin_transform(cred.verification_pin)

    print("=" * 72)
    print("KeygenMe_3_SWD")
    print("=" * 72)
    print(f"Username         : {cred.username}")
    print(f"Secret code      : {cred.secret_code}")
    print(f"Verification PIN : {cred.pin_string()}")
    print("=" * 72)


def demo() -> None:
    for name in ("Admin", "player", "Reverse101", "guest", "USER"):
        print_bundle(name)
        print()


def interactive() -> None:
    print("Interactive mode. Type 'quit' to exit.")
    while True:
        try:
            raw = input("username> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not raw:
            continue
        if raw.lower() in {"q", "quit", "exit"}:
            return
        try:
            print_bundle(raw)
        except ValueError as exc:
            print(f"[!] {exc}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        print("Default demo username 'Admin':\n")
        print_bundle("Admin")
        return 0

    arg = argv[1]
    if arg in {"--interactive", "-i"}:
        interactive()
        return 0
    if arg in {"--demo", "-d"}:
        demo()
        return 0

    print_bundle(arg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
