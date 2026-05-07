#!/usr/bin/env python3
"""
KeygenMe_3_SWD.py

Proof-of-concept key generator for the KeygenMe_3_SWD challenge.

The recovered validation logic derives the expected key from the Windows
username:

    username -> SHA-256 hex digest -> filter digits -> map a-f into a-c

Usage:
    python KeygenMe_3_SWD.py <username>
    python KeygenMe_3_SWD.py --interactive
    python KeygenMe_3_SWD.py --demo
"""

from __future__ import annotations

import hashlib
import sys


def generate_key(username: str) -> tuple[str, str]:
    """Return (key, sha256_hex) for the supplied username."""
    digest = hashlib.sha256(username.encode("ascii")).hexdigest()
    key_chars: list[str] = []

    for char in digest:
        if char.isdigit():
            continue

        value = (ord(char) - ord("a")) // 2
        for digit in str(value):
            key_chars.append(chr(ord(digit) + 0x31))

    return "".join(key_chars), digest


def print_result(username: str) -> None:
    key, digest = generate_key(username)
    print("=" * 72)
    print("KeygenMe_3_SWD Key Generator")
    print("=" * 72)
    print(f"Username : {username}")
    print(f"SHA-256  : {digest}")
    print(f"Key      : {key}")
    print(f"Key Len  : {len(key)}")
    print("=" * 72)


def demo() -> None:
    for username in (
        "Admin",
        "Administrator",
        "User",
        "guest",
        "player",
        "Reverse101",
    ):
        print_result(username)
        print()


def interactive() -> None:
    print("KeygenMe_3_SWD interactive mode. Type 'quit' to exit.")
    while True:
        try:
            username = input("username> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not username:
            continue
        if username.lower() in {"q", "quit", "exit"}:
            return

        print_result(username)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: python KeygenMe_3_SWD.py <username>")
        print("       python KeygenMe_3_SWD.py --interactive")
        print("       python KeygenMe_3_SWD.py --demo")
        print()
        print("Default demo for username 'Admin':")
        print_result("Admin")
        return 0

    arg = argv[1]
    if arg in {"--interactive", "-i"}:
        interactive()
        return 0
    if arg in {"--demo", "-d"}:
        demo()
        return 0

    print_result(arg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
