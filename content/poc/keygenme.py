#!/usr/bin/env python3
"""
================================================================================
  KeyGenMe.exe - KeyGen (Proof of Concept)
  CTF Reverse Engineering Challenge
================================================================================

Description:
  This script generates valid "Identity Keys" for the KeyGenMe.exe challenge.
  The binary is a PE32+ x86-64 Windows console application that prompts the
  user for an "Identity Key" and validates it against a dynamically computed
  value derived from the current Windows username.

Algorithm (Reconstructed from Reverse Engineering):
  1. The program calls GetUserNameA() to retrieve the current Windows username.
  2. It computes SHA-256(username) producing a 64-character lowercase hex digest.
  3. Each character of the hex digest is processed:
     - Digit characters ('0'-'9') are SKIPPED (discarded).
     - Hex letter characters ('a'-'f') are transformed:
       a) val = floor( (ord(c) - ord('a')) / 2 )  [integer division]
       b) Convert val to its decimal string representation.
       c) For EACH digit character in that decimal string:
          new_char = chr( ord(digit) + 0x31 )
       d) Append each new_char to the output key string.
  4. The user's input is compared (length + memcmp) against the generated key.

Hex Letter Mapping:
  'a' -> val=0 -> "0" -> 'a'     'b' -> val=0 -> "0" -> 'a'
  'c' -> val=1 -> "1" -> 'b'     'd' -> val=1 -> "1" -> 'b'
  'e' -> val=2 -> "2" -> 'c'     'f' -> val=2 -> "2" -> 'c'

Key Findings from Binary Analysis:
  - Standard SHA-256 implementation verified (H0-H7 and K[0..63] match spec).
  - GetUserNameA imported from ADVAPI32.dll for dynamic username retrieval.
  - IsDebuggerPresent imported (anti-debug, but not fatal).
  - Compiled with MSVC (PDB: CrackMe.pdb), statically linked CRT.
  - The ostringstream hex formatting uses std::hex with std::setw(2) and
    std::setfill('0') to produce zero-padded 2-digit lowercase hex per byte.
  - Key comparison uses memcmp with prior length check.

Usage:
  python keygenme_keygen.py <username>     Generate key for given username
  python keygenme_keygen.py --interactive  Interactive prompt mode
  python keygenme_keygen.py --demo         Demo with common usernames

Author: CTF Solver
================================================================================
"""

import hashlib
import sys
import os


def generate_key(username: str) -> tuple[str, str]:
    """
    Generate the correct Identity Key for a given username.

    Args:
        username: The Windows username (as returned by GetUserNameA).

    Returns:
        A tuple of (key, sha256_hex_digest).
    """
    # Step 1: Compute SHA-256 of the username
    sha256_hex = hashlib.sha256(username.encode('ascii')).hexdigest()

    # Step 2: Process each character of the hex digest
    key_chars = []
    for c in sha256_hex:
        # Skip digit characters (0-9)
        if c.isdigit():
            continue

        # Process hex letter (a-f only, since output is lowercase hex)
        val = (ord(c) - ord('a')) // 2

        # Convert integer to decimal string, then transform each digit
        for digit_char in str(val):
            key_chars.append(chr(ord(digit_char) + 0x31))

    return ''.join(key_chars), sha256_hex


def print_separator(char='=', width=80):
    print(char * width)


def demo_mode():
    """Demonstrate the KeyGen with common Windows usernames."""
    print_separator()
    print("  KeyGenMe.exe - KeyGen Proof of Concept (Demo Mode)")
    print_separator()
    print()

    test_usernames = [
        "Admin",
        "Administrator",
        "User",
        "test",
        "root",
        "guest",
        "John",
        "player",
        "DESKTOP-ABC",
        "WorkPC",
    ]

    for username in test_usernames:
        key, sha256_hex = generate_key(username)
        print(f"  Username : {username}")
        print(f"  SHA-256  : {sha256_hex}")
        print(f"  Key      : {key}")
        print(f"  Key Len  : {len(key)}")
        print()


def interactive_mode():
    """Run the KeyGen in interactive mode."""
    print_separator()
    print("  KeyGenMe.exe - Interactive KeyGen")
    print("  Enter a username to generate the corresponding Identity Key.")
    print("  Press Ctrl+C or type 'quit' to exit.")
    print_separator()
    print()

    while True:
        try:
            username = input("  Enter username> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  Goodbye!")
            break

        if not username:
            continue
        if username.lower() in ('quit', 'exit', 'q'):
            print("\n  Goodbye!")
            break

        key, sha256_hex = generate_key(username)
        print(f"  SHA-256  : {sha256_hex}")
        print(f"  Key      : {key}")
        print()


def show_algorithm():
    """Display the algorithm explanation."""
    print_separator()
    print("  Algorithm Explanation")
    print_separator()
    print("""
  The KeyGenMe.exe binary computes a dynamic key based on the Windows username:

  1. Retrieve username via GetUserNameA() API call.
  2. Compute SHA-256 hash of the username (standard FIPS 180-4).
  3. Convert the 32-byte hash to a 64-character lowercase hex string.
  4. Filter and transform the hex string:
     - REMOVE all digit characters ('0' through '9')
     - For each remaining hex letter, compute a mapped value:
         c = 'a' or 'b' -> 0 -> appends 'a'
         c = 'c' or 'd' -> 1 -> appends 'b'
         c = 'e' or 'f' -> 2 -> appends 'c'
     - The mapping is: floor((ASCII(c) - ASCII('a')) / 2) -> str(val)
       then each digit of str(val) has 0x31 added to its ASCII code.
  5. Compare the result against user input (exact length + byte comparison).

  This means the key is purely deterministic given the username - it is a
  mathematical function of SHA-256(username) with a specific character-level
  transformation applied to the hex digest.
""")


def main():
    if len(sys.argv) < 2:
        print("  Usage: python keygenme_keygen.py <username>")
        print("         python keygenme_keygen.py --interactive")
        print("         python keygenme_keygen.py --demo")
        print("         python keygenme_keygen.py --algorithm")
        print()
        print("  Generating key for 'Admin' as default...")
        print()
        key, sha256_hex = generate_key("Admin")
        print(f"  Username : Admin")
        print(f"  SHA-256  : {sha256_hex}")
        print(f"  Key      : {key}")
        print()
        return

    arg = sys.argv[1]

    if arg in ('--interactive', '-i'):
        interactive_mode()
    elif arg in ('--demo', '-d'):
        demo_mode()
    elif arg in ('--algorithm', '-a'):
        show_algorithm()
    else:
        # Generate key for the given username
        username = arg
        key, sha256_hex = generate_key(username)
        print_separator()
        print("  KeyGenMe.exe - KeyGen")
        print_separator()
        print(f"  Username : {username}")
        print(f"  SHA-256  : {sha256_hex}")
        print(f"  Key      : {key}")
        print(f"  Key Len  : {len(key)}")
        print_separator()


if __name__ == '__main__':
    main()
