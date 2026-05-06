#!/usr/bin/env python3
"""
=============================================================================
  "Almost" (AI - Almost Impossible) - Reverse Engineering PoC & Solver
=============================================================================

Binary: almost (ELF 64-bit LSB PIE executable, x86-64, stripped)
Challenge: Understand validation logic and find the correct QR code input.

Author: Reverse Engineering Analysis
=============================================================================
"""

import ecdsa
import struct
import sys
import os
import hashlib

# =============================================================================
# SECTION 1: Cryptographic Primitives (extracted from binary)
# =============================================================================

def splitmix64(seed: int) -> int:
    """
    SplitMix64 PRNG - extracted from binary at address 0x7b2a.

    Assembly reconstruction:
        rax = 0x9e3779b97f4a7c15 (golden ratio constant)
        rax += rdi (seed)
        rdi = rax
        rdi >>= 30; rdi ^= rax
        rdi *= 0xbf58476d1ce4e5b9
        rdx = rdi; rdx >>= 27; rdx ^= rdi
        rdx *= 0x94d049bb133111eb
        rax = rdx; rax >>= 31; rax ^= rdx
        ret
    """
    seed = (seed + 0x9e3779b97f4a7c15) & 0xFFFFFFFFFFFFFFFF
    z = seed
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & 0xFFFFFFFFFFFFFFFF
    z = (z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF
    return z


def xor_decrypt(data: bytes, key32: int) -> bytes:
    """
    XOR stream cipher - extracted from binary at 0x89ad and 0x8a9c.

    Algorithm:
    1. Compute seed = (uint32_t)key32 ^ 0xa6f1d249e13b7c55
    2. Initial state = splitmix64(seed) [stepping stone, not directly used]
    3. For each byte index i:
       - If i % 8 == 0: state = splitmix64(state + i + 1)
       - key_byte = (state >> ((i % 8) * 8)) & 0xFF
       - output[i] = data[i] ^ key_byte
    """
    MAGIC_XOR = 0xa6f1d249e13b7c55
    seed = (key32 & 0xFFFFFFFF) ^ MAGIC_XOR
    state = splitmix64(seed)  # Initial stepping stone

    result = bytearray(len(data))
    for i in range(len(data)):
        if i % 8 == 0:
            state = splitmix64(state + i + 1)
        key_byte = (state >> ((i % 8) * 8)) & 0xFF
        result[i] = data[i] ^ key_byte
    return bytes(result)


# =============================================================================
# SECTION 2: EC Operations (replicating binary behavior)
# =============================================================================

# Binary uses EC_GROUP_new_by_curve_name(0x2CA) = secp256k1 (NID 714)
CURVE_NID = 714  # 0x2CA
CURVE = ecdsa.SECP256k1
G = CURVE.generator
ORDER = CURVE.order

# Validation constraints extracted from binary:
# RAND_bytes(4 bytes) → AND 0xFFFFFF → OR 0x1000000
SCALAR_MIN = 0x1000000       # 16777216
SCALAR_MAX = 0x1FFFFFF       # 33554431
SCALAR_RANGE = SCALAR_MAX - SCALAR_MIN + 1  # 16777216 (~16.7M)

# XOR masks for key derivation (from addresses 0x9a64 and 0x9b64)
KEY_MASK_ECPOINT = 0x13579BDF   # Used to derive encryption key for EC point
KEY_MASK_FLAG   = 0x2468ACE1    # Used to derive encryption key for flag


def scalar_to_compressed_point(scalar: int) -> bytes:
    """Compute compressed EC point from scalar on secp256k1."""
    sk = ecdsa.SigningKey.from_secret_exponent(scalar, curve=CURVE)
    vk = sk.get_verifying_key()
    return vk.to_string("compressed")


def point_add(p1, p2):
    """Add two EC points on secp256k1."""
    return p1 + p2


def scalar_mult(scalar: int):
    """Compute scalar * G on secp256k1, return EC point object."""
    return scalar * G


# =============================================================================
# SECTION 3: Target Generation (simulating binary at 0x6a40-0x6dce)
# =============================================================================

def generate_target(random_scalar=None):
    """
    Simulates the binary's target generation at startup.

    Flow (extracted from binary):
    1. RAND_bytes(&buf, 4)        @ 0x6a76
    2. scalar = buf & 0xFFFFFF    @ 0x6ad7
    3. scalar |= 0x1000000        @ 0x6adc
    4. EC_GROUP_new_by_curve_name(0x2CA)  @ 0x6b5b
    5. EC_GROUP_set_asn1_flag(group, 1)   @ 0x6bbc
    6. BN_new + BN_set_word(scalar)       @ 0x6c19, 0x6c70
    7. EC_POINT_mul(group, P, scalar, NULL, NULL, ctx)  @ 0x7de9
    8. EC_POINT_point2oct(group, P, 2, buf, len, ctx)   @ 0x6d32

    Returns: (scalar, compressed_point, encrypted_point, encrypted_flag_bytes)
    """
    if random_scalar is None:
        import random
        random_scalar = random.randint(SCALAR_MIN, SCALAR_MAX)

    assert SCALAR_MIN <= random_scalar <= SCALAR_MAX

    # Step 7: Compute P = scalar * G
    compressed_point = scalar_to_compressed_point(random_scalar)

    # Step 8: Export as compressed point (already done above)
    # The binary also does a second point2oct with a pre-allocated buffer

    return random_scalar, compressed_point


def encrypt_target(compressed_point: bytes, flag: bytes, scalar: int):
    """
    Encrypts the compressed EC point and flag using the scalar-derived keys.

    Two encryption operations:
    1. encrypt_point = xor_decrypt(compressed_point, scalar ^ KEY_MASK_ECPOINT)
    2. encrypt_flag   = xor_decrypt(flag, scalar ^ KEY_MASK_FLAG)
    """
    key_ec = scalar ^ KEY_MASK_ECPOINT
    key_flag = scalar ^ KEY_MASK_FLAG

    enc_point = xor_decrypt(compressed_point, key_ec)
    enc_flag = xor_decrypt(flag, key_flag)

    return enc_point, enc_flag


# =============================================================================
# SECTION 4: Verification (replicating binary at 0x9900-0x9c2c)
# =============================================================================

def verify(scalar: int, hex_flag: str, enc_point: bytes, enc_flag: bytes) -> tuple:
    """
    Replicates the complete verification logic from the binary.

    Binary verification flow (0x9900-0x9c2c):
    1. BN_dec2bn(&bn, qr_decimal_string)   @ 0x995f
    2. EC_POINT_mul(group, Q, bn, ...)     @ 0x7de9 (via 0x999d)
    3. EC_POINT_point2oct(group, Q, ...)    @ 0x6d32 (via 0x999d)
    4. Parse hex string from QR as bytes    @ 0x9a6a
    5. xor_decrypt(enc_point, scalar ^ 0x13579bdf) → decrypted_point  @ 0x9a64-0x9a6a
    6. EC_POINT_oct2point(group, R, decrypted_point)   @ 0x9adc
    7. EC_POINT_cmp(group, Q, R) == 0      @ 0x9b44 → Check 1
    8. xor_decrypt(enc_flag, scalar ^ 0x2468ace1) → decrypted_flag   @ 0x9b64-0x9b6a
    9. memcmp(decrypted_flag, hex_bytes)    @ 0x9b87-0x9bad → Check 2
    10. Both checks pass → "Access granted."  @ 0x9cc6

    Returns: (success: bool, message: str, decrypted_flag: bytes)
    """
    # Validate scalar range
    if not (SCALAR_MIN <= scalar <= SCALAR_MAX):
        return False, f"Scalar {scalar} out of range [{SCALAR_MIN}, {SCALAR_MAX}]", b""

    # Check 1: EC Point comparison
    # Compute Q = scalar * G
    computed_point = scalar_to_compressed_point(scalar)

    # Decrypt the target's encrypted EC point
    key_ec = scalar ^ KEY_MASK_ECPOINT
    decrypted_point = xor_decrypt(enc_point, key_ec)

    # Compare: this is the equivalent of EC_POINT_cmp
    if computed_point != decrypted_point:
        return False, "EC_POINT_cmp failed: points do not match", b""

    # Check 2: Flag comparison
    key_flag = scalar ^ KEY_MASK_FLAG
    decrypted_flag = xor_decrypt(enc_flag, key_flag)

    expected_flag = bytes.fromhex(hex_flag)
    if decrypted_flag != expected_flag:
        return False, f"Flag mismatch: expected {expected_flag.hex()}, got {decrypted_flag.hex()}", decrypted_flag

    return True, "Access granted!", decrypted_flag


# =============================================================================
# SECTION 5: Brute-Force Attack (exploiting small 25-bit key space)
# =============================================================================

def brute_force_scalar(target_compressed_point: bytes) -> int:
    """
    Brute forces the scalar by computing k*G for all k in [SCALAR_MIN, SCALAR_MAX]
    and comparing with the target compressed point.

    Since the scalar is only 25 bits (~16.7M values), this is feasible.
    Uses baby-step giant-step optimization potential, but simple brute force
    is fast enough for this range.

    Returns: The scalar value, or None if not found.
    """
    from ecdsa.ellipticcurve import Point, INFINITY

    # Parse target point
    target_vk = ecdsa.VerifyingKey.from_string(target_compressed_point, curve=CURVE)
    target_pt = target_vk.pubkey.point

    print(f"[*] Target compressed point: {target_compressed_point.hex()}")
    print(f"[*] Searching scalar range: 0x{SCALAR_MIN:08x} - 0x{SCALAR_MAX:08x}")
    print(f"[*] Total search space: {SCALAR_RANGE:,} values")

    # Start from SCALAR_MIN * G
    current = scalar_mult(SCALAR_MIN)

    for offset in range(SCALAR_RANGE):
        if offset % 2000000 == 0:
            pct = 100 * offset // SCALAR_RANGE
            current_scalar = SCALAR_MIN + offset
            print(f"    [{pct:3d}%] Testing scalar 0x{current_scalar:08x} ({current_scalar})...")

        if current.x() == target_pt.x() and current.y() == target_pt.y():
            found_scalar = SCALAR_MIN + offset
            print(f"\n[+] FOUND SCALAR: {found_scalar} (0x{found_scalar:08x})")
            return found_scalar

        current = point_add(current, G)

    print("[-] Scalar not found in range!")
    return None


# =============================================================================
# SECTION 6: PoC QR Code Generation
# =============================================================================

def generate_qr_payload(scalar: int, flag_bytes: bytes) -> str:
    """
    Generates the QR code payload in the format expected by the binary:
    <decimal_scalar>:<16_hex_characters>

    Format validation (from binary at 0x9561-0x96c5):
    - Split by ':' (memchr with 0x3A)
    - Part before ':': must be all digits 0-9 (checked at 0x9866)
    - Part before ':': parsed as decimal, must be 0x1000000-0x1FFFFFF
    - Part after ':': must be exactly 16 hex chars [0-9A-F] (checked at 0x96aa)
    """
    hex_flag = flag_bytes.hex().upper()
    assert len(hex_flag) == 16, f"Flag must be 8 bytes (16 hex chars), got {len(hex_flag)}"
    return f"{scalar}:{hex_flag}"


def generate_poc_png_qr(payload: str, output_path: str):
    """
    Generates a PNG image containing a QR code with the given payload.
    This creates the "artifact" that the binary will validate.

    Requires: qrcode, Pillow packages
    """
    try:
        import qrcode
        from PIL import Image
    except ImportError:
        print("[!] Installing qrcode and Pillow packages...")
        os.system("pip install qrcode[pil] Pillow -q")
        import qrcode
        from PIL import Image

    print(f"[*] Generating QR code with payload: {payload}")
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)
    print(f"[+] QR code PNG saved to: {output_path}")
    return output_path


# =============================================================================
# SECTION 7: Full Attack Pipeline
# =============================================================================

def full_attack_demo():
    """
    Demonstrates the complete attack pipeline:
    1. Generate a target (simulating binary startup)
    2. Encrypt target data
    3. Brute-force the scalar from the compressed EC point
    4. Decrypt the flag
    5. Generate the PoC QR code PNG
    """
    print("=" * 70)
    print("  'Almost' Binary - Complete Attack Pipeline")
    print("=" * 70)

    # --- Step 1: Generate target ---
    print("\n[STEP 1] Generate Target")
    print("-" * 70)
    FLAG = b"ALMOST_W"  # 8 bytes for 16 hex chars
    scalar, compressed_point = generate_target(random_scalar=0x1ABCDEF)
    print(f"    Scalar:       {scalar} (0x{scalar:08x})")
    print(f"    EC Point:     {compressed_point.hex()}")

    # --- Step 2: Encrypt target data ---
    print("\n[STEP 2] Encrypt Target Data")
    print("-" * 70)
    enc_point, enc_flag = encrypt_target(compressed_point, FLAG, scalar)
    print(f"    Enc Point:    {enc_point.hex()}")
    print(f"    Enc Flag:     {enc_flag.hex()}")

    # --- Step 3: Brute-force scalar ---
    print("\n[STEP 3] Brute-Force Scalar from EC Point")
    print("-" * 70)
    found_scalar = brute_force_scalar(compressed_point)
    assert found_scalar == scalar, f"Mismatch: found {found_scalar}, expected {scalar}"
    print(f"    [+] Confirmed: brute-forced scalar matches original!")

    # --- Step 4: Decrypt flag ---
    print("\n[STEP 4] Decrypt Flag")
    print("-" * 70)
    key_flag = found_scalar ^ KEY_MASK_FLAG
    decrypted_flag = xor_decrypt(enc_flag, key_flag)
    print(f"    Decrypted:    {decrypted_flag}")
    print(f"    As string:    {decrypted_flag.decode('ascii', errors='replace')}")
    print(f"    As hex:       {decrypted_flag.hex().upper()}")
    assert decrypted_flag == FLAG

    # --- Step 5: Verify ---
    print("\n[STEP 5] Verify Complete Solution")
    print("-" * 70)
    hex_flag_str = FLAG.hex().upper()
    success, msg, _ = verify(found_scalar, hex_flag_str, enc_point, enc_flag)
    print(f"    Verification: {msg}")

    # --- Step 6: Generate PoC ---
    print("\n[STEP 6] Generate PoC QR Code")
    print("-" * 70)
    payload = generate_qr_payload(found_scalar, FLAG)
    print(f"    QR Payload:   {payload}")
    poc_path = "/home/z/my-project/download/poc_artifact.png"
    generate_poc_png_qr(payload, poc_path)

    # --- Summary ---
    print("\n" + "=" * 70)
    print("  ATTACK SUMMARY")
    print("=" * 70)
    print(f"  Curve:           secp256k1 (NID 714)")
    print(f"  Scalar:          {found_scalar} (0x{found_scalar:08x})")
    print(f"  Flag:            {decrypted_flag.decode('ascii', errors='replace')}")
    print(f"  QR Payload:      {payload}")
    print(f"  PoC Artifact:    {poc_path}")
    print(f"  Time to Brute:   ~seconds (16.7M EC ops)")
    print("=" * 70)

    return found_scalar, decrypted_flag, payload


# =============================================================================
# SECTION 8: Standalone Solver (given intercepted data)
# =============================================================================

def solve_from_intercepted_data(compressed_point_hex: str, encrypted_flag_hex: str):
    """
    Given intercepted data from the binary (e.g., from its GUI display):
    - compressed_point_hex: hex string of the target compressed EC point
    - encrypted_flag_hex: hex string of the encrypted flag bytes

    This function brute-forces the scalar, decrypts the flag,
    and generates the PoC QR code.
    """
    print("=" * 70)
    print("  Solver - From Intercepted Data")
    print("=" * 70)

    compressed_point = bytes.fromhex(compressed_point_hex)
    enc_flag = bytes.fromhex(encrypted_flag_hex)

    # We need both the encrypted EC point AND encrypted flag
    # For this, we would also need the encrypted point (from the binary's display)
    # Here we show how to brute-force given the compressed point

    found_scalar = brute_force_scalar(compressed_point)
    if found_scalar is None:
        print("[-] Failed to find scalar!")
        return None

    # Decrypt the flag
    key_flag = found_scalar ^ KEY_MASK_FLAG
    decrypted_flag = xor_decrypt(enc_flag, key_flag)
    print(f"\n[+] Decrypted flag: {decrypted_flag.decode('ascii', errors='replace')}")
    print(f"[+] Flag hex:       {decrypted_flag.hex().upper()}")

    # Generate PoC
    payload = generate_qr_payload(found_scalar, decrypted_flag)
    poc_path = "/home/z/my-project/download/poc_artifact.png"
    generate_poc_png_qr(payload, poc_path)

    return found_scalar, decrypted_flag, payload


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "solve":
        # Solver mode: provide hex data
        if len(sys.argv) != 4:
            print(f"Usage: {sys.argv[0]} solve <compressed_point_hex> <encrypted_flag_hex>")
            print(f"Example: {sys.argv[0]} solve 02abc...123 def456...")
            sys.exit(1)
        solve_from_intercepted_data(sys.argv[2], sys.argv[3])
    else:
        # Demo mode
        full_attack_demo()
