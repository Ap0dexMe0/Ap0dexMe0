#!/usr/bin/env python3
"""
POC for CTF challenge: a.out reverse engineering
===============================================

This script solves the CTF challenge by statically analyzing the obfuscated
ELF binary and extracting the correct password.

The binary is a compiled Brainfuck program with heavy obfuscation layers:
  - XOR operations with 0xDEADBEEF
  - usleep(0) timing delays
  - getpid() + sign checks (always passes on normal systems)
  - write(2, buf, 0) no-op syscalls
  - Dummy loops that add 0 to a junk variable
  - Pointer shuffling through temporary stack variables
  - 160KB+ main function to obscure the logic

The underlying Brainfuck program:
  1. Sets cell[0] = 1 (match flag)
  2. Reads 8 characters into cell[1] one at a time
  3. For each character, subtracts a specific value
  4. If the result is zero (character matches), the match flag stays 1
  5. If non-zero, loops zero out both the character cell and the flag
  6. After all 8 characters, if the flag is still set, outputs success message
"""

import re
import sys
import subprocess
import os


def extract_bf_operations(disasm_lines):
    """
    Parse x86-64 disassembly and extract Brainfuck-like operations,
    filtering out obfuscation noise.
    
    Key variable mappings:
      -0x7540(%rbp) = buffer (30000 bytes, zeroed by memset)
      -0x88b0(%rbp) = ptr (pointer into buffer)
      -0x88a8(%rbp) = aux (junk variable, written but never read meaningfully)
    
    Obfuscation patterns (ignored):
      - usleep(0) calls
      - getpid() + test + jns (getpid always returns positive)
      - XOR with 0xDEADBEEF (result goes to junk variable)
      - write(2, buf, 0) no-op writes
      - Dummy loops: counter=0; while(counter<=0){aux+=counter;counter++}
      - Pointer copying through temp variables (ptr -> temp -> ptr)
      - Null pointer wrap-around checks
    """
    instructions = []
    for line in disasm_lines:
        line = line.strip()
        m = re.match(r'^\s*([0-9a-f]+):\s+(.+)$', line)
        if m:
            addr = int(m.group(1), 16)
            instr = m.group(2).strip()
            instructions.append((addr, instr))
    
    # Build address-to-index map
    addr_to_idx = {}
    for idx, (addr, _) in enumerate(instructions):
        addr_to_idx[addr] = idx
    
    # Find all loop end addresses (test %al,%al; jne backward)
    # These are BF ']' operations
    loop_body_addrs = set()
    loop_ends = []
    for i, (addr, instr) in enumerate(instructions):
        if 'test   %al,%al' in instr:
            if i + 1 < len(instructions):
                _, next_instr = instructions[i+1]
                jm = re.match(r'jne\s+([0-9a-f]+)', next_instr)
                if jm:
                    target = int(jm.group(1), 16)
                    if target < addr:  # backward jump = loop end
                        loop_ends.append({
                            'test_addr': addr,
                            'body_start': target,
                        })
                        # Mark all addresses in loop body
                        for a, _ in instructions:
                            if target <= a <= addr:
                                loop_body_addrs.add(a)
    
    # Find getchar addresses (BF ',' operations)
    getchar_addrs = []
    for addr, instr in instructions:
        if 'call   1080 <getchar@plt>' in instr:
            getchar_addrs.append(addr)
    
    return instructions, addr_to_idx, loop_body_addrs, getchar_addrs


def count_decrements_per_input(instructions, addr_to_idx, loop_body_addrs, getchar_addrs):
    """
    For each of the 8 input characters, count the number of decrement
    operations applied to the cell BEFORE any loop check.
    
    Since the loops are '[-]' (zero-out) patterns that only execute
    when the character doesn't match, the correct password character
    for each position is simply: chr(decrement_count)
    
    The logic: input_char - decrement_count = 0  =>  input_char = decrement_count
    """
    password_chars = []
    
    for i in range(len(getchar_addrs)):
        start_addr = getchar_addrs[i]
        end_addr = getchar_addrs[i + 1] if i + 1 < len(getchar_addrs) else 0x282d6
        
        # Count decrements outside loop bodies
        # (inside loops only execute on mismatch, so they don't affect the correct password)
        dec_count = 0
        
        for j, (addr, instr) in enumerate(instructions):
            if addr < start_addr or addr >= end_addr:
                continue
            if addr in loop_body_addrs:
                continue
            
            # Detect DEC_BYTE pattern: movzbl (%rax),%eax; lea -0x1(%rax),%edx; mov %dl,(%rax)
            if 'movzbl (%rax),%eax' in instr:
                for k in range(j + 1, min(j + 4, len(instructions))):
                    _, ni = instructions[k]
                    if 'lea    -0x1(%rax),%edx' in ni:
                        # Verify the store instruction follows
                        for m in range(k + 1, min(k + 4, len(instructions))):
                            _, si = instructions[m]
                            if 'mov    %dl,(%rax)' in si:
                                dec_count += 1
                                break
                        break
        
        char = chr(dec_count) if 32 <= dec_count < 127 else '?'
        password_chars.append(char)
        print(f"  Input {i+1}: {dec_count} decrements -> '{char}' (ASCII {dec_count})")
    
    return ''.join(password_chars)


def verify_password(binary_path, password):
    """Verify the password by running the binary and checking output."""
    try:
        proc = subprocess.Popen(
            [binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = proc.communicate(input=password.encode(), timeout=10)
        return out.decode(errors='replace'), err.decode(errors='replace')
    except subprocess.TimeoutExpired:
        proc.kill()
        return None, None


def main():
    binary_path = "/path/to/a.out"
    
    # Check if we have a pre-extracted disassembly, otherwise generate it
    disasm_path = "/path/to/main_disasm.txt"
    if not os.path.exists(disasm_path):
        print("[*] Extracting disassembly...")
        result = subprocess.run(
            ["objdump", "-d", binary_path, "-j", ".text",
             "--start-address=0x1199", "--no-show-raw-insn"],
            capture_output=True, text=True
        )
        with open(disasm_path, 'w') as f:
            f.write(result.stdout)
        disasm_lines = result.stdout.splitlines()
    else:
        with open(disasm_path, 'r') as f:
            disasm_lines = f.readlines()
    
    print("[*] Analyzing binary...")
    print(f"    Binary: {binary_path}")
    print(f"    Type: ELF 64-bit LSB PIE executable, x86-64")
    print(f"    Main function size: ~160KB (0x2713e bytes)")
    print()
    
    print("[*] Extracting Brainfuck operations from obfuscated x86-64...")
    instructions, addr_to_idx, loop_body_addrs, getchar_addrs = extract_bf_operations(disasm_lines)
    print(f"    Total instructions: {len(instructions)}")
    print(f"    Loop bodies detected: {len(set(a for a in loop_body_addrs))} addresses")
    print(f"    Input operations (getchar): {len(getchar_addrs)}")
    print()
    
    print("[*] Counting decrements per input character (excluding loop bodies)...")
    password = count_decrements_per_input(instructions, addr_to_idx, loop_body_addrs, getchar_addrs)
    print()
    
    print(f"[+] PASSWORD FOUND: \"{password}\"")
    print()
    
    # Verify
    print("[*] Verifying password against binary...")
    stdout, stderr = verify_password(binary_path, password)
    if stdout is not None:
        print(f"    stdout: {repr(stdout)}")
        print(f"    stderr: {repr(stderr)}")
        if stdout.strip():
            print(f"\n[+] SUCCESS! Program output: \"{stdout.strip()}\"")
        else:
            print("\n[-] No output received (password may be incorrect)")
    else:
        print("    Verification timed out")
    
    return password


if __name__ == "__main__":
    password = main()
    print(f"\n{'='*50}")
    print(f"Password: {password}")
    print(f"{'='*50}")
