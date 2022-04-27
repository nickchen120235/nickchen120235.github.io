---
layout: post
title: Reversing with GDB - picoCTF easy as GDB
tags: [CTF, reverse]
---
> The flag has got to be checked somewhere... File: [brute](https://mercury.picoctf.net/static/84a60a8ccee38ac906f28075221fa2e6/brute)

## Ghidra
This is a PIE binary, so first we have to find the main funtion.

Starting from `entry`
```c
void entry(void)

{
  __libc_start_main(FUN_000109af);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
There's the main function
```c
undefined4 main(void)

{
  char *input;
  size_t target_len;
  undefined4 input_with_magic;
  int iVar1;
  
  input = (char *)calloc(0x200,1);
  printf("input the flag: ");
  fgets(input,0x200,stdin);
  target_len = strnlen(&DAT_00012008,0x200);
  input_with_magic = FUN_0001082b(input,target_len);
  FUN_000107c2(input_with_magic,target_len,1);
  iVar1 = check(input_with_magic,target_len);
  if (iVar1 == 1) {
    puts("Correct!");
  }
  else {
    puts("Incorrect.");
  }
  return 0;
}
```
`FUN_0001082b`, `FUN_000107c2` are some manipulation functions, and I don't want to reversing the mechanism behind them. Instead I'll see what check is done in `check`.
```c
undefined4 check(char *input,uint target_len)

{
  char *__dest;
  char *__dest_00;
  uint correct_len;
  
  __dest = (char *)calloc(target_len + 1,1);
  strncpy(__dest,input,target_len);
  FUN_000107c2(__dest,target_len,0xffffffff);
  __dest_00 = (char *)calloc(target_len + 1,1);
  strncpy(__dest_00,&DAT_00012008,target_len);
  FUN_000107c2(__dest_00,target_len,0xffffffff);
  puts("checking solution...");
  correct_len = 0;
  while( true ) {
    if (target_len <= correct_len) {
      return 1;
    }
    if (__dest[correct_len] != __dest_00[correct_len]) break;
    correct_len = correct_len + 1;
  }
  return 0xffffffff;
}
```
So if `correct_len` is equal or greater than `target_len`, we have the correct input. Therefore, we can use gdb to check the value of `correct_len` during runtime.

## GDB with PIE binary
Follow these steps to analyze a PIE binary:
1. Load the file into gdb and `starti` to load the binary into memory.
  > starti: Start the debugged program stopping at the first instruction.

    ```
    ───────────────────────────────────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "brute", stopped 0xf7fe2510 in _start (), reason: STOPPED
    ─────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
    [#0] 0xf7fe2510 → _start()
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
    gef➤ 
    ```
2. Use `info file` to find the after-start entry point.
    ```
    gef➤  info file
    Symbols from "/home/nick/coding/ctf/reverse/easy-as-gdb/brute".
    Native process:
            Using the running image of child process 27597.
            While running this, GDB does not access memory from...
    Local exec file:
            `/home/nick/coding/ctf/reverse/easy-as-gdb/brute', file type elf32-i386.
            Entry point: 0x56555580
            ...
    ```
3. Break at the entry point. The program should stop at the `entry` function we see in Ghidra. `$eip` minus the address of `entry` in Ghidra is the base address of the program.
    ```
    $eip   : 0x56555580  →   xor ebp, ebp
    "entry" is at 0x10580, so the base address is at 0x56555580 - 0x10580 = 0x56545000
    ```
4. To analyze any function/instruction, use the offset shown in Ghidra plus the base address, and set a breakpoint at it.

## Attack
Let's break before `check` returns, which is at offset `0x109a7`. So if we have one correct input, `correct_len` will increase by one. We break before `check` returns and examine the value of `correct_len`.
```
   0x5655599f                  mov    eax, DWORD PTR [ebp-0x14]
   0x565559a2                  cmp    eax, DWORD PTR [ebp+0xc]
   0x565559a5                  jb     0x56555978
 → 0x565559a7                  mov    eax, DWORD PTR [ebp-0x18]
   0x565559aa                  mov    ebx, DWORD PTR [ebp-0x4]
   0x565559ad                  leave  
   0x565559ae                  ret
```
`correct_len` is at `ebp-0x14`.

For example, if we use `a` as our input, `correct_len` is `0`.
```
gef➤  x $ebp-0x14
0xffffcb34:     0x00000000
```
But if we use `p` as our input, `correct_len` will be `1`.
```
gef➤  x $ebp-0x14
0xffffcb34:     0x00000001
```
My solution script guesses one character at a time. If `correct_len` is greater than the length of our current `flag`, we find a correct character.
```python
from pwn import *
import string
from tqdm import tqdm

valid_input = string.printable[:-6]

mygdb = process(['gdb', './brute'])
offset = 0x109a7 - 0x10580

mygdb.sendline(b'starti')
mygdb.sendline(b'info file')
mygdb.recvuntil(b'Entry point: ')
entry = mygdb.recvline().decode().strip()
log.info(f'Entry address: {entry}')
bp = hex(int(entry, 16)+offset).encode()
log.info(f'Breakpoint at: {bp.decode()}')
mygdb.sendline(b'break *' + bp)
mygdb.clean()

flag = ''
while '}' not in flag:
  for c in tqdm(valid_input):
    mygdb.sendline(b'run')
    mygdb.clean()
    mygdb.sendline((flag+c).encode())
    mygdb.clean()
    mygdb.sendline(b'x $ebp-0x14')
    try:
      count = int(mygdb.recvline().split()[1].decode(), 16)
      if count > len(flag):
        flag += c
        log.info(f'Current flag: {flag}')
        break
    except ValueError:
      log.warn(f'Error occurred during output parsing, current character: {c}')
      pass
```
Let it run and we get the flag.

## Reference
- [debugging - Set a breakpoint on GDB entry point for stripped PIE binaries without disabling ASLR - Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/questions/8724/set-a-breakpoint-on-gdb-entry-point-for-stripped-pie-binaries-without-disabling)
- [https://www.youtube.com/watch?v=KYWxsxOugu4](https://www.youtube.com/watch?v=KYWxsxOugu4)