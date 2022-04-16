---
layout: post
title: My own password checker - picoCTF Rolling My Own
tags: [CTF, reverse]
---
> I don't trust password checkers made by other people, so I wrote my own. It doesn't even need to store the password! If you can crack it I'll give you a flag. [remote](https://mercury.picoctf.net/static/1b702a6eaf5123b544441f8a5fd03f01/remote) nc mercury.picoctf.net 57112
>
> Hint: It's based on this [paper](http://pages.cpsc.ucalgary.ca/~aycock/papers/eicar06-ad.pdf)
>
> Hint: Here's the start of the password: `D1v1`

## Overview
`checksec` ~~This is not a pwn challenge anyway.~~
```
❯ checksec remote
[*] '/home/nick/coding/ctf/reverse/rolling-my-own/remote'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Try running it
```
❯ ./remote
Password: 123456
[1]    28101 illegal hardware instruction (core dumped)  ./remote
❯ ./remote
Password: asdf
[1]    28111 segmentation fault (core dumped)  ./remote
```
It seems that the input has something to do with the control flow.

## Ghidra
There's no "`main`" function, but `entry` function normally does the same job. `FUN_00100b6a` seems to be the real "`main`" function, as the function call graph suggests.

{% include aligner.html images="posts/rolling-my-own/function-call-graph.png" column=1 %}

```c
/* WARNING: Could not reconcile some variable overlaps */

undefined8 FUN_00100b6a(void)

{
  size_t input_len;
  void *md5_result;
  undefined8 *run_ptr;
  long in_FS_OFFSET;
  int i;
  int j;
  int offset [4];
  undefined8 run;
  undefined8 local_d0;
  char salt [32];
  char input [65];
  char local_58 [72];
  long _stack_canary;
  
  _stack_canary = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  salt._0_8_ = 0x57456a4d614c7047;
  salt._8_8_ = 0x6b6d6e6e6a4f5670;
  salt._16_8_ = 0x367064656c694752;
  salt._24_8_ = 0x736c787a6563764d;
  offset[0] = 8;
  offset[1] = 2;
  offset[2] = 7;
  offset[3] = 1;
  memset(input + 1,0,0x40);
  memset(local_58,0,0x40);
  printf("Password: ");
  fgets(input + 1,0x40,stdin);
  input_len = strlen(input + 1);
  input[input_len] = '\0';
  for (i = 0; i < 4; i = i + 1) {
    strncat(local_58,input + (long)(i << 2) + 1,4);
    strncat(local_58,salt + (i << 3),8);
  }
  md5_result = malloc(0x40);
  input_len = strlen(local_58);
  md5(md5_result,local_58,input_len & 0xffffffff);
  for (i = 0; i < 4; i = i + 1) {
    for (j = 0; j < 4; j = j + 1) {
      *(undefined *)((long)&run + (long)(j * 4 + i)) =
           *(undefined *)((long)md5_result + (long)(offset[j] + j * 0x10 + i));
    }
  }
  run_ptr = (undefined8 *)mmap((void *)0x0,0x10,7,0x22,-1,0);
  *run_ptr = run;
  run_ptr[1] = local_d0;
  (*(code *)run_ptr)(print_flag);
  free(md5_result);
  if (_stack_canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
So according to the paper mentioned in the hint,
1. The key is appended with a salt value
2. The salted key is hashed using a hash function.
3. Part of the hash result is the shellcode to be run.

In this challenge,
1. Input is divided into 4-byte chunks, each chunk is appended with a salt value.
    - chunk 1 + `GpLaMjEW` (remember we are working on little endian)
    - chunk 2 + `pVOjnnmk`
    - chunk 3 + `RGiledp6`
    - chunk 4 + `Mvcezxls`
2. The salted chunks are hashed using `md5`.
3. Parts of the hash result are used to built the final shellcode, which the `print_flag` function will be the first parameter.
    - hashed 1 [8:12]
    - hashed 2 [2:6]
    - hashed 3 [7:11]
    - hashed 4 [1:5]

There are only 4 salt values so the input length is only 16 bytes.

> For example if the input is `abcdefghijklmnop`
> 1. The salted chunks are
>     - `abcdGpLaMjEW`
>     - `efghpVOjnnmk`
>     - `ijklRGiledp6`
>     - `mnopMvcezxls`
> 2. The `md5`'d results are
>     - `80d218041c09fb220678d00421adc0f3`
>     - `294a4535c9c11c6fcc63aa80ba932e68`
>     - `46b4be289b403a62cf6b58e2de420aaa`
>     - `02f5c347b5257bf71cf3625fd5b4d6d7`
> 3. The extracted shellcode are
>     - `0678d004`
>     - `4535c9c1`
>     - `62cf6b58`
>     - `f5c347b5`

Next we have to construct the shellcode. The first 4 bytes of the key is given, which can be converted to the first 4 bytes of the shellcode.
```
D1v1GpLaMjEW -> 23f144e08b603e724889fe489f78fa53 -> 4889fe48
0:  48 89 fe                mov    rsi,rdi
3:  48                      rex.W 
```
The second assembly should also be a `mov` instruction.

Also `print_flag` takes an argument which is compared within the function to determine whether or not to print the flag.
```c
void print_flag(long param_1)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 0x7b3dc26f1) {
    __stream = fopen("flag","r");
    if (__stream == (FILE *)0x0) {
      puts("Flag file not found. Contact an admin.");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    fgets(local_98,0x80,__stream);
    puts(local_98);
  }
  else {
    puts("Hmmmmmm... not quite");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
The x64 calling convention says that the first argument should be stored in `rdi`. The following is the target assembly
```
mov rsi, rdi /* given by hint, the address of print_flag is the argument, which is stored in rdi */
movabs rdi, 0x7b3dc26f1 /* prepare the argument */
call rsi /* call print_flag as the address is moved to rsi */
```
Which is assembled into
```
mov rsi, rdi -> 48 89 fe
movabs rdi, 0x7b3dc26f1 -> 48 bf f1 26 dc b3 07 00 00 00
call rsi -> ff d6
```
The target hashes are `4889fe48`, `bff126dc`, `b3070000`, `00ffd6`. The rest is to bruteforce the key out.
```python
from hashlib import md5
import string
from itertools import product
from tqdm import tqdm

valid_input = string.ascii_letters + string.digits

target = [
  ('GpLaMjEW', '4889fe48', 8),
  ('pVOjnnmk', 'bff126dc', 2),
  ('RGiledp6', 'b3070000', 7),
  ('Mvcezxls', '00ffd6', 1)
]

final = ''

for salt, hash_result, offset in target:
  for key in tqdm(product(valid_input, repeat=4)):
    shellcode = md5((''.join(key) + salt).encode('ascii')).hexdigest()
    if shellcode[(offset*2):].startswith(hash_result):
      print(''.join(key))
      final += ''.join(key)
      break

print(f"Key = {final}")
```
The key is `D1v1d3AndC0nqu3r`, netcat and get the flag.
```
❯ nc mercury.picoctf.net 57112
Password: D1v1d3AndC0nqu3r
picoCTF{r011ing_y0ur_0wn_crypt0_15_h4rd!_06746440}
```

## Reference
- [https://github.com/HHousen/PicoCTF-2021/tree/master/Reverse%20Engineering/Rolling%20My%20Own](https://github.com/HHousen/PicoCTF-2021/tree/master/Reverse%20Engineering/Rolling%20My%20Own)
- [https://tsalvia.hatenablog.com/entry/2021/04/08/110000#Rolling-My-Own---300-points](https://tsalvia.hatenablog.com/entry/2021/04/08/110000#Rolling-My-Own---300-points)