---
layout: post
title: Timing side channel analysis - picoCTF checkpass
tags: [CTF, reverse]
---
> What is the password? File: [checkpass](https://mercury.picoctf.net/static/f9620d2398e030be834cfa10fb8e971a/checkpass) Flag format: `picoCTF{...}`

## Ghidra
We're given a rust binary. Decompile it using Ghidra. There are some rust wrapper before the real main function. ~~It looks like a mess:~~
```c
/* WARNING: Removing unreachable block (ram,0x0010659a) */
/* WARNING: Removing unreachable block (ram,0x0010656c) */
/* WARNING: Removing unreachable block (ram,0x0010653e) */
/* WARNING: Removing unreachable block (ram,0x00106510) */
/* WARNING: Removing unreachable block (ram,0x001064e2) */
/* WARNING: Removing unreachable block (ram,0x001064b4) */
/* WARNING: Removing unreachable block (ram,0x00106486) */
/* WARNING: Removing unreachable block (ram,0x00106458) */
/* WARNING: Removing unreachable block (ram,0x0010642a) */
/* WARNING: Removing unreachable block (ram,0x001063fc) */
/* WARNING: Removing unreachable block (ram,0x001063ce) */
/* WARNING: Removing unreachable block (ram,0x001063a0) */
/* WARNING: Removing unreachable block (ram,0x00106372) */
/* WARNING: Removing unreachable block (ram,0x00106344) */
/* WARNING: Removing unreachable block (ram,0x00106316) */
/* WARNING: Removing unreachable block (ram,0x001062ff) */
/* WARNING: Removing unreachable block (ram,0x0010632d) */
/* WARNING: Removing unreachable block (ram,0x0010635b) */
/* WARNING: Removing unreachable block (ram,0x00106389) */
/* WARNING: Removing unreachable block (ram,0x001063b7) */
/* WARNING: Removing unreachable block (ram,0x001063e5) */
/* WARNING: Removing unreachable block (ram,0x00106413) */
/* WARNING: Removing unreachable block (ram,0x00106441) */
/* WARNING: Removing unreachable block (ram,0x0010646f) */
/* WARNING: Removing unreachable block (ram,0x0010649d) */
/* WARNING: Removing unreachable block (ram,0x001064cb) */
/* WARNING: Removing unreachable block (ram,0x001064f9) */
/* WARNING: Removing unreachable block (ram,0x00106527) */
/* WARNING: Removing unreachable block (ram,0x00106555) */
/* WARNING: Removing unreachable block (ram,0x00106583) */
/* WARNING: Removing unreachable block (ram,0x001065b1) */
/* WARNING: Removing unreachable block (ram,0x001062de) */

void FUN_00105960(void)

{
  long *plVar1;
  undefined4 *puVar2;
  long *plVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined **local_128;
  undefined8 uStack288;
  undefined8 local_118;
  undefined4 uStack272;
  undefined4 uStack268;
  long *local_108;
  undefined8 local_100;
  char local_f5;
  char local_f2;
  char local_f1;
  char local_f0;
  char local_ef;
  char local_ee;
  char local_ed;
  char local_ec;
  char local_eb;
  char local_ea;
  char local_e9;
  char local_e8;
  char local_e7;
  char local_e6;
  char local_e5;
  char local_e4;
  char local_e3;
  char local_e2;
  char local_e1;
  char local_e0;
  char local_df;
  char local_de;
  char local_dd;
  char local_dc;
  char local_db;
  char local_da;
  char local_d9;
  char local_d8;
  char local_d7;
  char local_d6;
  char local_d5;
  char local_d4;
  char local_d3;
  char local_d2;
  char local_d1;
  char local_d0;
  char local_cf;
  char local_ce;
  char local_cd;
  char local_cc;
  char local_cb;
  char local_ca;
  char local_c9;
  char local_c8;
  char local_c7;
  char local_c6;
  char local_c5;
  char local_c4;
  char local_c3;
  char local_c2;
  char local_c1;
  undefined8 *local_c0;
  undefined4 local_b8;
  undefined4 uStack180;
  long lStack176;
  long local_a8;
  code *pcStack160;
  undefined4 uStack144;
  undefined4 uStack140;
  long local_88 [2];
  long local_78;
  undefined local_70 [24];
  undefined4 uStack88;
  undefined4 uStack84;
  undefined local_50 [24];
  undefined4 uStack56;
  undefined4 uStack52;
  
  local_108 = &local_a8;
  FUN_0011f000(local_108);
  uStack272 = uStack144;
  uStack268 = uStack140;
  FUN_00106a00(local_88,&local_128);
  if (local_78 == 2) {
    if (*(long *)(local_88[0] + 0x28) == 0x29) {
      plVar3 = *(long **)(local_88[0] + 0x18);
      if (((plVar3 == (long *)&DAT_00139d78) || (*plVar3 == 0x7b4654436f636970)) &&
         ((plVar1 = plVar3 + 5, plVar1 == (long *)&DAT_00139d94 || (*(char *)plVar1 == '}')))) {
        if (*(char *)(plVar3 + 1) < -0x40) {
          FUN_00134220(plVar3,0x29,8,0x29,&PTR_s_src/main.rs_00348260);
        }
        else if (*(char *)plVar1 < -0x40) {
          FUN_00134220(plVar3 + 1,0x21,0,0x20,&PTR_s_src/main.rs_00348260);
        }
        else {
          local_c0 = (undefined8 *)thunk_FUN_0011ac90(0x20,1);
          if (local_c0 == (undefined8 *)0x0) {
            FUN_00132f80(0x20,1);
            do {
              invalidInstructionException();
            } while( true );
          }
          local_b8 = 0x20;
          uStack180 = 0;
          lStack176 = 0;
                    /* try { // try from 00105b2a to 00105b3a has its CatchHandler @ 001065c8 */
          FUN_00106720(&local_c0,0,0x20);
          uVar4 = *(undefined4 *)(plVar3 + 1);
          uVar5 = *(undefined4 *)((long)plVar3 + 0xc);
          uVar6 = *(undefined4 *)(plVar3 + 2);
          uVar7 = *(undefined4 *)((long)plVar3 + 0x14);
          uVar8 = *(undefined4 *)((long)plVar3 + 0x1c);
          uVar9 = *(undefined4 *)(plVar3 + 4);
          uVar10 = *(undefined4 *)((long)plVar3 + 0x24);
          puVar2 = (undefined4 *)((long)local_c0 + lStack176 + 0x10);
          *puVar2 = *(undefined4 *)(plVar3 + 3);
          puVar2[1] = uVar8;
          puVar2[2] = uVar9;
          puVar2[3] = uVar10;
          puVar2 = (undefined4 *)((long)local_c0 + lStack176);
          *puVar2 = uVar4;
          puVar2[1] = uVar5;
          puVar2[2] = uVar6;
          puVar2[3] = uVar7;
          if (lStack176 == 0) {
            local_128 = (undefined **)*local_c0;
            uStack288 = local_c0[1];
            local_118 = local_c0[2];
            uStack272 = *(undefined4 *)(local_c0 + 3);
            uStack268 = *(undefined4 *)((long)local_c0 + 0x1c);
                    /* try { // try from 00105b77 to 001065c2 has its CatchHandler @ 001065d7 */
            lStack176 = lStack176 + 0x20;
            FUN_001054e0(local_70,&local_128,0);
            uStack272 = uStack88;
            uStack268 = uStack84;
            FUN_001054e0(local_50,&local_128,1);
            uStack272 = uStack56;
            uStack268 = uStack52;
            FUN_001054e0(&local_a8,&local_128,2);
            uStack272 = uStack144;
            uStack268 = uStack140;
            FUN_001054e0(&local_e0,&local_128,3);
            local_e9 = local_dd;
            local_e3 = local_dc;
            local_ec = local_db;
            local_e1 = local_da;
            local_f0 = local_d9;
            local_e7 = local_d8;
            local_e2 = local_d6;
            local_ee = local_d5;
            local_e5 = local_d3;
            local_f1 = local_d1;
            local_ed = local_d0;
            local_e6 = local_cf;
            local_e4 = local_ce;
            local_ea = local_cc;
            local_eb = local_cb;
            local_ef = local_ca;
            local_e8 = local_c4;
            local_f2 = local_c2;
            local_128 = (undefined **)0x19;
            local_f5 = local_de;
            if ((((((local_c7 == -0x1a) && (local_128 = (undefined **)0x0, local_e0 == '\x1f')) &&
                  (local_128 = (undefined **)0xe, local_d2 == -0x3f)) &&
                 ((local_128 = (undefined **)0x13, local_cd == ':' &&
                  (local_128 = (undefined **)0x17, local_c9 == -0x62)))) &&
                ((((local_128 = (undefined **)0x1, local_df == '+' &&
                   ((local_128 = (undefined **)0x1d, local_c3 == '\x01' &&
                    (local_128 = (undefined **)0x1b, local_c5 == -0x62)))) &&
                  ((local_128 = (undefined **)0x1a, local_c6 == 'w' &&
                   (((((local_128 = (undefined **)0xc, local_d4 == -0x52 &&
                       (local_128 = (undefined **)0x1f, local_c1 == '{')) &&
                      (local_128 = (undefined **)0x6, local_da == ':')) &&
                     ((local_128 = (undefined **)0xa, local_d6 == -0x52 &&
                      (local_128 = (undefined **)0xf, local_d1 == 'H')))) &&
                    (local_128 = (undefined **)0x1e, local_c2 == 'z')))))) &&
                 (((((local_128 = (undefined **)0x7, local_d9 == -0x35 &&
                     (local_128 = (undefined **)0xb, local_d5 == -0x35)) &&
                    ((local_128 = (undefined **)0x5, local_db == '\"' &&
                     (((local_128 = (undefined **)0x16, local_ca == 'F' &&
                       (local_128 = (undefined **)0x10, local_d0 == '\x05')) &&
                      (local_128 = (undefined **)0x15, local_cb == -0x48)))))) &&
                   ((local_128 = (undefined **)0x3, local_dd == 'F' &&
                    (local_128 = (undefined **)0x14, local_cc == -0x33)))) &&
                  (local_128 = (undefined **)0x8, local_d8 == -0x44)))))) &&
               ((((local_128 = (undefined **)0x1c, local_c4 == -0x59 &&
                  (local_128 = (undefined **)0xd, local_d3 == ' ')) &&
                 ((local_128 = (undefined **)0x11, local_cf == '{' &&
                  (((local_128 = (undefined **)0x2, local_de == 'P' &&
                    (local_128 = (undefined **)0x9, local_d7 == 'z')) &&
                   (local_128 = (undefined **)0x4, local_dc == -0x48)))))) &&
                ((local_128 = (undefined **)0x18, local_c8 == -0x31 &&
                 (local_128 = (undefined **)0x12, local_ce == '{')))))) {
              FUN_001066a0();
            }
            else {
              FUN_00106650();
            }
          }
          else {
            lStack176 = lStack176 + 0x20;
            FUN_00106600();
          }
        }
      }
      else {
        FUN_00106650();
      }
    }
    else {
      FUN_00106600();
    }
  }
  else if (local_78 == 0) {
                    /* try { // try from 00105a53 to 00105b16 has its CatchHandler @ 001065e6 */
    FUN_001356a0(0,0,&PTR_s_src/main.rs_00348248);
  }
  else {
    local_a8 = local_88[0];
    pcStack160 = FUN_001054c0;
    local_128 = &PTR_DAT_00348228;
    uStack288 = 2;
    local_118 = 0;
    local_100 = 1;
    FUN_001083b0(&local_128);
    FUN_0011f1d0(1);
  }
  do {
    invalidInstructionException();
  } while( true );
}
```
Let's find some printables instead. There are `Invalid length`, `Invalid password`, `Success`, `picoCTF{`. So the program checks the input length and THEN the actual input. Also it checks if the password is in the form of `picoCTF{}`, as shown here
```c
if (((plVar3 == (long *)&DAT_00139d78) || (*plVar3 == 0x7b4654436f636970)) &&
   ((plVar1 = plVar3 + 5, plVar1 == (long *)&DAT_00139d94 || (*(char *)plVar1 == '}')))) {
```

But by viewing the disassembled part of the large `if`s, it seems that the flag is checked by cascading `if`s because of the continuous pattern of `MOV CMP JA LEA CMP JNZ`. This could attacked by timing side channel analysis if we don't want to reverse-engineer the whole process.

## Timing Side Channel Analysis
Side-channeling means that instead of directly analyzing the target, we use some other information like power consumption (which could be used to break AES), or in this case, code execution time. Consider a string comparison is implemented like this
```python
def string_compare(s1, s2):
  if len(s1) != len(s2): return False
  
  for x, y in zip(s1, s2):
    if x != y: return False

  return True
```
In the above function, we first compare the two strings' lengths and then compare the individual characters if they are of equal length. While iterating over the loop, if we encounter two different characters, we return false. If we do not find any difference, we return true. It seems to be a reasonable implementation for string comparison, but is it?

Let's assume it is used for a password comparison, which the correct password is 48571243. Instead of bruteforcing like `00000000`, `00000001`, ..., the attacker could guess like `00000000`, `10000000`. When he hits the first character, the program will execute slightly longer because the loop advances. This reduces the number of possible matches from 10^8 to only 10*8 since attacker knows that what he tried is correct during each iteration.

To fix the problem, we should make each loop run for a fixed amount of time. We could use a flag variable to same the current state of comparison.
```python
def string_compare(s1, s2):
  if len(s1) != len(s2): return False
  
  flag = True
  for x, y in zip(s1, s2):
    if x != y: flag = False

  return flag
```

## Attack
We're using [valgrind](https://valgrind.org/) to analyze the execution of the binary. There's a module called `cachegrind`, which
> simulates how your program interacts with a machine's cache hierarchy and (optionally) branch predictor. It simulates a machine with independent first-level instruction and data caches (I1 and D1), backed by a unified second-level cache (L2). This exactly matches the configuration of many modern machines.

Cachegrind gathers some statistics each run, one of them is the "`I` cache reads", which equals the number of instructions executed. So if one input has a greater number of execution than another, we may have guessed a correct character.

The following is my solution script. Each iteration contains two round. The first round looks for a possible character by write the same character at each unknown spot and see if the result is better than before. If we find one, the second round looks for the correct position of the character and updates the global best value so far.
```python
from pwn import *
import string

VALGRIND_BIN = '/home/nick/coding/ctf/tools/valgrind/bin/valgrind'
valid_input = string.printable[:-6]
context.log_level = 'error'

def sca(password: str) -> int:
  print(password)
  valgrind = process([VALGRIND_BIN, '--tool=cachegrind', '--cachegrind-out-file=/dev/null', './checkpass', 'picoCTF{' + password + '}'])
  valgrind.recvuntil(b'I   refs:')
  valgrind.close()
  return int(valgrind.recvline().decode('ascii').strip(' \n').replace(',', ''))

flag = '~' * 32
current_best = 0
found_pairs: list[tuple[str, int]] = []
while any([x == '~' for x in flag]):
  # stage 1: find possible character
  print('Stage 1: find possible character')
  current_character = ''
  for c in valid_input:
    guess = c * 32
    # replace placeholder characters with found characters
    guess = list(guess)
    for char, idx in found_pairs:
      guess[idx] = char
    guess = ''.join(guess)
    # guess!
    sca_res = sca(guess)
    assert sca_res >= current_best
    # print(sca_res)
    if current_best == 0:
      current_best = sca_res
      continue
    if sca_res > current_best:
      current_character = c
      break
  assert current_character != ''
  print(f'Best guess: {current_character}')

  # stage 2: find the correct position
  print('Stage 2: find the correct position')
  for i in range(len(flag)):
    # print(f'Currently trying: {i}')
    sca_res = sca(flag[:i] + current_character + flag[i+1:])
    # print(sca_res)
    if sca_res > current_best:
      current_best = sca_res # only update current_best if the position is correct
      found_pairs.append((current_character, i))
      print(f'Best guess: {current_character} at {i}')
      # put the found character into the flag
      flag = list(flag)
      flag[i] = current_character
      flag = ''.join(flag)
      break
  print(f'\nCurrent flag: {flag}, refs = {current_best}\n')
  print('==== End of round ====\n')
```
It takes a while because execution is a lot slower when using `valgrind`. When it finishes, we get the flag.
```
...
Stage 1: find possible character
0000n000000h00000_00Q0f0xl30P0GQ
1111n111111h11111_11Q1f1xl31P1GQ
2222n222222h22222_22Q2f2xl32P2GQ
3333n333333h33333_33Q3f3xl33P3GQ
Best guess: 3
Stage 2: find the correct position
3~~~n~~~~~~h~~~~~_~~Q~f~xl3~P~GQ
~3~~n~~~~~~h~~~~~_~~Q~f~xl3~P~GQ
~~3~n~~~~~~h~~~~~_~~Q~f~xl3~P~GQ
~~~3n~~~~~~h~~~~~_~~Q~f~xl3~P~GQ
~~~~3~~~~~~h~~~~~_~~Q~f~xl3~P~GQ
~~~~n3~~~~~h~~~~~_~~Q~f~xl3~P~GQ
~~~~n~3~~~~h~~~~~_~~Q~f~xl3~P~GQ
~~~~n~~3~~~h~~~~~_~~Q~f~xl3~P~GQ
~~~~n~~~3~~h~~~~~_~~Q~f~xl3~P~GQ
~~~~n~~~~3~h~~~~~_~~Q~f~xl3~P~GQ
~~~~n~~~~~3h~~~~~_~~Q~f~xl3~P~GQ
~~~~n~~~~~~3~~~~~_~~Q~f~xl3~P~GQ
~~~~n~~~~~~h3~~~~_~~Q~f~xl3~P~GQ
~~~~n~~~~~~h~3~~~_~~Q~f~xl3~P~GQ
~~~~n~~~~~~h~~3~~_~~Q~f~xl3~P~GQ
~~~~n~~~~~~h~~~3~_~~Q~f~xl3~P~GQ
Best guess: 3 at 15

Current flag: ~~~~n~~~~~~h~~~3~_~~Q~f~xl3~P~GQ, refs = 490589

==== End of round ====
...
Stage 1: find possible character
t1mingS1deCha0n3l_gVQSfJxl3VPFGQ
t1mingS1deCha1n3l_gVQSfJxl3VPFGQ
t1mingS1deCha2n3l_gVQSfJxl3VPFGQ
t1mingS1deCha3n3l_gVQSfJxl3VPFGQ
t1mingS1deCha4n3l_gVQSfJxl3VPFGQ
t1mingS1deCha5n3l_gVQSfJxl3VPFGQ
t1mingS1deCha6n3l_gVQSfJxl3VPFGQ
t1mingS1deCha7n3l_gVQSfJxl3VPFGQ
t1mingS1deCha8n3l_gVQSfJxl3VPFGQ
t1mingS1deCha9n3l_gVQSfJxl3VPFGQ
t1mingS1deChaan3l_gVQSfJxl3VPFGQ
t1mingS1deChabn3l_gVQSfJxl3VPFGQ
t1mingS1deChacn3l_gVQSfJxl3VPFGQ
t1mingS1deChadn3l_gVQSfJxl3VPFGQ
t1mingS1deChaen3l_gVQSfJxl3VPFGQ
t1mingS1deChafn3l_gVQSfJxl3VPFGQ
t1mingS1deChagn3l_gVQSfJxl3VPFGQ
t1mingS1deChahn3l_gVQSfJxl3VPFGQ
t1mingS1deChain3l_gVQSfJxl3VPFGQ
t1mingS1deChajn3l_gVQSfJxl3VPFGQ
t1mingS1deChakn3l_gVQSfJxl3VPFGQ
t1mingS1deChaln3l_gVQSfJxl3VPFGQ
t1mingS1deChamn3l_gVQSfJxl3VPFGQ
t1mingS1deChann3l_gVQSfJxl3VPFGQ
Traceback (most recent call last):
  File "/home/nick/coding/ctf/reverse/checkpass/./solve.py", line 31, in <module>
    assert sca_res >= current_best
AssertionError
❯ ./checkpass picoCTF{t1mingS1deChann3l_gVQSfJxl3VPFGQ}
Success
```

## Reference
- [https://www.youtube.com/watch?v=HPmAzLMkENk](https://www.youtube.com/watch?v=HPmAzLMkENk)
- [https://valgrind.org/docs/manual/cg-manual.html](https://valgrind.org/docs/manual/cg-manual.html)
- [https://medium.com/spidernitt/introduction-to-timing-attacks-4e1e8c84b32b](https://medium.com/spidernitt/introduction-to-timing-attacks-4e1e8c84b32b)