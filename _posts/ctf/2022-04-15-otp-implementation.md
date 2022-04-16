---
layout: post
title: One time password? - picoCTF OTP Implementation
tags: [CTF, reverse]
---
> Yay reversing! Relevant files: [otp](https://jupiter.challenges.picoctf.org/static/929a56f71d3918fc903c68b3ea4a76da/otp) [flag.txt](https://jupiter.challenges.picoctf.org/static/929a56f71d3918fc903c68b3ea4a76da/flag.txt)

`flag.txt` seems to be an encrypted flag in hex format. ~~This is a reverse challenge anyway, so let's head over to Ghidra.~~
## Ghidra
This is the decompiled `main` function. Variables are renamed for readability.
```c
int main(int argc,char **argv)
{
  char jumble_result;
  byte shift;
  int is_valid;
  long in_FS_OFFSET;
  int while_idx;
  int i;
  char input_key [100];
  undefined _;
  char output [104];
  long _stack_canary;
  
  _stack_canary = *(long *)(in_FS_OFFSET + 0x28);
  if (argc < 2) {
    printf("USAGE: %s [KEY]\n",*argv);
    is_valid = 1;
  }
  else {
    strncpy(input_key,argv[1],100);
    _ = 0;
    while_idx = 0;
    while( true ) {
      is_valid = valid_char(input_key[while_idx]);
      if (is_valid == 0) break;
      if (while_idx == 0) {
        jumble_result = jumble();
        shift = (byte)(jumble_result >> 7) >> 4;
        output[0] = (jumble_result + shift & 0xf) - shift;
      }
      else {
        jumble_result = jumble();
        shift = (byte)((int)jumble_result + (int)output[while_idx + -1] >> 0x37);
        output[while_idx] =
             ((char)((int)jumble_result + (int)output[while_idx + -1]) + (shift >> 4) & 0xf) -
             (shift >> 4);
      }
      while_idx = while_idx + 1;
    }
    for (i = 0; i < while_idx; i = i + 1) {
      output[i] = output[i] + 'a';
    }
    if (while_idx == 100) {
      is_valid = strncmp(output,
                         "lfmhjmnahapkechbanheabbfjladhbplbnfaijdajpnljecghmoafbljlaamhpaheonlmnpmad dhngbgbhobgnofjgeaomadbidl"
                         ,100);
      if (is_valid == 0) {
        puts("You got the key, congrats! Now xor it with the flag!");
        is_valid = 0;
        goto LAB_001009ea;
      }
    }
    puts("Invalid key!");
    is_valid = 1;
  }
LAB_001009ea:
  if (_stack_canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return is_valid;
}
```
So the program takes an input of 100 characters, do some transformation and compare with the target string. The `valid_char` function restricts the input characters to be only one of `0123456789abcdef`. The `jumble` function does some computation to initial input.
```c
char jumble(char param_1)
{
  byte ZERO;
  char local_c;
  
  local_c = param_1;
  if ('`' < param_1) {
    local_c = param_1 + '\t';
  }
  ZERO = (byte)(local_c >> 7) >> 4;
  local_c = ((local_c + ZERO & 0xf) - ZERO) * '\x02';
  if ('\x0f' < local_c) {
    local_c = local_c + '\x01';
  }
  return local_c;
}
```
> Note: I don't know why when decompiling `main`, there are `jumble()` calls without arguments.

## Attack
The solution is simple. Since we have the decompiled code, we can just implement our version of `jumble` and all the other transformation with guessing mechanism. ~~I don't know why but I struggled through this.~~

After getting the key, `xor` the key with `flag.txt` and get the real flag.

The following is my solution script
```python
target = [ord(x) - ord('a') for x in "lfmhjmnahapkechbanheabbfjladhbplbnfaijdajpnljecghmoafbljlaamhpaheonlmnpmaddhngbgbhobgnofjgeaomadbidl"]
valid_input = "0123456789abcdef"
output = [0] * 100
key = [0] * 100

def jumble(c: str) -> int:
  assert len(c) == 1
  local_c = ord(c)
  if (ord('`') < local_c): local_c = local_c + ord('\t')
  somevar = (local_c >> 7) >> 4
  local_c = ((local_c + somevar & 0xf) - somevar) * 0x02
  if (0xf < local_c): local_c = local_c + 1
  return local_c

for i in range(100):
  for c in valid_input:
    if i == 0:
      a = jumble(c)
      shift = (a >> 7) >> 4
      res = (a + shift & 0xf) - shift
      if (res == target[0]):
        print(f"Found key[0] = {c}")
        output[i] = res
        key[i] = c
        break
    else:
      a = jumble(c)
      shift = a + output[i-1] >> 0x37
      res = (a + output[i-1]) + (shift >> 4) & 0xf - (shift >> 4)
      if (res == target[i]):
        print(f"Found key[{i}] = {c}")
        output[i] = res
        key[i] = c
        break

final_key = ''.join(key)
print(f"Key = {final_key}")

with open("flag.txt", "r") as f:
  flag_enc = f.read()
flag_xor = int(flag_enc, 16) ^ int(final_key, 16)
flag_str = hex(flag_xor)[2:]
flag = "".join([chr(int(flag_str[i:i+2], 16)) for i in range(0, len(flag_str), 2)])
print(f"Flag = {flag}")
```
> Note: Some writeups use `ltrace` output as an oracle to bruteforce the key. That's also a good strategy if you don't want to deal with the logic within the program.