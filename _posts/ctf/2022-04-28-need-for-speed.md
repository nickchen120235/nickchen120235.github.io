---
layout: post
title: Change the flow of execution with GDB - picoCTF Need for Speed
tags: [CTF, reverse]
---
> The name of the game is [speed](https://www.youtube.com/watch?v=8piqd2BWeGI). Are you quick enough to solve this problem and keep it above 50 mph? [need-for-speed](https://jupiter.challenges.picoctf.org/static/cd51b2c95be9f3626db6fe6665afb5a3/need-for-speed).

*"Get ready for rush hour."*

## Ghidra
The `main` function is quite simple. It sets an alarm that triggers a `SIGALRM`, which then the program will exit. If we somehow get through it, we get the flag.
```c
undefined8 main(void)

{
  header();
  set_timer();
  get_key();
  print_flag();
  return 0;
}
```
```c
void set_timer(void)

{
  __sighandler_t p_Var1;
  
  p_Var1 = __sysv_signal(0xe,alarm_handler);
  if (p_Var1 == (__sighandler_t)0xffffffffffffffff) {
    puts("\n\nSomething bad happened here. ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  alarm(1);
  return;
}
```
`get_key` sets a global variable `key`, which will then be used by `print_flag`.
```c
void get_key(void)

{
  puts("Creating key...");
  key = calculate_key();
  puts("Finished");
  return;
}
```
```c
void print_flag(void)

{
  puts("Printing flag:");
  decrypt_flag(key);
  puts(flag);
  return;
}
```

## Attack
GDB can be used to modify values of variables and change the flow of execution on the fly. So here's our plan
1. Break at `main` to create a bullet-time effect.
2. Check what `calculate_key` returns and set it manually by using `set` command in GDB.
3. Call `print_flag` directly by using `call` command in GDB.
4. Hopefully it prints the flag!

`calculate_key` returns `0xed0cc64a`, the while loop is just for timing out the alarm.
```c
undefined4 calculate_key(void)

{
  int local_c;
  
  local_c = -0x25e6736c;
  do {
    local_c = local_c + -1;
  } while (local_c != -0x12f339b6);
  return 0xed0cc64a;
}
```
Disassemble `get_key`, and we see where `key` is.
```
gef➤  disass get_key
Dump of assembler code for function get_key:
   0x000055555540087d <+0>:     push   rbp
   0x000055555540087e <+1>:     mov    rbp,rsp
   0x0000555555400881 <+4>:     lea    rdi,[rip+0x1a0]        # 0x555555400a28
   0x0000555555400888 <+11>:    call   0x555555400610 <puts@plt>
   0x000055555540088d <+16>:    mov    eax,0x0
   0x0000555555400892 <+21>:    call   0x5555554007f1 <calculate_key>
   0x0000555555400897 <+26>:    mov    DWORD PTR [rip+0x2007bf],eax        # 0x55555560105c <key>
   0x000055555540089d <+32>:    lea    rdi,[rip+0x194]        # 0x555555400a38
   0x00005555554008a4 <+39>:    call   0x555555400610 <puts@plt>
   0x00005555554008a9 <+44>:    nop
   0x00005555554008aa <+45>:    pop    rbp
   0x00005555554008ab <+46>:    ret    
End of assembler dump.
```
At `0x55555560105c`. We then set its value to `0xed0cc64a` and call `print_flag` directly.
```
gef➤  set *0x55555560105c=0xed0cc64a
gef➤  call (int)print_flag()
Printing flag:
PICOCTF{Good job keeping bus #24c43740 speeding along!}
$1 = 0x38
```
There's the flag!

## Reference
- [https://sourceware.org/gdb/onlinedocs/gdb/Assignment.html](https://sourceware.org/gdb/onlinedocs/gdb/Assignment.html)
- [https://sourceware.org/gdb/onlinedocs/gdb/Calling.html#Calling](https://sourceware.org/gdb/onlinedocs/gdb/Calling.html#Calling)
- [https://www.youtube.com/watch?v=Eex75CLv66w](https://www.youtube.com/watch?v=Eex75CLv66w)