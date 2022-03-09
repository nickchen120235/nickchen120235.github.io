---
layout: post
title: JavaScript VM? - TSJ CTF 2022 javascript_vm
tags: [CTF, reverse]
---
> There are two kinds of Javascript virtual machines. Those who understand Javascript (like node.js) and those who don’t (like … ?).
>
> Author: @wxrdnx

Attached are [chall.bin](https://github.com/nickchen120235/nickchen120235.github.io/raw/master/assets/data/javascript_vm.bin) and [the link to VM repo](https://github.com/francisrstokes/16bitjs).

## Disassemble
First I wrote a disassembler according to the VM repo.
```python
INSTRUCTION_MAP = ['MVR', 'MVV', 'LDR', 'STA', 'ATH', 'CAL', 'JCP', 'PSH', 'POP', 'JMP', 'JMR', 'LDA', 'STR', 'NOA']

REGISTERS = ['A', 'B', 'C', 'D']

def split_instruction(ins: int) -> tuple[int, int, int, int, int]:
  return (ins & 0b0000000000001111), ((ins & 0b0000000000110000) >> 4), (ins & 0b0000000011000000) >> 6, (ins & 0b1111111100000000) >> 8, (ins & 0b1111111111000000) >> 6

def decode_alu(high8: int, rs: int, rd: int) -> tuple[int, int, int]:
  return (high8 & 0b00001111), rd if ((high8 & 0b00010000) >> 4) == 0 else rs, (high8 & 0b11100000) >> 5

def decode(ins: int) -> str:
  opcode, rd, rs, high8, high10 = split_instruction(ins)
  jump_address = REGISTERS[high8 & 0b11]
  jump_offset = (ins >> 4)
  
  match INSTRUCTION_MAP[opcode]:
    case 'CAL': return f'CAL {REGISTERS[rd]}' # CAL D

    case 'JCP':
      match (high8 >> 2):
        case 0: return f'JEQ {REGISTERS[rd]} {REGISTERS[rs]} {jump_address}' # JUMP.EQ   JEQ D, S, A
        case 1: return f'JNE {REGISTERS[rd]} {REGISTERS[rs]} {jump_address}' # JUMP.NEQ  JNE D, S, A
        case 2: return f'JLT {REGISTERS[rd]} {REGISTERS[rs]} {jump_address}' # JUMP.LT   JLT D, S, A
        case 3: return f'JGT {REGISTERS[rd]} {REGISTERS[rs]} {jump_address}' # JUMP.GT   JGT D, S, A
        case 4: return f'JLE {REGISTERS[rd]} {REGISTERS[rs]} {jump_address}' # JUMP.LTE  JLE D, S, A
        case 5: return f'JGE {REGISTERS[rd]} {REGISTERS[rs]} {jump_address}' # JUMP.GTE  JGE D, S, A
        case 6: return f'JZE {REGISTERS[rd]} {REGISTERS[rs]} {jump_address}' # JUMP.ZER  JZE D, S, A
        case 7: return f'JNZ {REGISTERS[rd]} {REGISTERS[rs]} {jump_address}' # JUMP.NZE  JNZ D, S, A
    case 'JMP': return f'JMP {hex(jump_offset)}'   # JMP V
    case 'JMR': return f'JMR {REGISTERS[rd]}' # JMR S

    case 'MVR': return f'MVR {REGISTERS[rd]} {REGISTERS[rs]} {hex(high8)}' # MVR D, S, V
    case 'MVV':
      match (high10 & 3):
        case 0: return f'MVI {REGISTERS[rd]} {hex(high8)}' # MVI D, V
        case 1: return f'ADI {REGISTERS[rd]} {hex(high8)}' # ADI D, S
        case 2: return f'MUI {REGISTERS[rd]} {hex(high8)}' # MUI D, V
        case 3: return f'AUI {REGISTERS[rd]} {hex(high8)}' # AVI D, S
    case 'LDR': return f'LDR {REGISTERS[rd]} {REGISTERS[rs]} {hex(high8)}' # LDR D, S[, V]
    case 'LDA': return f'LDA {REGISTERS[rd]} {hex(high10)}'                # LDA D, M
    case 'STA': return f'STA {REGISTERS[rd]} {hex(high10)}'                # STA D, M
    case 'STR': return f'STR {REGISTERS[rd]} {REGISTERS[rs]} {hex(high8)}' # STR D, S[, V]

    case 'ATH':
      op, result_reg, shift = decode_alu(high8, rs, rd)
      match op:
        case 0: return f'ADD {REGISTERS[rd]} {REGISTERS[rs]}' if result_reg == rd else f'ADDS {REGISTERS[rd]} {REGISTERS[rs]}' # ADD(S) D, S
        case 1: return f'SUB {REGISTERS[rd]} {REGISTERS[rs]}' if result_reg == rd else f'SUBS {REGISTERS[rd]} {REGISTERS[rs]}' # SUB(S) D, S
        case 2: return f'MUL {REGISTERS[rd]} {REGISTERS[rs]}' if result_reg == rd else f'MULS {REGISTERS[rd]} {REGISTERS[rs]}' # MUL(S) D, S
        case 3: return f'DIV {REGISTERS[rd]} {REGISTERS[rs]}' if result_reg == rd else f'DIVS {REGISTERS[rd]} {REGISTERS[rs]}' # DIV(S) D, S
        case 4: return f'INC {REGISTERS[rd]}' # INC D
        case 5: return f'DEC {REGISTERS[rd]}' # DEC D

        case 6: return f'LSF {REGISTERS[rd]} {hex(shift)}' # LSF D, A
        case 7: return f'LSR {REGISTERS[rd]} {hex(shift)}' # LSR D, A

        case 8: return f'AND {REGISTERS[rd]} {REGISTERS[rs]}' # AND D, S
        case 9: return f'OR {REGISTERS[rd]} {REGISTERS[rs]}' # OR D, S
        case 10: return f'XOR {REGISTERS[rd]} {REGISTERS[rs]}' # XOR D, S
        case 11: return f'NOT {REGISTERS[rd]}' # NOT D

    case 'PSH': return f'PSH {REGISTERS[rs]}' # PSH S
    case 'POP': return f'POP {REGISTERS[rd]}' # POP D

    case 'NOA':
      match ((ins & 0xF0) >> 4):
        case 0: return f'NOP'
        case 1: return f'RET'
        case 2: return f'SYS'
        case 3: return f'HLT'

    case _: return 'Unknown instruction'

def chunks(lst: list, n: int):
  for i in range(0, len(lst), n):
    yield lst[i:i+n]

with open('./chall.bin', 'rb') as chall:
  raw = chall.read()
  num = 0
  for ins in chunks(raw, 2):
    try:
      print(f'[{hex(num)[2:]}] 0x{hex(int.from_bytes(ins, "little"))[2:].zfill(4)} -> {decode(int.from_bytes(ins, "little"))}')
    except Exception:
      print(f'[{hex(num)[2:]}] 0x{hex(int.from_bytes(ins, "little"))[2:].zfill(4)} -> Unable to disassemble, may be {chr(ins[1])}{chr(ins[0])}')
    # if decode(int.from_bytes(ins, "little")) == 'HLT': break
    num += 1
```

The disassembled instruction can be found [here](https://gist.github.com/nickchen120235/94eabbc4c53ce6586f9e1ac44591f083#file-disassembled). Notice that some portions of the binary may be static data, but I decoded them anyway.

## Analyse
Going through the disassembled instructions, the program can be divided into several parts by identifying the function prologue and epilogue like

### Function 1 (0x4b ~ 0x9b)
The first function deals with the inputs. Inputs are stored in offset `0x155` ~ `0x188`.

### Function 2 (0x9c ~ 0xd2)
This function is a permutation box, the main structure of this function is the following:
```
load from mem[0x155+C] into A -> B # load flag[C]
load from mem[0x120+C] into D      # load offset
load from mem[0x155+D](aka mem[0x155+mem[0x120+C]]) into D # load flag[D]
store D into mem[0x155+C] # store flag[D] into flag[C]
load from mem[0x120+C] into D # load offset
store B into mem[0x155+D] # store flag[C] into flag[D]
```

The swapping pairs can be found [here](https://gist.github.com/nickchen120235/94eabbc4c53ce6586f9e1ac44591f083#file-swapping-pairs).

### Function 3 (0xd3 ~ 0x11a)
This function does some sort of encoding. It loads a value from memory, adds with input, and `& 0xff` to extract only the last two bytes.

### Main Function (0x0 ~ 0x4a)
This is the main function where it calls the other three functions and do the final comparison. The inputs are processed 20 times by function 2 and 3. Notice that the offset where function 3 takes the value to be added is affected by the number of loops.

## Solve
```python
import copy
import itertools
import string

def chunks(lst: list, n: int):
  for i in range(0, len(lst), n):
    yield lst[i:i+n]

with open('./chall.bin', 'rb') as chall:
  raw = chall.read()

swap_index: list[int] = []
num = 0
for c in chunks(raw, 2):
  if num < 0x120:
    num += 1
    continue
  if num > 0x153: break
  cur = int.from_bytes(c, "little")
  assert 0 <= cur <= 51
  swap_index.append(cur)
  num += 1
assert len(swap_index) == 0x34

encode_list: list[int] = []
num = 0
for c in chunks(raw, 2):
  if num < 0x18a:
    num +=1
    continue
  if num > 0x1bf: break
  encode_list.append(int.from_bytes(c, "little"))
  num += 1

final_list: list[int] = []
num = 0
for c in chunks(raw, 2):
  if num < 0x1bf:
    num += 1
    continue
  if num > 0x1f2: break
  final_list.append(int.from_bytes(c, "little"))
  num += 1
assert len(final_list) == 0x34

input_flag = bytearray('TSJ{' + 'x'*(0x34-4-1) + '}', 'ascii')
assert len(input_flag) == 0x34
for pos in range(4, 0x34-1):
  # print(f'Bruteforcing position {pos}')
  result: list[int] = []
  for c in string.printable:
    input_flag[pos] = ord(c)
    flag = bytearray(copy.deepcopy(input_flag))

    for i in range(0x20):
      for j in range(0x34):
        temp = flag[j]
        flag[j] = flag[swap_index[j]]
        flag[swap_index[j]] = temp

      for j in range(0x34):
        d = i + j + 0xb
        a = d // 0x34
        a = a * 0x34
        d = d - a
        a = encode_list[d]
        b = flag[j]
        a = (a + b) & 0xff
        flag[j] = a
    result.append([flag[j] == final_list[j] for j in range(0x34)].count(True))
  print(string.printable[result.index(max(result))], end='', flush=True)
```
This is the final bruteforcing script. At first I tried to bruteforced all possible combinations but it turned out that each position of the input only affects one position of the output.

`TSJ{17_15_n07_7h3_j4v45cr1p7_vm_y0u_r_f4m1l14r_w17h}`