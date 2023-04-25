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
  - Higher stirage capacity

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
   0x0000054d <+0>:	    push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:	    mov    ebp,esp   # <---- 2. Creates new Stack Frame
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 # <---- 3. Moves ESP to the top
   <...SNIP...>
   0x00000580 <+51>:	leave  
   0x00000581 <+52>:	ret    :	ret    
```

This is called the Prologue. Moving the ESP on the top for operations.



### Epilogue

```shell
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       
   0x0000054e <+1>:	    mov    ebp,esp   
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 
   <...SNIP...>
   0x00000580 <+51>:	leave  # <----------------------
   0x00000581 <+52>:	ret    # <--- Leave stack frame
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

## Determine the Length for Shellcode

## Identification of Bad Characters

## Generating Shellcode

## Identification of the Return Address

# Proof-Of-Concept

## Public Exploit Modification

## Prevention Techniques and Mechanisms

# Skills Assessment

## Skills Assessment - Buffer Overflow
