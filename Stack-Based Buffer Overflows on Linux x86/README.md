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

## CPU Registers

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
