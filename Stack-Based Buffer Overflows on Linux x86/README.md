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
    - Prevent system from functioning
      - Crash
        - Individual software
        - Entire system
  - WebApp
    - Allow command injection on
      - Application
      - Underlying database

## CPU Architecture

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
