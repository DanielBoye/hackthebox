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
