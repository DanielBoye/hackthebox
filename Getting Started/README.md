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

## Whatweb





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

