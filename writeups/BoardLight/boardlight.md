---
title: "BoardLight(HTB)"
permalink: /writeups/boardlight
---

# <a href="https://app.hackthebox.com/machines/BoardLight" target="_blank">BoardLight (HTB)</a>

![BoardLight HTB Logo](/writeups/BoardLight/logo.png "Logo")

## Tags
ctf, htb, hack the box, easy, BoardLight

## Metadata

| Written | 23/08/2024
| Author | Thetvdh
| Platform | HackTheBox
| Box Type | Linux

# Foreword

This writeup is for the HackTheBox machine "BoardLight". I am going to do a hybrid style writeup with a part similar to my original writeups from before, but with a few extra bits to make it more pentest report style. Some parts will detail as if this was a real company approaching myself to test their application. I hope you enjoy reading it.

# Introduction

A new startup known as "BoardLight" approached the pentester known as "the tester" for a web application and web infrastructure test. It was agreed between the tester and the company that any Tool, Tactic, or Procedure (TTP) was allowed, excluding Denial of Service with the goal of gaining access to the web infrastructure and compromising an administrative account. The tester was provided with an IP address and no further information meaning this is a "black box" penetration test. No blue team would be working against the tester meaning there was no requirement to operate quietly. A Virtual Private Network (VPN) connection will be provided to the tester to access the corporate network so they are able to target the server without it requiring an internet connection. The IP address provided to the tester was 10.10.11.11 and the IP address of the VPN connection from the testers "attacker" machine was 10.10.14.223.

# Mission Objectives

- Find vulnerabilities in the website
- Attempt to compromise the underlying infrastructure
- Compromise the administrative "root" account on the host
- Find and retrieve "flags" (user.txt, root.txt) placed on the host

# Executive Summary

A test of BroadLight's web application revealed multiple critical vulnerabilities that can be easily exploited which would allow unauthorized access to BroadLight web infrastructure and potentially lead to compromise of sensitive business data.

## Key findings

- Remote Code execution:
    A vulnerable version of the application "Dolibarr" is running on a subdomain of the main website. This exposed the application to remote code execution allowing an attacker to run commands on the server.

- Plain text credentials:
    Configuration files for "Dolibarr" contained plain text credentials for a MySQL database user, allowing unauthorised access to the database. This could be used to steal sensitive business information or gain credentials to further compromise other business assets

- Password Reuse:
    The database user account and the user "larissa" shared the same password. This allows an attacker to compromise a higher privileged user account using credentials found for a different user. Password reuse significantly increases chance of further compromise should one of the accounts be compromised.

- Default Credentials: 
    The Dolibarr installation was found to be using the default credentials. This indicates a significant security oversight and allowed unauthorised access.

- Privilege Escalation Vulnerability
    The Desktop Environment "Enlightenment" was present on the system and was found to be vulnerable, allowing for escalation to root privileges. This would allow an attacker to gain complete control over a system.

## Remediation recommendations

- Dolibarr patch:
    Apply the most up to date patch for Dolibarr to remove the remote code execution vulnerability.

- Secure Configuration Files:
    Store sensitive configuration details in a secure manner, such as using encryption or a secrets manager

- Implement Strong Password Policies:
    Enforce strong password policies to prevent weak and reused passwords.

- Regular Security Assessments
    Once remediation actions have taken place, retest the application by either using methodology outlined in this report or use a pentester to test for you.

Following these remediation steps will significantly reduce the risk of a cyberattack against BroadLight, and any reputational or financial consequences that would come out of any breaches.


# Technical report

Target IP: 10.10.11.11
Attacker IP: 10.10.14.223

## Vulnerabilities overview

| Name | Vulnerability | Type | CVSS score | CWE ID
| Dolibarr Remote Code execution | CVE-2023-30253 | RCE | 8.8 | CWE-78
| Plaintext Database Credentials | N/A | Information Disclosure | N/A | CWE-312
| Password Reuse | N/A | Identification and Authentication Failures | N/A | CWE-255
| Default Credentials| N/A | Identification and Authentication Failures | N/A | CWE-255
| Enlightenment Privilege Escalation | CVE-2022-37706 | Privilege Escalation | 7.8 | CWE-269

## Methodology

### Tool based enumeration

**Tools Used**
- nmap
- Burp Suite
- ping
- Fuzz Faster (ffuf)


Initial ICMP packets were sent via the ping command to ensure the server was alive, once this was confirmed two nmap scans were run against the target machine. One scan was to enumerate the 1000 most common ports with service enumeration and common scripts enabled, the second was to enumerate all open TCP ports.

The results of these nmap scans are as follows:

**1000 most common ports**
```
# Nmap 7.94SVN scan initiated Fri Aug 23 16:28:20 2024 as: nmap -sV -sC -T4 -oN nmap/normal 10.10.11.11
Nmap scan report for 10.10.11.11
Host is up (0.027s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 23 16:28:29 2024 -- 1 IP address (1 host up) scanned in 9.38 seconds
```

**All ports scan:**
```
# Nmap 7.94SVN scan initiated Fri Aug 23 16:28:40 2024 as: nmap -p- -oN nmap/allports 10.10.11.11
Nmap scan report for 10.10.11.11
Host is up (0.022s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Fri Aug 23 16:29:29 2024 -- 1 IP address (1 host up) scanned in 49.38 seconds
```

These nmap scans reveal that there are two open ports:

- Port 22: SSH
- Port 80: http

Accessing the IP address via a web browser revealed the company's website. The website appeared to be in early stages and a predominantly static website with the contact forms and other buttons not appearing to do anything significant. Burp Suite was used to log crawling of the website to gather all HTTP requests sent while navigating the website. This did not lead to any significant findings.

Fuzz Faster (ffuf) was used to fuzz for potential hidden directories and or pages on the website. A common paths wordlist was used along with a command line argument to additonally search for .php files. The command was as follows:
```sh
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.11.11/FUZZ
```
This led to no significant findings.

### Manual enumeration

Manual analysis of the site content revealed a contact email address at the bottom of the homepage. The email address in question, info@board.htb, allowed for an educated guess that the IP address would resolve to the same domain should DNS be used upon deployment. Manually adding this domain to the hosts file allowed for further tool based enumeration of the web applicaiton.

### Further tool based enumeration

Using ffuf once again, a scan for subdomains was launched by fuzzing the Host HTTP parameter. The command was as follows:
```sh
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://board.htb -H "Host: FUZZ.board.htb"
```

This command generated a large number of false positives and as such a filter was added to eliminate invalid findings

```sh
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://board.htb -H "Host: FUZZ.board.htb" -fs 15949
```

This revealed the subdomain crm.board.htb

Testers Note:

At this point it is important to note that this enumeration needed to be done in this manner because the website does not interface with any public DNS records. Should the site be put live, the subdomain would likely be crawled by search engines and publically accessible without needing to perform host fuzzing.

### crm.board.htb enumeration

Upon discovery of the subdomain, crm.board.htb was added to the hosts file on the attackers local machine. Then a new nmap scan was run against the domain and some new findings were revealed.

```
# Nmap 7.94SVN scan initiated Fri Aug 23 16:52:52 2024 as: nmap -sC -sV -p80 -oN nmap/crm80scan crm.board.htb
Nmap scan report for crm.board.htb (10.10.11.11)
Host is up (0.039s latency).
rDNS record for 10.10.11.11: board.htb

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login @ 17.0.0
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 23 16:53:00 2024 -- 1 IP address (1 host up) scanned in 7.61 seconds
```

The main finding from this nmap scan was the revealing of the robots.txt file, contents of which can be found below:
```
User-agent: *
Allow: /public/agenda/agendaexport.php
Allow: /public/demo/
Allow: /public/members/new.php
Allow: /index.php
#Allow: /$
Disallow: /
```

These endpoints were briefly checked but did not lead to anything, they were checked while unauthenticated.

The landing page for crm.broad.htb was a login page and a Google search led to discovering default credentials for the application to be admin:admin on a forum post <a href="https://www.dolibarr.org/forum/t/login-after-installation/16088">https://www.dolibarr.org/forum/t/login-after-installation/16088</a>

Furthermore, the initial landing page showed the version number of Dolibarr which led to the discovery that this version was vulnerable to CVE-2023-30253.

To summarise, CVE-2023-30253 is a remote code execution vulnerability by an authenticated user by abusing poor input sanitisation allowing for a <?PHP to be considered legitimate PHP code and executed.

This is a high severity vulnerability but in the context of BroadLight's application, I believe it to be a critical vulnerability as this is easily chained with the use of default credentials.

For exploitation, a POC exploit was used from GitHub <a href="https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253?tab=readme-ov-file">https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253?tab=readme-ov-file</a>

Creating a netcat listener on the attack machine on port 4432 allowed for a reverse shell to be spawned and a connection established between the server and the attacker.

**MISSION OBJECTIVES 1 AND 2 COMPLETE**

### www-data escalation to larissa

The initial shell was stabilised using the following commands:

```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
CTRL+Z stty -echo raw;fg
```

This allowed for a more stable shell where autocompletion, arrow keys for command history, and protection from accidentally killing the shell using CTRL+C

**Enumeration**

Reading of the Dolibarr documentation pointed to a config file called conf.php. Using the find command this file was able to be located at /var/www/html/crm.board.htb/htdocs/conf/conf.php

Command used:
```sh
find / -name conf.php 2>/dev/null
```

Accessing this file revealed plain text credentials for the database user "dolibarrowner"

Enumeration of the database led to discovery of the password hash for the Dolibarr superuser. As the website had already been compromised via the Remote Code Execution exploit, and the has was identified as Bcrypt using name-that-hash, it was decided that cracking was unneccessary at this time.

Further enumeration of the /etc/passwd file revealed the user "larissa". Users with logins are identified using the following command:

```sh
grep -E /bin/(bash|sh) /etc/passwd
```

Upon this discovery, checks were made to see if the user www-data could run any commands as larissa via sudo, cron, SUID/SGID, along with other unsucessful methods of enumeration.

After enumeration, the discovered password in the conf.php file was used to successfully switch to the larissa user, leading to the discovery of the artefact user.txt

**MISSION OBJECTIVE 4.1 (user.txt) COMPLETE**

### Privilege escalation to root

To maintain better persistence as larissa, ssh keys were generated using ssh-keygen. As this is an already open, preconfigured port, this will allow any further traffic to blend in with existing traffic over the network.

Using the newly created ssh session as larissa, enumeration on basics was undertaken.

Findings:

- User cannot run sudo (sudo -l)
- User has no cron jobs (crontab -e)
- SUID bits set on: 
    - /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
    - /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
    - /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
    - /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset

These are non standard SUID bits and therefore stood out.

Searches for vulnerabilities of enlightenment revealed CVE-2022-37706 which mishandles pathnames that begin with a /dev/../ substring. This exploit is compiled into a bash script at <a href="https://www.exploit-db.com/exploits/51180">https://www.exploit-db.com/exploits/51180</a>

The script needed to be slightly refactored to execute correctly, executing the script granted root privileges and navigating to the /root directory led to root.txt

**ALL MISSION OBJECTIVES COMPLETE**

### Cleanup

All artefacts were removed from the system post exploitation, below is a list of artefacts created:

- /home/larissa/Documets/exploit.sh
- /tmp/exploit
- /dev/../tmp/

# Afterword

I am no pentester, I have only ever written a pentest report for uni and it was (ironically) my lowest mark to date. I hope this report was interesting to read and if anyone has any feedback on how I can improve please let me know on Twitter @Thetvdh1. Thank you all for reading, I hope you found this informative without being my usual step by step walkthrough of the box.