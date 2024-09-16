---
title: "Linux Cheatsheet!"
permalink: /useful/linux
---

# Find Distro and Kernel Information
```sh
cat /etc/*release # Shows Distro related information

uname -a #Useful for finding distro/kernel specific exploits
```

# Disk and Hardware information

```sh
free -h # Shows the system memory
cat /proc/cpuinfo
nproc # Shows number of cores
df  -h # Shows the space across the different volumes
lsblk # lists all available device drives
sudo du / -hd1 # Shows disk usage in human readable formats, d1 shows level of detail (folder depth)
sudo lshw > sysinfo.txt # Shows generic information about the system
ip addr # New way of listing adapter details 
```

# Find

```sh
find / -perm -u=s -type f 2>/dev/null # Finds all files with the SUID bit set.
```

# Misc

```sh
grep -i "/bin/bash" /etc/passwd | awk -F ":" '{print $1}' | sort > users.txt # list of users with a logon shell
```
