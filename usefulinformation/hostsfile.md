---
title: "Adding entries to your hosts file"
permalink: /useful/hostsfile
---

# Step 1: Open your /etc/hosts file as root in an editor of your choice

`sudo vim /etc/hosts`

# Step 2: Write a new line to the file
```
127.0.0.1 view-localhost
# Loopback entries; do not change.
# For historical reasons, localhost precedes localhost.localdomain:
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
# See hosts(5) for proper format and other examples:
# 192.168.1.10 foo.mydomain.org foo
# 192.168.1.13 bar.mydomain.org bar

{IPADDR}	{DOMAIN}
```

# Step 3: Save and exit the hosts file.
After saving and exiting the hosts file ping the domain you have added to see if it can resolve correctly.