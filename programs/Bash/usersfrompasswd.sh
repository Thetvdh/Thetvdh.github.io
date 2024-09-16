#!/bin/sh
grep -i "/bin/bash" /etc/passwd | cut -d ":" -f 1 > users.txt
