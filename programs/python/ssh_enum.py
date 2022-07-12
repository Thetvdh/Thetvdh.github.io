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
