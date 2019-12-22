import os
import subprocess
import socket
import time

# stage 1
args = list("A"*100)
args[0] = "/home/input2/input"
args[ord('A')] = ""
args[ord('B')] = "\x20\x0a\x0d"
args[ord("C")] = "8080"

# stage 2
stdin_r, stdin_w = os.pipe()
stderr_r, stderr_w = os.pipe()
os.write(stdin_w, "\x00\x0a\x00\xff")
os.write(stderr_w, "\x00\x0a\x02\xff")

# stage 3
env = {"\xde\xad\xbe\xef": "\xca\xfe\xba\xbe"}

# stage 4
with open("\x0a", "wb") as f:
    f.write("\x00"*4)

# open a subprocess here because we need a server
p = subprocess.Popen(args, stdin=stdin_r,stderr=stderr_r,env=env)

# stage 5
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1) # wait 4 server
s.connect(("127.0.0.1", 8080))
s.send("\xde\xad\xbe\xef")
s.close()